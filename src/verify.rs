//! Checks whether a jitoSOL vote-override proposal can actually be submitted and
//! executed, against live chain state.
//!
//! Ported from Jito's proposal tooling so both report identically; only the
//! account-layout import below differs, pointing at `crate::governance`.

use std::{path::PathBuf, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use borsh::BorshDeserialize;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;

use crate::governance::{
    get_proposal_transaction_address, GovernanceV2, InstructionData, ProposalTransactionV2,
    ProposalV2,
};

use crate::{
    invariants::{
        canonical_digest, check_invariants, distinct_stake, unexpected_options, vote_tally,
        DecodedOverride, InvariantParams, Problem, VoteSplit,
    },
    svmgov::{anchor_discriminator, fold_merkle_proof, sha256, SvmgovProposal},
    timestamp::{format_utc, humanise_seconds},
};

/// How far past the check the payload must stay executable when no horizon is given.
/// A verifier that only asks "is it valid right now" answers a question nobody needs:
/// the payload is signed now and executed later.
pub const DEFAULT_HORIZON_SECONDS: i64 = 72 * 3_600;

/// Decoded `ncn_snapshot::MetaMerkleProof` account data.
struct OnChainMetaProof {
    voting_wallet: Pubkey,
    vote_account: Pubkey,
    stake_merkle_root: [u8; 32],
    active_stake: u64,
    proof: Vec<[u8; 32]>,
    close_timestamp: i64,
}

/// MetaMerkleProof layout: discriminator(8) payer(32) consensus_result(32)
/// leaf{voting_wallet(32) vote_account(32) stake_merkle_root(32) active_stake(8)}
/// proof(4 + 32n) close_timestamp(8).
fn decode_meta_merkle_proof(data: &[u8]) -> Result<OnChainMetaProof> {
    if data.len() < 180 {
        bail!("MetaMerkleProof account is only {} bytes", data.len());
    }
    let count = u32::from_le_bytes(data[176..180].try_into().unwrap()) as usize;
    let end = 180 + 32 * count;
    if data.len() < end + 8 {
        bail!(
            "MetaMerkleProof declares {count} proof nodes but is only {} bytes",
            data.len()
        );
    }
    Ok(OnChainMetaProof {
        voting_wallet: Pubkey::new_from_array(data[72..104].try_into().unwrap()),
        vote_account: Pubkey::new_from_array(data[104..136].try_into().unwrap()),
        stake_merkle_root: data[136..168].try_into().unwrap(),
        active_stake: u64::from_le_bytes(data[168..176].try_into().unwrap()),
        proof: (0..count)
            .map(|i| data[180 + 32 * i..212 + 32 * i].try_into().unwrap())
            .collect(),
        close_timestamp: i64::from_le_bytes(data[end..end + 8].try_into().unwrap()),
    })
}

/// Extracts the proposal address from a Realms URL or accepts a bare address.
fn parse_realms_proposal(value: &str) -> Result<Pubkey> {
    let trimmed = value
        .split(['?', '#'])
        .next()
        .unwrap_or(value)
        .trim_end_matches('/');
    let candidate = trimmed.rsplit('/').next().unwrap_or(trimmed);
    Pubkey::from_str(candidate).map_err(|_| {
        anyhow!("could not read a proposal address out of {value:?} (parsed {candidate:?})")
    })
}

/// Reads a submitted proposal's instructions back out of its on-chain
/// ProposalTransaction accounts.
fn load_onchain_instructions(
    state: &GovernanceContext,
    proposal: &Pubkey,
) -> Result<(Vec<InstructionData>, Vec<Problem>, Option<i64>)> {
    let mut problems = Vec::new();
    let data = state
        .rpc
        .get_account_data(proposal)
        .with_context(|| format!("fetching Realms proposal {proposal}"))?;
    let parsed = ProposalV2::deserialize(&mut &data[..]).context("borsh-decoding ProposalV2")?;

    println!("Realms proposal      : {proposal}");
    println!("  name               : {}", parsed.name);
    println!("  state              : {:?}", parsed.state);
    println!("  governance         : {}", parsed.governance);
    if parsed.governance != state.governance {
        problems.push(Problem {
            check: "governance",
            detail: format!(
                "proposal is governed by {}, expected {}",
                parsed.governance, state.governance
            ),
        });
    }

    if parsed.options.is_empty() {
        bail!("proposal {proposal} has no options");
    }
    // Every option, not just option 0. Under SingleChoice the resolver picks the
    // winning option by vote weight, so an option this tool never reads is exactly
    // the one that could execute. The audited creation path only ever builds option
    // 0, which makes anything under a higher option a finding rather than a variant.
    println!("  options            : {}", parsed.options.len());
    // Flagged up front, before any of them is read, so an option carrying transactions
    // is reported even if fetching its accounts later fails.
    for index in unexpected_options(
        &parsed
            .options
            .iter()
            .map(|option| option.transactions_count)
            .collect::<Vec<_>>(),
    ) {
        problems.push(Problem {
            check: "unexpected option",
            detail: format!(
                "option {index} ({}) carries {} transaction(s); the generator only ever \
                 populates option 0, so these were added by something else and are not \
                 covered by the reviewed payload",
                parsed.options[index].label, parsed.options[index].transactions_count
            ),
        });
    }

    let mut instructions = Vec::new();
    let mut missing = Vec::new();
    let mut executed = 0usize;
    let mut max_hold_up = 0u32;
    for (option_index, option) in parsed.options.iter().enumerate() {
        let expected = option.transactions_count;
        println!(
            "    option {option_index} ({}) : {expected} declared, {} executed",
            option.label, option.transactions_executed_count
        );
        let option_seed = u8::try_from(option_index)
            .map_err(|_| anyhow!("proposal has more than 255 options"))?;
        for index in 0..expected {
            let address = get_proposal_transaction_address(
                &state.program_id,
                proposal,
                &option_seed.to_le_bytes(),
                &index.to_le_bytes(),
            );
            match state.rpc.get_account_data(&address) {
                Ok(bytes) => {
                    let transaction = ProposalTransactionV2::deserialize(&mut &bytes[..])
                        .with_context(|| format!("borsh-decoding ProposalTransaction {address}"))?;
                    if transaction.executed_at.is_some() {
                        executed += 1;
                    }
                    max_hold_up = max_hold_up.max(transaction.hold_up_time);
                    instructions.extend(transaction.instructions);
                }
                Err(_) => missing.push((option_index, index)),
            }
        }
    }
    // A gap means an insert never landed — the proposal looks complete in the UI
    // but would execute short.
    if !missing.is_empty() {
        problems.push(Problem {
            check: "missing transactions",
            detail: format!(
                "{} ProposalTransaction account(s) do not exist (first few, as \
                 option/index: {:?})",
                missing.len(),
                &missing[..missing.len().min(5)]
            ),
        });
    }
    if executed > 0 {
        println!("  already executed   : {executed} transaction(s)");
    }

    // The earliest moment the chain will let this execute. Derived, not guessed: a
    // proof that closes before this can never be used, no matter when anyone acts.
    let earliest_execution =
        derive_earliest_execution(state, &parsed, max_hold_up).unwrap_or_else(|err| {
            println!("  execution window   : not derivable ({err:#})");
            None
        });
    if let Some(at) = earliest_execution {
        println!(
            "  can execute from   : {} (hold-up {max_hold_up}s)",
            format_utc(at)
        );
    }
    Ok((instructions, problems, earliest_execution))
}

/// Prints the verdict and its reasons.
///
/// The list is capped: a wholly malformed payload produces one problem per instruction,
/// and 882 lines of the same message buries anything else that was found.
fn print_verdict(problems: &[Problem]) {
    const SHOWN: usize = 20;
    println!();
    if problems.is_empty() {
        println!("EXECUTABLE — every precondition checked out.");
        return;
    }
    println!("NOT EXECUTABLE — {} problem(s):", problems.len());
    for problem in problems.iter().take(SHOWN) {
        println!("  [{}] {}", problem.check, problem.detail);
    }
    if let Some(hidden) = problems.len().checked_sub(SHOWN).filter(|n| *n > 0) {
        println!("  ... and {hidden} more");
    }
}

/// When the chain will first allow `ExecuteTransaction`, from the proposal's own state.
///
/// A proposal still in Voting has not fixed its completion time, so the latest possible
/// end of voting is used — the conservative choice, since assuming an earlier deadline
/// would understate how long the proofs must survive.
fn derive_earliest_execution(
    state: &GovernanceContext,
    proposal: &ProposalV2,
    hold_up: u32,
) -> Result<Option<i64>> {
    if let Some(completed) = proposal.voting_completed_at {
        return Ok(Some(completed + hold_up as i64));
    }
    let Some(voting_at) = proposal.voting_at else {
        // Still a draft: nothing has started, so there is no window to compute.
        return Ok(None);
    };
    let data = state
        .rpc
        .get_account_data(&proposal.governance)
        .with_context(|| format!("fetching governance {}", proposal.governance))?;
    let governance =
        GovernanceV2::deserialize(&mut &data[..]).context("borsh-decoding GovernanceV2")?;
    let base = proposal
        .max_voting_time
        .unwrap_or(governance.config.voting_base_time) as i64;
    Ok(Some(
        voting_at + base + governance.config.voting_cool_off_time as i64 + hold_up as i64,
    ))
}

/// Everything the checks need about the DAO, so this module does not depend on
/// the proposal tool's `DaoState`.
pub struct GovernanceContext<'a> {
    pub rpc: &'a RpcClient,
    /// spl-governance program owning the realm.
    pub program_id: Pubkey,
    pub governance: Pubkey,
    pub native_treasury: Pubkey,
}

/// What a verification run concluded, returned rather than only printed.
///
/// `NOT EXECUTABLE` used to exit 0, so nothing automated could gate on the verdict.
/// The caller now decides the exit status, and `--report` renders from these fields
/// instead of re-deriving them.
pub struct Verdict {
    pub problems: Vec<Problem>,
    pub instructions: usize,
    pub stake_accounts: usize,
    pub total_stake: u64,
    pub votes: std::collections::BTreeMap<VoteSplit, Vec<usize>>,
    pub digest: String,
}

impl Verdict {
    pub fn executable(&self) -> bool {
        self.problems.is_empty()
    }
}

pub fn verify_proposal(
    state: &GovernanceContext,
    proposal_path: Option<&PathBuf>,
    realms_url: Option<&str>,
    svmgov_program_id: &Pubkey,
    snapshot_program_id: &Pubkey,
    max_instruction_bytes: usize,
    execution_horizon: Option<i64>,
) -> Result<Verdict> {
    // Set only on the on-chain path; an artifact has no voting schedule to derive from.
    let mut execution_at: Option<i64> = None;
    // Size only gates submission. Instructions already on-chain cleared it by
    // definition, so the budget check is skipped for the on-chain path.
    let (raw_instructions, mut problems, check_size) = match (proposal_path, realms_url) {
        (Some(path), None) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            let doc: serde_json::Value = serde_json::from_str(&raw)
                .with_context(|| format!("parsing {}", path.display()))?;
            let encoded = doc
                .get("instructions_base64")
                .and_then(|value| value.as_array())
                .ok_or_else(|| anyhow!("{} has no instructions_base64 array", path.display()))?;
            let mut decoded = Vec::with_capacity(encoded.len());
            for (index, value) in encoded.iter().enumerate() {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(value.as_str().unwrap_or_default())
                    .with_context(|| format!("instructions_base64[{index}] is not valid base64"))?;
                decoded.push(InstructionData::try_from_slice(&bytes).with_context(|| {
                    format!("instructions_base64[{index}] is not an InstructionData")
                })?);
            }
            println!("{}", path.display());
            (decoded, Vec::new(), true)
        }
        (None, Some(url)) => {
            let address = parse_realms_proposal(url)?;
            let (instructions, problems, earliest) = load_onchain_instructions(state, &address)?;
            execution_at = earliest;
            (instructions, problems, false)
        }
        _ => bail!("pass exactly one of --proposal or --realms-url"),
    };

    // --- 1. shape --------------------------------------------------------
    // Every rule that needs nothing but the payload lives in `invariants`, which is
    // pure and unit-tested. Below this point the checks need the chain.
    let params = InvariantParams {
        svmgov_program_id: *svmgov_program_id,
        discriminator: anchor_discriminator("global:cast_vote_override"),
    };
    let (overrides, shape_problems) = check_invariants(&raw_instructions, &params);
    problems.extend(shape_problems);
    // Fingerprint of how this run *interpreted* the payload, for comparison against an
    // independent implementation. Equal digests mean equal readings, not equal bytes.
    let digest = canonical_digest(&raw_instructions);
    if overrides.is_empty() {
        // Every instruction failed. That is a verdict, not an inability to check, so it
        // has to exit like one: bailing here reported exit 1 ("could not complete") for
        // a payload that is definitively wrong.
        problems.push(Problem {
            check: "payload",
            detail: format!(
                "none of the {} instruction(s) decoded as a valid cast_vote_override",
                raw_instructions.len()
            ),
        });
        println!("  invariant digest   : {digest}");
        print_verdict(&problems);
        return Ok(Verdict {
            problems,
            instructions: 0,
            stake_accounts: 0,
            total_stake: 0,
            votes: std::collections::BTreeMap::new(),
            digest,
        });
    }
    let (stake_accounts, total_stake) = distinct_stake(&overrides);
    println!("  instructions       : {}", overrides.len());
    // Counted per stake account, not per instruction. The payload bundles three
    // svmgov proposals, so summing instructions reports three times the real weight.
    println!(
        "  stake              : {:.0} SOL across {stake_accounts} stake account(s)",
        total_stake as f64 / 1e9
    );
    // Every distinct vote, not just instruction 0's. Printing only the first is how a
    // payload with one instruction flipped rendered identically to a clean one.
    let tally = vote_tally(&overrides);
    for (vote, indices) in &tally {
        println!(
            "  vote               : {vote} on {} instruction(s){}",
            indices.len(),
            if tally.len() > 1 {
                format!(
                    " (first: ix {})",
                    indices.first().copied().unwrap_or_default()
                )
            } else {
                String::new()
            }
        );
    }
    println!("  invariant digest   : {digest}");

    // --- 2. signer authority --------------------------------------------
    let signers = overrides
        .iter()
        .map(|o| o.signer)
        .collect::<std::collections::BTreeSet<_>>();
    for signer in &signers {
        if *signer != state.native_treasury && *signer != state.governance {
            problems.push(Problem {
                check: "signer authority",
                detail: format!(
                    "{signer} is neither the governance {} nor its treasury {}; \
                     ExecuteTransaction cannot sign for it",
                    state.governance, state.native_treasury
                ),
            });
        }
    }

    // --- 3. svmgov proposal + voting window ------------------------------
    let svmgov_proposals = overrides
        .iter()
        .map(|o| o.svmgov_proposal)
        .collect::<std::collections::BTreeSet<_>>();
    println!("  svmgov proposals   : {}", svmgov_proposals.len());

    let epoch_info = state.rpc.get_epoch_info().context("fetching epoch info")?;
    let mut consensus_results = std::collections::BTreeSet::new();
    for svmgov_proposal in &svmgov_proposals {
        let proposal_data = state
            .rpc
            .get_account_data(svmgov_proposal)
            .with_context(|| format!("fetching svmgov proposal {svmgov_proposal}"))?;
        let svm = SvmgovProposal::deserialize(&mut &proposal_data[8..])
            .context("borsh-decoding svmgov Proposal")?;
        let group = overrides
            .iter()
            .filter(|o| o.svmgov_proposal == *svmgov_proposal)
            .collect::<Vec<_>>();
        let (accounts, stake) = distinct_stake(group.iter().copied());
        println!(
            "    {svmgov_proposal}  {} ix  {accounts} stake  {:.0} SOL  epochs [{}, {})  {}",
            group.len(),
            stake as f64 / 1e9,
            svm.start_epoch,
            svm.end_epoch,
            svm.title
        );
        if svm.finalized {
            problems.push(Problem {
                check: "svmgov proposal",
                detail: format!("{svmgov_proposal} is already finalized"),
            });
        }
        if epoch_info.epoch < svm.start_epoch || epoch_info.epoch >= svm.end_epoch {
            problems.push(Problem {
                check: "voting window",
                detail: format!(
                    "{svmgov_proposal}: epoch {} is outside [{}, {})",
                    epoch_info.epoch, svm.start_epoch, svm.end_epoch
                ),
            });
        }
        match svm.consensus_result {
            Some(consensus) => {
                consensus_results.insert(consensus);
            }
            None => problems.push(Problem {
                check: "consensus result",
                detail: format!("{svmgov_proposal} has no consensus_result set"),
            }),
        }
    }
    // Every instruction embeds leaves and proofs from one snapshot, so a bundle
    // spanning two consensus results could never verify.
    if consensus_results.len() > 1 {
        bail!(
            "proposal bundles svmgov proposals across {} consensus results; they cannot share \
             one Realms proposal",
            consensus_results.len()
        );
    }
    let consensus_result = *consensus_results
        .iter()
        .next()
        .ok_or_else(|| anyhow!("no consensus result found"))?;
    for o in &overrides {
        if o.consensus_result != consensus_result {
            problems.push(Problem {
                check: "consensus result",
                detail: format!(
                    "ix {} references {}, expected {consensus_result}",
                    o.index, o.consensus_result
                ),
            });
        }
    }
    let consensus_data = state
        .rpc
        .get_account_data(&consensus_result)
        .with_context(|| format!("fetching consensus result {consensus_result}"))?;
    let meta_merkle_root: [u8; 32] = consensus_data
        .get(16..48)
        .ok_or_else(|| anyhow!("consensus result too short"))?
        .try_into()
        .unwrap();

    // --- 4. transaction size ---------------------------------------------
    let oversized = overrides
        .iter()
        .filter(|o| check_size && o.size > max_instruction_bytes)
        .collect::<Vec<_>>();
    if !oversized.is_empty() {
        let stake: u64 = oversized.iter().map(|o| o.active_stake).sum();
        problems.push(Problem {
            check: "transaction size",
            detail: format!(
                "{} instruction(s) exceed {max_instruction_bytes} B (largest {} B), carrying {:.0} SOL",
                oversized.len(),
                oversized.iter().map(|o| o.size).max().unwrap_or(0),
                stake as f64 / 1e9
            ),
        });
    }

    // --- 5. proof accounts, expiry, and both merkle tiers ----------------
    let now = state
        .rpc
        .get_block_time(state.rpc.get_slot().context("fetching slot")?)
        .context("fetching chain clock")?;
    let horizon = execution_horizon.unwrap_or(now + DEFAULT_HORIZON_SECONDS);
    println!("  chain time         : {}", format_utc(now));
    println!(
        "  execution horizon  : {} ({})",
        format_utc(horizon),
        if execution_horizon.is_some() {
            "given"
        } else {
            "default: chain time + 72h"
        }
    );
    if horizon < now {
        problems.push(Problem {
            check: "execution horizon",
            detail: format!(
                "horizon {} is already in the past (chain time {})",
                format_utc(horizon),
                format_utc(now)
            ),
        });
    }
    let mut missing = 0usize;
    // Collected as references, not counted: what a reader needs is how much stake is
    // at risk, and that has to be deduplicated across the three bundled proposals.
    let mut expired: Vec<&DecodedOverride> = Vec::new();
    // Separate from `expired`: a proof still alive now but closeable before the vote
    // executes is the case that used to read as EXECUTABLE right up until it wasn't.
    let mut closeable_before_horizon: Vec<&DecodedOverride> = Vec::new();
    let mut earliest_close: Option<i64> = None;
    let mut tier1_bad = 0usize;
    let mut tier2_bad = 0usize;
    let mut already_cast = 0usize;

    for chunk in overrides.chunks(100) {
        let proof_keys = chunk
            .iter()
            .map(|o| o.meta_merkle_proof)
            .collect::<Vec<_>>();
        let proofs = state
            .rpc
            .get_multiple_accounts(&proof_keys)
            .context("fetching MetaMerkleProof accounts")?;
        let override_keys = chunk.iter().map(|o| o.vote_override).collect::<Vec<_>>();
        let existing = state
            .rpc
            .get_multiple_accounts(&override_keys)
            .context("fetching VoteOverride accounts")?;

        for ((o, proof_account), override_account) in chunk.iter().zip(proofs).zip(existing) {
            if override_account.is_some() {
                already_cast += 1;
            }
            let Some(account) = proof_account else {
                missing += 1;
                continue;
            };
            if account.owner != *snapshot_program_id {
                problems.push(Problem {
                    check: "proof account owner",
                    detail: format!(
                        "ix {}: {} owned by {}",
                        o.index, o.meta_merkle_proof, account.owner
                    ),
                });
                continue;
            }
            let decoded = match decode_meta_merkle_proof(&account.data) {
                Ok(decoded) => decoded,
                Err(err) => {
                    problems.push(Problem {
                        check: "proof account decode",
                        detail: format!("ix {}: {err:#}", o.index),
                    });
                    continue;
                }
            };
            if decoded.vote_account != o.vote_account {
                problems.push(Problem {
                    check: "proof account",
                    detail: format!("ix {}: proof is for {}", o.index, decoded.vote_account),
                });
                continue;
            }
            // Closeable before the vote ends means anyone can reclaim the rent and
            // delete a proof this proposal still needs. Measured against the horizon,
            // not the moment of the check.
            if decoded.close_timestamp <= now {
                expired.push(o);
            } else if decoded.close_timestamp <= horizon {
                closeable_before_horizon.push(o);
            }
            if decoded.close_timestamp > now {
                earliest_close = Some(earliest_close.map_or(decoded.close_timestamp, |e: i64| {
                    e.min(decoded.close_timestamp)
                }));
            }

            // Tier 1: meta leaf -> consensus root.
            let mut meta_leaf = Vec::with_capacity(104);
            meta_leaf.extend_from_slice(decoded.voting_wallet.as_ref());
            meta_leaf.extend_from_slice(decoded.vote_account.as_ref());
            meta_leaf.extend_from_slice(&decoded.stake_merkle_root);
            meta_leaf.extend_from_slice(&decoded.active_stake.to_le_bytes());
            if fold_merkle_proof(&sha256(&[&meta_leaf]), &decoded.proof) != meta_merkle_root {
                tier1_bad += 1;
            }

            // Tier 2: our stake leaf -> that meta leaf's stake root.
            let mut stake_leaf = Vec::with_capacity(72);
            stake_leaf.extend_from_slice(o.voting_wallet.as_ref());
            stake_leaf.extend_from_slice(o.stake_account.as_ref());
            stake_leaf.extend_from_slice(&o.active_stake.to_le_bytes());
            if fold_merkle_proof(&sha256(&[&stake_leaf]), &o.stake_proof)
                != decoded.stake_merkle_root
            {
                tier2_bad += 1;
            }
        }
    }

    for (count, check, detail) in [
        (missing, "proof accounts", "MetaMerkleProof account(s) do not exist; those instructions fail with MustBeOwnedBySnapshotProgram"),
        (tier1_bad, "merkle tier 1", "meta leaf/proof do not fold to the on-chain consensus root"),
        (tier2_bad, "merkle tier 2", "stake leaf/proof do not fold to the meta leaf's stake root"),
        (already_cast, "already executed", "VoteOverride account(s) already exist; re-executing fails with 'already in use'"),
    ] {
        if count > 0 {
            problems.push(Problem { check, detail: format!("{count} instruction(s): {detail}") });
        }
    }

    println!(
        "  proof accounts     : {} / {} present",
        overrides.len() - missing,
        overrides.len()
    );
    println!(
        "  merkle tier 1      : {} verified",
        overrides.len() - missing - tier1_bad
    );
    println!(
        "  merkle tier 2      : {} verified",
        overrides.len() - missing - tier2_bad
    );
    if let Some(earliest) = earliest_close {
        println!("  earliest proof close: {}", format_utc(earliest));
        // The unambiguous case, needing no judgement about scheduling: a proof that
        // closes before the chain will even permit execution can never be used.
        if let Some(execution_at) = execution_at {
            if earliest <= execution_at {
                problems.push(Problem {
                    check: "execution window",
                    detail: format!(
                        "proof(s) start closing at {} but this cannot execute until {}; \
                         the payload can never fully execute",
                        format_utc(earliest),
                        format_utc(execution_at)
                    ),
                });
            } else {
                println!(
                    "  execution window   : {} wide ({} → {})",
                    humanise_seconds(earliest - execution_at),
                    format_utc(execution_at),
                    format_utc(earliest)
                );
            }
        }
    }
    for (affected, when) in [
        (&expired, "are already past close_timestamp".to_string()),
        (
            &closeable_before_horizon,
            format!(
                "become closeable before the horizon {}",
                format_utc(horizon)
            ),
        ),
    ] {
        if affected.is_empty() {
            continue;
        }
        let (accounts, stake) = distinct_stake(affected.iter().copied());
        problems.push(Problem {
            check: "proof expiry",
            detail: format!(
                "{accounts} stake account(s) carrying {:.0} SOL ({:.2}% of the vote) \
                 rely on proof(s) that {when} — anyone can close them and reclaim the \
                 rent, and the instruction then fails",
                stake as f64 / 1e9,
                100.0 * stake as f64 / total_stake.max(1) as f64,
            ),
        });
    }

    // --- verdict ----------------------------------------------------------
    print_verdict(&problems);
    Ok(Verdict {
        problems,
        instructions: overrides.len(),
        stake_accounts,
        total_stake,
        votes: tally,
        digest,
    })
}
