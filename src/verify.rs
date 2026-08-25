//! Checks whether a jitoSOL vote-override proposal can actually be submitted and
//! executed, against live chain state.
//!
//! The account layouts come from `crate::governance` rather than the
//! borsh-0.9-patched `spl-governance` dependency tree; see that module for why.
//!
//! Note on check 3: the for/against/abstain split must be *unanimous within each
//! svmgov proposal*, and is printed per proposal. Checking only one instruction's
//! split would not catch a single instruction among ~900 that votes the opposite
//! way — it sums to 10000 bp like all the others and passes every other check.

use std::{path::PathBuf, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;

use crate::governance::{
    get_proposal_transaction_address, InstructionData, ProposalTransactionV2, ProposalV2,
};
use crate::svmgov::{
    anchor_discriminator, fold_merkle_proof, sha256, SvmgovProposal, BASIS_POINTS_MAX,
};

/// Records one failed precondition.
struct Problem {
    check: &'static str,
    detail: String,
}

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

/// One decoded `cast_vote_override` from the proposal.
struct DecodedOverride {
    index: usize,
    size: usize,
    signer: Pubkey,
    svmgov_proposal: Pubkey,
    vote_account: Pubkey,
    vote_override: Pubkey,
    stake_account: Pubkey,
    consensus_result: Pubkey,
    meta_merkle_proof: Pubkey,
    voting_wallet: Pubkey,
    active_stake: u64,
    stake_proof: Vec<[u8; 32]>,
    for_bp: u64,
    against_bp: u64,
    abstain_bp: u64,
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
) -> Result<(Vec<InstructionData>, Vec<Problem>)> {
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

    let option = parsed
        .options
        .first()
        .ok_or_else(|| anyhow!("proposal {proposal} has no options"))?;
    let expected = option.transactions_count;
    println!(
        "  transactions       : {expected} declared, {} executed",
        option.transactions_executed_count
    );

    let mut instructions = Vec::new();
    let mut missing = Vec::new();
    let mut executed = 0usize;
    for index in 0..expected {
        let address = get_proposal_transaction_address(
            &state.program_id,
            proposal,
            &0u8.to_le_bytes(),
            &index.to_le_bytes(),
        );
        match state.rpc.get_account_data(&address) {
            Ok(bytes) => {
                let transaction = ProposalTransactionV2::deserialize(&mut &bytes[..])
                    .with_context(|| format!("borsh-decoding ProposalTransaction {address}"))?;
                if transaction.executed_at.is_some() {
                    executed += 1;
                }
                instructions.extend(transaction.instructions);
            }
            Err(_) => missing.push(index),
        }
    }
    // A gap means an insert never landed — the proposal looks complete in the UI
    // but would execute short.
    if !missing.is_empty() {
        problems.push(Problem {
            check: "missing transactions",
            detail: format!(
                "{} of {expected} ProposalTransaction account(s) do not exist (first few: {:?})",
                missing.len(),
                &missing[..missing.len().min(5)]
            ),
        });
    }
    if executed > 0 {
        println!("  already executed   : {executed} transaction(s)");
    }
    Ok((instructions, problems))
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

pub fn verify_proposal(
    state: &GovernanceContext,
    proposal_path: Option<&PathBuf>,
    realms_url: Option<&str>,
    svmgov_program_id: &Pubkey,
    snapshot_program_id: &Pubkey,
    max_instruction_bytes: usize,
) -> Result<()> {
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
            let (instructions, problems) = load_onchain_instructions(state, &address)?;
            (instructions, problems, false)
        }
        _ => bail!("pass exactly one of --proposal or --realms-url"),
    };

    let discriminator = anchor_discriminator("global:cast_vote_override");
    let mut overrides = Vec::new();
    // Keyed on the vote_override PDA, which is what `init` requires to be unique.
    // A stake account legitimately repeats across bundled svmgov proposals.
    let mut seen_override = std::collections::BTreeSet::new();

    // --- 1. shape --------------------------------------------------------
    for (index, instruction) in raw_instructions.iter().enumerate() {
        let encoded_len = instruction
            .try_to_vec()
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX);

        let mut fail = |detail: String| {
            problems.push(Problem {
                check: "instruction shape",
                detail: format!("ix {index}: {detail}"),
            })
        };
        if instruction.program_id != *svmgov_program_id {
            fail(format!("program id {}", instruction.program_id));
            continue;
        }
        if instruction.accounts.len() != 11 {
            fail(format!(
                "{} accounts, expected 11",
                instruction.accounts.len()
            ));
            continue;
        }
        let data = &instruction.data;
        if data.len() < 36 || data[..8] != discriminator {
            fail("wrong discriminator".to_string());
            continue;
        }
        let for_bp = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let against_bp = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let abstain_bp = u64::from_le_bytes(data[24..32].try_into().unwrap());
        if for_bp + against_bp + abstain_bp != BASIS_POINTS_MAX {
            fail(format!("vote split {for_bp}/{against_bp}/{abstain_bp}"));
            continue;
        }
        let nodes = u32::from_le_bytes(data[32..36].try_into().unwrap()) as usize;
        let leaf_at = 36 + 32 * nodes;
        if data.len() != leaf_at + 72 {
            fail("payload length does not match declared proof length".to_string());
            continue;
        }
        let stake_proof = (0..nodes)
            .map(|i| data[36 + 32 * i..68 + 32 * i].try_into().unwrap())
            .collect::<Vec<[u8; 32]>>();
        let voting_wallet = Pubkey::new_from_array(data[leaf_at..leaf_at + 32].try_into().unwrap());
        let leaf_stake =
            Pubkey::new_from_array(data[leaf_at + 32..leaf_at + 64].try_into().unwrap());
        let active_stake = u64::from_le_bytes(data[leaf_at + 64..leaf_at + 72].try_into().unwrap());

        let accounts = &instruction.accounts;
        if !accounts[0].is_signer || !accounts[0].is_writable {
            fail("account 0 must be a writable signer".to_string());
        }
        if accounts[0].pubkey != voting_wallet {
            fail("signer does not match the leaf voting_wallet".to_string());
        }
        if accounts[6].pubkey != leaf_stake {
            fail("stake account does not match the leaf".to_string());
        }
        if !seen_override.insert(accounts[4].pubkey) {
            fail(format!(
                "duplicate vote_override {} (stake {leaf_stake})",
                accounts[4].pubkey
            ));
        }

        overrides.push(DecodedOverride {
            index,
            size: encoded_len,
            signer: accounts[0].pubkey,
            svmgov_proposal: accounts[1].pubkey,
            vote_account: accounts[3].pubkey,
            vote_override: accounts[4].pubkey,
            stake_account: accounts[6].pubkey,
            consensus_result: accounts[8].pubkey,
            meta_merkle_proof: accounts[9].pubkey,
            voting_wallet,
            active_stake,
            stake_proof,
            for_bp,
            against_bp,
            abstain_bp,
        });
    }
    if overrides.is_empty() {
        bail!("no decodable cast_vote_override instructions found");
    }
    let total_stake: u64 = overrides.iter().map(|o| o.active_stake).sum();
    println!("  instructions       : {}", overrides.len());
    println!("  stake              : {:.0} SOL", total_stake as f64 / 1e9);

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
        // Every instruction for one svmgov proposal casts part of the same vote,
        // so they must all carry the same split. A bundle may legitimately vote
        // differently on *different* SGPs, which is why this groups per proposal
        // rather than globally. A mixed split means some of the pool's stake
        // votes the opposite way to the title — invisible in the Realms UI, and
        // it would execute exactly as written.
        let mut by_split: std::collections::BTreeMap<(u64, u64, u64), Vec<usize>> =
            std::collections::BTreeMap::new();
        for o in overrides
            .iter()
            .filter(|o| o.svmgov_proposal == *svmgov_proposal)
        {
            by_split
                .entry((o.for_bp, o.against_bp, o.abstain_bp))
                .or_default()
                .push(o.index);
        }
        let count: usize = by_split.values().map(|indices| indices.len()).sum();
        let split = if by_split.len() == 1 {
            let (for_bp, against_bp, abstain_bp) = *by_split.keys().next().unwrap();
            format!("{for_bp}/{against_bp}/{abstain_bp} bp")
        } else {
            problems.push(Problem {
                check: "vote split",
                detail: format!(
                    "{svmgov_proposal} mixes {} for/against/abstain splits across its {count} \
                     instructions: {}",
                    by_split.len(),
                    by_split
                        .iter()
                        .map(|((for_bp, against_bp, abstain_bp), indices)| format!(
                            "{for_bp}/{against_bp}/{abstain_bp} bp on {} ix (e.g. {:?})",
                            indices.len(),
                            &indices[..indices.len().min(3)]
                        ))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
            format!("{} MIXED SPLITS", by_split.len())
        };
        println!(
            "    {svmgov_proposal}  {count} ix  {split}  epochs [{}, {})  {}",
            svm.start_epoch, svm.end_epoch, svm.title
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
    let mut missing = 0usize;
    let mut expiring = 0usize;
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
            // Closeable before the vote ends means someone could reclaim the rent
            // and delete a proof this proposal still needs.
            if decoded.close_timestamp <= now {
                expiring += 1;
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
    if expiring > 0 {
        println!(
            "  WARNING            : {expiring} proof account(s) are already past close_timestamp"
        );
    }

    // --- verdict ----------------------------------------------------------
    println!();
    if problems.is_empty() {
        println!("EXECUTABLE — every precondition checked out.");
        return Ok(());
    }
    println!("NOT EXECUTABLE — {} problem(s):", problems.len());
    for problem in &problems {
        println!("  [{}] {}", problem.check, problem.detail);
    }
    Ok(())
}
