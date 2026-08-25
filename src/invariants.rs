//! Pure, RPC-free invariant checks over a vote-override payload.
//!
//! These are the rules the Security Council approves, written out in
//! `docs/VERIFICATION-SPEC.md`; everything here is a mechanical restatement of that
//! document. Deliberately split out of [`crate::verify`]: no network, no clock, no
//! chain state, so the rules can be unit-tested against hand-built payloads —
//! including deliberately tampered ones — without a validator.
//!
//! What lives here answers "is this payload the thing we agreed to submit?".
//! What lives in `verify` answers "will the chain accept it right now?".

use std::collections::{BTreeMap, BTreeSet};

use borsh::BorshSerialize;
use solana_sdk::pubkey::Pubkey;

use crate::governance::InstructionData;
use crate::svmgov::{sha256, BASIS_POINTS_MAX};

/// `cast_vote_override` takes exactly these accounts, in this order, per the
/// svmgov IDL (`svmgov/cli/idls/svmgov_program.json`).
pub const ACCOUNT_NAMES: [&str; 11] = [
    "signer",
    "proposal",
    "validator_vote",
    "spl_vote_account",
    "vote_override",
    "vote_override_cache",
    "spl_stake_account",
    "snapshot_program",
    "consensus_result",
    "meta_merkle_proof",
    "system_program",
];
pub const EXPECTED_ACCOUNTS: usize = ACCOUNT_NAMES.len();

/// Per-account `(is_signer, is_writable)` the IDL requires. Anything else means the
/// instruction grants an authority the program never asked for.
pub const EXPECTED_FLAGS: [(bool, bool); EXPECTED_ACCOUNTS] = [
    (true, true),   // 0  signer
    (false, true),  // 1  proposal
    (false, true),  // 2  validator_vote
    (false, false), // 3  spl_vote_account
    (false, true),  // 4  vote_override
    (false, true),  // 5  vote_override_cache
    (false, false), // 6  spl_stake_account
    (false, false), // 7  snapshot_program
    (false, false), // 8  consensus_result
    (false, false), // 9  meta_merkle_proof
    (false, false), // 10 system_program
];

pub const IX_SIGNER: usize = 0;
pub const IX_SVMGOV_PROPOSAL: usize = 1;
pub const IX_VOTE_ACCOUNT: usize = 3;
pub const IX_VOTE_OVERRIDE: usize = 4;
pub const IX_STAKE_ACCOUNT: usize = 6;
pub const IX_CONSENSUS_RESULT: usize = 8;
pub const IX_META_MERKLE_PROOF: usize = 9;

/// Records one failed precondition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub check: &'static str,
    pub detail: String,
}

/// The vote one instruction casts, in basis points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VoteSplit {
    pub for_bp: u64,
    pub against_bp: u64,
    pub abstain_bp: u64,
}

impl std::fmt::Display for VoteSplit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} for / {} against / {} abstain",
            self.for_bp, self.against_bp, self.abstain_bp
        )
    }
}

/// One decoded `cast_vote_override`.
#[derive(Debug, Clone)]
pub struct DecodedOverride {
    pub index: usize,
    pub size: usize,
    pub signer: Pubkey,
    pub svmgov_proposal: Pubkey,
    pub vote_account: Pubkey,
    pub vote_override: Pubkey,
    pub stake_account: Pubkey,
    pub consensus_result: Pubkey,
    pub meta_merkle_proof: Pubkey,
    pub voting_wallet: Pubkey,
    pub active_stake: u64,
    pub stake_proof: Vec<[u8; 32]>,
    pub vote: VoteSplit,
}

/// Constants the payload is checked against. Passed in rather than hardcoded so the
/// caller echoes exactly what it used — a run against the wrong program id should
/// never be indistinguishable from a correct one.
pub struct InvariantParams {
    pub svmgov_program_id: Pubkey,
    pub discriminator: [u8; 8],
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads the three vote fields, if the data is long enough to hold them.
fn read_vote(data: &[u8]) -> Option<VoteSplit> {
    if data.len() < 32 {
        return None;
    }
    Some(VoteSplit {
        for_bp: u64::from_le_bytes(data[8..16].try_into().ok()?),
        against_bp: u64::from_le_bytes(data[16..24].try_into().ok()?),
        abstain_bp: u64::from_le_bytes(data[24..32].try_into().ok()?),
    })
}

/// Checks every rule that needs only the payload itself.
///
/// Returns the decoded instructions alongside the problems found. Decoding continues
/// past a bad instruction wherever it can, so one malformed entry does not mask the
/// rest — the caller gets the complete list of what is wrong, not just the first.
pub fn check_invariants(
    instructions: &[InstructionData],
    params: &InvariantParams,
) -> (Vec<DecodedOverride>, Vec<Problem>) {
    let mut problems = Vec::new();
    let mut overrides: Vec<DecodedOverride> = Vec::new();
    let mut seen_override = BTreeSet::new();

    for (index, instruction) in instructions.iter().enumerate() {
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

        // I1 / I11 — every instruction is a svmgov call, and nothing else.
        if instruction.program_id != params.svmgov_program_id {
            fail(format!("program id {}", instruction.program_id));
            continue;
        }
        // I3 — the IDL account list, exactly.
        if instruction.accounts.len() != EXPECTED_ACCOUNTS {
            fail(format!(
                "{} accounts, expected {EXPECTED_ACCOUNTS}",
                instruction.accounts.len()
            ));
            continue;
        }
        let data = &instruction.data;
        // I2 — the staker-override function, and no other.
        if data.len() < 36 || data[..8] != params.discriminator {
            fail("wrong discriminator".to_string());
            continue;
        }
        let Some(vote) = read_vote(data) else {
            fail("payload too short to hold a vote".to_string());
            continue;
        };
        // I4 — the split is well-formed on its own terms.
        //
        // Each field is bounded BEFORE they are added. All three are attacker-chosen
        // u64s read straight out of the payload, and release builds do not check
        // overflow: `u64::MAX + 10001 + 0` wraps to exactly 10000, so a plain sum
        // accepts a payload voting u64::MAX basis points. Bounding first caps the sum
        // at 30000, which cannot wrap.
        if vote.for_bp > BASIS_POINTS_MAX
            || vote.against_bp > BASIS_POINTS_MAX
            || vote.abstain_bp > BASIS_POINTS_MAX
            || vote.for_bp + vote.against_bp + vote.abstain_bp != BASIS_POINTS_MAX
        {
            fail(format!("vote split {vote}"));
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
        // I14 — no account carries an authority the IDL does not ask for. Checked
        // slot by slot so the message names which one, rather than "flags differ".
        for (slot, (want_signer, want_writable)) in EXPECTED_FLAGS.iter().enumerate() {
            let meta = &accounts[slot];
            if meta.is_signer != *want_signer || meta.is_writable != *want_writable {
                fail(format!(
                    "account {slot} ({}) is {}{}, expected {}{}",
                    ACCOUNT_NAMES[slot],
                    if meta.is_signer { "signer " } else { "" },
                    if meta.is_writable {
                        "writable"
                    } else {
                        "read-only"
                    },
                    if *want_signer { "signer " } else { "" },
                    if *want_writable {
                        "writable"
                    } else {
                        "read-only"
                    },
                ));
            }
        }
        // I7 / I8 — the instruction acts on the accounts its own merkle leaf names.
        if accounts[IX_SIGNER].pubkey != voting_wallet {
            fail("signer does not match the leaf voting_wallet".to_string());
        }
        if accounts[IX_STAKE_ACCOUNT].pubkey != leaf_stake {
            fail("stake account does not match the leaf".to_string());
        }
        // I9 — the override PDA is seeded by (svmgov proposal, stake account), so a
        // repeat means the same stake would vote twice on the same proposal.
        if !seen_override.insert(accounts[IX_VOTE_OVERRIDE].pubkey) {
            fail(format!(
                "duplicate vote_override {} (stake {leaf_stake})",
                accounts[IX_VOTE_OVERRIDE].pubkey
            ));
        }

        overrides.push(DecodedOverride {
            index,
            size: encoded_len,
            signer: accounts[IX_SIGNER].pubkey,
            svmgov_proposal: accounts[IX_SVMGOV_PROPOSAL].pubkey,
            vote_account: accounts[IX_VOTE_ACCOUNT].pubkey,
            vote_override: accounts[IX_VOTE_OVERRIDE].pubkey,
            stake_account: accounts[IX_STAKE_ACCOUNT].pubkey,
            consensus_result: accounts[IX_CONSENSUS_RESULT].pubkey,
            meta_merkle_proof: accounts[IX_META_MERKLE_PROOF].pubkey,
            voting_wallet,
            active_stake,
            stake_proof,
            vote,
        });
    }

    problems.extend(check_vote_uniformity(&overrides));
    (overrides, problems)
}

/// I5 — every instruction must cast the *same* vote.
///
/// This is the check whose absence let a payload with one instruction flipped from
/// FOR to AGAINST verify clean: the per-instruction sum still came to 10000, and the
/// summary only ever printed instruction 0's value.
pub fn check_vote_uniformity(overrides: &[DecodedOverride]) -> Vec<Problem> {
    let tally = vote_tally(overrides);
    if tally.len() <= 1 {
        return Vec::new();
    }
    let mut described = tally
        .iter()
        .map(|(vote, indices)| {
            format!(
                "{vote} on {} instruction(s) (first: ix {})",
                indices.len(),
                indices.first().copied().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>();
    described.sort();
    vec![Problem {
        check: "vote direction",
        detail: format!(
            "payload casts {} different votes; every instruction must cast the same one — {}",
            tally.len(),
            described.join("; ")
        ),
    }]
}

/// Distinct votes in the payload, each with the instruction indices casting it.
pub fn vote_tally(overrides: &[DecodedOverride]) -> BTreeMap<VoteSplit, Vec<usize>> {
    let mut tally: BTreeMap<VoteSplit, Vec<usize>> = BTreeMap::new();
    for o in overrides {
        tally.entry(o.vote).or_default().push(o.index);
    }
    tally
}

/// Total stake, counting each stake account once.
///
/// The payload bundles three svmgov proposals, so a naive sum over instructions
/// counts every stake account three times and reports ~3x the real voting weight.
pub fn distinct_stake<'a>(
    overrides: impl IntoIterator<Item = &'a DecodedOverride>,
) -> (usize, u64) {
    let by_account = overrides
        .into_iter()
        .map(|o| (o.stake_account, o.active_stake))
        .collect::<BTreeMap<_, _>>();
    // Saturating: `active_stake` is payload-controlled, and a wrapped total would
    // under-report the stake at risk rather than over-report it.
    (
        by_account.len(),
        by_account
            .values()
            .fold(0u64, |acc, stake| acc.saturating_add(*stake)),
    )
}

/// I13 — which proposal options carry transactions the reviewed payload never covers.
///
/// The generator only ever populates option 0. Anything under a higher option was put
/// there by something else, and the old verifier could not see it at all: it read
/// `options.first()` and pinned the PDA seed to option 0. Under SingleChoice the
/// resolver picks the winning option by weight, so an unread option is exactly the one
/// that can execute.
///
/// Takes the declared transaction count per option, in option order.
pub fn unexpected_options(transactions_per_option: &[u16]) -> Vec<usize> {
    transactions_per_option
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, count)| **count > 0)
        .map(|(index, _)| index)
        .collect()
}

/// The canonical per-instruction fingerprint lines.
///
/// Two verifiers agreeing on the digest below agree on how they *interpreted* every
/// instruction, not merely that they read the same bytes. The line form is printable
/// on purpose: when digests differ, diffing the lines locates the instruction.
pub fn canonical_lines(instructions: &[InstructionData]) -> Vec<String> {
    instructions
        .iter()
        .enumerate()
        .map(|(index, ix)| {
            let disc = ix.data.get(..8).map(hex).unwrap_or_default();
            let vote = read_vote(&ix.data).unwrap_or(VoteSplit {
                for_bp: 0,
                against_bp: 0,
                abstain_bp: 0,
            });
            let accounts = ix
                .accounts
                .iter()
                .map(|m| {
                    format!(
                        "{}{}{}",
                        m.pubkey,
                        if m.is_signer { "s" } else { "-" },
                        if m.is_writable { "w" } else { "-" }
                    )
                })
                .collect::<Vec<_>>()
                .join("|");
            // The proof and leaf are hashed rather than inlined: they dominate the
            // instruction by size but only ever need to be compared, not read.
            let tail = hex(&sha256(&[ix.data.get(32..).unwrap_or_default()]));
            format!(
                "{index}|{}|{disc}|{}|{}|{}|{accounts}|{tail}",
                ix.program_id, vote.for_bp, vote.against_bp, vote.abstain_bp
            )
        })
        .collect()
}

/// SHA-256 over [`canonical_lines`] joined by newlines, hex-encoded.
pub fn canonical_digest(instructions: &[InstructionData]) -> String {
    let joined = canonical_lines(instructions).join("\n");
    hex(&sha256(&[joined.as_bytes()]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::AccountMetaData;

    fn key(seed: u8) -> Pubkey {
        Pubkey::new_from_array([seed; 32])
    }

    const SVMGOV: u8 = 9;
    const DISC: [u8; 8] = [225, 8, 137, 98, 214, 156, 183, 62];

    fn params() -> InvariantParams {
        InvariantParams {
            svmgov_program_id: key(SVMGOV),
            discriminator: DISC,
        }
    }

    /// A well-formed `cast_vote_override` voting `for_bp` on stake account `stake`.
    fn instruction(stake: u8, for_bp: u64, against_bp: u64) -> InstructionData {
        let signer = key(1);
        let stake_key = key(stake);
        let mut data = Vec::new();
        data.extend_from_slice(&DISC);
        data.extend_from_slice(&for_bp.to_le_bytes());
        data.extend_from_slice(&against_bp.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes()); // abstain
        data.extend_from_slice(&1u32.to_le_bytes()); // one proof node
        data.extend_from_slice(&[7u8; 32]);
        data.extend_from_slice(signer.as_ref()); // leaf.voting_wallet
        data.extend_from_slice(stake_key.as_ref()); // leaf.stake_account
        data.extend_from_slice(&1_000u64.to_le_bytes()); // leaf.active_stake

        let accounts = EXPECTED_FLAGS
            .iter()
            .enumerate()
            .map(|(slot, (is_signer, is_writable))| AccountMetaData {
                pubkey: match slot {
                    IX_SIGNER => signer,
                    IX_STAKE_ACCOUNT => stake_key,
                    IX_VOTE_OVERRIDE => key(100 + stake),
                    other => key(20 + other as u8),
                },
                is_signer: *is_signer,
                is_writable: *is_writable,
            })
            .collect();

        InstructionData {
            program_id: key(SVMGOV),
            accounts,
            data,
        }
    }

    fn clean_payload() -> Vec<InstructionData> {
        vec![
            instruction(31, 10_000, 0),
            instruction(32, 10_000, 0),
            instruction(33, 10_000, 0),
        ]
    }

    #[test]
    fn a_clean_payload_has_no_problems() {
        let (decoded, problems) = check_invariants(&clean_payload(), &params());
        assert_eq!(problems, vec![], "clean payload must verify");
        assert_eq!(decoded.len(), 3);
    }

    /// The regression this whole module exists for: flipping one instruction from FOR
    /// to AGAINST kept the per-instruction sum at 10000 and went unreported.
    #[test]
    fn a_single_flipped_vote_is_caught() {
        let mut payload = clean_payload();
        payload[1] = instruction(32, 0, 10_000);
        let (_, problems) = check_invariants(&payload, &params());
        assert_eq!(problems.len(), 1, "expected exactly the uniformity problem");
        assert_eq!(problems[0].check, "vote direction");
        assert!(
            problems[0].detail.contains("2 different votes"),
            "message should say how many distinct votes: {}",
            problems[0].detail
        );
    }

    #[test]
    fn a_foreign_program_id_is_caught() {
        let mut payload = clean_payload();
        payload[2].program_id = key(200);
        let (decoded, problems) = check_invariants(&payload, &params());
        assert_eq!(decoded.len(), 2, "the foreign instruction is not decoded");
        assert!(problems.iter().any(|p| p.detail.contains("program id")));
    }

    #[test]
    fn an_unexpected_writable_account_is_caught() {
        let mut payload = clean_payload();
        payload[0].accounts[IX_META_MERKLE_PROOF].is_writable = true;
        let (_, problems) = check_invariants(&payload, &params());
        assert!(
            problems
                .iter()
                .any(|p| p.detail.contains("meta_merkle_proof") && p.detail.contains("writable")),
            "got {problems:?}"
        );
    }

    #[test]
    fn an_extra_signer_is_caught() {
        let mut payload = clean_payload();
        payload[0].accounts[IX_SVMGOV_PROPOSAL].is_signer = true;
        let (_, problems) = check_invariants(&payload, &params());
        assert!(problems.iter().any(|p| p.detail.contains("proposal")));
    }

    #[test]
    fn a_duplicate_override_is_caught() {
        let mut payload = clean_payload();
        payload[2] = instruction(31, 10_000, 0); // same stake as payload[0]
        let (_, problems) = check_invariants(&payload, &params());
        assert!(problems.iter().any(|p| p.detail.contains("duplicate")));
    }

    #[test]
    fn a_malformed_vote_split_is_caught() {
        let payload = vec![instruction(31, 9_000, 0)]; // sums to 9000, not 10000
        let (_, problems) = check_invariants(&payload, &params());
        assert!(problems.iter().any(|p| p.detail.contains("vote split")));
    }

    /// A vote split that wraps u64 to exactly 10000. Against a plain sum in a release
    /// build this payload verified clean and printed
    /// "EXECUTABLE — every precondition checked out."
    #[test]
    fn a_vote_split_that_overflows_to_ten_thousand_is_caught() {
        assert_eq!(
            u64::MAX.wrapping_add(10_001),
            BASIS_POINTS_MAX,
            "premise: these values wrap to a valid-looking sum"
        );
        let payload = vec![instruction(31, u64::MAX, 10_001)];
        let (decoded, problems) = check_invariants(&payload, &params());
        assert!(
            problems.iter().any(|p| p.detail.contains("vote split")),
            "got {problems:?}"
        );
        assert!(decoded.is_empty(), "it must not be decoded as a valid vote");
    }

    #[test]
    fn any_single_field_above_ten_thousand_is_caught() {
        for (f, a, b) in [
            (10_001, 0, 0),
            (0, 10_001, 0),
            (0, 0, u64::MAX),
            (u64::MAX, u64::MAX, 2),
        ] {
            let mut ix = instruction(31, f, a);
            ix.data[24..32].copy_from_slice(&b.to_le_bytes());
            let (_, problems) = check_invariants(&[ix], &params());
            assert!(
                problems.iter().any(|p| p.detail.contains("vote split")),
                "{f}/{a}/{b} should be rejected"
            );
        }
    }

    #[test]
    fn stake_is_counted_once_per_account_not_once_per_instruction() {
        // Same three stake accounts bundled across two svmgov proposals.
        let mut payload = clean_payload();
        payload.extend(clean_payload().into_iter().map(|mut ix| {
            ix.accounts[IX_VOTE_OVERRIDE].pubkey = key(200 + ix.data[36]);
            ix
        }));
        let (decoded, _) = check_invariants(&payload, &params());
        assert_eq!(decoded.len(), 6, "six instructions");
        let (accounts, stake) = distinct_stake(&decoded);
        assert_eq!(accounts, 3, "but only three distinct stake accounts");
        assert_eq!(stake, 3_000, "and their stake counted once each");
    }

    #[test]
    fn the_digest_is_stable_and_sensitive() {
        let payload = clean_payload();
        assert_eq!(
            canonical_digest(&payload),
            canonical_digest(&clean_payload()),
            "same payload must digest identically"
        );

        let mut flipped = clean_payload();
        flipped[1] = instruction(32, 0, 10_000);
        assert_ne!(
            canonical_digest(&payload),
            canonical_digest(&flipped),
            "a flipped vote must change the digest"
        );

        let mut reflagged = clean_payload();
        reflagged[0].accounts[IX_META_MERKLE_PROOF].is_writable = true;
        assert_ne!(
            canonical_digest(&payload),
            canonical_digest(&reflagged),
            "an account flag change must change the digest"
        );
    }

    #[test]
    fn only_option_zero_may_carry_transactions() {
        // The real payload: one option, 882 transactions under it.
        assert_eq!(unexpected_options(&[882]), Vec::<usize>::new());
        // Empty higher options are how a multi-option proposal normally looks.
        assert_eq!(unexpected_options(&[882, 0, 0]), Vec::<usize>::new());
        // One transaction hidden under option 1 is the case the old verifier could
        // not see, because it only ever derived PDAs under option 0.
        assert_eq!(unexpected_options(&[882, 1]), vec![1]);
        assert_eq!(unexpected_options(&[882, 0, 5]), vec![2]);
        assert_eq!(unexpected_options(&[0, 3, 0, 7]), vec![1, 3]);
        // An empty option list cannot hide anything.
        assert_eq!(unexpected_options(&[]), Vec::<usize>::new());
    }

    /// The seed for a proposal transaction was pinned to option 0, so instructions
    /// under any other option were unreachable. This pins the fix: the option index
    /// must reach the seed, and each option must address a distinct account.
    #[test]
    fn the_transaction_pda_seed_carries_the_option_index() {
        use crate::governance::{
            get_proposal_transaction_address, get_proposal_transaction_address_seeds,
        };
        let program = key(50);
        let proposal = key(51);
        let addresses = (0u8..3)
            .map(|option| {
                get_proposal_transaction_address(
                    &program,
                    &proposal,
                    &option.to_le_bytes(),
                    &0u16.to_le_bytes(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            addresses.iter().collect::<BTreeSet<_>>().len(),
            3,
            "each option must address its own transaction account"
        );
        // And the seed really is the option byte, not a coincidence of hashing.
        let (option_seed, index_seed) = (1u8.to_le_bytes(), 0u16.to_le_bytes());
        let seeds = get_proposal_transaction_address_seeds(&proposal, &option_seed, &index_seed);
        assert_eq!(seeds[2], &[1u8], "third seed is the option index");
        assert_eq!(
            Pubkey::find_program_address(&seeds, &program).0,
            addresses[1]
        );
    }

    #[test]
    fn canonical_lines_are_one_per_instruction_and_diffable() {
        let payload = clean_payload();
        let lines = canonical_lines(&payload);
        assert_eq!(lines.len(), payload.len());
        assert!(lines[0].starts_with("0|"), "line is index-prefixed");
        assert_eq!(
            lines[0].split('|').count(),
            // index, program, disc, 3 vote fields, 11 accounts, tail hash
            6 + EXPECTED_ACCOUNTS + 1
        );
    }
}
