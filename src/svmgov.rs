//! The `svmgov` / `ncn-snapshot` layouts and merkle arithmetic the verifier
//! reproduces off-chain in order to predict whether `cast_vote_override` would
//! succeed on-chain.

use borsh::BorshDeserialize;
use solana_sdk::pubkey::Pubkey;

/// Solana network governance (`svmgov`) program on mainnet.
pub const SVMGOV_PROGRAM_ID: &str = "govYkyQ3ePtGULAtY6V75qjWE8UH4vCUVQ1W4HdCAZU";
/// Snapshot NCN that publishes the stake merkle roots svmgov verifies against.
pub const NCN_SNAPSHOT_PROGRAM_ID: &str = "ncnwF8AgynRcdEnGLcprSQNaKvgSMTgk3yPRc8cf9Zf";
/// Basis points a vote split must sum to.
pub const BASIS_POINTS_MAX: u64 = 10_000;

/// The svmgov `Proposal` account. Anchor prefixes an 8-byte discriminator, and
/// the supporter pubkeys live past the struct's borsh capacity, so this is read
/// from `data[8..]` with `deserialize` (tolerates trailing bytes) rather than
/// `try_from_slice` (rejects them).
#[derive(BorshDeserialize)]
#[allow(dead_code)]
pub struct SvmgovProposal {
    pub author: Pubkey,
    pub title: String,
    pub description: String,
    pub creation_epoch: u64,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub proposer_stake_weight_bp: u64,
    pub cluster_support_lamports: u64,
    pub for_votes_lamports: u64,
    pub against_votes_lamports: u64,
    pub abstain_votes_lamports: u64,
    pub voting: bool,
    pub finalized: bool,
    pub proposal_bump: u8,
    pub creation_timestamp: i64,
    pub vote_count: u32,
    pub index: u32,
    pub consensus_result: Option<Pubkey>,
    pub snapshot_slot: u64,
    pub proposal_seed: u64,
    pub vote_account_pubkey: Pubkey,
    pub num_supporters: u32,
}

/// Merkle domain separators used by `ncn-snapshot`'s `verify_helper`.
pub const MERKLE_LEAF_PREFIX: &[u8] = &[0];
pub const MERKLE_INTERMEDIATE_PREFIX: &[u8] = &[1];

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let owned = parts.concat();
    solana_sdk::hash::hash(&owned).to_bytes()
}

/// Folds a merkle proof the way `ncn-snapshot`'s `verify_helper` does: hash the
/// leaf with the leaf prefix, then combine with each sibling in sorted order.
pub fn fold_merkle_proof(leaf_hash: &[u8; 32], proof: &[[u8; 32]]) -> [u8; 32] {
    let mut node = sha256(&[MERKLE_LEAF_PREFIX, leaf_hash]);
    for sibling in proof {
        node = if node <= *sibling {
            sha256(&[MERKLE_INTERMEDIATE_PREFIX, &node, sibling])
        } else {
            sha256(&[MERKLE_INTERMEDIATE_PREFIX, sibling, &node])
        };
    }
    node
}

/// Fixed transaction overhead of a single-instruction `InsertTransaction`, in
/// bytes: 1 signature, the 3-byte header, 8 distinct 32-byte account keys (the
/// submitting CLI signs as both `governance_authority` and `payer`, so those
/// coalesce), the blockhash, and the borsh-encoded instruction args around the
/// payload.
///
/// Measured, not estimated: an 874-byte payload produces a 1257-byte transaction
/// (rejected as `too large: ... max: encoded/raw 1644/1232`), while 842 bytes is
/// accepted. 1257 - 874 = 383.
pub const INSERT_TRANSACTION_OVERHEAD: usize = 383;

/// Largest `InstructionData` that still fits a legacy `InsertTransaction`.
/// Anything above this needs a v0 transaction with an address lookup table.
/// This is the 849 in `--max-instruction-bytes`' help text; pass it explicitly
/// to check a proposal that will be submitted without a lookup table.
#[allow(dead_code)]
pub const MAX_INSERTABLE_INSTRUCTION_DATA: usize = 1232 - INSERT_TRANSACTION_OVERHEAD;

/// Same, for a submission that resolves the recurring keys through a single
/// address lookup table.
///
/// Measured on a fork, one table per transaction: a 970-byte payload compiles to
/// 1203 bytes and inserts; 1002 -> 1236 and 1066 -> 1299 are both rejected
/// against the 1232 limit. That puts the overhead at ~233 bytes and the true
/// ceiling at ~999.
///
/// Instruction sizes are quantised to `522 + 32 * proof_depth`, so the only sizes
/// near the boundary are 970 (depth 14) and 1002 (depth 15) — any cutoff in
/// 971..=1001 behaves identically. 998 is used because it was the first value
/// measured, and it admits every payload that actually fits.
///
/// This holds ONLY while a transaction draws on one lookup table. A second
/// contributing table costs ~35 more bytes and drops the ceiling to ~963.
pub const MAX_INSERTABLE_INSTRUCTION_DATA_V0: usize = 1232 - 234;

pub fn anchor_discriminator(preimage: &str) -> [u8; 8] {
    let hash = solana_sdk::hash::hash(preimage.as_bytes());
    let mut discriminator = [0u8; 8];
    discriminator.copy_from_slice(&hash.to_bytes()[..8]);
    discriminator
}
