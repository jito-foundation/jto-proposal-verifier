//! The handful of `spl-governance` 3.1.1 account layouts and PDA derivations
//! this verifier reads, mirrored field-for-field from the on-chain program.
//!
//! Why mirrored rather than imported: `spl-governance 3.1.1` implements borsh
//! 0.9 traits, while the published `spl-governance-tools`/`-addin-api` moved to
//! borsh 0.10, so depending on it requires vendoring and patching three crates.
//! The verifier needs six items out of that tree, and borsh's wire format for
//! these shapes (structs, `Vec`, `Option`, unit-ish enums, fixed arrays) is
//! identical across 0.9 and 0.10 — so declaring them here keeps this crate a
//! single dependency-clean crate.
//!
//! These layouts are positional: if a field is added, removed, or reordered
//! relative to the deployed program, decoding misreads. In practice a mismatch
//! fails loudly rather than silently — borsh hits a garbage length prefix on one
//! of the trailing `String` fields and the decode errors out with the context
//! attached at the call site. `spl-governance` 3.1.1 is a frozen, deployed
//! version, so these do not move.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_sdk::pubkey::Pubkey;

/// `spl_governance::PROGRAM_AUTHORITY_SEED`.
const PROGRAM_AUTHORITY_SEED: &[u8] = b"governance";

/// `spl_governance::state::enums::GovernanceAccountType`.
///
/// The full variant list matters: borsh encodes the variant *index*, so an
/// omitted variant would shift every discriminant after it.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum GovernanceAccountType {
    Uninitialized,
    RealmV1,
    TokenOwnerRecordV1,
    GovernanceV1,
    ProgramGovernanceV1,
    ProposalV1,
    SignatoryRecordV1,
    VoteRecordV1,
    ProposalInstructionV1,
    MintGovernanceV1,
    TokenGovernanceV1,
    RealmConfig,
    VoteRecordV2,
    ProposalTransactionV2,
    ProposalV2,
    ProgramMetadata,
    RealmV2,
    TokenOwnerRecordV2,
    GovernanceV2,
    ProgramGovernanceV2,
    MintGovernanceV2,
    TokenGovernanceV2,
    SignatoryRecordV2,
    ProposalDeposit,
}

/// `spl_governance::state::enums::ProposalState`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum ProposalState {
    Draft,
    SigningOff,
    Voting,
    Succeeded,
    Executing,
    Completed,
    Cancelled,
    Defeated,
    ExecutingWithErrors,
    Vetoed,
}

/// `spl_governance::state::enums::VoteThreshold`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum VoteThreshold {
    YesVotePercentage(u8),
    QuorumPercentage(u8),
    Disabled,
}

/// `spl_governance::state::enums::InstructionExecutionFlags`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum InstructionExecutionFlags {
    None,
    Ordered,
    UseTransaction,
}

/// `spl_governance::state::enums::TransactionExecutionStatus`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum TransactionExecutionStatus {
    None,
    Success,
    Error,
}

/// `spl_governance::state::proposal::OptionVoteResult`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum OptionVoteResult {
    None,
    Succeeded,
    Defeated,
}

/// `spl_governance::state::proposal::MultiChoiceType`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum MultiChoiceType {
    FullWeight,
    Weighted,
}

/// `spl_governance::state::proposal::VoteType`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum VoteType {
    SingleChoice,
    MultiChoice {
        choice_type: MultiChoiceType,
        min_voter_options: u8,
        max_voter_options: u8,
        max_winning_options: u8,
    },
}

/// `spl_governance::state::proposal::ProposalOption`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ProposalOption {
    pub label: String,
    pub vote_weight: u64,
    pub vote_result: OptionVoteResult,
    pub transactions_executed_count: u16,
    pub transactions_count: u16,
    pub transactions_next_index: u16,
}

/// `spl_governance::state::proposal::ProposalV2`.
///
/// Every field is required even though the verifier reads only `governance`,
/// `state`, `options`, and `name` — borsh is positional, and `name` sits after
/// the 64-byte reserved block.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ProposalV2 {
    pub account_type: GovernanceAccountType,
    pub governance: Pubkey,
    pub governing_token_mint: Pubkey,
    pub state: ProposalState,
    pub token_owner_record: Pubkey,
    pub signatories_count: u8,
    pub signatories_signed_off_count: u8,
    pub vote_type: VoteType,
    pub options: Vec<ProposalOption>,
    pub deny_vote_weight: Option<u64>,
    pub reserved1: u8,
    pub abstain_vote_weight: Option<u64>,
    pub start_voting_at: Option<i64>,
    pub draft_at: i64,
    pub signing_off_at: Option<i64>,
    pub voting_at: Option<i64>,
    pub voting_at_slot: Option<u64>,
    pub voting_completed_at: Option<i64>,
    pub executing_at: Option<i64>,
    pub closed_at: Option<i64>,
    pub execution_flags: InstructionExecutionFlags,
    pub max_vote_weight: Option<u64>,
    pub max_voting_time: Option<u32>,
    pub vote_threshold: Option<VoteThreshold>,
    pub reserved: [u8; 64],
    pub name: String,
    pub description_link: String,
    pub veto_vote_weight: u64,
}

/// `spl_governance::state::enums::VoteTipping`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum VoteTipping {
    Strict,
    Early,
    Disabled,
}

/// `spl_governance::state::governance::GovernanceConfig`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct GovernanceConfig {
    pub community_vote_threshold: VoteThreshold,
    pub min_community_weight_to_create_proposal: u64,
    pub min_transaction_hold_up_time: u32,
    pub voting_base_time: u32,
    pub community_vote_tipping: VoteTipping,
    pub council_vote_threshold: VoteThreshold,
    pub council_veto_vote_threshold: VoteThreshold,
    pub min_council_weight_to_create_proposal: u64,
    pub council_vote_tipping: VoteTipping,
    pub community_veto_vote_threshold: VoteThreshold,
    pub voting_cool_off_time: u32,
    pub deposit_exempt_proposal_count: u8,
}

/// `spl_governance::state::governance::GovernanceV2`.
///
/// The verifier reads `config.voting_base_time` and `config.voting_cool_off_time`
/// to project when a proposal could earliest execute.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct GovernanceV2 {
    pub account_type: GovernanceAccountType,
    pub realm: Pubkey,
    pub governed_account: Pubkey,
    pub reserved1: u32,
    pub config: GovernanceConfig,
    /// `spl_governance::state::legacy::Reserved120` — a 120-byte reserved block.
    pub reserved_v2: [u8; 120],
    pub active_proposal_count: u64,
}

/// `spl_governance::state::proposal_transaction::AccountMetaData`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct AccountMetaData {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// `spl_governance::state::proposal_transaction::InstructionData`.
///
/// This is the payload encoding used by `instructions_base64` in proposal JSON
/// and by `solana-cli`'s "Base64 InstructionData" output.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct InstructionData {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMetaData>,
    pub data: Vec<u8>,
}

/// `spl_governance::state::proposal_transaction::ProposalTransactionV2`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ProposalTransactionV2 {
    pub account_type: GovernanceAccountType,
    pub proposal: Pubkey,
    pub option_index: u8,
    pub transaction_index: u16,
    pub hold_up_time: u32,
    pub instructions: Vec<InstructionData>,
    pub executed_at: Option<i64>,
    pub execution_status: TransactionExecutionStatus,
    pub reserved_v2: [u8; 8],
}

/// `spl_governance::state::proposal_transaction::get_proposal_transaction_address_seeds`.
///
/// The option index is part of the seed, so each proposal option addresses its
/// own set of transaction accounts.
pub fn get_proposal_transaction_address_seeds<'a>(
    proposal: &'a Pubkey,
    option_index: &'a [u8; 1],
    instruction_index_le_bytes: &'a [u8; 2],
) -> [&'a [u8]; 4] {
    [
        PROGRAM_AUTHORITY_SEED,
        proposal.as_ref(),
        option_index,
        instruction_index_le_bytes,
    ]
}

/// `spl_governance::state::proposal_transaction::get_proposal_transaction_address`.
pub fn get_proposal_transaction_address(
    program_id: &Pubkey,
    proposal: &Pubkey,
    option_index_le_bytes: &[u8; 1],
    instruction_index_le_bytes: &[u8; 2],
) -> Pubkey {
    Pubkey::find_program_address(
        &get_proposal_transaction_address_seeds(
            proposal,
            option_index_le_bytes,
            instruction_index_le_bytes,
        ),
        program_id,
    )
    .0
}

/// `spl_governance::state::native_treasury::get_native_treasury_address`.
pub fn get_native_treasury_address(program_id: &Pubkey, governance: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"native-treasury", governance.as_ref()], program_id).0
}
