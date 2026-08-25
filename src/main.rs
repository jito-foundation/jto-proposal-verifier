//! Standalone verifier for JTO DAO jitoSOL vote-override proposals.
//!
//! Read-only: it never signs, never sends, and never asks for a key. Point it at
//! a generated JSON artifact before submission, or at a live Realms proposal
//! afterwards, and it reports whether every precondition for execution holds.

use anyhow::{bail, Context, Result};
use borsh::BorshDeserialize;
use clap::Parser;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use std::path::PathBuf;

mod governance;
mod svmgov;
mod verify;

use governance::{get_native_treasury_address, GovernanceAccountType};
use svmgov::{MAX_INSERTABLE_INSTRUCTION_DATA_V0, NCN_SNAPSHOT_PROGRAM_ID, SVMGOV_PROGRAM_ID};
use verify::{verify_proposal, GovernanceContext};

const JITO_GOV_PROGRAM_ID: &str = "jtogvBNH3WBSWDYD5FJfQP2ZxNTuf82zL8GkEhPeaJx";
const JTO_DAO_GOVERNANCE: &str = "8cEhMTswovtkzQKWZx7h66bL2ZKF8fBADyzfL6MPt4PK";

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Verify whether a JTO jitoSOL vote-override proposal can be submitted and executed",
    long_about = "Checks a vote-override proposal against live chain state and prints \
EXECUTABLE or NOT EXECUTABLE with the reasons.\n\n\
Pass --proposal to check a generated JSON artifact before submitting it, or \
--realms-url to check a proposal that is already on-chain. The on-chain path \
additionally reports the proposal's state and catches inserts that never landed.\n\n\
This tool is read-only and never signs a transaction."
)]
struct Args {
    #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
    rpc_url: String,

    #[arg(long, default_value = JITO_GOV_PROGRAM_ID)]
    program_id: Pubkey,

    #[arg(long, default_value = JTO_DAO_GOVERNANCE)]
    governance: Pubkey,

    /// Proposal JSON: `{"title", "description_link", "instructions_base64": [...]}`.
    #[arg(long, conflicts_with = "realms_url")]
    proposal: Option<PathBuf>,

    /// A Realms proposal URL (`https://app.realms.today/dao/JTO/proposal/<address>`)
    /// or a bare proposal address, verified on-chain.
    #[arg(long, conflicts_with = "proposal")]
    realms_url: Option<String>,

    #[arg(long, default_value = SVMGOV_PROGRAM_ID)]
    svmgov_program_id: Pubkey,

    #[arg(long, default_value = NCN_SNAPSHOT_PROGRAM_ID)]
    snapshot_program_id: Pubkey,

    /// Insert-size budget applied to a JSON artifact: 849 for legacy
    /// transactions, 998 when the submitter uses an address lookup table.
    /// Ignored for --realms-url, where the instructions are already on-chain.
    #[arg(long, default_value_t = MAX_INSERTABLE_INSTRUCTION_DATA_V0)]
    max_instruction_bytes: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.proposal.is_none() && args.realms_url.is_none() {
        bail!("pass exactly one of --proposal <file.json> or --realms-url <url|address>");
    }
    let rpc = RpcClient::new_with_commitment(args.rpc_url.clone(), CommitmentConfig::confirmed());

    // The verifier needs the realm's governance-controlled signers to confirm
    // ExecuteTransaction could actually sign the payload. Checking the owner and
    // account type here means a mistyped --governance fails with a clear message
    // rather than as a downstream signer-authority mismatch.
    let account = rpc
        .get_account(&args.governance)
        .with_context(|| format!("fetching governance account {}", args.governance))?;
    if account.owner != args.program_id {
        bail!(
            "governance account {} is owned by {}, not the governance program {}",
            args.governance,
            account.owner,
            args.program_id
        );
    }
    match GovernanceAccountType::deserialize(&mut &account.data[..]) {
        Ok(GovernanceAccountType::GovernanceV2) => {}
        Ok(other) => bail!("{} is a {other:?}, not a GovernanceV2", args.governance),
        Err(err) => bail!("{} has an unreadable account type: {err}", args.governance),
    }
    let native_treasury = get_native_treasury_address(&args.program_id, &args.governance);

    println!("Governance           : {}", args.governance);
    println!("Native treasury      : {native_treasury}");
    println!("RPC                  : {}", args.rpc_url);

    verify_proposal(
        &GovernanceContext {
            rpc: &rpc,
            program_id: args.program_id,
            governance: args.governance,
            native_treasury,
        },
        args.proposal.as_ref(),
        args.realms_url.as_deref(),
        &args.svmgov_program_id,
        &args.snapshot_program_id,
        args.max_instruction_bytes,
    )
}
