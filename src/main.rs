//! Standalone verifier for jitoSOL vote-override proposals.
//!
//! Read-only: it never signs or sends anything. Point it at a generated JSON
//! artifact before submission, or at a live Realms proposal afterwards, and it
//! reports whether every precondition for execution holds.
//!
//! The rules live in [`verify`], with the pure payload invariants in
//! [`invariants`] and the account layouts mirrored in [`governance`].

use anyhow::{Context, Result};
use borsh::BorshDeserialize;
use clap::Parser;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use std::path::PathBuf;

mod governance;
mod invariants;
mod svmgov;
mod timestamp;
mod verify;

use governance::{get_native_treasury_address, GovernanceV2};
use svmgov::{NCN_SNAPSHOT_PROGRAM_ID, SVMGOV_PROGRAM_ID};
use timestamp::parse_utc;
use verify::{verify_proposal, GovernanceContext, Verdict};

const JITO_GOV_PROGRAM_ID: &str = "jtogvBNH3WBSWDYD5FJfQP2ZxNTuf82zL8GkEhPeaJx";
const JTO_DAO_GOVERNANCE: &str = "8cEhMTswovtkzQKWZx7h66bL2ZKF8fBADyzfL6MPt4PK";

#[derive(Parser, Debug)]
#[command(
    about = "Verify whether a jitoSOL vote-override proposal can be submitted and executed",
    long_about = "Checks a vote-override proposal against live chain state and prints \
EXECUTABLE or NOT EXECUTABLE with the reasons.\n\n\
Pass --proposal to check a generated JSON artifact before submitting it, or \
--realms-url to check a proposal that is already on-chain. The on-chain path \
additionally reports the proposal's state and catches inserts that never landed.\n\n\
This tool is read-only and never signs a transaction.\n\n\
Exit status: 0 EXECUTABLE, 2 NOT EXECUTABLE, 1 the check could not be completed."
)]
struct Args {
    #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
    rpc_url: String,

    #[arg(long, default_value = JITO_GOV_PROGRAM_ID)]
    program_id: Pubkey,

    #[arg(long, default_value = JTO_DAO_GOVERNANCE)]
    governance: Pubkey,

    /// Proposal JSON produced by `proposal_tool create-vote-override`.
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
    /// transactions, 998 with `realms-cli --use-lookup-table`. Ignored for
    /// --realms-url, where the instructions are already on-chain.
    #[arg(long, default_value_t = 998)]
    max_instruction_bytes: usize,

    /// The moment by which the proposal must still be executable, as
    /// `YYYY-MM-DDTHH:MM:SSZ` (UTC) or Unix seconds. Proof accounts that anyone can
    /// close before this are reported. Defaults to chain time + 72h.
    #[arg(long)]
    execution_horizon: Option<String>,

    /// Print the one-page summary a Security Council member can read and compare
    /// against an independent verifier, instead of only the check-by-check log.
    #[arg(long)]
    report: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    // Parsed before any RPC so a malformed horizon fails immediately rather than
    // after a minute of network calls.
    let horizon = args
        .execution_horizon
        .as_deref()
        .map(parse_utc)
        .transpose()
        .context("parsing --execution-horizon")?;
    let rpc = RpcClient::new_with_commitment(args.rpc_url.clone(), CommitmentConfig::confirmed());

    // The verifier needs the realm's governance-controlled signers to confirm
    // ExecuteTransaction could actually sign the payload.
    let governance_data = rpc
        .get_account_data(&args.governance)
        .with_context(|| format!("fetching governance account {}", args.governance))?;
    GovernanceV2::deserialize(&mut &governance_data[..]).context("borsh-decoding GovernanceV2")?;
    let native_treasury = get_native_treasury_address(&args.program_id, &args.governance);

    // Every resolved constant is echoed, defaults included. A run against the wrong
    // svmgov program or size budget used to look identical to a correct one.
    println!("Governance           : {}", args.governance);
    println!("Native treasury      : {native_treasury}");
    println!("Realms program       : {}", args.program_id);
    println!("svmgov program       : {}", args.svmgov_program_id);
    println!("Snapshot program     : {}", args.snapshot_program_id);
    println!("Max instruction bytes: {}", args.max_instruction_bytes);
    println!(
        "Source               : {}",
        match (args.proposal.as_ref(), args.realms_url.as_deref()) {
            (Some(path), _) => format!("artifact {}", path.display()),
            (_, Some(url)) => format!("on-chain {url}"),
            _ => "none".to_string(),
        }
    );
    println!("RPC                  : {}", args.rpc_url);

    let verdict = verify_proposal(
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
        horizon,
    )?;

    if args.report {
        print_report(&args, &verdict);
    }

    // A failed verdict must be visible to a caller that reads only the exit status.
    // Reserving 1 for anyhow keeps "the check failed" distinct from "the check could
    // not be run", which are very different things to a script gating a signature.
    if !verdict.executable() {
        std::process::exit(2);
    }
    Ok(())
}

/// The one page a Council member reads: what is being voted, by how much stake, and
/// the digest to compare against an independent implementation.
fn print_report(args: &Args, verdict: &Verdict) {
    println!();
    println!("──────── VERIFICATION REPORT ────────");
    println!(
        "Verdict           : {}",
        if verdict.executable() {
            "EXECUTABLE"
        } else {
            "NOT EXECUTABLE"
        }
    );
    println!("Instructions      : {}", verdict.instructions);
    println!(
        "Stake             : {:.2} SOL across {} stake account(s)",
        verdict.total_stake as f64 / 1e9,
        verdict.stake_accounts
    );
    match verdict.votes.len() {
        1 => {
            let (vote, _) = verdict.votes.iter().next().expect("exactly one vote");
            println!("Vote              : {vote} — uniform across all instructions");
        }
        n => {
            println!("Vote              : NOT UNIFORM — {n} different votes");
            for (vote, indices) in &verdict.votes {
                println!(
                    "                    {vote} on {} instruction(s), first ix {}",
                    indices.len(),
                    indices.first().copied().unwrap_or_default()
                );
            }
        }
    }
    println!("svmgov program    : {}", args.svmgov_program_id);
    println!("Snapshot program  : {}", args.snapshot_program_id);
    println!("Invariant digest  : {}", verdict.digest);
    if verdict.problems.is_empty() {
        println!("Problems          : none");
    } else {
        println!("Problems          : {}", verdict.problems.len());
        for problem in &verdict.problems {
            println!("  [{}] {}", problem.check, problem.detail);
        }
    }
    // The stake set is cross-checked by a separate implementation on purpose; one
    // binary agreeing with itself proves nothing.
    println!("Cross-check       : reviews/coverage-check.mjs, then compare the digest above");
    println!("─────────────────────────────────────");
}
