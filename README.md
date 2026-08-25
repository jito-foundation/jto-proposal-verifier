# JTO proposal verifier

An independent, read-only checker for JTO DAO proposals that cast **jitoSOL
stake-pool vote overrides** in Solana network governance (`svmgov`).

It answers one question: *if the council approves this proposal, will it
actually execute on-chain, and will it cast the vote it claims to cast?*

Run it before you vote. It never signs, never sends a transaction, and never
asks for a key or a wallet.

---

## Why this tool exists

A single jitoSOL vote-override proposal is **~900 separate instructions** — the
`vote_override` PDA is seeded by the stake account, so the pool needs one
instruction per stake account, per SGP being voted on. You cannot eyeball that
in the Realms UI.

Worse, most of the ways such a proposal can be broken are invisible there. The
UI will happily show a well-formed proposal whose instructions will fail at
execution time, or that were never fully inserted, or whose embedded merkle
proofs do not match the on-chain snapshot. This tool reproduces every
precondition the on-chain programs enforce and reports what would happen.

### Why the JTO DAO can vote for the jitoSOL pool at all

Worth knowing before you review one of these, because it looks surprising:

The NCN snapshot maps a stake pool's **withdraw authority to the pool's
`manager`** and uses that as the `voting_wallet` on every one of the pool's
stake leaves. jitoSOL's manager is
`5eosrve6LktMZgVNszYzebgmmC7BjLK8NoWyRQtcmGTF`, which **is the JTO governance
native treasury PDA**. `ExecuteTransaction` signs the treasury PDA whenever it
appears in an instruction — so a JTO proposal can legitimately sign
`cast_vote_override` on the pool's behalf.

Check #2 below is what confirms that in any given proposal: every instruction's
signer must be the JTO governance or its native treasury, and nothing else.

---

## Build

Requires a stable Rust toolchain ([rustup.rs](https://rustup.rs)).

```bash
git clone <this repo>
cd jto-proposal-verifier
cargo build --release
```

The binary lands at `target/release/verify_proposal`. First build takes a few
minutes (it compiles the Solana SDK); after that it is instant.

---

## Usage

### Check a live proposal you are about to vote on

Paste the Realms URL, or just the proposal address:

```bash
./target/release/verify_proposal \
  --realms-url "https://app.realms.today/dao/JTO/proposal/<address>"
```

This reads the instructions back out of the proposal's on-chain
`ProposalTransaction` accounts — so it verifies **what is actually on chain**,
not what someone says is on chain. It also catches inserts that never landed.

### Check a proposal JSON artifact before it is submitted

```bash
./target/release/verify_proposal --proposal sgp-all-vote-override-for.json
```

Same checks, plus a transaction-size check (see #4). Useful for reviewing a
proposal before it hits the DAO.

### Options

| Flag | Default | Purpose |
|---|---|---|
| `--rpc-url` | `https://api.mainnet-beta.solana.com` | Use your own RPC if the public one rate-limits. |
| `--governance` | `8cEhMTswovtkzQKWZx7h66bL2ZKF8fBADyzfL6MPt4PK` | JTO DAO governance account. |
| `--program-id` | `jtogvBNH3WBSWDYD5FJfQP2ZxNTuf82zL8GkEhPeaJx` | Jito's spl-governance deployment. |
| `--svmgov-program-id` | `govYkyQ…HdCAZU` | Solana network governance program. |
| `--snapshot-program-id` | `ncnwF8Ag…8cf9Zf` | NCN snapshot program that publishes stake roots. |
| `--max-instruction-bytes` | `998` | Insert-size budget. `998` assumes the submitter uses an address lookup table; pass `849` for plain legacy transactions. |

Everything defaults to JTO mainnet, so the two commands above are usually all
you need.

---

## Reading the output

A healthy proposal ends with:

```
Governance           : 8cEhMTswovtkzQKWZx7h66bL2ZKF8fBADyzfL6MPt4PK
Native treasury      : 5eosrve6LktMZgVNszYzebgmmC7BjLK8NoWyRQtcmGTF
RPC                  : https://api.mainnet-beta.solana.com
Realms proposal      : <address>
  name               : jitoSOL: Vote FOR SGP-0001
  state              : Voting
  governance         : 8cEhMTswovtkzQKWZx7h66bL2ZKF8fBADyzfL6MPt4PK
  transactions       : 882 declared, 0 executed
  instructions       : 882
  stake              : 29567738 SOL
  svmgov proposals   : 3
    4aFA8K65…  294 ix  10000/0/0 bp  epochs [1021, 1024)  SGP-0001: The Solana Constitution
    7QJD8Mzh…  294 ix  10000/0/0 bp  epochs [1021, 1024)  Double Disinflation
    AGHDQ6gj…  294 ix  10000/0/0 bp  epochs [1021, 1024)  SGP-0003: Resource and Inclusion Fee
  proof accounts     : 882 / 882 present
  merkle tier 1      : 882 verified
  merkle tier 2      : 882 verified

EXECUTABLE — every precondition checked out.
```

Read the middle block as the **substance of the vote**: which SGPs, how much
stake, which direction. `NOT EXECUTABLE` lists each failed check with its
reason.

`10000/0/0 bp` is the **for/against/abstain** split, in basis points, that every
instruction for that SGP carries — so `10000/0/0` is a full-weight FOR vote and
`0/10000/0` is a full-weight AGAINST. A bundle may legitimately vote differently
on different SGPs, so read one line per SGP. `MIXED SPLITS` on a line means the
instructions for that SGP disagree with each other, and is always a failure
(see #3).

**`EXECUTABLE` is a mechanical verdict, not an endorsement.** It means the
instructions will land. Whether they *should* is your vote — so check that the
`svmgov proposals` listed, the `stake`, and each SGP's split are what the
proposal's title and forum post claim.

---

## What it checks

**1. Instruction shape.** Every instruction targets the `svmgov` program, has
exactly 11 accounts and the real `cast_vote_override` discriminator, and its
for/against/abstain split sums to 10000 bp. The declared merkle-proof depth
must match the actual payload length. Account 0 must be a writable signer and
must equal the `voting_wallet` embedded in the vote leaf; account 6 must equal
the leaf's stake account. No two instructions may share a `vote_override` PDA —
a duplicate would make the whole proposal fail on `init`.

**2. Signer authority.** Every signer must be the JTO governance account or its
native treasury PDA. Anything else cannot be signed by `ExecuteTransaction`, so
the instruction could never execute. This is the check that constrains *whose
stake* the proposal is voting.

**3. svmgov proposal state, voting window, and a unanimous split.** Each
referenced svmgov proposal is fetched live: it must not already be finalized,
and the current epoch must fall inside its `[start_epoch, end_epoch)` window. A
proposal bundling several SGPs must have them all on **one**
snapshot/consensus result — instructions embed leaves from a specific snapshot,
so a bundle spanning two could never verify. Every instruction is checked
against that consensus result.

Every instruction for a given SGP must also carry the **same**
for/against/abstain split, and the split is printed per SGP. This is what
catches a single instruction among ~900 that votes the opposite way to the
proposal's title — it sums to 10000 bp like all the others, passes every other
check, and is invisible in the Realms UI. The failure names the offending
instruction indices.

**4. Transaction size.** Instruction size is `522 + 32 × proof_depth`, and an
insert has a hard byte ceiling, so deep proofs can produce instructions that
*cannot be submitted*. Reported for JSON artifacts; skipped for on-chain
proposals, which cleared it by definition.

**5. Proof accounts exist and are valid.** `cast_vote_override` only *reads* the
per-validator `MetaMerkleProof` account — it never creates it. If it is
missing, that instruction fails. Each one is checked for existence, correct
owner program, and matching vote account. A warning is printed if any is
already past its `close_timestamp`, meaning someone could reclaim the rent and
delete a proof the proposal still needs.

**6. Merkle tier 1.** The on-chain `MetaMerkleProof`'s leaf and proof are folded
locally and must reproduce the consensus result's meta merkle root.

**7. Merkle tier 2.** The stake leaf and proof embedded *in the proposal's own
instruction data* are folded locally and must reproduce that validator's stake
merkle root. Tiers 6 and 7 together are what prove the proposal is voting real,
snapshotted stake with valid proofs — this is the core cryptographic check, and
it is done with local recomputation, trusting nothing but the on-chain roots.

**8. Not already executed.** If a `VoteOverride` account already exists,
re-executing fails with "already in use".

**9. On-chain integrity** (`--realms-url` only). The proposal is governed by the
expected governance account, and every declared `ProposalTransaction` account
actually exists. A gap means an insert never landed — the proposal looks
complete in the UI but would execute short.

### Limits worth knowing

- The split check (#3) confirms the instructions agree with **each other**. It
  cannot know what the forum post promised — compare the printed split against
  the proposal's stated intent yourself.
- Not every stake account in the pool appears in a snapshot. Transient accounts
  and anything activated after the snapshot slot hold no votable stake at that
  slot and are legitimately absent.
- Timing is not checked. `svmgov` voting is an epoch range; JTO governance is a
  5-day vote plus a 2-day cool-off, so a full-window council vote will usually
  miss the svmgov window — these proposals generally only land via vote
  tipping. Check the epoch window in the output against the calendar yourself.

---

## Security posture

- **Read-only.** The only RPC methods used are `getAccountInfo`,
  `getMultipleAccounts`, `getEpochInfo`, `getSlot`, and `getBlockTime`. There is
  no signing code, no keypair handling, and no transaction submission anywhere
  in this repo.
- **No trusted inputs.** Merkle roots come from on-chain accounts and the proofs
  are folded locally. Point `--rpc-url` at an RPC you trust and the result
  depends on nothing else.
- **Small dependency surface.** One crate, no vendored forks, no
  `[patch.crates-io]`: `anyhow`, `base64`, `borsh`, `clap`, `serde_json`,
  `solana-client`, `solana-sdk`.
- `src/governance.rs` mirrors the handful of `spl-governance` 3.1.1 account
  layouts and two PDA derivations that the checks read, rather than depending on
  that crate — `spl-governance` 3.1.1 needs a borsh-0.9 patch across three
  crates to build, which would have meant vendoring ~14k lines here. The
  mirrored layouts are validated against live mainnet accounts.

## Layout

```
src/main.rs         CLI, JTO mainnet defaults, governance account resolution
src/verify.rs       the checks — all nine, in the order above
src/svmgov.rs       svmgov Proposal layout, merkle folding, size constants
src/governance.rs   mirrored spl-governance account layouts and PDA seeds
```

`src/verify.rs` holds all nine checks and is the file to read if you want to
audit what this tool actually enforces. It depends only on `src/governance.rs`
for account layouts, so it can be reviewed top to bottom without following the
`spl-governance` dependency tree.
