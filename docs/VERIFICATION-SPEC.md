# What verification proves for a vote-override proposal

A jitoSOL vote-override proposal carries one `cast_vote_override` instruction per
(svmgov proposal, stake account) pair. The current SGP payload is 882 of them, casting
about 9.86M SOL across three svmgov proposals. Nobody can read that by hand, so the
decision to sign rests on tooling.

This document is the contract. It states, in plain language, what the tooling checks —
so a reviewer approves a **list of rules** rather than a program's output. If a rule is
not on this list, no tool checks it, and no one should assume otherwise.

Two things follow from that, and both are deliberate:

- **A clean verdict is not a statement about intent.** The tools prove the payload
  matches the rules below. Whether *these* proposals should get *this* vote is a
  governance question no invariant can answer.
- **Anything not listed is unverified.** Section "Deliberately not checked" says what
  falls outside, rather than leaving a reader to guess.

## The rules

Checks marked *offline* need only the artifact and run without network access, in
`cli/src/invariants.rs`. Checks marked *chain* additionally read live accounts, in
`cli/src/verify.rs`.

| # | Rule | Where |
|---|---|---|
| I1 | Every instruction targets the svmgov program, whose id is echoed in the output. | offline |
| I2 | Every instruction's discriminator is `cast_vote_override`. | offline |
| I3 | Every instruction carries exactly the 11 accounts the IDL declares, in IDL order. | offline |
| I4 | In each instruction, `for + against + abstain == 10000` basis points. | offline |
| I5 | **Every instruction casts the same vote.** All distinct votes are printed with counts. | offline |
| I6 | The only signer is the governance native treasury, which is what `ExecuteTransaction` can sign for. | chain |
| I7 | Account 0 equals the `voting_wallet` in the instruction's own merkle leaf. | offline |
| I8 | Account 6 equals the `stake_account` in that leaf. | offline |
| I9 | No two instructions share a `vote_override` PDA, so no stake votes twice on one proposal. | offline |
| I10 | Each proof account is owned by the snapshot program **and stays closed-proof until the execution horizon**. | chain |
| I11 | The payload contains nothing but `cast_vote_override` — no other instruction of any kind. | offline |
| I12 | **The stake-account set equals an independently derived pool set: none extra, none missing.** | separate tool |
| I13 | **Every proposal option is enumerated; options above 0 must carry no transactions.** | chain |
| I14 | **No account is marked writable or signer beyond what the IDL requires.** | offline |

Bold marks a rule that was not checked anywhere before this branch. Each of the four
corresponds to a way a payload could pass the old verifier while doing something other
than what was described.

### Why I5 exists

Instruction 441 of the real payload was changed from FOR to AGAINST and re-run through
the old verifier. It printed `vote split : 10000 bp for` and
`EXECUTABLE — every precondition checked out.` — output identical to the clean run
apart from the filename line. The per-instruction sum was still 10000, so I4 held; the
summary only ever printed instruction 0. One flipped instruction moved a validator's
entire stake to the other side of a governance vote, invisibly.

### Why I10 measures against a horizon

A vote is cast against a `meta_merkle_proof` account. `close_meta_merkle_proof` lets
whoever paid close it at any time, and lets **anyone** close it once its
`close_timestamp` passes. A closed proof makes its instruction fail, so the tally can
only shrink.

Asking "is this proof alive right now?" answers the wrong question: the payload is
signed now and executed later. `--execution-horizon` names the moment it must still be
executable at, and every proof closeable before then is reported with the stake behind
it. The default is chain time plus 72 hours.

### Why I13 reads every option

`ProposalV2` holds a list of options, each with its own transactions, keyed by option
index in the PDA seed. The old verifier read `options.first()` and pinned the seed to
option 0. Under SingleChoice the resolver picks the winning option by weight — so an
option the verifier could not see is exactly the one that could execute. The generator
only ever populates option 0, which makes anything under a higher option a finding
rather than a variation.

## Two implementations, one digest

An implementation checking itself proves nothing, so two exist and are compared:

- `cli/` — Rust, `verify_proposal`, using the repo's own types.
- `verify-artifact.mjs` plus `coverage-check.mjs` — Node, sharing **no code** with the
  Rust path. Its wire format comes from published spl-governance 3.1.1 and the on-chain
  IDL. This is on purpose: two implementations are only worth running if they can fail
  independently.

Both print an **invariant digest** over a canonical decoded form of the payload:

```
per instruction i, in payload order:
  line = i | base58(program_id) | hex(discriminator) | for | against | abstain
       | (base58(pubkey) + s|- + w|-) x 11
       | hex(sha256(instruction data from byte 32 on))
digest = sha256(lines joined by newline)
```

Equal digests mean the two implementations **decoded every instruction the same way**,
which is a far stronger statement than "both read the same file". The proof and leaf
are hashed rather than inlined so a line stays readable; the line form is dumpable
(`--dump-lines`) so a mismatch can be traced to the instruction that caused it.

I12 stays in Node on purpose. Deriving the stake-account set independently is the check
that found four validators worth 124,566.96 SOL silently dropped from the payload by the
instruction-size filter. Folding that derivation into the Rust binary would leave one
implementation agreeing with itself.

## Reading the exit status

| Code | Meaning |
|---|---|
| 0 | EXECUTABLE — every rule above holds. |
| 2 | NOT EXECUTABLE — at least one rule failed; the reasons are printed. |
| 1 | The check could not be completed (bad input, RPC failure). **Not a verdict.** |

`NOT EXECUTABLE` previously exited 0, so no script could gate on it. Anything automated
must distinguish 1 from 2: "the payload is wrong" and "we do not know" call for
different responses.

## Deliberately not checked

- **Whether the vote is the right one.** I5 proves all 882 instructions agree; it cannot
  say they agree on the correct answer. Confirm the direction against the governance
  decision by hand.
- **Whether the stake set is the intended one.** I12 compares the payload against the
  pool's on-chain validator list. If the pool itself is not what was intended, no check
  here notices.
- **Program upgrades.** All three programs involved are upgradeable, and the Realms
  program has no verified build. Verifying a payload against a program says nothing
  about what that program will be at execution time.
- **What happens after execution.** The tools cover submission and execution
  preconditions, not consequences.
- **The snapshot's correctness.** Merkle proofs are verified against the on-chain
  consensus root. Whether that root reflects reality is the snapshot system's problem.

## Running them

```sh
# Rust, before submission — artifact against live chain state.
verify_proposal --proposal proposals/sgp-all-vote-override-for.json \
                --execution-horizon 2026-08-30T00:00:00Z --report

# Rust, after submission — read the instructions back off-chain.
verify_proposal --realms-url <proposal address> --report

# Node, independent: shape, uniformity, and the same digest.
node verify-artifact.mjs proposals/sgp-all-vote-override-for.json

# Node, independent: I12, the stake set derived from the pool itself.
node coverage-check.mjs
```

Compare the two digests. If they differ, dump the lines from both and diff them.
