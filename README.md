# Regent Solana Programs

Three Anchor programs that put a tamper-evident record of AI-agent authority on
Solana: which agents exist, what they were permitted to spend, and proof that an
audit trail has not been rewritten.

They are the on-chain half of [Regent Protocol](https://regentprotocol.org), an
authorization layer for AI agents that move money. Before an agent pays, a gate
checks that a verified human stands behind it and that the request falls inside
the mandate that human issued. Every decision leaves a signed receipt; batches of
those records are Merkle-rooted and the root is anchored here.

## Why anchor at all

A decision log is only evidence if the party that wrote it cannot quietly rewrite
it. Our database can be altered by an administrator, so the log alone proves
nothing to a bank, an auditor or an insurer.

Anchoring the Merkle root of each batch to a public ledger fixes that: the root is
witnessed by a chain no party to the transaction controls. Anyone holding a record
can recompute its hash, walk the Merkle proof to the root, and compare that root
with what is on chain — without asking us for anything.

Solana is a good fit because anchoring happens **per batch, continuously**. At that
cadence, sub-cent fees and fast confirmation are what make per-batch anchoring
viable rather than something to be saved up and batched for cost.

## The programs

| Program | Devnet address | What it stores |
|---|---|---|
| `audit-anchor` | `8N1PpbJZKmvJjG86XWpP82XrWzp8HY5FHZuzyQTgjJas` | the Merkle root of a batch of audit events, with its batch id and timestamp |
| `agent-registry` | `5jBmqyeo1vUAjHbEFuY59NMGTQR8cEe9Jvz2uCwCjp3L` | that an agent exists, the responsible party behind it, the DID hash, and revocation |
| `mandate-registry` | `8HAzw3UFGmabsHJkAsuGLfBZG8djYQ3J1FRNUVjkseMr` | that a spending mandate exists and which agent it binds to, and revocation |

All three follow the same shape: a one-time `initialize` sets an operator
authority in a `config` PDA (`seeds = ["config"]`), and every writing instruction
is gated with `has_one = authority`. Records live in their own PDAs, derived from
the record id — `["batch", batch_id]`, `["agent", agent_id]`, `["mandate", mandate_id]`
— so anyone can compute where a record should be and read it directly.

### What is deliberately *not* on chain

No personal data, no amounts, no payees, no mandate terms. Only identifiers,
hashes and status. The terms of a mandate are revealed off-chain through a
commit-and-reveal scheme, so the chain carries proof without carrying content.

## Build and test

```bash
npm install
anchor build
anchor test          # ts-mocha + chai against a local validator
```

Requires Anchor 0.31.1 and the Solana toolchain. Rust edition 2021.

## Verifying a record

The offline verifiers are published separately and need nothing from us at
verification time:

- Python — [`regent-receipt-verify`](https://pypi.org/project/regent-receipt-verify/)
- Node — [`@regent-protocol/receipt-verify`](https://www.npmjs.com/package/@regent-protocol/receipt-verify)
- Source — [regent-protocol/regent-receipt-verify](https://github.com/regent-protocol/regent-receipt-verify)

## Status and security

**Devnet.** `audit-anchor` has been anchoring production audit batches since
12 April 2026: 160 anchor transactions, zero failures, as of 25 September 2026.
Mainnet deployment is planned *after* an independent security review, not before.

Three things a reader should know rather than discover:

1. **No independent audit yet.** These programs have not been reviewed by a
   third party. Commissioning that review is the reason mainnet is not the next
   step.
2. **Upgrade authority** for all three programs was moved to an offline key on
   25 September 2026. It has never been in a repository.
3. **Operator authority** — the key that may write records — is still a key that
   appeared in the history of a private repository. Only `agent-registry` has a
   `transfer_authority` instruction today; adding one to `audit-anchor` and
   `mandate-registry` so the operator can be rotated without redeploying is the
   next change to these programs.

There is no token, no treasury and nothing custodial in this repository.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
