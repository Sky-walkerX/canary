# CLAUDE.md — working context for Canary

Read this first. It records decisions already made so they don't get relitigated, and
names the mistakes that will be tempting to make.

---

## What this is

**Canary** detects when a BIP-352 silent-payments tweak indexer withholds data. Today a
light wallet cannot distinguish "nobody paid you" from "the server hid the payment" —
no error, no symptom, permanent.

Built for **BOSS Battle** (Bitshala), **7 Sep – 5 Oct 2026**, Cypherpunk/Privacy track.
Hard deadline. One winner per track, $1,000.

Repo: `github.com/Sky-walkerX/canary` (**private** until submission — publishing the
idea early hands it to competitors).

## Current state — 2026-09-06

**Design phase. Nothing is implemented, and nothing should be until the design is
approved section by section.**

| | |
|---|---|
| Architecture | Approved (sidecar + 4-step ladder + Nostr transport) |
| §1 Threat model | Settled |
| §2 Canonical sets + policy normalization | **Next. Blocks everything else** — it defines the data model |
| §3–§8 | Stubbed in the design doc, each with what it must resolve |

Design doc: `docs/design/2026-09-06-canary-design.md`
Research + citations: `docs/research/prior-art.md`

## Process we are following

`superpowers:brainstorming`, architectural path: context → questions → approaches →
**design presented in sections, approval after each** → written spec → `writing-plans`
→ implementation.

**The approval gate is hard.** Do not write code, scaffold packages, or invoke an
implementation skill until the user has approved the design. The user has explicitly
asked to "design things one by one" — they want the step-by-step, not a jump to output.

## Decisions already made — do not relitigate

| Decision | Why |
|---|---|
| **Layered: tool first, protocol second** | The client-side differ works against indexers as they exist and needs nobody's cooperation. The signed-commitment extension is the upgrade, not the foundation |
| **Sidecar daemon**, not library-first, not a public observatory | Works with unmodified `blindbitd` today; the library falls out of it for free. An observatory protects nobody, and the public-server substrate is dying (see below) |
| **Go** | blindbit-oracle, silentiumd and gobip352 are all Go; all three teammates are Go-capable |
| **Signet, not mainnet** | Mainnet needs an unpruned Core v30+ and days of IBD. Nothing in the design requires mainnet |
| **Nostr for commitment transport** | Free public signed timestamped bulletin board, no infrastructure for servers to run; clients subscribe to a relay instead of opening N connections, which also avoids leaking which blocks they care about |
| **Construct edge cases, don't scan for them** | Build signet transactions that deliberately hit ambiguous BIP-352 eligibility rules rather than hoping mainnet supplies one |
| **Run all indexers locally** | Never depend on a third-party public server being alive — that fragility is literally what the project is about |

**Superseded:** the original dossier proposed OpenTimestamps anchoring. Nostr events
replace it. OTS may return in v2 to anchor the event chain.

## Framing discipline — this is not optional

**Canary does not make tweak sourcing trustless. It makes it accountable.**

Say this first — in the README, in the docs, in the first 30 seconds of the pitch. A
limitation volunteered reads as rigor; the same limitation extracted by a judge reads as
overclaiming. The security claim is conditional and must always be stated with its
condition: *given at least one honest indexer publishing commitments, and an uncensored
path to a relay carrying them.*

Related discipline: cite Certificate Transparency (RFC 6962) for the split-view
insight. We are applying it, not inventing it.

## Team

3 people, all Go-capable. Interfaces frozen end of week 1; everyone runs the same signet
node.

- **Naman** — protocol design, commitments, demo narrative
- **Dev B** — indexer fork + signed roots (Go)
- **Dev C** — client differ + normalizer (Go)

## Mistakes that will be tempting

1. **Diffing raw tweak sets.** It produces nothing but false positives. Honest indexers
   legitimately serve different sets — blindbit-oracle does cut-through and dust
   filtering, silentiumd indexes only transactions with unspent taproot outputs.
   Normalization against a *declared policy* is the whole problem. This is §2.
2. **Claiming we solved commission attacks.** We did not. Injection-to-deanonymize is a
   different attack with the opposite structure; ephemeral Tor block fetching is the
   accepted answer. Our k-of-N rule raises the bar as a side effect — that is a note,
   not a claim.
3. **Reaching for mainnet.** Costs days, buys nothing the design needs.
4. **Building a wallet.** `blindbitd` is the wallet. Canary is a sidecar.
5. **Treating the research as durable.** `docs/research/prior-art.md` is dated and
   perishable — the entire project rests on the gap still being open. Re-verify before
   relying on it.
6. **Committing secrets.** `.gitignore` already covers `nsec*`, `*.key`, `*.pem`,
   `.env`, `blindbit.toml`, `bitcoin.conf`. We will handle Nostr signing keys and Core
   RPC config; keep them out.

## External facts worth not re-deriving

- **BIP-352 v1.1.0 (Mar 2026)** states the withholding trust assumption itself.
- **Bitshala's BIP-352 guide (3 Aug 2026)** calls trustless tweak sourcing "the big one."
- **Core PR #28241** (SP index) closed unmerged Feb 2025. Its "consistency check" means
  test-vector validation, not client-side detection. No collision.
- **Delving thread 891** (Jun 2024) is the canonical light-client discussion. harding's
  three attacks are all *commission*. Omission was never separately analyzed.
- **blindbit-oracle v2** needs Bitcoin Core **v30+**, unpruned, REST enabled
  (`/rest/spenttxouts`, Core PR #32540). `/info` already advertises policy-ish feature
  flags — a natural place to hang a policy declaration.
- **Signet SP faucet**: `https://silentpayments.dev/faucet/signet/` — removes the need
  for a counterparty when demonstrating receipt.
- **`bitcoin.silentium.dev` is dead.** The public indexer named in the light-client docs
  now redirects to a parked page returning HTTP 200 with an identical 533-byte body for
  every path. A client pointed at it gets success and no payments. Useful as both a
  motivating example and a warning about demo dependencies.

## Conventions

- Design docs: `docs/design/YYYY-MM-DD-<topic>.md`
- Commit messages explain *why*, not just what. Trailer:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- Work on `main` for now; branch when parallel tracks start.
