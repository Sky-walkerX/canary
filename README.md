# Canary

**A silent-payments wallet cannot tell the difference between "nobody paid you" and
"the server hid the payment." Canary makes that difference loud, and attributable to a
named server.**

---

## Status

**Design phase. No code yet.** All eight sections of the design doc are settled — threat
model, canonical sets, commitment format, verification ladder, tripwire, components,
testing, demo — and all 22 defects against it are closed: fifteen raised by a spec review
on 7 September, seven more by a self-review on 8 September. See
[`docs/design/2026-09-06-canary-design.md`](docs/design/2026-09-06-canary-design.md).

Three implementation plans follow it, split along the design's ownership boundaries —
[protocol core](docs/superpowers/plans/2026-09-08-canary-protocol-core.md) (16 tasks),
[indexer fork](docs/superpowers/plans/2026-09-08-canary-indexer-fork.md) (8), and
[sidecar](docs/superpowers/plans/2026-09-08-canary-sidecar.md) (9). Each is test-first
down to the step. Execution is next.

Built for [BOSS Battle](https://bitshala.org) (Bitshala), 7 Sep – 5 Oct 2026,
Cypherpunk / Privacy track.

## The problem

BIP-352 receiving requires a server to feed the client 33-byte tweaks, one per
eligible transaction. If that server omits a transaction, the payment is simply
invisible to the receiver. There is no error, no retry, no symptom — the wallet shows
the same empty balance it would show if nobody had paid.

The attacker with the clearest motive is not a stranger. An indexer cannot identify
which transactions pay a given silent-payment address — that requires the private scan
key — so targeted omission needs out-of-band knowledge of the payment. The party who
always has it is the sender:

> **The exchange that pays you is also the indexer that tells you whether you were paid.**

That is the default deployment for a light wallet: the vendor runs the backend. The
counterparty holds a signed record showing it paid. You see nothing. There is no error.

This is not a hypothetical. **BIP-352 v1.1.0 (March 2026) states the trust assumption
directly**: light-client approaches allow the indexer to withhold data, preventing the
receiver from seeing payments. Bitshala's own BIP-352 guide (3 August 2026) calls
trustless tweak sourcing "the big one" among the protocol's open problems and states
plainly that a client accepting tweaks from a server has no way to detect omission.

The production answer to date — Frigate, shipped with Sparrow 2.5.0 in May 2026 —
sidesteps the question by holding the user's scan key. It made scanning *fast*. It did
not make scanning *honest*, and it is explicit about that.

Nobody has shipped the thing that measures whether the assumption is being violated.

## What Canary does

A sidecar daemon between any light wallet and its indexers.

The load-bearing idea is one line. Every legitimate indexer policy — cut-through, dust
filtering, unspent-only indexing, a start height — only *removes* transactions. None
invents one. So:

> **Served ⊆ Canonical.** A tweak served but not committed is fabrication. A tweak
> committed but not served requires a reason.

Indexers commit to the policy-free canonical set for each block, and serve whatever
subset their policy allows. Storage policy stays free; accountability does not. That is
what makes comparison possible at all: honest indexers serve different sets, so diffing
raw responses produces nothing but false positives, and BIP-352 itself blesses the
divergence.

Everything else is a ladder ordered by cost. Detection is cheap and continuous;
attribution is expensive and on demand.

1. **Commitment tracking** — always on. Each indexer publishes a ~200-byte signed Nostr
   event per block carrying a 32-byte root over its canonical set. Two roots that
   disagree for the same block hash mean somebody is lying.
2. **Self-consistency** — when the wallet fetches a block, recompute the root from what
   was actually served. *Served ≠ committed* is proven against that server's own
   signature, from that one server alone. This is the rung that catches targeted
   omission.
3. **Gap resolution** — a server may legitimately decline a position it pruned, so fill
   the gap from another server *before* recomputing the root. A block whose root was never
   recomputed is not clean; it has no verdict. If nobody can fill the gap, the range is
   *unresolvable* — an ecosystem gap, deliberately not an accusation, and equally
   deliberately not a pass.
4. **Attribution** — recompute the canonical set from the transaction and its prevouts to
   decide *which* server lied. This needs a full node or another block source. A client
   without one records the signed evidence and hands the verdict to someone who has one,
   later or never.

Then the rung of last resort, the one that survives every queried indexer colluding:
**the tripwire.** Assert that a payment exists in a block — because you sent it, or
because the sender gave you the txid — and check whether each indexer reports it. It is
also the one place a client attributes without a node, because it holds the prevouts for
a transaction it made itself.

**The primary output is coverage, not alarms.** Per block range: verified, resolved,
unresolvable, unverified, disputed, compromised. An alarm that never fires looks like a
product that does nothing. Coverage is continuous, and it yields the line worth leading
with:

> **A balance computed over blocks you could not verify is a lower bound, not a balance.**

Commitments are published as signed Nostr events — a public, append-only bulletin board
with no infrastructure for servers to run. Clients subscribe to a relay rather than
opening N connections, which also avoids leaking which blocks they care about. Nostr
gives us *publication*, not timestamping: `created_at` is self-asserted and backdatable,
so ordering comes from the block hash.

## What Canary does *not* do

Stated first, deliberately.

- **It does not make tweak sourcing trustless.** It makes it *accountable*. If every
  indexer you query colludes and you have planted no canary, you learn nothing.
- **It does not solve commission attacks** — a malicious server injecting fake tweaks
  to learn a client's IP. Ephemeral Tor block fetching is the accepted answer there.
  Canary's k-of-N rule raises the bar as a side effect; that is not a claim to have
  solved it.
- **It does not make scanning faster.** Frigate solved cost. This is integrity, an
  orthogonal axis.
- **It is not a wallet**, not a new Bitcoin Core filter type, and not a succinct proof
  of correct indexing. That last one is the real endgame and is named as future work.

## Security claim

> Given at least one honest indexer publishing commitments, and an uncensored path to
> at least one relay carrying them, Canary converts omission from a silent, permanent
> failure into a detected event naming a server and a block.

Two qualifiers, stated with the claim rather than waiting to be extracted from it:

- **Detection is not proof.** Two roots that disagree are signed by different keys, so
  equivocation is provable to anyone. A single server's omission is provable to a third
  party only where that server signs receipts over its responses, which is the protocol
  layer. Against an unmodified indexer today, the victim knows and cannot prove it.
- **Timing depends on the attack.** Blanket omission and equivocation surface from the
  always-on commitment feed, roughly one block interval. Targeted omission surfaces when
  the client fetches the block it was lied about — about a block interval for a wallet at
  the tip, and whenever the rescan reaches that block for a rescan.

The security ladder degrades honestly:

| Assumption | Defeats |
|---|---|
| One indexer, publishing commitments | Targeted omission (the server cannot equivocate) |
| N indexers, at least one honest | Blanket omission as well |
| All N colluding | Only the tripwire, and only for payments you already know exist |

This is [Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)'s split-view
problem. CT answers it with gossip; Canary answers it with a public relay.

## Repository layout

```
docs/design/               design documents, one per dated revision
docs/research/             prior-art findings with citations
docs/superpowers/plans/    implementation plans, one per subsystem
```

## License

MIT (intended; not yet applied pending team agreement).
