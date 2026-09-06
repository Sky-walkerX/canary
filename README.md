# Canary

**A silent-payments wallet cannot tell the difference between "nobody paid you" and
"the server hid the payment." Canary makes that difference loud, provable, and
attributable to a named server.**

---

## Status

**Design phase.** No implementation yet. The threat model (§1 of the design doc) is
settled; the remaining sections are in progress. See
[`docs/design/2026-09-06-canary-design.md`](docs/design/2026-09-06-canary-design.md).

Built for [BOSS Battle](https://bitshala.org) (Bitshala), 7 Sep – 5 Oct 2026,
Cypherpunk / Privacy track.

## The problem

BIP-352 receiving requires a server to feed the client 33-byte tweaks, one per
eligible transaction. If that server omits a transaction, the payment is simply
invisible to the receiver. There is no error, no retry, no symptom — the wallet shows
the same empty balance it would show if nobody had paid.

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

A sidecar daemon between any light wallet and its indexers. It runs a four-step
verification ladder — detection is cheap and continuous, attribution is expensive and
on-demand:

1. **Continuous** — pull 32-byte signed per-block commitments from N indexers.
   Agreement costs almost nothing.
2. **On divergence** — fetch the full tweak sets from the disagreeing servers,
   normalize for each server's *declared* serving policy, and take the symmetric
   difference. Honest servers legitimately serve different sets; this step is what
   separates policy from dishonesty.
3. **Attribution** — for each disputed tweak, fetch that transaction and its prevouts
   from an independent source and recompute it. No full node required.
4. **Active** — plant self-payments at random intervals so there is known-good ground
   truth even when no real payments are arriving.

Commitments are published as signed Nostr events. Servers get a public, timestamped
bulletin board with no infrastructure to run; clients subscribe to a relay rather than
opening N connections, which also avoids leaking which blocks they care about.

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
> at least one relay carrying them, Canary converts targeted omission from a silent,
> permanent failure into a detected event with a named, non-repudiable accused party,
> within one block interval of the omission.

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
docs/design/      design documents, one per dated revision
docs/research/    prior-art findings with citations
```

## License

MIT (intended; not yet applied pending team agreement).
