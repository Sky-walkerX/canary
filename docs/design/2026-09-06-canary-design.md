# Canary — Design Document

**Status:** In progress. §1 settled; §2–§8 pending.
**Date:** 2026-09-06
**Target:** BOSS Battle (Bitshala), 7 Sep – 5 Oct 2026, Cypherpunk track
**Team:** 3, all Go-capable

---

## 0. Summary

Canary is a sidecar daemon that sits between a BIP-352 light wallet and its tweak
indexers, and detects when an indexer withholds tweak data. Detection is cheap and
continuous; attribution is expensive and on-demand. Indexers publish signed per-block
commitments to their tweak set as Nostr events; clients verify the data they were
served against those commitments, and cross-check commitments across indexers.

The project is layered deliberately:

- **Tool first.** The client-side differ works against indexers as they exist today
  and requires nobody's cooperation.
- **Protocol second.** The signed-commitment extension makes detection cheap (32 bytes
  per block per server, instead of N full fetches) and makes an accusation transferable
  and non-repudiable.

---

## 1. Scope and threat model — SETTLED 2026-09-06

### 1.1 Actors

| Actor | Description | Trust |
|---|---|---|
| **Client** | Light wallet holding a scan key, no full node | Honest (it is the victim) |
| **Indexers I₁…I_N** | Serve BIP-352 tweak data per block | Any may be malicious |
| **Relays** | Nostr relays distributing commitments | May censor or withhold |
| **Block source** | Independent source of a transaction and its prevouts | Used only during attribution; may be sampled/rotated |

### 1.2 Attacks in scope

| Attack | Status today | With Canary |
|---|---|---|
| **Targeted omission** — drop tweaks for one victim | Silent, permanent, symptomless | Detected within one block interval |
| **Blanket omission** — truncated, stale, or dead-but-200 index | Indistinguishable from "no payments" | Detected, and publicly visible |
| **Equivocation** — serve victim set X, serve world set Y | Undetectable | Detected against the server's own signature |
| **Retroactive revision** — rewrite history to cover tracks | Trivial | Defeated by published, signed, timestamped events |

Blanket omission is not theoretical. `bitcoin.silentium.dev`, the public indexer named
in the light-client documentation, no longer serves the API: the domain redirects to an
unrelated parked page that returns **HTTP 200 with an identical 533-byte body for every
path**, including `/v1/block/850000/scalars`. A client pointed at it does not receive an
error. It receives a success response and no payments. (Verified 2026-09-06.)

### 1.3 The equivocation insight

The requirement is not "compare N servers." It is: **the client must check the data it
was served against that server's own public commitment.** This binds a server to a
single answer for all clients, which changes the security ladder:

| Assumption | Defeats | Why |
|---|---|---|
| **One** indexer, publishing commitments | Targeted omission | The server must either omit from everyone — public, affects all users, detectable by anyone with a node — or serve data contradicting its own signature |
| **N** indexers, ≥1 honest | Blanket omission as well | The honest server's commitment differs; divergence is proof that someone is lying |
| **All N** colluding | Only the tripwire | And only for payments the client already knows exist |

This is the split-view problem from
[Certificate Transparency (RFC 6962)](https://www.rfc-editor.org/rfc/rfc6962). CT's
answer is gossip between clients; ours is a public relay. We cite it rather than
claiming to have invented it.

### 1.4 Security claim

> Given at least one honest indexer publishing commitments, and an uncensored path to
> at least one relay carrying them, Canary converts targeted omission from a silent,
> permanent failure into a detected event with a named, non-repudiable accused party,
> within one block interval of the omission.

### 1.5 Attacks explicitly out of scope

- **Commission / injection.** A malicious indexer inserting fake tweaks so the victim
  fetches a block and reveals their IP — the three attacks harding described on Delving
  Bitcoin in June 2024. The accepted mitigation is fetching blocks from random full
  nodes over ephemeral Tor identities. Canary's k-of-N rule (require a tweak to appear
  in multiple independent commitments before acting on it) raises the bar as a side
  effect; this is a note, not a claim.
- **Total collusion of all queried indexers.** Passively undetectable. The tripwire
  catches it only because the client has an independent path to know a payment exists —
  it sent that payment itself.
- **Network-level attacks** — eclipse, TLS interception. Assumed handled by transport.
- **A wallet that ignores the alarm.** Detection that is not surfaced changes nothing.

### 1.6 Non-goals

1. **Canary does not make tweak sourcing trustless.** It makes it accountable. This is
   stated first in the README and in the first 30 seconds of the pitch — a limitation
   volunteered reads as rigor; the same limitation extracted by a judge reads as
   overclaiming.
2. Not a solution to commission attacks (§1.5).
3. Not a scanning-performance project. Frigate solved cost in May 2026; integrity is an
   orthogonal axis.
4. Not a new BIP-158 filter type — that requires work in Bitcoin Core.
5. Not a wallet. blindbitd remains the wallet; Canary is a sidecar.
6. Not mainnet-scale indexing in v1. Signet, with bounded block ranges.
7. Not a succinct (SNARK) proof of correct indexing. Named as the endgame, not built.

---

## 2. Canonical tweak sets and policy normalization — PENDING

The hard problem. Honest indexers legitimately serve *different* tweak sets:
blindbit-oracle supports cut-through and dust filtering; silentiumd indexes only
transactions with unspent taproot outputs. A naive diff is all false positives. This
section must define the canonical set, how a server declares its serving policy, and how
a client normalizes before comparing.

## 3. Commitment format and Nostr transport — PENDING

Merkle construction over the canonical set, sort order, signing, event kind, and the
"commit at index time, prune freely afterward" property that lets a cut-through server
stay accountable for what it dropped at 32 bytes per block.

## 4. Client verification ladder — PENDING

The four steps in detail, including k-of-N policy and what happens on each failure mode.

## 5. Canary tripwire — PENDING

Self-payment scheduling that a selectively-malicious server cannot distinguish from
real traffic.

## 6. Components, interfaces, ownership — PENDING

Go package boundaries, the interfaces frozen at end of week 1, and the three-way split.

## 7. Testing — differential edge-case suite — PENDING

Constructed signet transactions that deliberately hit ambiguous BIP-352 eligibility
corners (NUMS point H script-path spends, mixed input types, non-standard scripts), run
against every implementation. Any disagreement is a real interop bug worth reporting
upstream.

## 8. Demo — PENDING

---

## Appendix A — Prior art

See [`../research/prior-art.md`](../research/prior-art.md).
