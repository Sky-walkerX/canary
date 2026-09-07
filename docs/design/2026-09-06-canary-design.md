# Canary — Design Document

**Status:** In progress. §1–§2 settled; §3–§8 pending.
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

## 2. Canonical tweak sets and policy normalization — SETTLED 2026-09-07

### 2.1 The separation: committed set vs. served set

BIP-352's scanning rule explicitly permits cut-through:

> The transaction contains at least one BIP341 taproot output (note: spent transactions
> optionally can be skipped by only considering transactions with at least one unspent
> taproot output)

Divergence between honest indexers is therefore *sanctioned by the specification*, not a
defect to be standardized away. Any design that requires all servers to serve identical
sets is dead on arrival.

Every real policy — cut-through, dust filtering, unspent-only indexing, start height —
**only removes** tweaks. None invents one. That asymmetry carries the section:

> **Served ⊆ Canonical.** A tweak served but not canonical is fabrication. A tweak
> canonical but not served requires a reason.

So we do not normalize served sets against each other. We define one policy-free set,
require the *commitment* to be over that set, and leave the wire format free.

**Consequence for the indexer.** A participating server must compute the full canonical
set even for transactions it will immediately discard — index time is the only moment it
holds both the block and its prevouts. Storage policy stays free; accountability does
not. This is the cost of adoption and must be stated plainly to any indexer we ask to
run it.

### 2.2 The canonical set `T_base(block)`

A pure function of a block and its prevouts. No chain state after the block, no
thresholds, no configuration. A transaction is included iff:

1. It has at least one BIP-341 taproot output — **without** the optional "unspent" clause
2. It has at least one input from *Inputs For Shared Secret Derivation* (P2TR, P2WPKH,
   P2SH-P2WPKH, P2PKH)
3. It spends no output with SegWit version > 1
4. `A_sum` is not the point at infinity, and `input_hash` is a valid scalar

The result is an ordered sequence of **(txid, tweak)** pairs in transaction-index order.

| Decision | Rejected alternative | Why |
|---|---|---|
| Transaction-index order | Lexicographic by tweak | Free — it is already the computation order — and position carries meaning: position *i* is a specific transaction, which is exactly what attribution (§4) needs |
| Leaf is `(txid, tweak)` | Leaf is the bare 33-byte tweak | A bare tweak is unverifiable against anything. `(txid, tweak)` is independently recomputable by anyone holding the transaction and its prevouts; a single eligibility disagreement then diffs by txid instead of shifting every later position; and "which transaction was hidden" is answered directly rather than derived |

**Stated limitation.** A light client cannot compute `T_base` — it needs prevouts. The
client verifies consistency and agreement, never correctness against the chain.
Correctness requires a full node computing `T_base` independently and comparing roots.
That is a distinct **auditor** role, defined in §6.

### 2.3 Policy declaration

Every field is subtractive.

| Field | Meaning |
|---|---|
| `network` | Comparison is only meaningful within one network |
| `start_height` | Below this, absence is not evidence |
| `prunes_spent` | Drops transactions with no unspent taproot outputs |
| `dust_threshold_sat` | 0 = none. Drops transactions whose taproot outputs are all below it |
| `dust_configurable` | Threshold is per-request; the client's own request parameter defines its expectation |

blindbit's cut-through and silentiumd's unspent-only indexing are collapsed into a single
`prunes_spent` flag. They differ in *when* the drop happens, not in what a client
observes, and under §2.1 both commit to the same `T_base`. The distinction has no
observable consequence.

The declaration does three things:

1. **A server declaring a full index that shows any gap has contradicted itself.** Alarm,
   purely local — no second server, no escalation. This is the "one honest indexer" row
   of §1.3 made mechanical.
2. **It makes the excuse non-repudiable.** "Dropped for cut-through" is available only if
   cut-through was declared before the block, publicly and signed.
3. **It bounds escalation.** The client knows in advance whose gaps require a second
   source.

**Tool-first bridge.** For the layer that works against indexers as they exist today, the
policy struct is derived from blindbit's existing `GET /info` feature flags. That is
unsigned and not per-block — a server can revise it retroactively — so it is strictly
weaker. It is also what lets the differ run against unmodified blindbit today. The signed
per-block policy is the protocol layer. This is where "tool first, protocol second" (§0)
becomes concrete rather than aspirational.

### 2.4 Wire model

Per-leaf Merkle inclusion proofs were considered and rejected: at `log n × 32` bytes each
they cost roughly 528 KB of proof to accompany 50 KB of tweaks on a mainnet-sized block.

Instead the response is the canonical-order list in which each position is **either the
full leaf or that leaf's 32-byte hash**. The client hashes the full leaves, splices in
the supplied hashes, and recomputes the root in a single pass.

- Serving everything: no overhead at all.
- Serving a subset: 32 bytes per withheld position, with no logarithmic factor.
- The server must produce the hash of the leaf it dropped. It cannot pretend the position
  does not exist, and it binds itself to a specific hidden value that another server's
  set can later be checked against. Preimage resistance means this leaks nothing.

Merkle proofs earn their place only for targeted queries ("positions 3, 7, 11 without the
block"). That is an optimization; see §3. §2 fixes only *what* is committed: the ordered
canonical leaf list and its length `n`.

### 2.5 Comparison procedure

Keyed on block **hash**, not height — this makes the procedure reorg-safe at no cost and
removes "it was a reorg" as an available excuse.

Given block hash `B`, server `S`, declared policy `P`, published root `R`, response `D`:

1. **No commitment for `B` → refuse the data.** Serving data for a block you have not
   committed to is a refusal of accountability.
2. **Recompute the root** from `D`. A mismatch means `S` served data contradicting its
   own signature. Proven and non-repudiable.
3. **Gap set `G`** = the positions returned as bare hashes.
4. If `P` declares no subtraction and `G ≠ ∅` → alarm. Local and immediate.
5. **Cross-check** `R` against other servers' roots for the same `B`. Equal → all
   committed to the same set, so fetch `G`'s positions from a server that retains them.
   Unequal → at least one is lying; escalate to attribution (§4).

Steps 1–4 require a single server. Step 5 costs 32 bytes per block per server as a
continuous background check.

**Three terminal states, not two:**

| State | Meaning |
|---|---|
| **Clean** | Roots agree; gaps resolved or expected under declared policy |
| **Omission detected** | Named server, block, transaction, signature |
| **Unresolvable** | Every queried server has pruned it. An ecosystem gap, not an attack, and it must not be reported as one |

**Mode-dependent tolerance.** A transaction can only be cut through once all its taproot
outputs are spent, which at the chain tip is nearly empty; and a spent output is one the
client either spent itself or never owned. Rescan-from-seed is where the light-client
specification already admits payments go missing. So a tip-following client accepts
cut-through gaps; a rescanning client escalates them.

### 2.6 What this fixes for the team

The interface frozen at the end of week 1:

```go
CanonicalSet(block, prevouts) []Leaf
```

Dev B's indexer commits to it; Dev C's differ compares against it; the differential suite
(§7) tests it.

§2 also generates §7's target list. Each item below is a place where two correct
implementations could disagree on `T_base`, and each is constructible on signet:

- NUMS point *H* detection via control-block parsing
- Malleated P2PKH `scriptSig` parsing — the BIP *requires* parsing non-template scriptSigs
- Uncompressed and hybrid public key rejection
- `outpoint_L` serialization and endianness
- SegWit version > 1 input exclusion
- Coinbase transactions
- `A_sum` at the point at infinity

### 2.7 Preconditions

The claim that all legitimate policy is subtractive holds given two conditions, stated
rather than assumed:

1. Both servers are indexing the **same network**.
2. Comparison is keyed on **block hash**, not height.

## 3. Commitment format and Nostr transport — PENDING

§2 settled *what* is committed: the ordered canonical leaf list and its length `n`.
This section settles *how*.

Open: leaf tagging and hashing; whether a Merkle tree is warranted at all, given §2.4
removed the need for inclusion proofs on the main path — the tree earns its place only
for targeted position queries and for the "commit at index time, prune freely afterward"
property; how `n` is bound; the Nostr event kind, tags, and signing; how a policy
declaration (§2.3) is published and bound to a commitment stream; and how a client
discovers and pins a server's identity key.

## 4. Client verification ladder — PENDING

The four steps in detail, including k-of-N policy and what happens on each failure mode.

## 5. Canary tripwire — PENDING

Self-payment scheduling that a selectively-malicious server cannot distinguish from
real traffic.

## 6. Components, interfaces, ownership — PENDING

Go package boundaries, the interfaces frozen at end of week 1, and the three-way split.
Must also define the **auditor** role that fell out of §2.2: a full node computing
`T_base` independently and comparing it against published roots. It is the only party
that can verify a root is *correct* rather than merely *consistent*.

## 7. Testing — differential edge-case suite — PENDING

Constructed signet transactions that deliberately hit ambiguous BIP-352 eligibility
corners (NUMS point H script-path spends, mixed input types, non-standard scripts), run
against every implementation. Any disagreement is a real interop bug worth reporting
upstream.

## 8. Demo — PENDING

---

## Appendix A — Prior art

See [`../research/prior-art.md`](../research/prior-art.md).
