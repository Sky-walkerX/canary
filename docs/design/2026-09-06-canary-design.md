# Canary — Design Document

**Status:** In progress. §1–§7 settled; §8 pending. A spec review on 2026-09-07 found 15
defects. The 8 editorial ones are corrected in place below; the 7 design-level ones are
open and tracked in `CLAUDE.md`.
**Date:** 2026-09-06, revised 2026-09-07
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

- **Tool first.** Against indexers as they exist today, with nobody's cooperation: take
  the union of what they serve (§4.3), read each server's policy from its existing
  `/info` (§2.3), and run the tripwire (§5), which detects *and* attributes without any
  server committing to anything.
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
| **Block source** | Independent source of a transaction and its prevouts, and of chain facts | Used during attribution, and as §4.6's chain anchor where one is needed; may be sampled/rotated |

### 1.2 Attacks in scope

| Attack | Status today | With Canary |
|---|---|---|
| **Targeted omission** — drop tweaks for one victim | Silent, permanent, symptomless | Detected when the client fetches the block (§1.4) |
| **Blanket omission** — truncated, stale, or dead-but-200 index | Indistinguishable from "no payments" | Detected, and publicly visible |
| **Equivocation** — serve victim set X, serve world set Y | Undetectable | Detected against the server's own signature |
| **Retroactive revision** — rewrite history to cover tracks | Trivial | Defeated by published, signed, **append-only** events (§3.3) |

Blanket omission is not theoretical. `bitcoin.silentium.dev`, the public indexer named
in the light-client documentation, no longer serves the API: the domain redirects to an
unrelated parked page that returns **HTTP 200 with an identical 533-byte body for every
path**, including `/v1/block/850000/scalars`. A client pointed at it does not receive an
error. It receives a success response and no payments. (Verified 2026-09-06.)

**How an attacker targets a victim at all** (added 2026-09-07, from §5.1). An indexer
holding a victim's *published* silent-payment address cannot determine which transactions
pay them: scanning requires `input_hash · b_scan · A_sum`, and the indexer has only the
tweak and `B_scan = b_scan·G`. It needs the private scan key. This is BIP-352's own
guarantee and it applies to the indexer like anyone else.

Targeted omission therefore requires out-of-band knowledge, which narrows the attacker
to three cases:

| Route | How the attacker knows | Assessment |
|---|---|---|
| **The attacker is the sender** | They paid the victim; they know the txid exactly | The realistic case |
| **Blanket degradation targeted by identity** | They do not know which tweaks are the victim's — they drop a fraction at random for that connection | Cheap; requires no identification at all |
| **Out-of-band leak** | Invoice, stated amount, timing correlation | Situational |

The first case is the motivating scenario and belongs in the README and the pitch:

> **The exchange that pays you is also the indexer that tells you whether you were paid.**

This is the default deployment for a light wallet — the vendor runs the backend. The
counterparty holds a signed record showing it paid; the victim sees nothing; there is no
error and no symptom. The analysis makes the threat more concrete rather than less: the
attacker who can identify a victim's payment is precisely the one who sent it, and
blanket degradation needs no identification whatsoever.

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
> at least one relay carrying them, Canary converts omission from a silent, permanent
> failure into a detected event naming a server and a block.

Two qualifiers travel with the claim rather than waiting to be extracted from it. An
earlier draft folded them in and overstated the claim in both directions.

**Detection is not proof.** Two roots that disagree are signed by two different keys, so
equivocation is provable to anyone. A *single* server's omission is `commitment ≠ what I
was served`, and HTTP responses carry no signature — so it is provable to a third party
only where the server signs receipts over its responses (§3.8), which exists in the
protocol layer and not in the tool layer. Against an unmodified indexer, the victim knows
and cannot prove it. Non-repudiation is a property of the protocol layer.

**Timing depends on the attack.** Blanket omission and equivocation are `committed ≠
canonical`, and surface from the always-on commitment feed — rung 1 (§4.1), about one
block interval. Targeted omission is `served ≠ committed`, and surfaces at rung 2, whose
trigger is the client fetching the block it was lied about. For a wallet following the
tip that is also about a block interval. For a rescan it is whenever the rescan reaches
that block, which may be much later. Even then it converts a permanent silent failure
into a named one attached to a specific block, which is the claim that matters. (Not a
*dated* one — the block orders it, not Nostr's self-asserted `created_at`. §3.5.)

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

Retention is deliberately **not** a field here. §2.4 makes a 144-block hash-retention
window a protocol constant, because a server allowed to declare its own window declares
zero.

**Tool-first bridge.** For the layer that works against indexers as they exist today, the
policy struct is derived from blindbit's existing `GET /info` feature flags. That is
unsigned and not per-block — a server can revise it retroactively — so it is strictly
weaker. It is also what lets the differ run against unmodified blindbit today. The signed
per-block policy is the protocol layer. This is where "tool first, protocol second" (§0)
becomes concrete rather than aspirational.

### 2.4 Wire model

Per-leaf Merkle inclusion proofs were considered and rejected: at `⌈log₂ n⌉ × 32` bytes
each — 352 bytes at `n ≈ 2000` — they cost about 700 KB of proof to accompany 130 KB of
leaves. `n ≈ 2000` is the order of magnitude for a mainnet block and is the figure used
throughout, including §3.2.

Instead the response is the canonical-order list in which each position is **the full
leaf, that leaf's 32-byte hash, or nothing**. The client hashes the full leaves, splices
in the supplied hashes, and recomputes the root in a single pass.

**The response is self-describing at length `n`.** The client must be able to tell which
of the three it is looking at for every position, without inference, and the list must be
exactly `n` long, matching the commitment. A response that is merely *shorter* is
indistinguishable from a smaller block, and under a single server there is no cross-check
to catch the difference.

- Serving everything: 65 bytes per position against 33 for a bare tweak — **roughly
  double today's response.** That is the honest cost and it is not avoidable: the txid
  has to be on the wire, because a light client does not know which transactions are in
  the set and so cannot supply it. Bandwidth doubles; storage stays free (§3.7).
- Serving a subset while retaining leaf hashes: 32 bytes per withheld position, with no
  logarithmic factor, and the response is verifiable from that one server alone.
- Serving a subset with the hash discarded: nothing on the wire for that position, and
  the block is verifiable only once the leaf is recovered elsewhere. Permitted only
  outside the retention window below.

**Retention is required inside a 144-block window and optional beyond it.** This
corrects an amendment made earlier on 2026-09-07, which dropped the retention requirement
outright and opened a hole in §2.5.

The amendment's reasoning was that retention is only an optimization, and that part was
right. If the client can obtain a missing leaf from *any* source, it hashes the candidate,
recomputes the root, and a match proves the leaf is what the server committed to. The
second server is never trusted — the first server's own signature does the work. A
retained hash is therefore a convenience, needed only when nobody can supply the leaf.

What the amendment missed is that *"nobody can supply the leaf"* is a state the server
gets to choose, and it was free. Marking the victim's position as a hole made the whole
block unverifiable, and §2.5's ordering then let it pass as clean.

The window is the smallest fix that closes it, and it is nearly free for the same reason
§2.5 gives about tip tolerance: a transaction can only be cut through once **all** its
taproot outputs are spent, which at the chain tip is close to empty. Servers retain hashes
exactly where there is almost nothing to retain, and prune freely in the deep history,
where a rescanning client can reach another server. The worst case is `W × n × 32` =
9.2 MB at `W` = 144 and `n ≈ 2000`, and reaching it would require dropping every leaf for
a day; the realistic figure is a rounding error.

`W` is a **protocol constant, not a declared policy field.** A per-server field lets a
server declare zero and walk straight back into the hole.

Merkle proofs earn their place for the evidence artifact and for targeted queries
("positions 3, 7, 11 without the block"), not for the main path. See §3.2. §2 fixes only
*what* is committed: the ordered canonical leaf list and its length `n`.

### 2.5 Comparison procedure

Keyed on block **hash**, not height — this makes the procedure reorg-safe at no cost and
removes "it was a reorg" as an available excuse.

Given block hash `B`, server `S`, declared policy `P`, published root `R`, response `D`.

**Step 0 — does `S` commit at all?** Three cases, and only the middle one is a refusal:

| `S` | Rule |
|---|---|
| Has never published a commitment, and claims none | Data is **Unverified** (§4.4). Accepted, and it feeds §4.3's union — but it is never *clean*, and only the tripwire (§5) can catch this server lying |
| Has published commitments for neighbouring blocks, but none for `B` | **Refuse the data.** Selective non-publication *is* the attack: commit to every block except the one you lied about |
| Published a commitment for `B` | Continue |

The middle row is what the original rule was reaching for. An earlier draft refused any
block without a commitment, which would have refused 100% of unmodified blindbit and
contradicted §0's "requires nobody's cooperation", §4.4's *Unverified* state, and
`start_height`. A server is expected to have a commitment for `B` because it published one
for a neighbouring block, not because it advertises that it might. **Evidence, not
advertisement.**

Then, for a server that did commit:

1. **Gap set `G`** = the positions `S` did not return in full. Each is a hash or a hole.
2. **Resolve `G`.** Recover the missing leaves — from `S`'s retained hashes where it kept
   them (§2.4), otherwise from another server. If any position is still unfilled, the
   block is *unresolvable* and there is no verdict. **This runs before the root is
   recomputed, not after.**
3. **Recompute the root** over all `n` positions. A mismatch means `S` served data
   contradicting its own signature. Proven and non-repudiable, from `S` alone.
4. If `P` declares no subtraction and `G ≠ ∅` → alarm. Local and immediate.
5. **Cross-check** `R` against other servers' roots for the same `B`. Equal → all
   committed to the same set. Unequal → at least one is lying; escalate to attribution
   (§4).

Steps 0–4 require a single server. Step 5 costs 32 bytes per block per server as a
continuous background check.

**Resolution before recomputation, and that ordering is load-bearing.** An earlier draft
recomputed the root first and resolved gaps last. A position returned as a hole then made
the root uncomputable, so the block was silently never verified. Step 3 is the only rung
that catches targeted omission (§1.4), so a server that could reach it first and decline
had a free, permanent way never to be verified — which is exactly the attack this section
exists to catch. **A block whose root has not been recomputed is not clean. It has no
verdict yet.**

**Three terminal states, not two:**

| State | Meaning |
|---|---|
| **Clean** | The root recomputed over all `n` positions and matched |
| **Omission detected** | Named server, block, transaction, signature |
| **Unresolvable** | A gap nobody can fill, so the root cannot be recomputed. Not an accusation, and it must not be reported as one — but not a pass either |

**Mode-dependent tolerance governs effort and reporting, never verification.** A
transaction can only be cut through once all its taproot outputs are spent, which at the
chain tip is nearly empty; and a spent output is one the client either spent itself or
never owned. Rescan-from-seed is where the light-client specification already admits
payments go missing. So a tip-following client spends less effort chasing a gap and
reports it more quietly; a rescanning client escalates. **Neither may skip step 3.** An
earlier draft had the tip-following client simply *accept* cut-through gaps, which
combined with a hashless gap to wave through the attack. The correct outcome for an
unfilled gap is *unresolvable*, which §6.2's refuse-in-path already knows how to handle.

### 2.6 What this fixes for the team

The interface frozen on day 2 (§6.3):

```go
func Set(net Network, blk *wire.MsgBlock, pv PrevoutSource) ([]Leaf, error)
```

Dev B's indexer commits to it; Dev C's differ compares against it; the differential suite
(§7) tests it.

§2 also generates §7's target list. Each item below is a place where two correct
implementations could disagree on `T_base`, and each is constructible **on regtest**
(§7.2 — public signet cannot be mined on demand):

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

## 3. Commitment format and Nostr transport — SETTLED 2026-09-07

§2 settled *what* is committed: the ordered canonical leaf list and its length `n`,
keyed on block hash. This section settles *how*.

### 3.1 Two independent checks

The format has to make both of these cheap, because neither subsumes the other.

| Check | Catches | Requires |
|---|---|---|
| **Self-consistency** — served data recomputes to the published root | *served ≠ committed* | One server |
| **Cross-check** — roots agree across servers for the same block hash | *committed ≠ canonical* | Two servers, at least one honest |

A server that lies about `n` — excising a position and renumbering — passes
self-consistency and fails cross-check. A server that commits honestly and then serves a
subset fails self-consistency. Both checks are load-bearing.

### 3.2 Merkle tree

§2.4 removed inclusion proofs from the main path, and that stands. The tree earns its
place elsewhere: **the evidence artifact.** When Canary fires, its output is a small
self-contained object — *server S signed root R for block B; leaf L is in R, here is the
proof; S served a set omitting L; S's declared policy forbids omission.* Proving leaf
membership from a flat hash requires all `n` leaf hashes, roughly 64 KB at mainnet scale.
With a tree it is about 350 bytes. That is the difference between an artifact someone
reads and an attachment they do not.

| Element | Construction |
|---|---|
| Leaf | `TaggedHash("canary/leaf/v1", txid ‖ tweak)` — 32 + 33 bytes |
| Internal node | `TaggedHash("canary/node/v1", left ‖ right)` |
| Odd node | **Promoted, never duplicated** |
| Root | `TaggedHash("canary/root/v1", network ‖ block_hash ‖ n_le32 ‖ merkle_root)` |

Duplicating an unpaired last node is CVE-2012-2459, Bitcoin's own Merkle vulnerability;
promotion avoids it, and distinct leaf and node tags make second-preimage substitution
impossible regardless. Binding `network`, `block_hash` and `n` inside the root means a
root cannot be replayed onto another block or reused with a different length.

**Preimage encodings, pinned here deliberately.** Every field is fixed-width, so the
concatenations need no length prefixes. An unpinned field in a hash preimage is an interop
break that presents as an attack.

| Field | Encoding |
|---|---|
| `txid` (leaf) | 32 bytes, **internal byte order** — as it appears in the transaction serialization, not the display-reversed hex |
| `tweak` (leaf) | 33 bytes, compressed SEC |
| `network` | 4 bytes — the network's P2P message-start bytes in the order they appear in a message header, i.e. the little-endian encoding of btcd's `wire.BitcoinNet` |
| `block_hash` | 32 bytes, **internal byte order** — the same rule as `txid` |
| `n_le32` | 4 bytes, unsigned little-endian |
| `merkle_root` | 32 bytes — the tree root, before the outer tagged hash |

`txid` and `block_hash` are the trap. Two implementations disagreeing on byte order
produce entirely different roots for identical data.

`network` is the message-start magic rather than an enum of our own, for one reason:
BIP-325 derives a custom signet's magic from its challenge, so two different signets get
two different values. §2.7's first precondition is that both servers index the same
network, and a private enum would erase exactly the distinction that precondition rests
on. The implementation reads the value from `chaincfg.Params.Net` rather than a literal
(informatively: main `f9beb4d9`, default signet `0a03cf40`, regtest `fabfb5da`), and
§7.4's regtest vectors pin the real value in CI — so a wrong constant fails a test instead
of becoming a silent fork.

### 3.3 The commitment object

| Field | Notes |
|---|---|
| `network` | `main` / `signet` / `regtest`. The event tag carries the display name; the root binds the 4-byte magic (§3.2), which also separates custom signets |
| `block_hash` | Authoritative key |
| `block_height` | Convenience only |
| `n` | Canonical set size |
| `root` | Per §3.2 |
| `policy_ref` | **Event id** of the policy declaration (§2.3) in force |
| signer | Implicit — the Nostr pubkey |

`policy_ref` binds by event id rather than inlining the policy. Policy changes rarely,
and binding by id means *"when did you declare cut-through?"* has an answer the server
cannot revise.

**This forces a Nostr detail that would otherwise silently void the entire
non-repudiation property: nothing in the trust path may use a replaceable event kind.**
Replaceable kinds (10000–19999) and parameterized replaceable kinds (30000–39999) are
overwritten in place, so a server could retroactively publish a cut-through declaration
*after* using it as cover and the original would be gone from relays. Policy events and
commitment events are both **regular kinds — append-only**.

Proposed kind **1352** (mnemonic; the regular range is 1000–9999). This must be checked
against the kind registry before shipping; it is not asserted to be unclaimed.

Tags carry `block_hash`, `height`, `n`, `network` and `policy_ref`; content carries the
root. A Nostr event id hashes the tags as well as the content, so the signature covers
all of it and no separate signed blob is needed. The redundancy between tags and root is
deliberate — any inconsistency between them is itself detectable.

### 3.4 Two channels, two jobs

§2.5 step 0's rule — *a server that commits elsewhere but not here is refused* — would
otherwise hand a veto to whoever controls the relay: censor a committing server's events
and it looks like a server that skipped this block. So the commitment travels two ways,
and they do different jobs.

| Channel | Job | On failure |
|---|---|---|
| **Pull from the indexer** — `GET /commitment/:blockhash`, returns the signed event | Gives the client a signed, non-repudiable statement from the party it is already talking to | A server that refuses to sign is refusing accountability, which is itself the alarm |
| **Subscribe via relays** | Makes the statement *public*, which is what enables equivocation detection | Relay censorship removes the audit trail, not the client's evidence |

A client isolated to a single malicious server therefore still extracts a signature it
can present later, to anyone, whenever it reaches them. The relay subscription is what
the privacy argument rests on: the client pulls *all* commitments from its configured
indexers and never reveals which block it cares about.

### 3.5 What we do not trust about Nostr

- **`created_at`.** Self-asserted and backdatable. Ordering comes from the block hash.
  Nostr gives us *publication*, not timestamping, and we should not claim otherwise.
- **Relay honesty.** A relay may drop, delay, or serve split views. Servers publish to
  several and clients subscribe to several. A client that sees a server's events on no
  relay while others do has learned something.
- **Relay independence.** An indexer can operate its own relay. Client-side relay choice
  is its own configuration and is never inherited from the indexer.

### 3.6 Identity

Client configuration is a set of `(indexer_url, indexer_nostr_pubkey)` pairs, **pinned
manually**. No discovery, no web of trust, and no trust-on-first-use by default: an
indexer's `/info` may advertise its npub as a convenience, but trusting that on first
contact hands the key to anyone able to intercept a single request. Manual pinning is the
honest scope for v1 and is stated as a limitation rather than papered over.

### 3.7 Cost

| Party | Cost |
|---|---|
| Indexer | One signature and ~200 bytes per block. Retained state: 36 bytes per block, a 32-byte root plus `n` — **about 35 MB for all of mainnet history** (≈965k blocks × 36 B), plus §2.4's 144-block hash window, bounded by 9.2 MB and near zero in practice |
| Client | One relay subscription filtered by author; 32 bytes per block per server to compare |
| Relay | ~144 events per day per indexer |

The prune-freely property now states cleanly: **commit at index time, discard at will
once a leaf is 144 blocks old** (§2.4).
The server holds the block and its prevouts exactly once, computes `T_base`, signs,
publishes — and remains accountable for what it dropped, forever, at 36 bytes per block.

The arithmetic is spelled out because §2.1 designates this table as the pitch to
indexers, and the first thing a skeptical indexer does is recompute it. An earlier draft
said 5 MB, which was wrong by about 7×. 35 MB is still a rounding error next to an
unpruned node, and the argument is unchanged — but a number that does not survive a
check costs more credibility than the number it was trying to buy.

### 3.8 Receipts

Added while working §4.3, which asked what we can *prove* rather than what we can
detect. The commitment alone is not enough:

| Statement | Provable to a third party? |
|---|---|
| S signed root R containing leaf L | Yes — signed |
| S's policy forbids pruning | Yes — signed |
| S's root differs from S′'s for the same block | Yes — both signed |
| **S served me a set omitting L** | **No. HTTP responses are not signed** |

As designed through §3.7, equivocation between two servers is provable to anyone, but a
single server's omission is provable only to its victim — materially weaker than §1.4's
security claim implies.

The server therefore signs a **receipt** over `(request_params, response_digest)`. A
Schnorr signature costs microseconds, and server cooperation is already assumed for
commitments.

> **The commitment says what exists. The receipt says what you were given.** Omission is
> `commitment ≠ receipt`, both signed by the same key.

The receipt MUST cover the request parameters — block hash, and any client-supplied dust
threshold — or a server can satisfy a request by replaying an older response.

Receipts exist only in the protocol layer. Against unmodified blindbit, omission is still
*detected* — the victim knows — but is not third-party provable. This is a concrete
reason to push for the protocol layer rather than a nice-to-have.

## 4. Client verification ladder — SETTLED 2026-09-07

§2.5 gave the per-block comparison; §3 gave the object being compared. This section gives
the ladder: what runs continuously, what escalates, what is expensive and on demand, and
how each result is surfaced to a wallet that has to act on it.

### 4.1 The ladder

Ordered by cost. Each rung runs only when the one above it says something.

| Rung | Trigger | Catches | Cost |
|---|---|---|---|
| **1. Commitment tracking** | Always on | Root divergence between servers, and chain contradiction — a height still contested six blocks later (§4.6) | One relay subscription; ~144 events/day/server |
| **2. Self-consistency** | Client fetches block *B* | Served ≠ committed; policy contradiction | Hashing `n` leaves. Microseconds |
| **3. Gap resolution** | Rung 2 found gaps | Whether a permitted gap is real | One targeted request |
| **4. Attribution** | Rung 1 found divergence | *Which* server lied, and about what | Requires prevouts — the expensive rung |

Rung 1 runs for blocks the client has not scanned and while the client is idle.
**Detection is decoupled from scanning**, so evidence accumulates continuously and an
alarm can fire before the user opens the wallet.

### 4.2 Detection needs no node; attribution does, and may be deferred

Attribution requires prevouts, therefore a full node or a third-party API. This does not
force a node onto the wallet, for two reasons.

**The privacy cost is near zero.** The disputed transaction set is chosen by the servers,
not the user — it is whatever two indexers publicly disagreed about. Querying those txids
reveals interest in a public dispute, not in the user's payments.

**Attribution is not time-critical.** Two signed roots are non-repudiable and do not
decay. A client with no node records the evidence and hands the verdict to anyone who has
one, later or never.

> **A light client detects. An auditor attributes.**

### 4.3 Union for tweaks; k-of-N belongs on filters

The omission/commission tension of §1 appears here as a direct conflict: omission wants
the **union** across servers, commission wants the **intersection**. They act at
different stages, which resolves it.

- Computing candidate outputs from tweaks is local and free — one EC multiplication, no
  network. So take the **union (1-of-N)**: a tweak in *any* server's committed set is
  scanned. This is what defeats omission, at no privacy cost.
- The leak is in fetching block data, which happens on a *filter* match — and whoever
  controls filter distribution can force a match. A k-of-N rule therefore belongs on
  **filters**, not tweaks.

v1 does not commit to filters, so that k-of-N rule is unverified best effort — a note,
not a claim (§1.5). The construction generalizes directly to filters and to UTXO
responses: same canonical set, same commitment. Tweaks were chosen because that is where
omission is silent.

### 4.4 The primary output is coverage, not alarms

An alarm that never fires looks like a product that does nothing. The ladder produces
something continuous and visible instead: **per-block-range scan coverage.**

| Coverage state | Meaning |
|---|---|
| **Verified** | Root agreed; served set complete |
| **Resolved** | Gap existed, filled from another server, root checked |
| **Unresolvable** | A gap nobody can fill, so the root was never recomputed (§2.5) — an ecosystem gap, not an attack, and not a pass |
| **Unverified** | No commitment available. The data is still used — it feeds §4.3's union — but nothing about it is checked (§2.5 step 0) |
| **Disputed** | Roots diverge — two named servers, one of them lying, not yet attributed (§4.5) |
| **Compromised** | Attributed — one named server, one named block |

*Disputed* and *Compromised* are separate states because §4.5 keeps them separate. Root
divergence names two servers without saying which lied, and collapsing that into a single
alarm is exactly how an attacker gets an honest server excluded.

Which determines what the wallet displays:

> **A balance computed over blocks that could not be verified is a lower bound, not a
> balance.**

A wallet with unresolvable ranges says so rather than printing a confident number.

**How coverage reaches the user.** Two paths, and only one of them works against a wallet
that does not know Canary exists:

| Consumer | Mechanism |
|---|---|
| A Canary-aware wallet, or `canary status` | Reads the coverage state and displays it |
| **Unmodified wallet** | It cannot display what it cannot see. Enforcement is §6.2's proxy **refusing to serve unverified data** — the wallet never receives a balance to print |

The refusal, not the display, is the answer to §1.5's "a wallet that ignores the alarm".
An earlier draft of this section claimed coverage is "always on screen", which is not
true of an unmodified `blindbitd`: there, coverage lives in `canary status`, which is the
log-nobody-reads that §6.2 dismisses.

### 4.5 Acting on alarms

Alarms are facts about `(server, block, txid)`. Persisted, deduplicated on that triple,
never auto-cleared.

**Automatic exclusion of a misbehaving server is itself an attack vector.** If a third
party can induce the detection, they can knock out honest servers and leave the victim
with the attacker's. So the two alarm types are treated differently:

| Alarm | Attributable? | Automatic action |
|---|---|---|
| Self-consistency failure | Yes — S's own signature against S's own data | Safe to down-rank automatically |
| Root divergence | No — it names two servers without saying which lied | **None** until rung 4 attributes it |

This asymmetry is why attribution is a separate rung rather than an action taken directly
on divergence.

### 4.6 Chain agreement

Two servers committing to different block hashes at the same height are on different
chain tips. That is a fork, not an omission, and reporting it as one would be the loudest
possible false positive.

An earlier draft answered this with *"Canary maintains its own header chain — 80 bytes
per block, PoW-verified, standard SPV."* **That is false where we run.** §1.6 fixes signet
as the v1 network, and a BIP-325 signet gets its integrity from a challenge signature in
the coinbase, not from accumulated work: difficulty is trivial and a laptop can outrun the
real chain. A client trusting most-work on signet can be handed a chain in which the
disputed block does not exist, which converts a real omission into "reorg" and defeats
§5.3 step 2. Asserting a security property that does not hold is worse than asserting
none, because a reader builds on it.

| Network | Chain integrity from |
|---|---|
| mainnet | Accumulated proof-of-work. Standard SPV, and it works |
| **signet** | The BIP-325 challenge signature in the coinbase. **Not** work |
| regtest | Nothing. Single-operator and local, so it is trusted by construction (§7.2) |

**How much of this is load-bearing, precisely.** Less than it first looks. §2.5 keys
comparison on block *hash*, so two servers arguing about the contents of hash `B` cannot
reach for the reorg excuse — they are talking about the same block by construction. What
is exposed is *chain membership*: whether `B` is in the chain at all. That matters in two
places, §5.3 step 2 and §4.4's coverage ranges, and nowhere else.

#### Chain agreement is an output, not an input

The reframe that fixes this: the chain is not a dependency Canary needs before it can
compare. It is the same problem Canary already solves. Several parties assert something,
they can disagree, and the disagreement is either transient or permanent. **Reorgs
resolve. Lies persist.**

A server following a fabricated chain has to publish commitments for it — §2.5 step 0
forces it to commit or be refused, and §3.3's append-only kinds mean it cannot withdraw
the commitment later. So the fabrication lands in the public feed, keyed by height and
hash, signed. A height where two servers name different hashes is **contested**. Contested
and transient is a reorg, and is ignored. Contested past six confirmations is a signed
statement about the chain contradicted by another signed statement — a heavier accusation
than omission, and it costs nothing new to detect, because the commitment already carries
both the height and the hash.

It also puts chain-contradiction detection at roughly six block intervals rather than one.
That is consistent with §1.4: timing depends on the attack.

#### The anchor, for when convergence is unavailable

Convergence needs two servers. With one server, or under total collusion, chain membership
cannot be derived from the indexer set at all — the attacker controls every input and can
simulate any world. That is information-theoretic rather than a design flaw, and the
honest response is to name the outside fact Canary requires instead of pretending it needs
none:

> **Canary needs one chain fact it did not learn from an indexer.**

Three ways to supply it. v1 takes the first two:

| Source | Cost | Trust required |
|---|---|---|
| **The user's own Core node**, where one is configured | Free — blindbit-oracle already requires Core v30+, so anyone running the full stack has one | None. It is their node |
| **A manually pinned recent `(height, hash)`** | Free | The pin, obtained out of band. The model §3.6 already chose for indexer identity, and stated as a limitation rather than papered over |
| **BIP-325 signet solution validation** | Two to three days, and it needs every txid in the block | **None at all**, which is the point |

The third is the correct answer, and it is specified here so it can be built. It is not a
v1 commitment. Validation means stripping the signet solution from the coinbase,
recomputing the merkle root and therefore the block hash, constructing BIP-325's
BIP-322-style `to_spend` / `to_sign` pair, and running a script engine against the signet
challenge. Because the result is self-verifying, the data may be fetched from an untrusted
indexer — a malicious server cannot forge the signet signer's signature — so it preserves
§4.2's *detection needs no node*. Signet blocks are small enough that fetching them whole
is cheap. It lands if week 3 has room (§6.6); until then the single-server case rests on
the pin, and §5.3 says so out loud.

**Consequence for §6.3:** the `headers` package is not an SPV chain. It is a store of
`(height, hash)` observations drawn from the commitment feed and the anchor, with the
contested-past-six-confirmations rule on top.

### 4.7 Evidence artifact

One file, **offline-verifiable**: `canary verify <file>` requires no network.

```
claim              omission | equivocation | self-contradiction
accused            npub
block              hash, height
signed_commitment  raw Nostr event
signed_policy      raw Nostr event
receipt            signed (request, response digest)   — protocol layer only (§3.8)
missing_leaf       {txid, tweak}
merkle_proof       ~350 bytes (§3.2)
```

This file is the demo. It is also what would be attached to a bug report or a public
disclosure — an accusation nobody can independently check is worth little.

## 5. Canary tripwire — SETTLED 2026-09-07

The rung of last resort, and the only one that survives *all* queried indexers colluding
(§1.3), because the client's knowledge originates outside the indexer system entirely.

### 5.1 Generalized statement

The tripwire is not "send yourself money." It is:

> **Assert that a payment exists in block B, then check whether each indexer reports it.**

The assertion has two sources:

| Source | Cost |
|---|---|
| **Self-payment** | Real on-chain fees |
| **Out-of-band knowledge of a real incoming payment** — the sender supplied the txid | **Free** |

BIP-352 already contemplates out-of-band notifications. Accepting them turns every such
payment into a free probe. Building around *expected payments* rather than
*self-payments* costs the same code and is strictly more useful, which matters because
the self-payment path is the only part of Canary with a marginal monetary cost.

### 5.2 Indistinguishability

Per §1.2, an attacker cannot identify a victim's self-payment from chain data. That is
the tripwire's foundation. What remains is metadata:

| Leak | Mitigation | In v1? |
|---|---|---|
| **Periodic timing** — a probe every 6 blocks is trivially whitelisted | Poisson scheduling (exponential inter-arrivals) — memoryless, so the last probe reveals nothing about the next | Yes |
| **Distinctive value** — a repeated or round amount | Randomized, non-round values | Yes |
| **Broadcast/query correlation** — broadcasting and then immediately querying that block | Broadcast over a different path from the one used to query indexers | Documented |
| **Funding linkage** — spending a UTXO the adversary sent, so they observe the victim transacting | Fund probes from UTXOs the adversary does not know about, where possible. **Not fully solvable** | Stated limitation |

**The honest ceiling.** A passed tripwire proves the server served *that one tweak*. It
is not proof of global honesty. Against blanket degradation it is quantifiable: an
attacker dropping a fraction `p` is caught by `k` probes with probability `1-(1-p)^k`, so
ten probes catch a 20% degradation 89% of the time. Against a targeted
single-transaction omission it helps only if the attacker cannot distinguish the probe.

### 5.3 What a negative result proves

Innocent explanations must be excluded first:

1. **Not yet indexed** — wait until the server's declared height exceeds B's, plus margin
2. **Reorg** — `B` must be in the chain Canary believes in (§4.6). With two or more
   servers that is convergence: a height still contested six blocks later is not a reorg.
   With one server it rests on §4.6's anchor, and a client with neither a node nor a pin
   cannot complete this step — the tripwire then returns *unresolvable*, not an accusation
3. **Never confirmed** — same check

After those, it is omission. And:

> **The tripwire is the one rung where a light client attributes without a node.**

§4.2 holds that detection needs no node but attribution does. The tripwire is the
exception: the client *made the transaction*, so it holds the prevouts and computes the
canonical leaf itself. It produces the exact missing leaf, a Merkle proof of its absence
from the signed commitment, and a named accused party — with no auditor and no full node.
That makes it the most self-contained evidence artifact in the system, which is what the
rung of last resort should be.

**One qualifier, added 2026-09-07.** The leaf and the proof genuinely need no node. Step 2
above does need a chain fact from outside the indexer set, which under total collusion
cannot come from the indexers by definition (§4.6). So the tripwire attributes without a
node and without an auditor *given an anchor*: a Core node, a pin, or eventually §4.6's
signet solution check. Lacking all three, a negative result is still recorded and still
signed, and it becomes an accusation the moment an anchor is available. Evidence does not
decay (§4.2).

### 5.4 Coverage integration and cost

A passed tripwire verifies one block for one server, so §4.4 coverage distinguishes
**verified-by-cross-check** from **verified-by-tripwire**. Under total collusion the
latter is the only verified state available.

> The tripwire is the only part of Canary with a marginal monetary cost. **The strongest
> guarantee is bought, literally, one transaction fee at a time.**

Probes are therefore rate-limited by a user budget rather than a fixed schedule, and
out-of-band assertions (§5.1) are free — a user receiving real payments accrues tripwire
coverage at no cost. On signet all of it is free, which is what makes the live demo
possible: send a payment, have a deliberately malicious indexer drop it, and watch Canary
name it.

The tripwire is the one path whose latency is not a block interval. The client already
knows the txid and the block, so detection is bounded by its own query once the server
has indexed that height — seconds, not §1.4's block interval. That is a property of the
tripwire alone and does not generalize to the other rungs.

## 6. Components, interfaces, ownership — SETTLED 2026-09-07

### 6.1 Binaries

| Binary | Role |
|---|---|
| `canaryd` | The sidecar. Subscribes to commitments, verifies, serves the wallet, reports coverage |
| `canary` | CLI — `canary status`, `canary verify <file>`, `canary probe` |
| `blindbit-oracle` (fork) | Indexer with `--commit`: computes `T_base`, publishes commitments, signs receipts |

### 6.2 Proxy, not observer

A sidecar can sit **beside** the wallet (querying independently, wallet unchanged) or
**in the data path** (the wallet points at it instead of the indexer). Canary is a proxy.

1. The wallet is genuinely unmodified — `blindbitd` works by changing one configuration
   line to point at `canaryd`.
2. Observer behaviour falls out of proxy mode for free; the reverse does not.
3. **It closes §1.5's "a wallet that ignores the alarm."** A component in the data path
   can refuse to serve unverified data. An observer can only write to a log the wallet
   never reads.

The cost is that `canaryd` must speak blindbit's API — but only the endpoints
`blindbitd` actually calls, which is a bounded list.

### 6.3 Packages and frozen interfaces

```go
// canonical — the reference implementation. Pure function. §2.2
type Network uint32 // the P2P message-start magic, per §3.2

type Leaf struct {
    TxID  [32]byte // INTERNAL byte order (§3.2)
    Tweak [33]byte // compressed SEC
}

type PrevoutSource interface {
    Prevout(op wire.OutPoint) (*wire.TxOut, error)
}

func Set(net Network, blk *wire.MsgBlock, pv PrevoutSource) ([]Leaf, error)

// commit — Merkle, tagged hashes, promotion on odd nodes. §3.2
type Proof struct {
    Index    uint32     // position in canonical order
    N        uint32     // set size — bound into the root, so a proof cannot be replayed
    Siblings [][32]byte // bottom-up
}

func Root(net Network, blockHash [32]byte, leaves []Leaf) [32]byte
func Prove(leaves []Leaf, i uint32) (Proof, error)
func VerifyProof(net Network, blockHash, root [32]byte, leaf Leaf, p Proof) bool

// policy — §2.3, including the tool-first bridge
type Policy struct {
    Network          Network
    StartHeight      uint32
    PrunesSpent      bool
    DustThresholdSat uint64
    DustConfigurable bool
}

func FromBlindBitInfo(r io.Reader) (Policy, error)

// feed — Nostr. §3.3, §3.4
type Commitment struct {
    Network     Network
    BlockHash   [32]byte
    BlockHeight uint32
    N           uint32
    Root        [32]byte
    PolicyRef   [32]byte // event id of the policy declaration in force
    Author      [32]byte // Nostr pubkey — implicit signer
}

func (c Commitment) ToEvent(sk [32]byte) (nostr.Event, error)
func FromEvent(e nostr.Event) (Commitment, error)

type Feed interface {
    Subscribe(ctx context.Context, authors [][32]byte) (<-chan Commitment, error)
    Get(ctx context.Context, author [32]byte, blockHash [32]byte) (Commitment, error)
}

// headers  — (height, hash) observations + the contested-past-6 rule. NOT SPV. §4.6
// ladder   — the four rungs and the coverage state machine. §4
// evidence — artifact construction and offline verification. §4.7
// tripwire — expected-payment assertions, Poisson scheduler. §5
```

An earlier draft of this block carried literal `...` in `VerifyProof`, which is not a
frozen interface. Everything above compiles as written.

**One of these is still known-open** (spec review, `CLAUDE.md`): `Feed.Get` cannot be
served by a relay as specified, because NIP-01 filters on single-letter tag names only and
§3.3 puts the block hash in a multi-letter tag. `headers` was the other; §4.6 now resolves
it, and the package is deliberately **not** an SPV chain.

**Interfaces freeze on day 2, not at the end of week 1.** On a 28-day clock, spending
the first quarter before parallel work begins is not affordable. Days 1–2 are all three
people co-writing type definitions with no logic behind them; everything after runs in
parallel against stubs.

### 6.4 gobip352 supplies the primitives — and what that costs

The library already exposes what `canonical` needs:

- `ExtractEligibleVins([]*Vin)` — input eligibility
- `ExtractPubKey(vin)` — per-type public key extraction, **including NUMS-H detection**
- `ComputeInputHash(vins, pubKeySum)`

So `canonical` is not "implement BIP-352." It is those primitives plus the
transaction-level rules (at least one taproot output, no SegWit v>1 input), plus ordering
and leaf construction. A large de-risk on the highest-risk component.

**It also invalidates a claim that would otherwise have been made carelessly.**
blindbit-oracle is by the same author and sits on the same library, so differential
testing `canonical` against blindbit-oracle exercises **the wrapper, not the
primitives** — both would be wrong together. Genuine independence requires a different
lineage: silentiumd, or the BIP's own vectors.

This surfaces a real gap: **BIP-352 ships send/receive test vectors but nothing for the
index-level canonical set** — transaction-granularity eligibility, ordering, set
membership. That is what §7 fills, it is needed regardless, and it is a legitimate
upstream contribution rather than a hackathon artifact.

One decision follows: **the indexer fork keeps blindbit-oracle's own computation path
rather than calling our `canonical` package.** Sharing the code would be convenient and
would make the differential test vacuous.

### 6.5 Ownership

| Owner | Surface |
|---|---|
| **Naman** | `canonical`, `commit`, `feed` — the protocol core. Then `tripwire` and `evidence` together, since §5.3 makes the tripwire the thing that produces a node-free artifact. Then demo and pitch |
| **Dev B** | Indexer fork: `T_base` at index time, commitment publishing, receipts, and the deliberately malicious mode |
| **Dev C** | `canaryd` — proxy, `ladder`, `policy`, `headers`, coverage, CLI |

The malicious indexer mode belongs to whoever owns the indexer; it is a configuration
flag on code they already know, not a separate project. The protocol core is owned by
whoever can unblock the other two fastest, because both tracks consume it.

### 6.6 Dependency order

Coarse only. The detailed plan is `writing-plans`' output, not this document's.

| Phase | Gate |
|---|---|
| **Day 1–2** | Signet, Core v30 and blindbit-oracle running for all three. **Interfaces frozen** |
| **Week 1** | `canonical` agreeing with blindbit-oracle across ~1000 signet blocks. `commit`. Nostr round-trip |
| **Week 2** | Commitments published end to end. Rungs 1–2. Coverage. Proxy passing `blindbitd` traffic |
| **Week 3** | Tripwire, evidence and `canary verify`, malicious mode, rungs 3–4. §7 suite. If there is room: §4.6's BIP-325 signet solution check |
| **Week 4** | Demo, hardening, documentation, pitch. **Feature freeze 1 October**, four days before the deadline |

The week-1 gate matters most: *do we and blindbit-oracle produce the same set across
1000 signet blocks?* is a cheap harness, it is the differential suite in embryo, and it
is the earliest possible signal that `canonical` is wrong.

**Configure that comparison correctly or the gate tests nothing.** blindbit-oracle's
default response is policy-filtered, and diffing a filtered response against `T_base` is
the false-positive machine §2.1 exists to kill. Run it with its full-index option
(`tweaks_full_basic=1` — confirm the flag name against the version pinned on day 1) and
no dust threshold, which yields an index comparable to `T_base`. This is a configuration
line, not a fork: the gate does not wait on Dev B's week-2 work.

**Rung 4 has two forms and only one is on the critical path.** The tripwire's node-free
attribution (§5.3) lands in week 3 alongside the tripwire, because there the client holds
the prevouts for a transaction it made itself. The general auditor form, which needs
prevouts for someone else's transaction, is §6.7's stretch component and deliberately has
no week.

### 6.7 Risks

| Risk | Mitigation |
|---|---|
| `canonical` subtly wrong | Week-1 agreement harness; BIP vectors; §7 |
| Core v30 unpruned signet fails to come up | Verify on day 1, not week 2 — it gates everything the indexer track does |
| Relay dependency | Run our own (`strfry` / `nostr-rs-relay`) alongside public ones, consistent with running everything locally |
| Auditor scope creep | **Not on the critical path.** §5.3's tripwire attributes without a node, so the demo never requires the auditor. It is the stretch component |

## 7. Testing — differential edge-case suite — SETTLED 2026-09-07

### 7.1 Three layers

| Layer | Covered by | Independent? |
|---|---|---|
| **A. Primitives** — tweak from a given input set | BIP-352's `send_and_receive_test_vectors.json` | Yes — it is the specification |
| **B. Canonical set** — which transactions, in what order | **Nothing. No vectors exist** | — |
| **C. Real-chain agreement** — us against blindbit-oracle over N blocks | Week-1 harness (§6.6) | No — shared gobip352 |

Layer A is someone else's test, but it is the only independent check we have on our
dependency, so we run it. Layer C catches wrapper bugs but not primitive bugs, and it is
the cheapest early signal.

**Layer B is the work**, and it is the contribution: BIP-352 specifies index-level
eligibility in prose and ships no vectors for it.

Realistic independent lineages within four weeks: the BIP vectors (free), blindbit-oracle
(wrapper level only), and **silentiumd if it runs easily**. Core PR #28241 is a genuinely
independent C++ lineage but is a closed PR against an old tree — named, not budgeted.

### 7.2 Regtest, not signet

This amends the earlier decision to construct edge cases on signet. Several corners
require arbitrary scripts and controlled block composition; on public signet we cannot
mine, so construction waits on someone else's block template and depends on non-standard
transactions relaying. Regtest gives instant blocks, arbitrary transactions, no faucet
dependency, and reproducible CI.

> **Regtest for the edge-case suite. Signet for the end-to-end demo.**

To verify on day 1: blindbit-oracle's `network` configuration accepting regtest, and
Core's REST endpoints behaving there.

### 7.3 The corners

| Case | Construction | Expected |
|---|---|---|
| **NUMS-H script path** | P2TR with internal key *H*, spent via script path | Input **excluded**. If it is the only eligible input, the transaction is not eligible |
| **NUMS-H, parity flipped** | *H* as internal key, control block's parity bit flipped | Input **excluded**. Byte 0 is `leaf_version \| parity`; bytes 1..33 are still *H*. Catches an implementation that compares the control block from byte 0 and so stops recognising *H* whenever parity or leaf version differs |
| **Ordinary script-path spend** | Random internal key *P* ≠ *H*, script path | Input **included** — only *H* is excluded, not script-path spends in general |
| **Malleated P2PKH** | `<dummy> OP_DROP <sig> <pubkey>` | Public key **must** still be found — the BIP says MUST |
| **Uncompressed P2PKH key** | 65-byte public key | **Excluded** — compressed and x-only only |
| **SegWit v>1 input** | Spend a v2 witness program | **Whole transaction excluded** |
| **Mixed input types** | P2TR + P2WPKH + P2PKH in one transaction | All three summed |
| **Taproot output, no eligible input** | P2WSH inputs only | Not eligible |
| **Eligible input, no taproot output** | P2TR in, P2WPKH out | Not eligible |
| **Coinbase** | — | Not eligible — null prevout |
| **`A_sum` = point at infinity** | See below | **Skip the transaction** |
| **`outpoint_L` ties** | Two inputs from the same txid, adjacent vouts | Tests serialization and endianness |

The infinity case looks unreachable and is not. Two taproot inputs cannot produce it —
both lift to even Y. But take `a`, let `P = aG` with even Y; fund a **P2TR** output to
x-only `P` and a **P2WPKH** output to the compressed encoding of `−P` (private key `n−a`,
prefix `0x03`); spend both in one transaction. Then `A_sum = P + (−P) = ∞`. Both keys are
ours and it is trivial on regtest.

This is the case most likely to find a real bug: libraries commonly error or silently
return a zero point on addition to infinity, and it is essentially unreachable by
accident.

**The parity-flip row was inverted in the first draft of this table.** It said
*included*, reasoning that a changed control block should read as a different key. It
does not. Flipping parity changes byte 0 only, and an implementation reading bytes 1..33
still sees *H* and still excludes the input. A correct implementation would have failed
that vector, and "fixing" the implementation to pass it would have introduced the exact
bug the vector exists to catch. §7.6 ships these upstream, so the expectation column is
the part that has to be right, and every row's expectation is derived from the BIP text
rather than from what our implementation does.

### 7.4 Vector format

```json
{
  "name": "nums-h-only-eligible-input",
  "network": "regtest",
  "block": "<full block hex>",
  "prevouts": { "<txid>:<vout>": { "scriptPubKey": "...", "value": 12345 } },
  "expected": {
    "n": 0,
    "leaves": [],
    "root": "<32-byte hex>"
  },
  "rationale": "BIP-352: script-path spends with internal key H are skipped..."
}
```

The **prevout map** is what makes a vector self-contained — it is exactly what a node
would otherwise supply. Any implementation can consume this with no node and no network.

Including `expected.root` means the vectors also exercise §3.2's tagged hashing and
odd-node promotion, covering the whole `canonical` + `commit` stack rather than
eligibility alone. That makes them worth more to an adopter.

**CI is hermetic.** Generation requires regtest and Core and runs as a dev-time task; the
committed JSON runs under plain `go test` with no node and no network.

### 7.5 Property tests

Structural, and not reachable by fixed vectors. Each row defends a specific §3.2
decision.

| Property | Defends |
|---|---|
| `VerifyProof(Root(L), i, Prove(L, i))` for all `i`, random `L` | Basic soundness |
| Permuting transaction order changes the root | Accidental sorting — §2.2 chose transaction order deliberately |
| A root over `n` leaves never validates as a root over `n′ ≠ n` | §3.2's `n` binding |
| `n ∈ {1, 2, 3, 5, 2ᵏ, 2ᵏ+1}` | **Odd-node promotion**, where CVE-2012-2459-class bugs live |
| An internal node hash never validates as a leaf | The distinct leaf and node tags |

### 7.6 Upstream, and expectations

Disagreements sort into three buckets:

- **We are wrong** — fix, and keep the vector
- **They are wrong** — report with the vector attached. A failing vector is a far better
  bug report than prose
- **The BIP is ambiguous** — the valuable case. BIP-352 v1.1.0 is recent and actively
  maintained, so an index-level vector contribution is plausibly acceptable upstream

**Expectations, so a quiet suite is not read as a failed one:** the likely outcome is
zero to two real bugs. The suite is the contribution either way. *"We tested this against
N implementations and they agree"* is a legitimate and reportable result, and it is the
answer to a judge asking how we know the canonical set is right.

This is week 3 and it is time-boxed. The vectors ship whether or not they find anything.

## 8. Demo — PENDING

Anchored on §5.4: a signet self-payment, an indexer configured to drop it, and Canary
naming the accused within seconds of the query — the tripwire path, whose latency is not
a block interval (§5.4). Open: the exact narrative order,
what is shown on screen (§4.4 coverage versus the §4.7 evidence artifact), how the
malicious indexer is configured so the drop is visibly deliberate rather than a bug, and
the fallback if signet block timing does not cooperate on the day.

---

## Appendix A — Prior art

See [`../research/prior-art.md`](../research/prior-art.md).
