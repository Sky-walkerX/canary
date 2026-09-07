# Canary — Design Document

**Status:** In progress. §1–§6 settled; §7–§8 pending.
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
- Serving a subset while retaining leaf hashes: 32 bytes per withheld position, with no
  logarithmic factor, and the response is verifiable from that one server alone.

**Retaining leaf hashes is optional, not required.** An earlier draft of this section
required the server to produce the hash of every leaf it dropped. It does not have to. A
server that discarded a leaf entirely can simply declare the position withheld; the
client reconstructs it from another source and checks the root regardless, falling back
to the *unresolvable* state (§2.5) if nobody retains it. The requirement mattered because
a retained hash costs 32 bytes against a 65-byte leaf — it would have consumed most of
cut-through's saving, which is the entire reason a server would adopt this. Dropping the
requirement restores it. Whether a server retains hashes is discovered from its response;
it needs no policy field.

Merkle proofs earn their place for the evidence artifact and for targeted queries
("positions 3, 7, 11 without the block"), not for the main path. See §3.2. §2 fixes only
*what* is committed: the ordered canonical leaf list and its length `n`.

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

**Interop trap, pinned here deliberately:** `txid` is used in **internal byte order**, as
it appears in the transaction serialization — not the display-reversed hex. Two
implementations disagreeing on this produce entirely different roots for identical data,
and the failure presents as an attack.

### 3.3 The commitment object

| Field | Notes |
|---|---|
| `network` | signet / main |
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

§2.5's rule — *no commitment, no data* — would otherwise hand a veto to whoever controls
the relay: censor the events and every honest server looks unaccountable. So the
commitment travels two ways, and they do different jobs.

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
| Indexer | One signature and ~200 bytes per block. Retained state: 36 bytes per block — **~5 MB for all of mainnet history** |
| Client | One relay subscription filtered by author; 32 bytes per block per server to compare |
| Relay | ~144 events per day per indexer |

The prune-freely property now states cleanly: **commit at index time, discard at will.**
The server holds the block and its prevouts exactly once, computes `T_base`, signs,
publishes — and remains accountable for what it dropped, forever, at 36 bytes per block.

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
| **1. Commitment tracking** | Always on | Root divergence between servers | One relay subscription; ~144 events/day/server |
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
| **Unresolvable** | Every queried server pruned it — an ecosystem gap (§2.5), not an attack |
| **Unverified** | No commitment available |
| **Compromised** | Alarm — named server, named block |

Which determines what the wallet displays:

> **A balance computed over blocks that could not be verified is a lower bound, not a
> balance.**

A wallet with unresolvable ranges says so rather than printing a confident number. This
is the answer to §1.5's "a wallet that ignores the alarm": coverage is always on screen,
so it cannot be ignored the way an alarm can.

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

### 4.6 Dependency: an independent header chain

Two servers committing to different block hashes at the same height are on different
chain tips. That is a fork, not an omission, and reporting it as one would be the loudest
possible false positive.

Comparisons must therefore be keyed on a block hash the client independently believes in,
which means **Canary maintains its own header chain** — 80 bytes per block, PoW-verified,
standard SPV. Cheap, but a real component; it is owned in §6 rather than assumed.

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
2. **Reorg** — check against the header chain (§4.6)
3. **Never confirmed** — same check

After those, it is omission. And:

> **The tripwire is the one rung where a light client attributes without a node.**

§4.2 holds that detection needs no node but attribution does. The tripwire is the
exception: the client *made the transaction*, so it holds the prevouts and computes the
canonical leaf itself. It produces the exact missing leaf, a Merkle proof of its absence
from the signed commitment, and a named accused party — with no auditor and no full node.
That makes it the most self-contained evidence artifact in the system, which is what the
rung of last resort should be.

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
name it within about thirty seconds (§8).

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
type Leaf struct {
    TxID  [32]byte  // INTERNAL byte order (§3.2)
    Tweak [33]byte  // compressed
}
func Set(net Network, blk *wire.MsgBlock, pv PrevoutSource) ([]Leaf, error)

// commit — Merkle, tagged hashes, promotion on odd nodes. §3.2
func Root(net Network, blockHash [32]byte, leaves []Leaf) [32]byte
func Prove(leaves []Leaf, i int) Proof
func VerifyProof(root [32]byte, ..., leaf Leaf, p Proof) bool

// policy — §2.3, including the tool-first bridge
type Policy struct {
    Network Network; StartHeight uint32
    PrunesSpent bool; DustThresholdSat uint64; DustConfigurable bool
}
func FromBlindBitInfo(r io.Reader) (Policy, error)

// feed — Nostr. §3.3, §3.4
func (c Commitment) ToEvent(sk) nostr.Event
func FromEvent(e nostr.Event) (Commitment, error)
type Feed interface {
    Subscribe(ctx, authors [][32]byte) <-chan Commitment
    Get(ctx, author [32]byte, blockHash [32]byte) (Commitment, error)
}

// headers  — PoW-verified SPV chain. §4.6
// ladder   — the four rungs and the coverage state machine. §4
// evidence — artifact construction and offline verification. §4.7
// tripwire — expected-payment assertions, Poisson scheduler. §5
```

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
| **Naman** | `canonical`, `commit`, `feed` — the protocol core. Then the evidence artifact, demo and pitch |
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
| **Week 3** | Tripwire, evidence and `canary verify`, malicious mode, rung 3. §7 suite |
| **Week 4** | Demo, hardening, documentation, pitch. **Feature freeze 1 October**, four days before the deadline |

The week-1 gate matters most: *do we and blindbit-oracle produce the same set across
1000 signet blocks?* is a cheap harness, it is the differential suite in embryo, and it
is the earliest possible signal that `canonical` is wrong.

### 6.7 Risks

| Risk | Mitigation |
|---|---|
| `canonical` subtly wrong | Week-1 agreement harness; BIP vectors; §7 |
| Core v30 unpruned signet fails to come up | Verify on day 1, not week 2 — it gates everything the indexer track does |
| Relay dependency | Run our own (`strfry` / `nostr-rs-relay`) alongside public ones, consistent with running everything locally |
| Auditor scope creep | **Not on the critical path.** §5.3's tripwire attributes without a node, so the demo never requires the auditor. It is the stretch component |

## 7. Testing — differential edge-case suite — PENDING

§6.4 sharpened what this section is for. Differential testing against blindbit-oracle
exercises the wrapper only, since both sit on gobip352; and BIP-352's published vectors
cover send/receive but nothing at the index level.

Open: which implementation lineages are genuinely independent and worth testing against;
the constructed signet transactions for each ambiguous corner named in §2.6 (NUMS point
*H*, malleated P2PKH `scriptSig`, uncompressed and hybrid keys, `outpoint_L` endianness,
SegWit v>1, coinbase, point at infinity); the format of the index-level test vectors we
publish; how the suite runs in CI without a node; and which disagreements are worth
reporting upstream versus absorbing.

## 8. Demo — PENDING

Anchored on §5.4: a signet self-payment, an indexer configured to drop it, and Canary
naming the accused within roughly one block interval. Open: the exact narrative order,
what is shown on screen (§4.4 coverage versus the §4.7 evidence artifact), how the
malicious indexer is configured so the drop is visibly deliberate rather than a bug, and
the fallback if signet block timing does not cooperate on the day.

---

## Appendix A — Prior art

See [`../research/prior-art.md`](../research/prior-art.md).
