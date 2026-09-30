# Canary design document

| | |
|---|---|
| **Design** | Settled and approved 2026-09-08, after a spec review on 2026-09-07 and a self-review on 2026-09-08 |
| **Amended** | 2026-09-30, with the eight changes listed under [Amendments of 2026-09-30](#amendments-of-2026-09-30) |
| **Implementation** | The protocol core is built: `canonical`, `commit`, `feed`, `policy`, the test vectors and the `wire` tweak-list format. All tests pass as of 30 Sep 2026. Receipts and the rest of v1 are in progress, due 5 Oct 2026 |
| **Exact formats** | [v1 formats](2026-09-30-v1-formats.md) gives the byte layouts of the response, the receipt, the evidence file and the state file |
| **Terms** | [Glossary](../glossary.md) |
| **Target** | BOSS Battle (Bitshala), 7 Sep to 5 Oct 2026, Cypherpunk track |
| **Team** | One person plus Claude, decided 2026-09-30. [Ownership](#65-ownership) still records the original three-person split |

## Amendments of 2026-09-30

1. **Retention rule.** A hole inside the 144-block window is an omission that names the
   server ([Comparison procedure](#25-comparison-procedure)).
2. **Receipts** sign the server's tip and a digest of the served bytes. They live in the
   core `wire` package and travel in a response header ([Receipts](#38-receipts)).
3. **Evidence files** carry the served bytes and the receipt, and `canary verify`
   recomputes the result from them ([Evidence artifact](#47-evidence-artifact)).
4. **Limits named.** v1 does not check output data. Hash-only withholding under a
   declared pruning or dust policy passes the per-block check. A server that declares no
   filtering and still sends a hash gets a warning, not an accusation, because v1 policies
   are unsigned. And v1 is built and tested on regtest only ([Limits of v1](#limits-of-v1)).
5. **Demo** on regtest, 3:15 to 4:30 long, with the withholding switch named
   `--withhold-txid` and a neutral list of questions and answers ([Demo](#8-demo)).
6. **No daemon and no proxy in v1.** The v2 proxy targets BlindBit v1 clients and refuses
   Compromised and Disputed blocks only ([Binaries](#61-binaries),
   [Proxy, not observer](#62-proxy-not-observer)). A server that signs commitments for
   neighbouring blocks but not for this one is no longer refused. v1 marks the block
   Unverified with a warning ([Comparison procedure](#25-comparison-procedure), step 0).
7. **The `network` tag** carries the network magic as a decimal number
   ([The commitment object](#33-the-commitment-object)).
8. **Default track: Cypherpunk only.** Canary adds Freedom Stack only if the 7 Sep
   handbook allows a second track, and only with a genuine crossover pitch.

**A note, not an amendment.** The same day corrected the prior art and the quotes.
SPCOMMIT is now cited, and the BIP-352 citation quotes the BIP itself
([Summary](#0-summary), [Appendix A](#appendix-a-prior-art)).

---

## 0. Summary

Canary detects when a BIP-352 tweak indexer withholds entries from the tweak data it
serves a light wallet. It makes tweak sourcing accountable, not trustless. That holds
given at least one honest indexer publishing commitments, and an uncensored path to a
relay carrying them ([Security claim](#14-security-claim)).

Indexers publish a signed commitment to each block's tweak set as a Nostr event. Clients
check the data they were served against those commitments, and compare commitments across
indexers. Detection is cheap and continuous; attribution is expensive and on demand.

The full design puts Canary in the wallet's data path as a sidecar daemon. v1 is smaller:
a command-line checker and a reference indexer, with no daemon and no proxy
([Binaries](#61-binaries)).

The project is layered deliberately:

- **Tool first.** Against indexers as they exist today, with nobody's cooperation: take
  the union of what they serve (§4.3), read each server's policy from its existing
  `/info` (§2.3), and run the tripwire (§5), which detects *and* attributes without any
  server committing to anything.
- **Protocol second.** The signed-commitment extension makes detection cheap — a
  ~200-byte signed event per block per server, carrying the 32-byte root that is actually
  compared, against N full fetches — and makes an accusation transferable and
  non-repudiable, once the server signs receipts ([Receipts](#38-receipts)).

**The problem, in the sources' own words.** BIP-352 leaves it open. A footnote says: "It
is still an open question as to how Bob can source the 33 bytes per transaction in a
trustless manner." Its Appendix A on light clients is "out of scope for the current BIP
... included to motivate further research". The BIP never says an indexer can withhold
data. Others say it plainly:

- Bitshala's guide to BIP-352 (3 Aug 2026): "A light client that accepts tweak data from a
  server has no way to detect omission."
- SomberNight, the Electrum maintainer, in cake_wallet#2395 (Jul 2025): "I presently do not
  see a way how to fix this while using cut-through."
- The BIP-352 index-server specification asks: "How does a wallet know all tweaks were
  received for a given block request?"

**Prior art.** Canary applies the split-view idea from Certificate Transparency
(RFC 6962). It is also not the first tweak-set commitment. SPCOMMIT, by Rob Segers, has
published commitments on mainnet since 2026-09-01. Segers posted the specification and a
bitcoin-dev announcement on 2026-09-02. Bitcoin Optech #422 (2026-09-11) described the
scheme without naming it.

SPCOMMIT is a flat hash chain over the unfiltered tweak set. Only the chain head is
signed, as a Nostr kind-1 note every 6 hours. We found no wallet-side verifier for it
(checked 2026-09-30). What Canary's design adds, of which v1 builds only part
([Binaries](#61-binaries)):

- a signed commitment for every block, which a client can fetch by block hash;
- a check in the client each time it fetches a block;
- commitments that still work when a server filters: the gaps become explicit and
  checkable against a signed root, though a filtered gap still cannot be proven
  legitimate;
- coverage states, portable evidence files and tripwires.

SPCOMMIT's v2 format also covers each transaction's output prefixes and the block's spent
outputs, which Canary v1 does not ([Limits of v1](#limits-of-v1)).
[Appendix A](#appendix-a-prior-art) lists the sources.

---

## 1. Scope and threat model

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
| **Targeted omission** — drop tweaks for one victim | Silent, permanent, symptomless | Detected when the client fetches the block (§1.4), except the two variants in [Limits of v1](#limits-of-v1) |
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
tweak and `B_scan = b_scan·G`. It needs the private scan key. BIP-352's privacy rests on
this, and it binds the indexer like anyone else.

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
| **One** indexer, publishing commitments | Targeted omission | The server must either omit from everyone — public, affects all users, detectable by anyone with a node — or serve data contradicting its own signature. A hole inside the retention window counts as the second ([Comparison procedure](#25-comparison-procedure)). Two variants escape: an entry served as a hash under a declared pruning or dust policy, and output data hidden while the entry is served ([Limits of v1](#limits-of-v1)) |
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

Three qualifiers travel with the claim rather than waiting to be extracted from it. An
earlier draft folded the first two in and overstated the claim in both directions.

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

**The claim covers the tweak list, not payments.** Canary checks the `(txid, tweak)`
entries a server serves for a block. A wallet also decides from output data that Canary v1
does not commit to. So a server can serve the right entry and still hide the payment.
[Limits of v1](#limits-of-v1) lists this gap and two others.

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
  v1 surfaces it only through `canary status` and `canary ui`. The v2 proxy closes this
  gap by refusing blocks ([Proxy, not observer](#62-proxy-not-observer)).
- **Output-side withholding, in v1.** A server can serve the correct entry and still hide
  the payment in the output data the wallet matches against. v1 does not detect this. v2
  plans to cover the filter and `outputs_short`, but not a false spent flag. The next
  subsection gives the detail.

#### Limits of v1

Canary v1 checks the tweak list a server serves for each block. **Verified means the tweak
list was checked. It never means payments were checked.** Three limits follow. The README
and the demo's last act state them too.

| Limit | What happens | Status in v1 |
|---|---|---|
| **Output-side withholding** | The server serves the correct `(txid, tweak)` entry. Then it leaves the payment's output out of the new-UTXO filter or the `/utxos` list, marks it spent, or drops its 8-byte prefix from BlindBit v2's `outputs_short`. Wallets on BlindBit v1 then skip the payment without an error | Not detected. Every check passes and the block reads Verified. The sender in [Attacks in scope](#12-attacks-in-scope) knows the output key it created, so this costs it no more than hiding the entry. v2 plans to add each transaction's taproot output keys to its entry. That covers the filter and `outputs_short`. A false spent flag stays outside any per-block commitment, because whether an output is spent depends on later blocks, and it remains a limit after v2 |
| **Hash-only withholding under a declared policy** | A server that declares a subtractive policy, such as pruning (`prunes_spent`) or a dust threshold, serves the victim's entry as its 32-byte hash. The root recomputes and matches, the policy permits the gap, and the retention rule is met because the hash was kept | Passes the per-block check. The block reads *Checked, gap filled*: state `resolved`, reason `hash_retained`. The union ([Union for tweaks](#43-union-for-tweaks-k-of-n-belongs-on-filters)) still recovers the payment when any other server the client consults serves the entry in full. Otherwise nothing in the per-block check catches it. The tripwire can, for a payment the client made itself, when the local Core node shows one of its taproot outputs unspent. That finding is not provable to others ([Canary tripwire](#5-canary-tripwire)). So can an auditor holding the block, who can show the policy did not permit the gap. For example, the transaction behind a hashed entry may still have an unspent taproot output at or above the declared dust threshold ([Policy declaration](#23-policy-declaration)). v1 reads policy from the unsigned `/info`. A server that declares no filtering and still sends a hash gets a warning with the reason `hash_without_policy`. It is never an accusation, because nothing the server signed declares its policy ([v1 formats](2026-09-30-v1-formats.md)) |
| **Regtest only** | v1 is built and tested on regtest only, against its own reference indexer | Nothing has been shown on signet or mainnet, or with an unmodified wallet in the path |

### 1.6 Non-goals

1. **Canary does not make tweak sourcing trustless.** It makes it accountable. The README
   and the video state this early, before anyone has to ask.
2. Not a solution to commission attacks (§1.5).
3. Not a scanning-performance project. Frigate solved cost in May 2026; integrity is an
   orthogonal axis.
4. Not a new BIP-158 filter type — that requires work in Bitcoin Core.
5. Not a wallet. The wallet stays what it is; Canary checks its data. blindbitd, the wallet
   this item first named, was archived on 2025-08-14. Today's realistic BlindBit v1
   clients are blindbit-scan and Dana ([Proxy, not observer](#62-proxy-not-observer)).
6. Not mainnet-scale indexing in v1. v1 is built and tested on regtest only
   ([Limits of v1](#limits-of-v1)).
   Signet, with bounded block ranges, is the first public network after it.
7. Not a succinct (SNARK) proof of correct indexing. Named as the endgame, not built.

---

## 2. Canonical tweak sets and policy normalization

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
| `dust_threshold_sat` | 0 = none. Drops transactions whose taproot outputs are all below it. **Declared, never verified** — see below |
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

**In v1, items 1 and 2 wait for a signed policy.** Both hold a server to a policy it
signed. v1 publishes no policy event, so `policy_ref` is 64 zeros and the policy comes
from the unsigned `/info`. A server can revise that at will. So when a server that
declares no filtering sends a position as a hash, v1 shows a warning with the reason
`hash_without_policy`, never an accusation
([v1 formats](2026-09-30-v1-formats.md)). A hole inside the retention window needs no
policy at all. It is still an omission ([Comparison procedure](#25-comparison-procedure),
step 1).

**`dust_threshold_sat` cannot be verified, and does not need to be.** The leaf is
`(txid, tweak)` and carries no output value (§3.2), so a client holding a commitment can
never confirm that a dust-justified gap was legitimate. That reads like a hole and is
not, because the threshold is never load-bearing. If a gap resolves (§2.5), the root is
recomputed and matches, and *why* the server dropped the position stops mattering. If it
does not resolve, there is no leaf to carry a value either, and the range is
*unresolvable* whatever the declaration says. **No verdict in §2.5 takes the threshold as
an input.**

It survives for two jobs that are not verification. It routes effort — §2.5's tolerance
governs how hard a client works, and a declared threshold predicts which gaps are likely
benign. And it creates a contradiction that a rung-4 attributor, who holds the block and
therefore the output values, *can* check: a server that declared 1,000 sat and dropped a
50,000-sat payment has contradicted its own signed policy. Declaring in advance is what
makes that catchable at all.

**Rejected: putting the output value in the leaf.** It would make the threshold checkable
during gap resolution, at 8 bytes on every leaf plus a rule for which of several taproot
outputs counts. It buys nothing. A resolved gap needs no reason, and an unresolved gap
has no leaf to carry the value.

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

Per-leaf Merkle inclusion proofs were considered and rejected. Each proof is
`⌈log₂ n⌉ × 32` bytes, which is 352 bytes at `n ≈ 2000`. Proofs for all 2000 leaves come
to about 700 KB (2000 × 352 bytes), to accompany a 132 KB list. `n ≈ 2000` is the
order of magnitude for a mainnet block. This document uses that figure throughout,
including in [Merkle tree](#32-merkle-tree).

Instead the response is the canonical-order list in which each position is **the full
leaf, that leaf's 32-byte hash, or nothing**. The client hashes the full leaves, splices
in the supplied hashes, and recomputes the root in a single pass.

**The response is self-describing at length `n`.** The client must be able to tell which
of the three it is looking at for every position, without inference, and the list must be
exactly `n` long, matching the commitment. A response that is merely *shorter* is
indistinguishable from a smaller block, and under a single server there is no cross-check
to catch the difference.

- Serving everything: 66 bytes per position, a 1-byte kind plus the 65-byte leaf, against
  33 for a bare tweak. The whole list is `4 + 66n` bytes, with a 4-byte count in front,
  so about 132 KB at `n ≈ 2000`. That is **roughly double today's response.** It is the
  honest cost and it is not avoidable. The txid has to be on the wire, because a light
  client does not know which transactions are in the set and so cannot supply it.
  Bandwidth doubles, and storage stays free ([Cost](#37-cost)).
- Serving a subset while retaining leaf hashes: 33 bytes per withheld position, the kind
  byte plus the hash. No logarithmic factor applies, and the response is verifiable from
  that one server alone.
- Serving a subset with the hash discarded: 1 byte for that position, the kind alone. The
  block is verifiable only once the leaf is recovered elsewhere. Permitted only outside
  the retention window below.

[v1 formats](2026-09-30-v1-formats.md) gives the exact byte layout.

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

[The comparison procedure](#25-comparison-procedure) enforces the window. Its step 1
treats a hole inside the window as an omission, measured against the tip the server signs
into its receipt.

Merkle proofs earn their place for the evidence artifact and for targeted queries
("positions 3, 7, 11 without the block"), not for the main path. See §3.2. §2 fixes only
*what* is committed: the ordered canonical leaf list and its length `n`.

### 2.5 Comparison procedure

Keyed on block **hash**, not height — this makes the procedure reorg-safe at no cost and
removes "it was a reorg" as an available excuse.

Given block hash `B`, server `S`, declared policy `P`, published root `R`, response `D`.

**Step 0 — does `S` commit at all?** Three cases. None of them is an accusation in v1:

| `S` | Rule |
|---|---|
| Has never published a commitment, and claims none | Data is **Unverified** (§4.4). Accepted, and it feeds §4.3's union — but it is never *clean*, and only the tripwire (§5) can catch this server lying |
| Has published commitments for neighbouring blocks, but none for `B` | **Unverified, with a warning.** Selective non-publication *is* the attack: commit to every block except the one you lied about. v1 marks the block Unverified with the reason `no_record_for_block` ([v1 formats](2026-09-30-v1-formats.md)) and does not accuse. A missing commitment is not a signed statement, so no file can show it to anyone else. Whether the v2 proxy refuses such a block is a v2 decision ([Proxy, not observer](#62-proxy-not-observer)) |
| Published a commitment for `B` | Continue |

The middle row is what the original rule was reaching for. An earlier draft refused any
block without a commitment, which would have refused 100% of unmodified blindbit and
contradicted §0's "requires nobody's cooperation", §4.4's *Unverified* state, and
`start_height`. A server is expected to have a commitment for `B` because it published one
for a neighbouring block, not because it advertises that it might. **Evidence, not
advertisement.**

A later draft refused the data in the middle row. The amendment of 2026-09-30 moved every
refusal into the v2 proxy, which refuses only Compromised and Disputed blocks. So v1 warns
and does not refuse. This weakens one argument in [Chain agreement](#46-chain-agreement),
which says what now replaces it.

Then, for a server that did commit:

1. **Gap set `G`** = the positions `S` did not return in full. Each is a hash or a hole.
   **A hole inside the retention window is an omission.** The block's depth is the tip
   height `S` signed into its receipt ([Receipts](#38-receipts)) minus the block height
   in `S`'s signed commitment. If the block is fewer than 144 blocks below that tip,
   [the wire model](#24-wire-model) required `S` to keep at least the entry's hash. The
   hole is then *Omission detected*, named against `S`, whatever the later steps find.
2. **Resolve `G`.** Recover the missing leaves — from `S`'s retained hashes where it kept
   them (§2.4), otherwise from another server. If any position is still unfilled and
   step 1 found no omission, the block is *unresolvable* and there is no verdict. **This
   runs before the root is recomputed, not after.**
3. **Recompute the root** over all `n` positions. A mismatch means `S` served data
   contradicting its own signature. Proven and non-repudiable, from `S` alone.
4. If `P` declares no subtraction and `G ≠ ∅` → alarm. Local and immediate. This step
   needs a signed `P`, so it belongs to the protocol layer. v1's policy is unsigned, so
   there a hash from a server that declares no filtering gives a warning with the reason
   `hash_without_policy`, never an accusation
   ([Policy declaration](#23-policy-declaration)).
5. **Cross-check** `R` against other servers' roots for the same `B`. Equal → all
   committed to the same set. Unequal → at least one is lying; escalate to attribution
   (§4).

Steps 0–4 require a single server. Step 5 costs 32 bytes per block per server as a
continuous background check.

**The retention rule, added 2026-09-30.** Step 1 turns the window in
[the wire model](#24-wire-model) from a promise into a check. It does not change the
order: the client still fills every gap before it recomputes the root. Filling still
matters after step 1 has fired. The filled entry names the transaction that was left out,
and the recomputed root ties that entry to `S`'s signed commitment. Three conditions
travel with the rule:

- **Proof needs a receipt.** With one, the hole and the tip sit in `S`'s own signed
  statement, so anyone can check the omission offline. Without one, the client measures
  depth against its own view of the chain. It then knows about the omission but cannot
  prove it to others ([Security claim](#14-security-claim)).
- **Both ends of the depth are signed.** The receipt signs the tip's hash as well as its
  height, and the commitment signs the block's height. To push a block outside the
  window, a server must overstate its tip or understate the block's height. Either way it
  signs a false statement about the chain. When the signed values put the block inside
  the window, they settle the question with no outside chain fact, because an honest
  server never signs a tip and a height that convict it. The client needs a chain fact
  only to reject a gap that the signed values place outside the window
  ([Chain agreement](#46-chain-agreement)).
- **A hash is not a hole.** A server that declares a subtractive policy, pruning or a dust
  threshold, and returns the entry's hash satisfies the rule. The root recomputes and
  matches, so the per-block check passes and the block reads *Checked, gap filled*
  (reason `hash_retained`). The union still recovers the payment if another consulted
  server serves the entry in full. Otherwise nothing in the per-block check catches this
  variant. The tripwire can, and so can an auditor holding the block, who can show the
  policy did not permit the gap ([Limits of v1](#limits-of-v1)). A server that declares no
  filtering and sends a hash gets the warning from step 4.

[v1 formats](2026-09-30-v1-formats.md) pins the exact boundary of the window.

**Resolution before recomputation, and that ordering is load-bearing.** An earlier draft
recomputed the root first and resolved gaps last. A position returned as a hole then made
the root uncomputable, so the block was silently never verified. In that draft, step 3
was the only step that caught targeted omission (§1.4), so a server that could reach it
first and decline had a free, permanent way never to be verified — which is exactly the
attack this section exists to catch. **A block whose root has not been recomputed is not
clean. It has no verdict yet.** The retention rule in step 1 is the one exception: it
names the server before any root is recomputed. It never makes a block clean, and the
client still fills the gap and recomputes the root when it can.

**Three terminal states, not two:**

| State | Meaning |
|---|---|
| **Clean** | The root recomputed over all `n` positions and matched |
| **Omission detected** | Named server and block, backed by the server's signature. The finding names the transaction only when its entry was recovered. Otherwise it names the server, the block and the position. Reached when the recomputed root does not match `S`'s signed root, or when step 1 finds a hole inside the retention window. The tripwire reaches it too ([Canary tripwire](#5-canary-tripwire)). Coverage shows it as **Compromised**, labelled *Data withheld* on screen |
| **Unresolvable** | The root could not be recomputed. The usual cause is a gap outside the retention window that nobody can fill. [v1 formats](2026-09-30-v1-formats.md) lists the others, such as a list the server never served. Not an accusation, and it must not be reported as one. Not a pass either |

**Mode-dependent tolerance governs effort and reporting, never verification.** A
transaction can only be cut through once all its taproot outputs are spent, which at the
chain tip is nearly empty; and a spent output is one the client either spent itself or
never owned. Rescan-from-seed is where the light-client specification already admits
payments go missing. So a tip-following client spends less effort chasing a gap and
reports it more quietly; a rescanning client escalates. **Neither may skip step 3.** An
earlier draft had the tip-following client simply *accept* cut-through gaps, which
combined with a hashless gap to wave through the attack. The correct outcome for an
unfilled gap outside the retention window is *unresolvable*. Inside the window, a hole is
an omission (step 1). Whether the v2 proxy refuses unresolvable blocks is still open
([Proxy, not observer](#62-proxy-not-observer)).

### 2.6 What this fixes for the team

The interface frozen on day 2 (§6.3):

```go
func Set(net Network, blk *wire.MsgBlock, pv PrevoutSource) ([]Leaf, error)
```

The indexer commits to it, the checker compares against it, and the differential suite
tests it ([Testing](#7-testing-with-a-differential-edge-case-suite)).

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

## 3. Commitment format and Nostr transport

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
proof; S's signed receipt shows a response with a hole where L belongs, while B was inside
the retention window* ([Evidence artifact](#47-evidence-artifact)). Proving leaf
membership from a flat hash requires all `n` leaf hashes, roughly 64 KB at mainnet scale.
With a tree it is about 350 bytes. That is the difference between an artifact someone
reads and an attachment they do not.

| Element | Construction |
|---|---|
| Leaf | `TaggedHash("canary/leaf/v1", txid ‖ tweak)` — 32 + 33 bytes |
| Internal node | `TaggedHash("canary/node/v1", left ‖ right)` |
| Odd node | **Promoted, never duplicated** |
| Single leaf (`n = 1`) | `merkle_root` is that leaf's hash — promotion applied zero times |
| Empty set (`n = 0`) | `merkle_root` is 32 zero bytes. The outer root is computed over it unchanged |
| Root | `TaggedHash("canary/root/v1", network ‖ block_hash ‖ n_le32 ‖ merkle_root)` |

**The empty set is committed, not skipped.** `n = 0` is the common case, not a corner —
most regtest blocks and many signet blocks hold no eligible transaction at all, and
§7.4's own example vector is one. Defining `merkle_root(∅)` as 32 zero bytes avoids
inventing a fourth tag, and it is safe because `n` is already bound into the outer
preimage: an `n = 0` root cannot collide with any `n ≥ 1` root for the same block. A
server with nothing to commit still publishes, because skipping would hand back exactly
the excuse §2.5 step 0 exists to remove, wearing the phrase *"no commitment, because
there was nothing to commit."* An `n = 0` commitment is a real assertion and a checkable
one: the client recomputes the canonical set from the block and confirms it is empty.

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
| `network` | The 4-byte network magic from [the Merkle tree section](#32-merkle-tree), written in the event tag as a decimal number: btcd's `wire.BitcoinNet` value. Regtest's message-start bytes `fabfb5da` are the value `0xdab5bffa`, written `3669344250`. The root binds the same value, which keeps two custom signets apart. A display name would merge them. `FromEvent` reads the network back from this tag |
| `block_hash` | Authoritative key |
| `block_height` | Not the key; the block hash is. Since 2026-09-30 the retention rule in [the comparison procedure](#25-comparison-procedure) reads it, so a wrong height is a signed false statement |
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

**Tag names are forced by NIP-01, not chosen.** A relay indexes only **single-letter**
tag names, and a filter can query only those. A `block_hash` tag would be stored, signed,
and entirely unqueryable, which leaves §6.3's `Feed.Get` unimplementable against any real
relay. So the block hash goes in a single-letter tag and everything else is carried for
readers rather than for filters:

| Tag | Contents | Indexed |
|---|---|---|
| `b` | Block hash, display hex | **Yes** — this is the query key |
| `height`, `n`, `network`, `policy_ref` | As named. `network` holds the decimal magic described above. v1 publishes no policy event, so its `policy_ref` is 64 zeros | No |
| `root` | The root, hex. It must equal the event's content | No |

A fetch is `{"kinds":[1352], "authors":[<pk>], "#b":[<hash>, ...]}`. **There is no range
query.** Tag filters have no range or ordering operators, and `since`/`until` act on
`created_at`, which §3.5 says we do not trust. A client covering a range of blocks
therefore batches the block hashes it already knows into one filter, chunked to the
relay's limit — which is why §6.3's `Feed.Get` takes a slice rather than a single hash.

Content carries the root. A Nostr event id hashes the tags as well as the content, so the
signature covers all of it and no separate signed blob is needed. The redundancy between
tags and root is deliberate — any inconsistency between them is itself detectable.

### 3.4 Two channels, two jobs

§2.5 step 0 warns about a server that commits to neighbouring blocks but not to this one.
If commitments came only from relays, that warning would hand a veto to whoever controls
the relay. Censoring a committing server's events would make it look like a server that
skipped this block, and its data would fall back to Unverified. So the commitment travels
two ways, and they do different jobs.

| Channel | Job | On failure |
|---|---|---|
| **Pull from the indexer** — `GET /commitment/:blockhash`, returns the signed event | Gives the client a signed, non-repudiable statement from the party it is already talking to | A server that refuses to sign is refusing accountability. Its blocks read Unverified, with a warning where it signed their neighbours |
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
once a leaf is 144 blocks old**, meaning its block sits 144 or more blocks below the
server's signed tip ([Wire model](#24-wire-model)).
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

The server therefore signs a **receipt** for every response. A Schnorr signature costs
microseconds, and server cooperation is already assumed for commitments.

> **The commitment says what exists. The receipt says what you were given.** Omission is
> `commitment ≠ receipt`, both signed by the same key.

The receipt signs these fields, amended 2026-09-30.
[v1 formats](2026-09-30-v1-formats.md) gives the 178-byte layout.

| Field | Why it is signed |
|---|---|
| Format version | Lets v2 change the layout without ambiguity |
| Network | Stops a receipt from one chain from passing as one from another |
| Resource type | Marks the response as a tweak list, so a v2 receipt for filters or output data cannot pass as one |
| Block hash | Names the block the response is about |
| Request parameters, such as a client-supplied dust threshold | Without them, a server can answer a request by replaying an older response |
| The server's tip height and tip hash when it served | Lets anyone apply the retention rule in [the comparison procedure](#25-comparison-procedure) offline. Signing the hash means a server that overstates its tip must name a block that does not exist yet |
| A digest of the exact bytes served | Binds the receipt to the response, so the response itself becomes evidence |

A hole inside the retention window is then a contradiction between the server's own
signatures. The receipt's tip and the commitment's block height put the block inside the
window, and the receipt's signed bytes show the hole.

**Where the code lives.** The `Receipt` type, its digest and `VerifyReceipt` belong to the
core `wire` package, next to the response format. They do not belong to the indexer. The
client has to verify receipts, and a Go module cannot import another module's `internal/`
packages. The indexer only signs.

**Transport.** The receipt travels in an `X-Canary-Receipt` response header, next to the
body it signs. The body stays in the plain `wire` format.
[v1 formats](2026-09-30-v1-formats.md) gives the exact digest and header encoding.

Receipts exist only in the protocol layer. Against unmodified blindbit, omission is still
*detected* — the victim knows — but is not third-party provable. This is a concrete
reason to push for the protocol layer rather than a nice-to-have.

## 4. Client verification ladder

§2.5 gave the per-block comparison; §3 gave the object being compared. This section gives
the ladder: what runs continuously, what escalates, what is expensive and on demand, and
how each result is surfaced to a wallet that has to act on it.

### 4.1 The ladder

Ordered by cost. Each rung runs only when the one above it says something.

| Rung | Trigger | Catches | Cost |
|---|---|---|---|
| **1. Commitment tracking** | Always on | Root divergence between servers, and chain contradiction — a height still contested six blocks later (§4.6) | One relay subscription; ~144 events/day/server |
| **2. Self-consistency** | Client fetches block *B* | Served ≠ committed; policy contradiction, only a warning in v1 because v1 policies are unsigned; a hole inside the retention window ([Comparison procedure](#25-comparison-procedure), step 1) | Hashing `n` leaves. Microseconds |
| **3. Gap resolution** | Rung 2 found gaps, **before rung 2 can finish** | Whether a permitted gap is real | One targeted request |
| **4. Attribution** | Rung 1 found divergence | *Which* server lied, and about what | Requires prevouts — the expensive rung |

**Rung 3 runs inside rung 2, not after it**, and this is the one place the table's
top-to-bottom reading misleads. §2.5 resolves gaps *before* the root is recomputed, and
the recomputation is what rung 2 actually catches. A gap nobody can fill leaves the root
uncomputed and the block *unresolvable* — never clean. Implementing the two as strictly
sequential stages rebuilds the hole §2.5 closed, which is why the ordering is called
load-bearing there.

Rung 1 runs for blocks the client has not scanned and while the client is idle.
**Detection is decoupled from scanning**, so evidence accumulates continuously and an
alarm can fire before the user opens the wallet.

### 4.2 Detection needs no node; attribution does, and may be deferred

Attribution here means deciding which of two disagreeing servers lied. A server that
contradicts its own signatures needs no attribution, because its own statements name it.
An in-window hole needs no outside chain fact either. The server signed both its tip and
the block's height, and those two values put the block inside the window. The client
needs a chain fact only to reject a gap that the signed values place outside the window
([Comparison procedure](#25-comparison-procedure)).

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
not a claim (§1.5).

**The same gap matters for omission, and the union does not close it.** The union assumes
that once a tweak is scanned, the server answers honestly about the outputs: the filter,
the UTXO list and `outputs_short`. A server can hide a payment there as silently as in
the tweak list. A wallet on BlindBit v1 skips a block without error when the served filter
does not match. v1 does not check this ([Limits of v1](#limits-of-v1)). An earlier draft
said tweaks were chosen because that is where omission is silent, which was wrong.

The construction extends to part of the output data. Adding each transaction's taproot
output keys to its entry keeps Served ⊆ Canonical, because the keys come from the block
alone. Committed output keys cover the new-UTXO filter and `outputs_short`. v2 plans this
change. A false spent flag in `/utxos` stays outside it. Whether an output is spent
depends on later blocks, so the flag cannot enter a per-block canonical set, and it
remains a named limit after v2.

### 4.4 The primary output is coverage, not alarms

An alarm that never fires looks like a product that does nothing. The ladder produces
something continuous and visible instead: **per-block-range scan coverage.**

| Coverage state | Meaning |
|---|---|
| **Verified** | The recomputed root matched the signed root, with no gap to fill. Qualified by *how*: **by cross-check**, where another server's root agreed; **by tripwire**, where a planted assertion came back (§5.4); or **by own record**, where one server's served list matches its own signature and nothing checks that the record itself is complete. Under total collusion only the tripwire form says anything about completeness. It means the tweak list was checked, never that payments were ([Limits of v1](#limits-of-v1)). [v1 formats](2026-09-30-v1-formats.md) gives the reason codes |
| **Resolved** | Some positions came as hashes or had to be filled before the root was recomputed, and then the root matched. For example, another server supplied an entry, or the client computed it from a payment it declared |
| **Unresolvable** | The client could not recompute the root, so there is no verdict. The usual cause is a gap outside the retention window that nobody can fill ([Comparison procedure](#25-comparison-procedure)). It is not an attack and not a pass |
| **Unverified** | No signed record to check against. For example, the server signs nothing, has not indexed the block yet, or did not answer. The data is still used, and it feeds the union ([Union for tweaks](#43-union-for-tweaks-k-of-n-belongs-on-filters)), but nothing about it is checked ([Comparison procedure](#25-comparison-procedure), step 0) |
| **Disputed** | Roots diverge — two named servers, one of them lying, not yet attributed (§4.5) |
| **Compromised** | Attributed — one named server, one named block |

*Disputed* and *Compromised* are separate states because §4.5 keeps them separate. Root
divergence names two servers without saying which lied, and collapsing that into a single
alarm is exactly how an attacker gets an honest server excluded.

**Mapping from §2.5.** The comparison procedure returns three terminal states for one
`(server, block)`; coverage aggregates them across ranges and adds two that comparison
never produces. *Clean* becomes **Verified** where no gap existed and **Resolved** where
one was filled. *Unresolvable* carries across unchanged. *Omission detected* becomes
**Compromised**. **Unverified** comes from step 0 and **Disputed** from step 5, and
neither is a terminal state of the per-block procedure. Both step 0 cases that stop
before comparison map to **Unverified**. Where the server signed commitments for
neighbouring blocks but not this one, the block also carries a warning, the reason
`no_record_for_block` in [v1 formats](2026-09-30-v1-formats.md). v1 does not accuse on
it.

Which determines what the wallet displays:

> **A balance computed over blocks that could not be verified is a lower bound, not a
> balance.**

A wallet with unresolvable ranges says so rather than printing a confident number.

**How coverage reaches the user.** Two paths, and only one of them works against a wallet
that does not know Canary exists:

| Consumer | Mechanism |
|---|---|
| A Canary-aware wallet, or `canary status` and `canary ui` | Reads the coverage state and displays it. In v1 this is the only path |
| **Unmodified wallet** | It cannot display what it cannot see. Enforcement is the v2 proxy ([Proxy, not observer](#62-proxy-not-observer)), which **refuses Compromised and Disputed blocks**, so the wallet never receives a balance built on them |

The refusal, not the display, is the answer to §1.5's "a wallet that ignores the alarm".
An earlier draft of this section claimed coverage is "always on screen", which is not
true of an unmodified wallet: there, coverage lives in `canary status`, which is the
log-nobody-reads that §6.2 dismisses. v1 has no proxy, so v1 does not close this gap. An
earlier draft also said the proxy refuses *unverified* data. That rule would refuse every
block from today's servers, which publish no commitments.

### 4.5 Acting on alarms

An alarm is a fact about a server and a block, and v1 records it as a finding. Canary
keys each finding by the entry's position when it knows the position, and by the txid
otherwise. Keying on the position keeps one id when a later run recovers an entry that an
earlier run could not. Canary persists findings and copies them forward from run to run.

It drops a finding automatically in one case only: the local Core node no longer has
the block's header, as when a regtest chain is wiped and mined again. A reorg does not
drop a finding, because Core keeps the headers of blocks that left its best chain.
Evidence files stay on disk either way. [v1 formats](2026-09-30-v1-formats.md) gives the
exact id.

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
per block, PoW-verified, standard SPV."* **That is false where we run.** Signet is the
first public network Canary targets ([Non-goals](#16-non-goals)). v1 itself is built and
tested on regtest only, which is local and trusted by construction (table below). A BIP-325 signet gets
its integrity from a challenge signature in the coinbase, not from accumulated work:
difficulty is trivial and a laptop can outrun the real chain. A client trusting
most-work on signet can be handed a chain in which the disputed block does not exist,
which converts a real omission into "reorg" and defeats §5.3 step 2. Asserting a security
property that does not hold is worse than asserting none, because a reader builds on it.

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

A server following a fabricated chain has to sign commitments for it if it wants its
blocks checked. The client pulls a signed commitment from the server for every block it
fetches ([Two channels, two jobs](#34-two-channels-two-jobs)). A server that declines
leaves those blocks Unverified, with the warning from §2.5 step 0 where it signed their
neighbours. Neither outcome is a pass. §3.3's append-only kinds mean a server cannot
withdraw a commitment once published. So a fabrication that the server does sign lands in
the public feed, keyed by height and hash. A height where two servers name different
hashes is **contested**. Contested and transient is a reorg, and is ignored. Contested
past six confirmations is a signed statement about the chain contradicted by another
signed statement — a heavier accusation than omission, and it costs nothing new to
detect, because the commitment already carries both the height and the hash.

This is weaker than the argument an earlier draft made. That draft said step 0 forced a
server to commit or be refused. Since 2026-09-30, v1 refuses nothing, so a server can
decline to sign for the fabricated blocks. They then read Unverified, not checked, but
the fabrication also stays out of the public feed, where convergence would catch it. For
those blocks only the anchor below helps.

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
is cheap. It is not part of v1. Until it lands, the single-server case rests on the Core
node or the pin, and §5.3 says so.

**Consequence for §6.3:** the `headers` package is not an SPV chain. It is a store of
`(height, hash)` observations drawn from the commitment feed and the anchor, with the
contested-past-six-confirmations rule on top.

### 4.7 Evidence artifact

One file, **offline-verifiable**: `canary verify <file>` requires no network.
[v1 formats](2026-09-30-v1-formats.md#6-the-evidence-file) defines the file,
`canary-evidence/1`: its fields, its name and the order in which `canary verify` checks
it. That definition replaces the field list and check order this section used to give.
This section says only why the file holds what it holds.

The file carries the server's signed record for the block, the receipt, the exact bytes
the server served, the left-out entry, and a Merkle proof that the entry is in the signed
root, about 350 bytes ([Merkle tree](#32-merkle-tree)).

**Amended 2026-09-30: the file carries what the server served.** An earlier version held
only the commitment and the proof. That shows the server committed to the entry. It does
not show the server withheld it, and anyone could build such a file against an honest
server.

`canary verify` does not trust the `claim` field. It recomputes the result from the file.
First it checks the signed record, its signer and its block, then the Merkle proof that
the left-out entry is in the signed root. None of that needs a receipt. With a receipt, it
then checks the receipt under the same key and the served bytes it covers. Last, it checks
that the entry's position is a hole inside the retention window, or holds data that
contradicts the signed root ([Comparison procedure](#25-comparison-procedure)). The
window check needs no node, because the server signed both the tip and the block's
height.

The claim holds only if the file's contents produce it. **Without a receipt, the file
proves inclusion only**: the server signed a commitment that contains the entry. Nothing
ties the served bytes to the server, so the file cannot show withholding. `canary verify`
then reports *inclusion only*. Whoever ran the original check saw the omission and can be
sure of it, but the file cannot prove it to anyone else.

**v1 defines one claim, `omission`.** The server signed a record that contains an entry,
then served a list that did not carry it. Other signed contradictions have no file format
yet. Two servers' differing records are one. A receipted list whose length differs from
the record's `n` is another. v1 records both as findings, marked not provable to others.

This file is the demo. It is also what would be attached to a bug report or a public
disclosure — an accusation nobody can independently check is worth little.

## 5. Canary tripwire

The rung of last resort, and the only one that survives *all* queried indexers colluding
(§1.3), because the client's knowledge originates outside the indexer system entirely.

### 5.1 Generalized statement

The tripwire is not "send yourself money." It is:

> **Assert that a payment exists in block B, then check whether each indexer reports it.**

The assertion has two sources:

| Source | Cost | What it gives |
|---|---|---|
| **Self-payment** | A real fee | Everything. The client made the transaction, so it holds the prevouts, computes the canonical leaf, builds the missing-leaf proof, and attributes with no node and no auditor (§5.3) |
| **Out-of-band txid, disclosed by the payer** | Free | **Detection only.** *Does server S report txid X in block B* needs no prevouts. Attribution does — with no prevouts there is no tweak, so no leaf and no §4.7 artifact until a block source turns up |

BIP-352 already contemplates out-of-band notifications and accepting them is cheap. Two
limits travel with the feature, because an earlier draft of this section called it
*"strictly more useful"* and that is wrong twice over.

**It does not inherit the self-payment's node-free attribution.** §5.3's exception rests
entirely on the client having made the transaction. A bare txid supplies no prevouts, so
the client cannot compute the tweak, cannot build the left-out entry, and cannot produce
an artifact anyone else can check.

**It is unavailable against §1.2's attacker by construction.** A sender hiding a payment
from you does not hand you its txid — and a sender who does disclose one has to serve
that txid honestly or be caught immediately by an assertion they created themselves. So
out-of-band probes accrue free coverage against any indexer that is *not* the discloser,
which is a real and common case because the payer and the indexer are usually unrelated,
and they contribute nothing against the one adversary §1.2 names as most likely. They are
an addition to the self-payment path, not a replacement for it.

### 5.2 Indistinguishability

Per §1.2, an attacker cannot identify a victim's self-payment from chain data. That is
the tripwire's foundation. What remains is metadata:

| Leak | Mitigation | In v1? |
|---|---|---|
| **Periodic timing** — a probe every 6 blocks is trivially whitelisted | Poisson scheduling (exponential inter-arrivals) — memoryless, so the last probe reveals nothing about the next | v2 ([roadmap F25](../roadmap/2026-09-30-feature-roadmap.md)) |
| **Distinctive value** — a repeated or round amount | Randomized, non-round values | v2 ([roadmap F25](../roadmap/2026-09-30-feature-roadmap.md)) |
| **Broadcast/query correlation** — broadcasting and then immediately querying that block | Broadcast over a different path from the one used to query indexers | Documented |
| **Funding linkage** — spending a UTXO the adversary sent, so they observe the victim transacting | Fund probes from UTXOs the adversary does not know about, where possible. **Not fully solvable** | Stated limitation |

The v1 tripwire is one declared payment. The user makes a payment and names it to
`canary check` with `--expect`. v1 has no scheduler and picks no values, so the first two
mitigations wait for v2.

**The honest ceiling.** A passed tripwire proves the server served *that one tweak*. It
is not proof of global honesty, and it says nothing about the output data for that
payment ([Limits of v1](#limits-of-v1)). Against blanket degradation it is quantifiable: an
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

[Detection needs no node](#42-detection-needs-no-node-attribution-does-and-may-be-deferred)
holds that detection needs no node but attribution does. The tripwire is the exception.
The client *made the transaction*, so it holds the prevouts and computes the canonical
entry itself, with no auditor. What the negative result proves depends on where the entry
went missing. v1 treats three cases differently
([v1 formats](2026-09-30-v1-formats.md)):

| Where the entry is missing | v1 result | Provable to others? |
|---|---|---|
| The signed record contains the entry, and the list leaves it out inside the retention window | The ordinary omission. The client fills the gap with the entry it computed, and the evidence file notes that the tripwire found it | Yes, with a receipt. It is the standard evidence file ([Evidence artifact](#47-evidence-artifact)) |
| The signed record itself leaves the entry out | Always an accusation. No spent check applies, because the record commits to the full canonical set whether or not outputs are spent ([The canonical set](#22-the-canonical-set-t_baseblock)) | No. The evidence file carries an inclusion proof, and v1 has no way to prove that an entry is absent from a root. The user knows, and nobody else can confirm it from Canary's files |
| The list carries only the entry's hash, or marks it absent outside the retention window | An accusation only when the local Core node shows one of the payment's taproot outputs unspent, at or above the server's declared dust threshold. Then pruning cannot explain the gap | No. The evidence file has no way to show an output unspent |

[v1 formats](2026-09-30-v1-formats.md) gives the reason code for each case.

**One qualifier, added 2026-09-07.** In the full design the entry needs no node, because
the wallet holds the prevouts of its own transaction. v1 has no wallet in the path, so
`canary check` reads the declared payment from the local Core node. Step 2 above also
needs a chain fact from outside the indexer set. Under total collusion that fact cannot
come from the indexers, by definition ([Chain agreement](#46-chain-agreement)). So the
tripwire attributes without an auditor *given an anchor*: a Core node, a pin, or
eventually the signet solution check. Lacking all three, a negative result is still
recorded, and the server's signed record and receipt still stand. It becomes an
accusation the moment an anchor is available, because signed evidence does not decay.

### 5.4 Coverage integration and cost

A passed tripwire verifies one block for one server, so
[coverage](#44-the-primary-output-is-coverage-not-alarms) records how a block was
verified: **by cross-check**, **by tripwire** or **by own record**. Under total collusion
only the tripwire form says anything about completeness.

> The tripwire is the only part of Canary with a marginal monetary cost. **The strongest
> check is bought one transaction fee at a time.**

In the full design, probes are therefore rate-limited by a user budget rather than a
fixed schedule. v1 sends no probes of its own. Its tripwire is one payment the user
declares ([Indistinguishability](#52-indistinguishability)).

Out-of-band assertions ([Generalized statement](#51-generalized-statement)) are free. A
user receiving real payments gains tripwire coverage at no cost. That coverage counts
only against servers other than the payer who disclosed the txid, and only as detection.
On a test network every probe is free. That is what makes [the demo](#8-demo) possible:
send a payment, have a deliberately malicious indexer drop it, and watch Canary name it.

The tripwire is the one path whose latency is not a block interval. The client already
knows the txid and the block, so detection is bounded by its own query once the server
has indexed that height — seconds, not §1.4's block interval. That is a property of the
tripwire alone and does not generalize to the other rungs.

## 6. Components, interfaces, ownership

### 6.1 Binaries

**v1 ships no daemon and no proxy (amended 2026-09-30).** `canary check` runs once and
writes a state file. `canary ui` reads that file and serves a local page. Nothing sits in
a wallet's data path.

| Binary | Role in v1 |
|---|---|
| `canary` | The command-line tool. `canary check` fetches commitments and responses, runs [the comparison procedure](#25-comparison-procedure) and writes the state file. It pins the indexer's public key by flag and reads block hashes from the local Bitcoin Core node. `canary verify <file>` checks an evidence file offline. `canary status [--json]` prints coverage from the state file, and `canary ui` serves a local page that reads it |
| `canary-indexer` | The v1 reference indexer, on regtest. It publishes one signed commitment per block, signs a receipt on every response, and has a `--withhold-txid <txid>` switch for the demo |

**The v1 reference indexer reuses the `canonical` package.** That breaks the rule in
[the BIP-352 library section](#64-the-bip-352-library-supplies-the-primitives--and-what-that-costs)
that the indexer keeps its own computation path. It also makes differential testing
against this indexer meaningless for v1. Both sides run the same code, so they agree
whether or not the code is right. Independence returns in v2, with an indexer that
computes the canonical set on its own path.

The full design, which v2 builds toward:

| Binary | Role |
|---|---|
| `canaryd` | The sidecar. Subscribes to commitments, verifies, serves the wallet, reports coverage |
| `canary` | CLI — `canary status`, `canary verify <file>`, `canary probe` |
| `blindbit-oracle` (fork) | Indexer with `--commit`: computes `T_base`, publishes commitments, signs receipts |

### 6.2 Proxy, not observer

**Status: v2.** v1 has no proxy ([Binaries](#61-binaries)). This section records the
design the proxy will follow, amended 2026-09-30.

A sidecar can sit **beside** the wallet (querying independently, wallet unchanged) or
**in the data path** (the wallet points at it instead of the indexer). Canary is a proxy.

1. The wallet is unmodified. blindbitd, the wallet this section first assumed, was
   archived on 2025-08-14. The realistic clients today are blindbit-scan, a headless Go
   scanner, and Dana through its spdk library. Both speak the BlindBit v1 HTTP API, and
   each points at the proxy by changing one server URL.
2. Observer behaviour falls out of proxy mode for free; the reverse does not.
3. **It closes §1.5's "a wallet that ignores the alarm."** A component in the data path
   can refuse to serve a block. An observer can only write to a log the wallet never
   reads.

**A reverse proxy for BlindBit v1.** The proxy passes every route through unchanged and
intercepts only the tweak routes, `/tweaks/{height}` and `/tweak-index/{height}`. Both
are keyed by height. The proxy resolves each height to a block hash from its chain anchor
([Chain agreement](#46-chain-agreement)) and runs the comparison on the hash, because
Canary compares blocks by hash. An earlier plan answered 404 for every route except
`/tweaks`. Every v1 client would then fail at its first `/info`, `/block-height` or
`/filter` request. The routes passed through carry output data that Canary does not yet
check ([Limits of v1](#limits-of-v1)), so the proxy never labels them as checked.

**What the proxy refuses.** It refuses **Compromised** and **Disputed** blocks only. An
earlier draft refused *Unverified* data. Today's servers publish no commitments, so every
block they serve is Unverified, and that rule would refuse all of them. The proxy passes
Unverified data through, labelled as unchecked.

Refusing a Disputed block does not exclude either server, which
[Acting on alarms](#45-acting-on-alarms) forbids doing automatically. It holds that one
block back from the wallet until the dispute is attributed.

Two further refusals are open v2 decisions:

- whether the proxy refuses **Unresolvable** blocks;
- whether it refuses an Unverified block from a server that signed commitments for the
  neighbouring blocks but not this one ([Comparison procedure](#25-comparison-procedure),
  step 0). v1 marks such a block with a warning and does not accuse.

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
    // Batched deliberately: NIP-01 offers no range query, so a range fetch is one
    // filter over block hashes the client already knows. §3.3
    Get(ctx context.Context, author [32]byte, blockHashes [][32]byte) ([]Commitment, error)
}

// wire     — the response format (§2.4) and receipts: Receipt, VerifyReceipt (§3.8)
// headers  — (height, hash) observations + the contested-past-6 rule. NOT SPV. §4.6
// ladder   — the four rungs and the coverage state machine. §4
// evidence — artifact construction and offline verification. §4.7
// tripwire — expected-payment assertions; the Poisson scheduler is v2. §5
```

An earlier draft of this block carried literal `...` in `VerifyProof`, which is not a
frozen interface. Everything above compiles as written.

**Nothing above is known-open as of 2026-09-08.** `Feed.Get` was, until §3.3 moved the
block hash into the indexed `b` tag and made the call batched; `headers` was the other,
and §4.6 resolves it — the package is deliberately **not** an SPV chain.

**Interfaces freeze on day 2, not at the end of week 1.** On a 28-day clock, spending
the first quarter before parallel work begins is not affordable. Days 1–2 are all three
people co-writing type definitions with no logic behind them; everything after runs in
parallel against stubs.

### 6.4 The BIP-352 library supplies the primitives — and what that costs

**The import path is `github.com/setavenger/go-bip352`, package `bip352`, v0.1.8.**
Verified 2026-09-08 against the published module. This matters more than a naming detail:
the older `github.com/setavenger/gobip352` path is v0.1.4, and it does **not** export
`ExtractEligibleVins` or `ExtractPubKey` — its own README says input eligibility is out of
scope. Every de-risking claim in this section is a claim about `go-bip352`. Pointing
`go.mod` at the old path silently removes the eligibility layer and leaves the team
writing it by hand.

Signatures, verbatim from `go doc`:

```go
func ExtractEligibleVins(vins []*Vin) ([]*Vin, error)  // deep-copies; sets the Taproot flag
func ExtractPubKey(vin *Vin) ([]byte, TypeUTXO)        // no error — check TypeUTXO != Unknown
func ComputeInputHash(vins []*Vin, publicKeySum [33]byte) ([32]byte, error)
func TaggedHash(tag string, msg []byte) [32]byte       // confirmed BIP-340 construction
var NumsH = []byte{...}                                // the 32-byte x-only NUMS point
```

`TaggedHash` being a real BIP-340 tagged hash is load-bearing for §3.2 and was checked
against `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)` rather than assumed. `NumsH` being
exported means §7.3's NUMS-H corners can assert against the library's own constant instead
of a copied literal.

**A byte-order trap, and it is exactly the one §3.2 warns about.** `bip352.Vin.Txid` is
documented as *"the normal human-readable format"* — display order, byte-reversed.
`ComputeInputHash` and `FindSmallestOutpoint` both require it that way. §3.2 pins the leaf
preimage txid as **internal** byte order. So `canonical` converts at the boundary, in one
place, and §7.4's vectors pin the result. Two representations of a txid in one package is
how implementations silently fork.

Two further behaviours worth pinning, both verified rather than inferred:
`ExtractEligibleVins` on an empty slice returns `(empty, nil)` and not `ErrVinsEmpty`; and
`ExtractPubKey` signals failure by returning `TypeUTXO == Unknown` rather than an error.

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
would make the differential test vacuous. v1 departs from this on purpose: its reference
indexer calls `canonical`, and [Binaries](#61-binaries) records what that costs.

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

**Superseded for v1 (2026-09-30).** This whole section assumed three people, four weeks,
signet and a blindbit-oracle fork. v1 is one person plus Claude. It ships no proxy
([Binaries](#61-binaries)), is built and tested on regtest only ([Demo](#8-demo)) and
needs no signet funding. The section is kept as the record of the original plan.

Coarse only. The detailed plan is `writing-plans`' output, not this document's.

| Phase | Gate |
|---|---|
| **Day 1–2** | Signet, Core v30 and blindbit-oracle running for all three. **Interfaces frozen** |
| **Week 1** | `canonical` agreeing with blindbit-oracle across ~1000 signet blocks. `commit`. Nostr round-trip. **Fund the signet UTXOs the signet demo needed** |
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
line, not a fork: the gate does not wait on the indexer track's week-2 work.

**Two demo tasks had a lead time longer than week 4 in the original plan.** Signet
funding had to exist before the faucet stopped existing, so it landed in week 1. Recording
had to start as soon as the end-to-end path worked, in week 3, so that week 4 was editing
rather than first takes. The v1 demo runs on regtest, so the first task no longer applies.

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
| Auditor scope creep | **Not on the critical path.** §5.3's tripwire attributes without a node on the self-payment path, and the demo's detection uses the retention rule ([Comparison procedure](#25-comparison-procedure)), so the demo never requires the auditor. It is the stretch component |

## 7. Testing with a differential edge-case suite

### 7.1 Three layers

| Layer | Covered by | Independent? |
|---|---|---|
| **A. Primitives** — tweak from a given input set | BIP-352's `send_and_receive_test_vectors.json` | Yes — it is the specification |
| **B. Canonical set** — which transactions, in what order | **Nothing. No vectors exist** | — |
| **C. Real-chain agreement** — us against blindbit-oracle over N blocks | Week-1 harness (§6.6) | No — shared `go-bip352` (§6.4) |

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

> **Regtest for the edge-case suite, and for the v1 end-to-end demo. Signet comes after
> v1.**

The v1 demo moved to regtest on 2026-09-30. [What the format dictates](#81-what-the-format-dictates)
gives the reason.

The original plan also listed a day-1 check that blindbit-oracle accepts regtest. v1 uses
its own reference indexer instead ([Binaries](#61-binaries)), so only one check remains:
Core's REST endpoints behave as expected on regtest.

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
| `n ∈ {0, 1, 2, 3, 5, 2ᵏ, 2ᵏ+1}` | **Odd-node promotion**, where CVE-2012-2459-class bugs live, plus §3.2's `n = 0` and `n = 1` base cases |
| An internal node hash never validates as a leaf | The distinct leaf and node tags |

### 7.6 Upstream, and expectations

Disagreements sort into three buckets:

- **We are wrong** — fix, and keep the vector
- **They are wrong** — report with the vector attached. A failing vector is a far better
  bug report than prose
- **The BIP is ambiguous** — the valuable case. BIP-352 is actively maintained (version
  1.1.1, 2026-04-16, added a test vector), so an index-level vector contribution is
  plausibly acceptable upstream

**Expectations, so a quiet suite is not read as a failed one:** the likely outcome is
zero to two real bugs. The suite is the contribution either way. *"We tested this against
N implementations and they agree"* is a legitimate and reportable result. It answers the
question of how we know the canonical set is right.

The work is time-boxed. The vectors ship whether or not they find anything.

## 8. Demo

Amended 2026-09-30: regtest, a new first act, a longer target, the `--withhold-txid`
switch, and a neutral list of questions and answers.

### 8.1 What the format dictates

BOSS Battle is asynchronous. The deliverable is a recorded video plus a repository that
has to read on its own. That fixes four things before any content decision:

1. **Nothing is faked.** A bad take is re-recorded, so no screen needs to be faked. The
   rule: every frame must come from a real run.
2. **Two kinds of reader, served separately.** Some people watch the video and never open
   the repository. Others open the repository and never finish the video. The video
   serves the first group and [the repository path](#85-the-repository-path-for-readers-who-do-not-watch-the-video)
   serves the second. Neither depends on the other.
3. **The first twenty seconds state the problem**, because a viewer who has just started
   has no context yet.
4. **The target length is 3:15 to 4:30, and at least 180 seconds.** One competitor,
   QuietRelay, reports a 3-to-5-minute rule (180 to 300 seconds) from the organizers'
   private participant handbook, which we have not seen. A video in this range meets the
   rule if it holds, and costs nothing if it does not.

**The network is regtest.** v1 is built and tested on regtest only, and the video says so
on screen and says why. One person plus Claude builds the core loop in the final week. A signet run would
need a synced node and would wait on public block timing that nobody controls. Regtest
mines a block on command and needs no faucet. Anyone with Bitcoin Core can repeat the run
on one machine. The cost is real: the video cannot claim a run on a public network.
[Regtest, not signet](#72-regtest-not-signet) already uses regtest for the edge-case
suite.

### 8.2 Show the loss before the tool

The narrative order is fixed, and it is not the architecture order. The problem is
invisible by construction; that is the whole project. So the video's first job is to make
the invisibility visible. Opening on a diagram or on Canary's own output asks the viewer
to take the problem on faith.

v1 has no wallet in the path ([Binaries](#61-binaries)). Act 1 therefore shows the served
data directly: the chain holds the payment, and the indexer's response has no entry for
it.

| Act | Time | On screen | What it establishes |
|---|---|---|---|
| **1. The loss** | 0:00–0:40 | Split screen. Left: Bitcoin Core on regtest shows the payment, confirmed in block *B*. Right: the indexer's response for *B*, HTTP 200, with no entry for that transaction | A client reading this response finds no payment. The response carries no error, and a hole is also what an honest server sends for an old, pruned block |
| **2. The cause** | 0:40–1:05 | The `--withhold-txid <txid>` switch on the indexer's command line, with its help text. Then the indexer's log: no error, no warning | That is the whole attack. It produces no error because it needs none |
| **3. Detection** | 1:05–2:05 | `canary check` fetches the signed commitment and the response with its receipt. It finds a hole inside the retention window. It fills the gap with the entry it computes from the payment declared with `--expect`, which the local Core node supplies. Then it recomputes the root, and names the server, the block and the txid | The server's own signed statements contradict each other ([Comparison procedure](#25-comparison-procedure)). One server is enough, with no trust in it. Its signed tip and its signed block height put the block inside the window, so no outside chain fact is needed. The local Core node supplies the block hashes and the declared payment, not the verdict |
| **3b. The other branch** | 2:05–2:35 | A second, honest indexer. The attacker now signs a record for the set without the entry. The two roots differ, and the block reads *Servers disagree*, the Disputed state | Committing to the smaller set shows up in the cross-check instead, as a dispute between two named servers. It is not yet an attribution. v1 detects this case. Only staging the scene is optional |
| **4. Independent check** | 2:35–3:20 | A second terminal, with the network interface visibly down and `canary` built beforehand. `canary verify evidence/<file>.json` passes. A tampered copy, with the flipped byte named, fails | The accusation survives without us and without the internet ([Evidence artifact](#47-evidence-artifact)) |
| **5. The limit** | 3:20–4:10 | The limits from [Limits of v1](#limits-of-v1): output-side withholding, hash-only withholding under a declared pruning or dust policy, and v1 built and tested on regtest only. It closes on `canary status` showing a *Can't be checked* range, the unresolvable state. Closing line: accountable, not trustless | The boundary, stated before anyone asks. Can't be checked is neither a pass nor an accusation |

Without act 3b the video runs about 3:40 (4:10 minus 0:30), still inside the target.

**Staging act 3b.** v1 detects Servers disagree, so the scene would show a real v1
result. Staging it needs an indexer switch that signs a record without the entry.
[v1 formats](2026-09-30-v1-formats.md) defines only `--withhold-txid`, which still signs
an honest record. So the scene depends on a switch outside the frozen formats, and it is
the first cut if the video runs long. It runs without `--expect`. A declared payment would
turn the block into Data withheld, because the withholder's own record would leave out a
declared entry, and Data withheld takes precedence over Servers disagree.

**Act 5 is not optional.** Most demos end on the result. This one ends on the boundary:
what v1 does not check, and *unresolvable*, a state designed neither to accuse nor to
pass. It shows how the design treats what it cannot know. It also answers several
questions in [Questions and answers](#87-questions-and-answers) before anyone asks them.

**The attack is already running in act 1. Act 2 reveals it rather than applies it.** The
alternative is to open on a complete response, switch the flag on camera and watch the
entry disappear. That shows the change, but it spends fifteen seconds before the problem
appears, and it opens on a screen where nothing is wrong. The change worth the time is
act 3's: the same data, now producing an accusation.

**Cast the adversary as the sender**, per [Attacks in scope](#12-attacks-in-scope). The
exchange that pays you is the indexer that tells you whether you were paid. One
adversary, one motive, one victim, and no third party introduced to make the plot work.

### 8.3 What is on screen: coverage or the artifact

Both, at different acts, and they are not interchangeable.

| Output | Nature | Acts | Why there |
|---|---|---|---|
| **Coverage** (§4.4) | Continuous. The product | 5 | It is what Canary does when nothing is wrong, which is most of the time |
| **Evidence artifact** (§4.7) | Discrete. The event | 3, 4 | It is the accusation, and the only thing a third party can check |

Opening on coverage means opening on a screen that reads *fine*, which shows no problem.
Showing only the artifact presents Canary as an alarm box, which
[The primary output is coverage](#44-the-primary-output-is-coverage-not-alarms) rejects.
Coverage sets the context, and the artifact is the event.

### 8.4 Staging the adversary so the attack is visibly deliberate

A missing entry on screen reads as a bug in Canary unless the viewer watched it being
caused. Five rules follow.

1. **The switch is on screen, with its help text visible.** `--withhold-txid <txid>` on
   the v1 reference indexer ([Binaries](#61-binaries)). The viewer sees the attack being
   switched on.
2. **It targets a txid, not an address.** An indexer cannot select by address, because
   that needs the scan key it does not have ([Attacks in scope](#12-attacks-in-scope)).
   Targeting by txid is exactly the capability the sender-attacker holds. An address
   filter would concede the premise the threat model rests on.
3. **The withholding indexer keeps publishing honest commitments and receipts.** Act 3
   works because the commitment includes the entry, and the signed receipt shows a hole
   inside the retention window. The indexer serves a hole, not a hash. A server that
   served the hash under a declared pruning or dust policy would pass the per-block check,
   and act 5 says so. Act 3b is the branch where the attacker commits to the smaller set
   instead.
4. **The payment stays inside the retention window.** The run never mines 144 or more
   blocks between the payment and the check. Outside the window a hole is permitted, and
   the correct result would be *unresolvable*, not an accusation.
5. **Nothing is cut inside a take.** Dead time between takes is cut, timestamps stay
   visible so each cut is legible, and no output is fabricated or retyped.

### 8.5 The repository path, for readers who do not watch the video

`evidence/` holds a real file from a real recorded run, not a hand-built fixture. The
README's first code block verifies it:

```
go run ./cmd/canary verify evidence/<file>.json
```

The first build downloads the Go module dependencies, so it needs a network connection
unless the module cache already holds them or the modules are vendored. After that one
online build, verification needs no node, no network and no indexer. The target is under
60 seconds from opening the README to a result in the reader's own
terminal. A CI test verifies the same file, so a change that breaks it fails the build.

With a receipt in the file, the result is an accusation anyone can check. Without one,
`canary verify` reports *inclusion only* and says why
([Evidence artifact](#47-evidence-artifact)).

If the run's signed events are also published to public relays, a reader can fetch the
same commitment independently. Publishing is a stretch goal for v1, and the README claims
it only if it happened. Relays differ in how long they keep events, so the publisher
picks relays it has checked for retention.

### 8.6 Fallbacks

The run is on regtest, so block timing is under our control, and no public faucet or
server is involved. The remaining risks are in the build, and each has a stated fallback:

| Risk | Fallback |
|---|---|
| The scripted end-to-end run is not ready | Record a manual run of the same steps, and say so on screen and in the README |
| The tripwire does not pass in time | It becomes a named limit, not a scene |
| Receipt checking in `canary verify` is not ready | The file proves inclusion only. `canary verify`, the README and the video all say so |
| The staged Can't be checked range for act 5 is not ready | Staging it is a stretch item in the v1 plan. Act 5 then names the state and what it means without showing a range, and says so |

### 8.7 Questions and answers

**Isn't this Certificate Transparency?**
It applies Certificate Transparency's split-view idea, and
[The equivocation insight](#13-the-equivocation-insight) cites RFC 6962 for it. The
difference is the data. A log entry is whatever the log says it is. A tweak list is
derived from a block by rules that honest servers apply differently: cut-through, dust
limits, start height. Committing to one policy-free list per block, while servers serve
less of it, is the part Certificate Transparency does not have.

**How does this differ from SPCOMMIT?**
SPCOMMIT, by Rob Segers, came first. It has published tweak-set commitments on mainnet
since 2026-09-01. It is a flat hash chain over the unfiltered set, and only the chain head
is signed, every 6 hours. Its author writes that a client given a filtered response
"cannot check the subset for completeness". Canary signs a commitment for every block and
checks each block when the client fetches it. It makes a filtered response's gaps
explicit and checkable against the signed root, though it cannot prove a filtered gap was
legitimate either. SPCOMMIT's v2 format also covers each transaction's output prefixes
and the block's spent outputs, which Canary v1 does not ([Limits of v1](#limits-of-v1)).

**Why would a withholding server commit honestly?**
It cannot withdraw a published commitment, and three of its choices meet a different
check each. If it commits honestly and leaves a hole inside the retention window, its own
signed receipt shows the hole; one server is enough. If it serves a wrong entry, the
recomputed root does not match its signature. If it commits to the smaller set, any
honest server's root differs, and the two servers stand as Disputed until attribution
names the liar. For a payment the client declared, the smaller set names the server
directly, because its own record leaves out the entry. The client knows, but v1 cannot
prove it to others ([Canary tripwire](#5-canary-tripwire)). Two variants pass the
per-block check: serving the entry's hash under a
declared pruning or dust policy, and hiding the output data instead of the entry.
[Limits of v1](#limits-of-v1) states both.

**Can't you run two indexers and diff what they serve?**
No. Honest indexers serve different sets, and BIP-352 permits it: "spent transactions
optionally can be skipped". A raw diff reports every such difference as an alarm. Canary
compares committed canonical sets instead
([Canonical tweak sets](#2-canonical-tweak-sets-and-policy-normalization)).

**What if every indexer colludes?**
Then comparing servers shows nothing. The tripwire still works, but only for payments the
client knows exist because it made them ([Canary tripwire](#5-canary-tripwire)).

**Does this need a full node?**
Detecting a problem does not. A server that contradicts its own signatures is named
without a node. A hole inside the retention window needs no outside chain fact either,
because the server signed both its tip and the block's height. A chain fact is needed
only to reject a gap that the signed values place outside the window.

Deciding which of two disagreeing servers lied (attribution) needs prevouts, from a full
node or a third-party API. That can wait, because signed evidence does not expire
([Detection needs no node](#42-detection-needs-no-node-attribution-does-and-may-be-deferred)).
The tripwire attributes without a node, given one outside chain fact, because the client
made the transaction and holds its prevouts. v1's `canary check` still reads block hashes
and declared payments from a local Bitcoin Core node.

**Is a detected omission proof?**
Only with a receipt. The evidence file then carries the served bytes and the server's
signature over them, so anyone can check the omission offline. Without a receipt, the
client knows, and others can check only that the server committed to the entry
([Receipts](#38-receipts)).

**Does Canary stop fake entries?**
No. Canary covers hiding only. A server that adds fake entries (commission) is out of
scope ([Attacks explicitly out of scope](#15-attacks-explicitly-out-of-scope)).

**What does Verified mean?**
The block's tweak list was checked against a signed root. It does not mean the block's
payments were checked ([Limits of v1](#limits-of-v1)).

**Why regtest?**
Time and reproducibility, at the cost of not showing a run on a public network.
[What the format dictates](#81-what-the-format-dictates) gives the full reason.

---

## Appendix A. Prior art

The full survey is in [prior-art.md](../research/prior-art.md). These are the sources
this document relies on, checked 2026-09-30:

- **[BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki).** A
  footnote says: "It is still an open question as to how Bob can source the 33 bytes per
  transaction in a trustless manner." Appendix A (Light Client Support) is "out of scope
  for the current BIP ... included to motivate further research". Neither passage
  mentions withholding, and both date from the first draft. Version 1.1.0 (2026-03-02)
  only added the per-group recipient limit `K_max`.
- **[Bitshala, "Silent Payments: A Technical Guide to BIP 352"](https://x.com/bitshala_org/status/2084131259375296785)**
  (3 Aug 2026): "A light client that accepts tweak data from a server has no way to detect
  omission."
- **[SomberNight, cake_wallet#2395](https://github.com/cake-tech/cake_wallet/issues/2395)**
  (Jul 2025): "what if the server lies by omission?" and "I presently do not see a way how
  to fix this while using cut-through."
- **[BIP-352 index-server specification](https://github.com/silent-payments/BIP0352-index-server-specification)**:
  "How does a wallet know all tweaks were received for a given block request?"
- **[SPCOMMIT](https://github.com/bitsagarob/silentpayments-measurements)**, by Rob
  Segers. Live on mainnet since 2026-09-01; specification and bitcoin-dev post on
  2026-09-02. [Bitcoin Optech #422](https://bitcoinops.org/en/newsletters/2026/09/11/)
  (2026-09-11) described it without the name. A flat hash chain over the unfiltered set,
  signed only as a kind-1 chain head every 6 hours. We found no wallet-side verifier.
- **[Certificate Transparency, RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)**: the
  split-view problem, which [The equivocation insight](#13-the-equivocation-insight)
  applies.
- **[Delving Bitcoin thread 891](https://delvingbitcoin.org/t/silent-payments-light-client-protocol/891)**
  (Jun 2024): the light-client discussion. harding's three attacks there are all
  commission, not omission.
