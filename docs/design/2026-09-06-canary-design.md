# Canary design document

| | |
|---|---|
| **Design** | Settled and approved 2026-09-08, after a spec review on 2026-09-07 and a self-review on 2026-09-08 |
| **Amended** | 2026-09-30, with the eight changes listed under [Amendments of 2026-09-30](#amendments-of-2026-09-30) |
| **Implementation** | Built and tested: `canonical`, `commit`, `feed`, `policy`, the test vectors, the `wire` tweak list with its receipts, the reference indexer, the state file, and the local dashboard, which runs today over sample data. The commands `canary check`, `canary verify`, `canary status` and `canary ui`, evidence files and the tripwire are still to build. v1 is due 5 Oct 2026 |
| **Exact formats** | [v1 formats](2026-09-30-v1-formats.md) gives the byte layouts of the response, the receipt, the evidence file and the state file. Where this document and the formats doc disagree, the formats doc wins |
| **Terms** | [Glossary](../glossary.md) |
| **History** | [Decision log](../decisions.md): why each rule is what it is, and what earlier drafts said |
| **Target** | BOSS Battle (Bitshala), 7 Sep to 5 Oct 2026, Cypherpunk track |
| **Team** | One person plus Claude, decided 2026-09-30. The original three-person split is in the decision log |

**Start here.** This document says why each rule exists. Read [Summary](#0-summary)
first, then [Canonical tweak sets](#2-canonical-tweak-sets-and-policy-normalization),
which the rest depends on. [v1 formats](2026-09-30-v1-formats.md) gives the exact bytes,
and [How Canary works](../how-canary-works.md) gives the whole system on one page.

This document uses the design's own names. Other docs and the screens use plainer ones:

| This document says | Other docs and screens say |
|---|---|
| commitment | signed record |
| leaf | entry, one `(txid, tweak)` pair |
| indexer | index server, or server |
| prevouts | the outputs a transaction spends |
| Verified, Resolved, Unresolvable, Unverified, Disputed, Compromised | Checked; Checked, gap filled; Can't be checked; Not checked; Servers disagree; Data withheld |

Section numbers stay in the headings because Go comments cite them.

## Amendments of 2026-09-30

On 30 Sep 2026 the user approved eight changes to the settled design. Every doc that
lists them uses this numbering.

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
6. **No daemon and no proxy in v1.** The v2 proxy targets BlindBit v1 clients. It refuses
   Compromised and Disputed blocks, and whether it refuses any others is an open v2
   decision ([Binaries](#61-binaries), [Proxy, not observer](#62-proxy-not-observer)).
   A server that signs commitments for neighbouring blocks but not for this one is no
   longer refused. v1 marks the block Unverified with a warning
   ([Comparison procedure](#25-comparison-procedure), step 0).
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
indexers. Detection is cheap and continuous. Attribution is expensive and on demand.

The full design puts Canary in the wallet's data path as a sidecar daemon. v1 is smaller:
a command-line checker and a reference indexer, with no daemon and no proxy
([Binaries](#61-binaries)).

The project has two layers, on purpose:

- **Tool first.** This layer works against indexers as they exist today, with nobody's
  cooperation. It takes the union of what they serve
  ([Union for tweaks](#43-union-for-tweaks-k-of-n-belongs-on-filters)). It reads each
  server's policy from its existing `/info` ([Policy declaration](#23-policy-declaration)).
  And it runs the [tripwire](#5-canary-tripwire), which detects *and* attributes without
  any server committing to anything.
- **Protocol second.** Signed commitments make detection cheap. Each server publishes a
  signed event of about 200 bytes per block, which carries the 32-byte root that clients
  actually compare. The alternative is N full fetches. Once the server also signs
  receipts ([Receipts](#38-receipts)), an accusation can be handed to others and the
  server cannot deny it.

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
(checked 2026-09-30). Canary's design adds the following, and v1 builds only part of it
([Binaries](#61-binaries)):

- a signed commitment for every block, which a client can fetch by block hash;
- a check in the client each time it fetches a block;
- commitments that still work when a server filters. The gaps become explicit and
  checkable against a signed root, though a filtered gap still cannot be proven
  legitimate;
- coverage states, portable evidence files and tripwires.

SPCOMMIT's v2 format also covers each transaction's output prefixes and the block's spent
outputs, which Canary v1 does not ([Limits of v1](#limits-of-v1)).
[Appendix A](#appendix-a-prior-art) lists the sources.

---

## 1. Scope and threat model

Canary protects a light wallet from an indexer that hides data. This section names the
attacks it catches and the ones it leaves out.

### 1.1 Actors

Canary assumes an honest client and trusts no single indexer or relay. It needs at least
one honest indexer publishing commitments and an uncensored path to a relay carrying them.
It also needs one chain fact from outside the indexers
([Chain agreement](#46-chain-agreement)).

| Actor | Description | Trust |
|---|---|---|
| **Client** | Light wallet holding a scan key, no full node | Honest (it is the victim) |
| **Indexers I₁…I_N** | Serve BIP-352 tweak data per block | Any may be malicious |
| **Relays** | Nostr relays distributing commitments | May censor or withhold |
| **Block source** | Independent source of a transaction and its prevouts, and of chain facts | Used during attribution, and as the chain anchor in [Chain agreement](#46-chain-agreement) where one is needed. It may be sampled or rotated |

### 1.2 Attacks in scope

Canary covers four ways an indexer can hide data from a client.

| Attack | Status today | With Canary |
|---|---|---|
| **Targeted omission.** Drop tweaks for one victim | Silent, permanent, no symptom | Detected when the client fetches the block ([Security claim](#14-security-claim)), except the two variants in [Limits of v1](#limits-of-v1) |
| **Blanket omission.** A truncated, stale, or dead-but-200 index | Looks exactly like "no payments" | Detected, and publicly visible |
| **Equivocation.** Serve the victim set X and the world set Y | Undetectable | Detected against the server's own signature |
| **Retroactive revision.** Rewrite history to cover tracks | Trivial | Defeated by published, signed, **append-only** events ([The commitment object](#33-the-commitment-object)) |

Blanket omission is not theoretical. `bitcoin.silentium.dev`, the public indexer named
in the light-client documentation, no longer serves the API. The domain redirects to an
unrelated parked page that returns **HTTP 200 with an identical 533-byte body for every
path**, including `/v1/block/850000/scalars`. A client pointed at it does not receive an
error. It receives a success response and no payments. (Verified 2026-09-06.)

**How an attacker targets a victim at all.** An indexer holding a victim's *published*
silent-payment address cannot tell which transactions pay them. Scanning requires
`input_hash · b_scan · A_sum`, and the indexer has only the tweak and
`B_scan = b_scan·G`. It needs the private scan key. BIP-352's privacy rests on this, and
it binds the indexer like anyone else.

Targeted omission therefore needs outside knowledge, which narrows the attacker to three
cases:

| Route | How the attacker knows | Assessment |
|---|---|---|
| **The attacker is the sender** | They paid the victim, so they know the txid exactly | The realistic case |
| **Blanket degradation targeted by identity** | They do not know which tweaks are the victim's. They drop a random fraction for that connection | Cheap, and needs no identification at all |
| **Outside leak** | Invoice, stated amount, timing correlation | Situational |

The first case is the motivating scenario and belongs in the README and the pitch:

> **The exchange that pays you is also the indexer that tells you whether you were paid.**

This is the default deployment for a light wallet, because the vendor runs the backend.
The counterparty holds a signed record showing it paid. The victim sees nothing, with no
error and no symptom. So the analysis makes the threat more concrete, not less. The
attacker who can identify a victim's payment is exactly the one who sent it, and blanket
degradation needs no identification whatsoever.

### 1.3 The equivocation insight

The requirement is not "compare N servers." It is: **the client must check the data it
was served against that server's own public commitment.** This binds a server to one
answer for all clients, which changes what each assumption buys:

| Assumption | Defeats | Why |
|---|---|---|
| **One** indexer, publishing commitments | Targeted omission | The server must either omit from everyone, or serve data contradicting its own signature. Omitting from everyone is public, affects all users, and anyone with a node can detect it. A hole inside the retention window counts as contradicting its signature ([Comparison procedure](#25-comparison-procedure)). Two variants escape: an entry served as a hash under a declared pruning or dust policy, and output data hidden while the entry is served ([Limits of v1](#limits-of-v1)) |
| **N** indexers, at least one honest | Blanket omission as well | The honest server's commitment differs, and divergence proves someone is lying |
| **All N** colluding | Only the tripwire | And only for payments the client already knows exist |

This is the split-view problem from
[Certificate Transparency (RFC 6962)](https://www.rfc-editor.org/rfc/rfc6962). CT's
answer is gossip between clients, and ours is a public relay. We cite it rather than
claim to have invented it.

### 1.4 Security claim

Canary makes one claim, under two conditions:

> Given at least one honest indexer publishing commitments, and an uncensored path to
> at least one relay carrying them, Canary converts omission from a silent, permanent
> failure into a detected event naming a server and a block.

Three qualifiers travel with the claim, so nobody has to extract them from it.

**Detection is not proof.** Two roots that disagree are signed by two different keys, so
anyone can check the equivocation. A *single* server's omission is `commitment ≠ what I
was served`, and HTTP responses carry no signature. So a third party can check it only
where the server signs receipts over its responses ([Receipts](#38-receipts)). Receipts
exist in the protocol layer, not in the tool layer. Against an unmodified indexer, the
victim knows and cannot prove it. Only the protocol layer stops a server from denying an
omission.

**Timing depends on the attack.** Blanket omission and equivocation are `committed ≠
canonical`. They show up in the always-on commitment feed through commitment tracking
([The ladder](#41-the-ladder)), within about one block interval. Targeted omission is
`served ≠ committed`. It shows up in the self-consistency check, which runs when the
client fetches the block it was lied about. For a wallet following the tip, that is also
about a block interval. For a rescan, it is whenever the rescan reaches that block, which
may be much later. Even then, a permanent silent failure becomes a named one attached to
a specific block, which is the claim that matters. It is not a *dated* one: the block
orders it, not Nostr's self-asserted `created_at`
([What we do not trust about Nostr](#35-what-we-do-not-trust-about-nostr)).

**The claim covers the tweak list, not payments.** Canary checks the `(txid, tweak)`
entries a server serves for a block. A wallet also decides from output data that Canary v1
does not commit to. So a server can serve the right entry and still hide the payment.
[Limits of v1](#limits-of-v1) lists this gap and two others.

### 1.5 Attacks explicitly out of scope

Canary does not claim to catch these.

- **Commission, or injection.** A malicious indexer inserts fake tweaks so the victim
  fetches a block and reveals their IP. These are the three attacks harding described on
  Delving Bitcoin in June 2024. The accepted answer is fetching blocks from random full
  nodes over short-lived Tor identities. Canary's k-of-N rule raises the bar as a side
  effect: it requires a tweak to appear in several independent commitments before the
  client acts on it. That is a note, not a claim.
- **Total collusion of all queried indexers.** It cannot be detected passively. The
  tripwire catches it only because the client has an independent way to know a payment
  exists: it sent that payment itself.
- **Network-level attacks,** such as eclipse attacks and TLS interception. Canary assumes
  the transport handles them.
- **A wallet that ignores the alarm.** Detection that nobody sees changes nothing. v1
  shows it only through `canary status` and `canary ui`. The v2 proxy closes this gap by
  refusing blocks ([Proxy, not observer](#62-proxy-not-observer)).
- **Output-side withholding, in v1.** A server can serve the correct entry and still hide
  the payment in the output data the wallet matches against. v1 does not detect this. v2
  plans to cover the filter and `outputs_short`, but not a false spent flag. The next
  subsection gives the detail.

#### Limits of v1

This subsection names what v1 does not check, so no claim about v1 reaches past it.

Canary v1 checks the tweak list a server serves for each block. **Verified, shown as
Checked, means the tweak list was checked. It never means payments were checked.** Three
limits follow. The README and the demo's last act state them too.

| Limit | What happens | Status in v1 |
|---|---|---|
| **Output-side withholding** | The server serves the correct `(txid, tweak)` entry. Then it leaves the payment's output out of the new-UTXO filter or the `/utxos` list, marks it spent, or drops its 8-byte prefix from BlindBit v2's `outputs_short`. Wallets on BlindBit v1 then skip the payment without an error | Not detected. Every check passes and the block reads Verified. The sender in [Attacks in scope](#12-attacks-in-scope) knows the output key it created, so this costs it no more than hiding the entry. v2 plans to add each transaction's taproot output keys to its entry. That covers the filter and `outputs_short`. A false spent flag stays outside any per-block commitment, because whether an output is spent depends on later blocks. It remains a limit after v2 |
| **Hash-only withholding under a declared policy** | A server declares a subtractive policy, such as pruning (`prunes_spent`) or a dust threshold. It serves the victim's entry as its 32-byte hash. The root recomputes and matches, the policy permits the gap, and the retention rule is met because the hash was kept | Passes the per-block check. The block reads *Checked, gap filled*: state `resolved`, reason `hash_retained`. The union ([Union for tweaks](#43-union-for-tweaks-k-of-n-belongs-on-filters)) still recovers the payment when any other server the client consults serves the entry in full. Otherwise nothing in the per-block check catches it. The tripwire can, for a payment the client made itself, when the local Core node shows one of its taproot outputs unspent. That finding is not provable to others ([Canary tripwire](#5-canary-tripwire)). An auditor holding the block can also catch it, by showing the policy did not permit the gap. For example, the transaction behind a hashed entry may still have an unspent taproot output at or above the declared dust threshold ([Policy declaration](#23-policy-declaration)). v1 reads policy from the unsigned `/info`. A server that declares no filtering and still sends a hash gets a warning with the reason `hash_without_policy`. It is never an accusation, because nothing the server signed declares its policy ([v1 formats](2026-09-30-v1-formats.md)) |
| **Regtest only** | v1 is built and tested on regtest only, against its own reference indexer | Nothing has been shown on signet or mainnet, or with an unmodified wallet in the path |

### 1.6 Non-goals

These are outside the project, on purpose.

1. **Canary does not make tweak sourcing trustless.** It makes it accountable. The README
   and the video state this early, before anyone has to ask.
2. Not a solution to commission attacks
   ([Attacks explicitly out of scope](#15-attacks-explicitly-out-of-scope)).
3. Not a scanning-performance project. Frigate solved cost in May 2026, and integrity is a
   separate question.
4. Not a new BIP-158 filter type, which would need work in Bitcoin Core.
5. Not a wallet. The wallet stays what it is, and Canary checks its data. blindbitd was
   archived on 2025-08-14. Today's realistic BlindBit v1 clients are blindbit-scan and
   Dana ([Proxy, not observer](#62-proxy-not-observer)).
6. Not mainnet-scale indexing in v1. v1 is built and tested on regtest only
   ([Limits of v1](#limits-of-v1)). Signet, with bounded block ranges, is the first
   public network after it.
7. Not a succinct (SNARK) proof of correct indexing. It is named as the last phase, not
   built.

---

## 2. Canonical tweak sets and policy normalization

A server commits to one policy-free list per block. Every honest server computes that
list the same way, whatever it chooses to serve.

### 2.1 The separation: committed set vs. served set

Servers commit to the full set and may serve any subset of it. This is the idea the rest
of the design rests on.

BIP-352's scanning rule explicitly permits cut-through:

> The transaction contains at least one BIP341 taproot output (note: spent transactions
> optionally can be skipped by only considering transactions with at least one unspent
> taproot output)

So the specification itself allows honest indexers to diverge. That is not a defect to
standardize away. Any design that requires all servers to serve identical sets is dead on
arrival.

Every real policy **only removes** tweaks: cut-through, dust filtering, unspent-only
indexing and a start height. None invents one. That asymmetry carries the section:

> **Served ⊆ Canonical.** A tweak served but not canonical is fabrication. A tweak
> canonical but not served requires a reason.

So Canary does not normalize served sets against each other. It defines one policy-free
set, requires the *commitment* to be over that set, and leaves the wire format free.

**Consequence for the indexer.** A participating server must compute the full canonical
set even for transactions it will discard at once. Index time is the only moment it holds
both the block and its prevouts. Storage policy stays free, and accountability does not.
This is the cost of adoption, and it must be stated plainly to any indexer asked to run
it.

### 2.2 The canonical set

The canonical set is a pure function of a block and its prevouts. No chain state after
the block, no thresholds and no configuration enter it. A transaction is included if and
only if all four rules hold:

1. It has at least one BIP-341 taproot output, **without** the optional "unspent" clause.
2. It has at least one input from *Inputs For Shared Secret Derivation*: P2TR, P2WPKH,
   P2SH-P2WPKH or P2PKH.
3. It spends no output with SegWit version > 1.
4. `A_sum` is not the point at infinity, and `input_hash` is a valid scalar.

The result is an ordered sequence of **(txid, tweak)** pairs in transaction-index order.
Older text writes the set as `T_base(block)`.

| Decision | Rejected alternative | Why |
|---|---|---|
| Transaction-index order | Lexicographic by tweak | It is free, because it is already the computation order. And position carries meaning: position *i* is a specific transaction, which is exactly what attribution ([Client verification ladder](#4-client-verification-ladder)) needs |
| Leaf is `(txid, tweak)` | Leaf is the bare 33-byte tweak | A bare tweak cannot be checked against anything. Anyone holding the transaction and its prevouts can recompute `(txid, tweak)`. A single eligibility disagreement then shows up as one txid, instead of shifting every later position. And "which transaction was hidden" is answered directly, not derived |

**Stated limitation.** A light client cannot compute the canonical set, because it needs
prevouts. The client checks consistency and agreement, never correctness against the
chain. Correctness needs a full node that computes the canonical set on its own and
compares roots. That is a separate **auditor** role
([Components, interfaces, ownership](#6-components-interfaces-ownership)).

### 2.3 Policy declaration

A server declares how its served lists fall short of the canonical set. Every field is
subtractive.

| Field | Meaning |
|---|---|
| `network` | Comparison is only meaningful within one network |
| `start_height` | Below this, absence is not evidence |
| `prunes_spent` | Drops transactions with no unspent taproot outputs |
| `dust_threshold_sat` | 0 = none. Drops transactions whose taproot outputs are all below it. **Declared, never verified.** See below |
| `dust_configurable` | The threshold is set per request. The client's own request parameter defines what it expects |

blindbit's cut-through and silentiumd's unspent-only indexing fold into a single
`prunes_spent` flag. They differ in *when* the drop happens, not in what a client sees.
Under [the separation](#21-the-separation-committed-set-vs-served-set), both commit to
the same canonical set, so the distinction has no visible consequence.

The declaration does three things:

1. **A server that declares a full index and shows any gap has contradicted itself.**
   That raises an alarm, purely local, with no second server and no escalation. This is
   the "one honest indexer" row of
   [The equivocation insight](#13-the-equivocation-insight), made mechanical.
2. **It stops the server from denying its excuse later.** "Dropped for cut-through" is
   available only if cut-through was declared before the block, publicly and signed.
3. **It bounds escalation.** The client knows in advance whose gaps need a second source.

**In v1, items 1 and 2 wait for a signed policy.** Both hold a server to a policy it
signed. v1 publishes no policy event, so `policy_ref` is 64 zeros and the policy comes
from the unsigned `/info`. A server can revise that at will. So when a server that
declares no filtering sends a position as a hash, v1 shows a warning with the reason
`hash_without_policy`, never an accusation
([v1 formats](2026-09-30-v1-formats.md)). A hole inside the retention window needs no
policy at all. It is still an omission ([Comparison procedure](#25-comparison-procedure),
step 1).

**`dust_threshold_sat` cannot be verified, and does not need to be.** The leaf is
`(txid, tweak)` and carries no output value ([Merkle tree](#32-merkle-tree)). So a client
holding a commitment can never confirm that a dust-justified gap was legitimate. That
reads like a hole and is not, because no verdict depends on the threshold. If a gap is
filled ([Comparison procedure](#25-comparison-procedure)), the root is recomputed and
matches, and *why* the server dropped the position stops mattering. If it is not filled,
there is no leaf to carry a value either, and the range is *unresolvable* whatever the
declaration says. **No verdict in the comparison procedure takes the threshold as an
input.**

The field survives for two jobs that are not verification. It routes effort: the
comparison procedure's tolerance decides how hard a client works, and a declared
threshold predicts which gaps are likely benign. And it creates a contradiction that
attribution *can* check, because an auditor holds the block and therefore the output
values. A server that declared 1,000 sat and dropped a 50,000-sat payment has
contradicted its own signed policy. Declaring in advance is what makes that catchable at
all.

**Rejected: putting the output value in the leaf.** It would make the threshold checkable
while filling gaps. It costs 8 bytes on every leaf, plus a rule for which of several
taproot outputs counts. It buys nothing. A filled gap needs no reason, and an unfilled
gap has no leaf to carry the value.

Retention is deliberately **not** a field here. [The wire model](#24-wire-model) makes a
144-block hash-retention window a protocol constant, because a server allowed to declare
its own window declares zero.

**Bridge to today's servers.** For the layer that works against indexers as they exist,
the policy struct comes from blindbit's existing `GET /info` feature flags. That is
unsigned and not per block, so a server can revise it after the fact, and it is strictly
weaker. It is also what lets the checker run against unmodified blindbit today. The
signed per-block policy is the protocol layer. This is where "tool first, protocol
second" ([Summary](#0-summary)) becomes concrete.

### 2.4 Wire model

A server's response lists every position of the canonical set, each as the full leaf,
its hash, or nothing. Inside a 144-block window it must keep at least the hash.

Per-leaf Merkle inclusion proofs were considered and rejected. Each proof is
`⌈log₂ n⌉ × 32` bytes, which is 352 bytes at `n ≈ 2000`. Proofs for all 2000 leaves come
to about 700 KB (2000 × 352 bytes), to go with a 132 KB list. `n ≈ 2000` is the order of
magnitude for a mainnet block. This document uses that figure throughout, including in
[Merkle tree](#32-merkle-tree).

Instead, the response is the canonical-order list in which each position is **the full
leaf, that leaf's 32-byte hash, or nothing**. The client hashes the full leaves, splices
in the supplied hashes, and recomputes the root in a single pass.

**The response is self-describing at length `n`.** The client must be able to tell which
of the three it is looking at for every position, without inference. The list must be
exactly `n` long, matching the commitment. A response that is merely *shorter* looks
exactly like a smaller block, and with a single server nothing cross-checks the
difference.

- Serving everything: 66 bytes per position, a 1-byte kind plus the 65-byte leaf, against
  33 for a bare tweak. The whole list is `4 + 66n` bytes, with a 4-byte count in front,
  so about 132 KB at `n ≈ 2000`. That is **roughly double today's response.** It is the
  honest cost and it is not avoidable. The txid has to be on the wire, because a light
  client does not know which transactions are in the set and so cannot supply it.
  Bandwidth doubles, and storage stays free ([Cost](#37-cost)).
- Serving a subset while keeping leaf hashes: 33 bytes per withheld position, the kind
  byte plus the hash. No logarithmic factor applies, and that one server's response can
  be checked on its own.
- Serving a subset with the hash discarded: 1 byte for that position, the kind alone. The
  block can be checked only once the leaf is recovered elsewhere. This is permitted only
  outside the retention window below.

[v1 formats](2026-09-30-v1-formats.md) gives the exact byte layout.

**Retention is required inside a 144-block window and optional beyond it.**

Retention is only an optimization, and that part is true. If the client can get a
missing leaf from *any* source, it hashes the candidate and recomputes the root. A match
proves the leaf is what the server committed to. The second source is never trusted,
because the first server's own signature does the work. So a kept hash is a convenience,
needed only when nobody can supply the leaf.

But *"nobody can supply the leaf"* is a state the server gets to choose, and without a
window it is free. Marking the victim's position as a hole would make the whole block
impossible to check. The [Decision log](../decisions.md) records the draft that allowed
this.

The window is the smallest fix that closes the hole, and it is nearly free. A transaction
can only be cut through once **all** its taproot outputs are spent, which at the chain
tip is close to empty. Servers keep hashes exactly where there is almost nothing to keep,
and prune freely in the deep history, where a rescanning client can reach another server.
The worst case is `W × n × 32` = 9.2 MB at `W` = 144 and `n ≈ 2000`. Reaching it would
require dropping every leaf for a day, and the realistic figure is a rounding error.

`W` is a **protocol constant, not a declared policy field.** A per-server field lets a
server declare zero and walk straight back into the hole.

[The comparison procedure](#25-comparison-procedure) enforces the window. Its step 1
treats a hole inside the window as an omission, measured against the tip the server signs
into its receipt.

Merkle proofs earn their place in the evidence artifact and in targeted queries, such as
"positions 3, 7, 11 without the block". They are not for the main path
([Merkle tree](#32-merkle-tree)). This section fixes only *what* is committed: the
ordered canonical leaf list and its length `n`.

### 2.5 Comparison procedure

This procedure turns one server's commitment and response for one block into a verdict.
It fills gaps before it recomputes the root, and it never calls a block clean whose root
was not recomputed.

The procedure is keyed on block **hash**, not height. That makes it safe across reorgs at
no cost, and it removes "it was a reorg" as an excuse.

Given block hash `B`, server `S`, declared policy `P`, published root `R`, response `D`.

**Step 0: does `S` commit at all?** There are three cases, and none of them is an
accusation in v1:

| `S` | Rule |
|---|---|
| Has never published a commitment, and claims none | Data is **Unverified** ([Coverage](#44-the-primary-output-is-coverage-not-alarms)). It is accepted, and it feeds the union ([Union for tweaks](#43-union-for-tweaks-k-of-n-belongs-on-filters)). But it is never *clean*, and only the [tripwire](#5-canary-tripwire) can catch this server lying |
| Has published commitments for neighbouring blocks, but none for `B` | **Unverified, with a warning.** Selective non-publication *is* the attack: commit to every block except the one you lied about. v1 marks the block Unverified with the reason `no_record_for_block` ([v1 formats](2026-09-30-v1-formats.md)) and does not accuse. A missing commitment is not a signed statement, so no file can show it to anyone else. Whether the v2 proxy refuses such a block is a v2 decision ([Proxy, not observer](#62-proxy-not-observer)) |
| Published a commitment for `B` | Continue |

Refusing every block without a commitment would refuse all data from unmodified
blindbit. That contradicts the tool-first layer ([Summary](#0-summary)), the *Unverified*
state and `start_height`. So a server is expected to have a commitment for `B` because
it published one for a neighbouring block, not because it advertises that it might.
**Evidence, not advertisement.**

v1 warns on the middle row and refuses nothing. Every refusal belongs to the v2 proxy,
which refuses Compromised and Disputed blocks. This weakens one argument in
[Chain agreement](#46-chain-agreement), which says what replaces it.

Then, for a server that did commit:

1. **Gap set `G`** = the positions `S` did not return in full. Each is a hash or a hole.
   **A hole inside the retention window is an omission.** The block's depth is the tip
   height `S` signed into its receipt ([Receipts](#38-receipts)) minus the block height
   in `S`'s signed commitment. If the block is fewer than 144 blocks below that tip,
   [the wire model](#24-wire-model) required `S` to keep at least the entry's hash. The
   hole is then *Omission detected*, named against `S`, whatever the later steps find.
2. **Fill `G`.** Recover the missing leaves: from `S`'s kept hashes where it kept them
   ([Wire model](#24-wire-model)), otherwise from another server. If any position is
   still unfilled and step 1 found no omission, the block is *unresolvable* and there is
   no verdict. **This runs before the root is recomputed, not after.**
3. **Recompute the root** over all `n` positions. A mismatch means `S` served data that
   contradicts its own signature. That is proven from `S` alone, and `S` cannot deny it.
4. If `P` declares no subtraction and `G ≠ ∅`, raise an alarm. It is local and
   immediate. This step needs a signed `P`, so it belongs to the protocol layer. v1's
   policy is unsigned. So in v1, a hash from a server that declares no filtering gives a
   warning with the reason `hash_without_policy`, never an accusation
   ([Policy declaration](#23-policy-declaration)).
5. **Cross-check** `R` against other servers' roots for the same `B`. Equal roots mean
   all committed to the same set. Unequal roots mean at least one is lying, and the
   client escalates to attribution ([Client verification ladder](#4-client-verification-ladder)).

Steps 0 to 4 need a single server. Step 5 costs 32 bytes per block per server, as a
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
  the window, they settle the question with no outside chain fact. An honest server
  never signs a tip and a height that convict it. The client needs a chain fact
  only to reject a gap that the signed values place outside the window
  ([Chain agreement](#46-chain-agreement)).
- **A hash is not a hole.** A server may declare a subtractive policy, pruning or a dust
  threshold, and return the entry's hash. That satisfies the rule. The root recomputes
  and matches, so the per-block check passes and the block reads *Checked, gap filled*
  (reason `hash_retained`). The union still recovers the payment if another consulted
  server serves the entry in full. Otherwise nothing in the per-block check catches this
  variant. The tripwire can, and so can an auditor holding the block, who can show the
  policy did not permit the gap ([Limits of v1](#limits-of-v1)). A server that declares no
  filtering and sends a hash gets the warning from step 4.

[v1 formats](2026-09-30-v1-formats.md) pins the exact boundary of the window.

**Fill before recomputing. The design depends on this order.** Suppose the root were
recomputed first and gaps filled last. A position returned as a hole would make the root
uncomputable, so the block would silently never be checked. Without the retention rule,
step 3 would be the only check on targeted omission
([Security claim](#14-security-claim)). A server could then skip it for free, forever, by
sending one hole. That is exactly the attack this section exists to catch. **A block
whose root has not been recomputed is not clean. It has no verdict yet.** The retention
rule in step 1 catches a hole inside the window whatever the order, and names the server
before any root is recomputed. Outside the window, this order is what keeps a hole from
reading as clean. The rule never makes a block clean, and the client still fills the gap
and recomputes the root when it can.

**Three terminal states, not two:**

| State | Meaning |
|---|---|
| **Clean** | The root recomputed over all `n` positions and matched |
| **Omission detected** | A named server and block, backed by the server's signature. The finding names the transaction only when its entry was recovered. Otherwise it names the server, the block and the position. It is reached when the recomputed root does not match `S`'s signed root, or when step 1 finds a hole inside the retention window. The tripwire reaches it too ([Canary tripwire](#5-canary-tripwire)). Coverage shows it as **Compromised**, labelled *Data withheld* on screen |
| **Unresolvable** | The root could not be recomputed. The usual cause is a gap outside the retention window that nobody can fill. [v1 formats](2026-09-30-v1-formats.md) lists the others, such as a list the server never served. It is not an accusation, and it must not be reported as one. It is not a pass either. On screen it reads *Can't be checked* |

**Tolerance depends on the client's mode, and it governs effort and reporting, never
verification.** A transaction can only be cut through once all its taproot outputs are
spent, which at the chain tip is nearly empty. And a spent output is one the client
either spent itself or never owned. Rescanning from a seed is where the light-client
specification already admits payments go missing. So a tip-following client spends less
effort chasing a gap and reports it more quietly, and a rescanning client escalates.
**Neither may skip step 3.** A tip-following client must not simply accept cut-through
gaps, because with a hashless gap that waves the attack through. An unfilled gap outside
the retention window is *unresolvable*. Inside the window, a hole is an omission
(step 1). Whether the v2 proxy refuses unresolvable blocks is still open
([Proxy, not observer](#62-proxy-not-observer)).

### 2.6 What this fixes for the team

The canonical set gives every component one interface and every test one target list.

The interface frozen on day 2 ([Packages and frozen interfaces](#63-packages-and-frozen-interfaces)):

```go
func Set(net Network, blk *wire.MsgBlock, pv PrevoutSource) ([]Leaf, error)
```

The indexer commits to it, the checker compares against it, and the differential suite
tests it ([Testing](#7-testing-with-a-differential-edge-case-suite)).

This section also generates the test suite's target list. Each item below is a place
where two correct implementations could disagree on the canonical set. Each can be built
**on regtest**, because public signet cannot be mined on demand
([Regtest, not signet](#72-regtest-not-signet)):

- NUMS point *H* detection via control-block parsing
- Malleated P2PKH `scriptSig` parsing. The BIP *requires* parsing non-template
  scriptSigs
- Uncompressed and hybrid public key rejection
- `outpoint_L` serialization and endianness
- SegWit version > 1 input exclusion
- Coinbase transactions
- `A_sum` at the point at infinity

### 2.7 Preconditions

The claim that all legitimate policy is subtractive holds under two conditions, stated
here instead of assumed:

1. Both servers are indexing the **same network**.
2. Comparison is keyed on **block hash**, not height.

## 3. Commitment format and Nostr transport

[Canonical tweak sets](#2-canonical-tweak-sets-and-policy-normalization) settled *what*
is committed: the ordered canonical leaf list and its length `n`, keyed on block hash.
This section settles *how*: the hash construction, the Nostr event, how it travels, and
the receipt that pairs with it.

### 3.1 Two independent checks

The format has to make two checks cheap, because neither covers the other.

| Check | Catches | Requires |
|---|---|---|
| **Self-consistency.** Served data recomputes to the published root | *served ≠ committed* | One server |
| **Cross-check.** Roots agree across servers for the same block hash | *committed ≠ canonical* | Two servers, at least one honest |

A server that lies about `n`, by cutting out a position and renumbering, passes
self-consistency and fails the cross-check. A server that commits honestly and then
serves a subset fails self-consistency. The design needs both checks.

### 3.2 Merkle tree

The root is a tagged-hash Merkle tree over the leaves, bound to the network, the block
hash and `n`.

[The wire model](#24-wire-model) removed inclusion proofs from the main path, and that
stands. The tree earns its place elsewhere: **the evidence artifact**
([Evidence artifact](#47-evidence-artifact)). When Canary fires, its output is a small
self-contained object that says three things:

- *server S signed root R for block B;*
- *leaf L is in R, and here is the proof;*
- *S's signed receipt shows a response with a hole where L belongs, while B was inside
  the retention window.*

Proving leaf membership from a flat hash needs all `n` leaf hashes, roughly 64 KB at
mainnet scale. With a tree it is about 350 bytes. That is the difference between an
artifact someone reads and an attachment they do not.

| Element | Construction |
|---|---|
| Leaf | `TaggedHash("canary/leaf/v1", txid ‖ tweak)`, over 32 + 33 bytes |
| Internal node | `TaggedHash("canary/node/v1", left ‖ right)` |
| Odd node | **Promoted, never duplicated** |
| Single leaf (`n = 1`) | `merkle_root` is that leaf's hash, with promotion applied zero times |
| Empty set (`n = 0`) | `merkle_root` is 32 zero bytes. The outer root is computed over it unchanged |
| Root | `TaggedHash("canary/root/v1", network ‖ block_hash ‖ n_le32 ‖ merkle_root)` |

**The empty set is committed, not skipped.** `n = 0` is the common case, not a corner.
Most regtest blocks and many signet blocks hold no eligible transaction at all, and the
example vector in [Vector format](#74-vector-format) is one. Defining `merkle_root(∅)` as
32 zero bytes avoids inventing a fourth tag. It is safe because `n` is already bound into
the outer preimage, so an `n = 0` root cannot collide with any `n ≥ 1` root for the same
block. A server with nothing to commit still publishes. Skipping would hand back the
excuse that [Comparison procedure](#25-comparison-procedure) step 0 exists to remove,
now worded *"no commitment, because there was nothing to commit."* An `n = 0` commitment
is a real assertion and a checkable one: the client recomputes the canonical set from the
block and confirms it is empty.

Duplicating an unpaired last node is CVE-2012-2459, Bitcoin's own Merkle vulnerability.
Promotion avoids it, and distinct leaf and node tags make second-preimage substitution
impossible regardless. Binding `network`, `block_hash` and `n` inside the root means a
root cannot be replayed onto another block or reused with a different length.

**Preimage encodings, pinned here on purpose.** Every field is fixed-width, so the
concatenations need no length prefixes. An unpinned field in a hash preimage breaks
interoperability, and the break looks like an attack.

| Field | Encoding |
|---|---|
| `txid` (leaf) | 32 bytes, **internal byte order**: as it appears in the transaction serialization, not the display-reversed hex |
| `tweak` (leaf) | 33 bytes, compressed SEC |
| `network` | 4 bytes: the network's P2P message-start bytes in the order they appear in a message header, that is, the little-endian encoding of btcd's `wire.BitcoinNet` |
| `block_hash` | 32 bytes, **internal byte order**, the same rule as `txid` |
| `n_le32` | 4 bytes, unsigned little-endian |
| `merkle_root` | 32 bytes: the tree root, before the outer tagged hash |

`txid` and `block_hash` are the trap. Two implementations that disagree on byte order
produce entirely different roots for identical data.

`network` is the message-start magic, not an enum of our own, for one reason. BIP-325
derives a custom signet's magic from its challenge, so two different signets get two
different values. The first [precondition](#27-preconditions) is that both servers index
the same network, and a private enum would erase exactly that distinction. The
implementation reads the value from `chaincfg.Params.Net`, never from a literal. For
reference: main `f9beb4d9`, default signet `0a03cf40`, regtest `fabfb5da`. The regtest
vectors ([Vector format](#74-vector-format)) pin the real value in CI, so a wrong
constant fails a test instead of silently giving different roots.

### 3.3 The commitment object

A commitment is one regular-kind Nostr event per block per server, queried by block hash.

| Field | Notes |
|---|---|
| `network` | The 4-byte network magic from [the Merkle tree section](#32-merkle-tree), written in the event tag as a decimal number: btcd's `wire.BitcoinNet` value. Regtest's message-start bytes `fabfb5da` are the value `0xdab5bffa`, written `3669344250`. The root binds the same value, which keeps two custom signets apart. A display name would merge them. `FromEvent` reads the network back from this tag |
| `block_hash` | The authoritative key |
| `block_height` | Not the key; the block hash is. The retention rule in [the comparison procedure](#25-comparison-procedure) reads it, so a wrong height is a signed false statement |
| `n` | Canonical set size |
| `root` | As defined in [Merkle tree](#32-merkle-tree) |
| `policy_ref` | **Event id** of the policy declaration ([Policy declaration](#23-policy-declaration)) in force |
| signer | Implicit: the Nostr pubkey |

`policy_ref` binds by event id, not by inlining the policy. Policy changes rarely, and
binding by id means *"when did you declare cut-through?"* has an answer the server
cannot revise.

**This forces a Nostr rule: nothing in the trust path may use a replaceable event kind.**
Without it, a server could deny its own statements. Replaceable kinds (10000–19999) and
parameterized replaceable kinds (30000–39999) are overwritten in place. So a server could
publish a cut-through declaration *after* using it as cover, and the original would be
gone from relays. Policy events and commitment events are both **regular kinds, so they
are append-only**.

Proposed kind **1352**, chosen as a mnemonic. The regular range is 1000–9999. Check it
against the kind registry before shipping; nobody asserts that it is unclaimed.

**NIP-01 forces the tag names.** A relay indexes only **single-letter** tag names, and a
filter can query only those. A `block_hash` tag would be stored and signed, and no
filter could query it. Then `Feed.Get`
([Packages and frozen interfaces](#63-packages-and-frozen-interfaces)) could not work
against any real relay. So the block hash goes in a single-letter tag, and every other
tag is carried for readers, not for filters:

| Tag | Contents | Indexed |
|---|---|---|
| `b` | Block hash, display hex | **Yes.** This is the query key |
| `height`, `n`, `network`, `policy_ref` | As named. `network` holds the decimal magic described above. v1 publishes no policy event, so its `policy_ref` is 64 zeros | No |
| `root` | The root, hex. It must equal the event's content | No |

A fetch is `{"kinds":[1352], "authors":[<pk>], "#b":[<hash>, ...]}`. **There is no range
query.** Tag filters have no range or ordering operators. `since` and `until` act on
`created_at`, which Canary does not trust
([What we do not trust about Nostr](#35-what-we-do-not-trust-about-nostr)). So a client
covering a range of blocks batches the block hashes it already knows into one filter,
split to the relay's limit. That is why `Feed.Get` takes a slice, not a single hash.

Content carries the root. A Nostr event id hashes the tags as well as the content, so the
signature covers all of it and no separate signed blob is needed. The root appears in
both a tag and the content on purpose, because any inconsistency between them is itself
detectable.

### 3.4 Two channels, two jobs

A commitment travels two ways: pulled from the indexer, and published to relays.

[Comparison procedure](#25-comparison-procedure) step 0 warns about a server that commits
to neighbouring blocks but not to this one. If commitments came only from relays, that
warning would hand a veto to whoever controls the relay. Censoring a committing server's
events would make it look like a server that skipped this block, and its data would fall
back to Unverified. So the commitment travels two ways, and they do different jobs.

| Channel | Job | On failure |
|---|---|---|
| **Pull from the indexer:** `GET /commitment/:blockhash` returns the signed event | Gives the client a signed statement, which the server cannot deny, from the party it is already talking to | A server that refuses to sign is refusing accountability. Its blocks read Unverified, with a warning where it signed their neighbours |
| **Subscribe via relays** | Makes the statement *public*, which is what enables equivocation detection | Relay censorship removes the public record, not the client's evidence |

So a client cut off with a single malicious server still extracts a signature it can show
later, to anyone, whenever it reaches them. The privacy argument rests on the relay
subscription. The client pulls *all* commitments from its configured indexers and never
reveals which block it cares about.

### 3.5 What we do not trust about Nostr

Canary uses Nostr for publication and trusts nothing else about it.

- **`created_at`.** The author sets it and can backdate it. Order comes from the block
  hash. Nostr gives *publication*, not timestamping, and Canary does not claim otherwise.
- **Relay honesty.** A relay may drop events, delay them, or show different clients
  different views. Servers publish to several relays and clients subscribe to several. A
  client that sees a server's events on no relay while others do has learned something.
- **Relay independence.** An indexer can operate its own relay. The client chooses its
  relays in its own configuration and never inherits them from the indexer.

### 3.6 Identity

The client pins each indexer's key by hand, and never learns it from the indexer.

Client configuration is a set of `(indexer_url, indexer_nostr_pubkey)` pairs, **pinned
manually**. There is no discovery, no web of trust, and no trust on first use by default.
An indexer's `/info` may advertise its npub as a convenience. But trusting that on first
contact hands the key to anyone able to intercept a single request. Manual pinning is the
honest scope for v1, and the design states it as a limitation.

### 3.7 Cost

Commitments cost an indexer 36 bytes per block to keep, about 35 MB for all of mainnet.

| Party | Cost |
|---|---|
| Indexer | One signature and ~200 bytes per block. Retained state: 36 bytes per block, a 32-byte root plus `n`. That is **about 35 MB for all of mainnet history** (≈965k blocks × 36 B). Add the 144-block hash window from [Wire model](#24-wire-model), bounded by 9.2 MB and near zero in practice |
| Client | One relay subscription filtered by author, and 32 bytes per block per server to compare |
| Relay | ~144 events per day per indexer |

The prune-freely property now states cleanly: **commit at index time, discard at will
once a leaf is 144 blocks old.** That means its block sits 144 or more blocks below the
server's signed tip ([Wire model](#24-wire-model)). The server holds the block and its
prevouts exactly once. It computes the canonical set, signs and publishes. It then stays
accountable for what it dropped, forever, at 36 bytes per block.

The arithmetic is written out because this table is the pitch to indexers
([The separation](#21-the-separation-committed-set-vs-served-set)). The first thing a
skeptical indexer does is recompute it. 35 MB is a rounding error next to an unpruned
node. A number that does not survive that check costs more credibility than it was meant
to buy. The [Decision log](../decisions.md) records the wrong figure an earlier draft
gave.

### 3.8 Receipts

A receipt is the server's signature over one response, so the response itself becomes
evidence.

The commitment alone is not enough:

| Statement | Provable to a third party? |
|---|---|
| S signed root R containing leaf L | Yes, signed |
| S's policy forbids pruning | Yes, signed |
| S's root differs from S′'s for the same block | Yes, both signed |
| **S served me a set omitting L** | **No. HTTP responses are not signed** |

Without receipts, anyone can check equivocation between two servers, but only the victim
can know about a single server's omission. That is much weaker than the
[security claim](#14-security-claim) implies.

So the server signs a **receipt** for every response. A Schnorr signature costs
microseconds, and the design already assumes the server cooperates for commitments.

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
*detected*, so the victim knows, but a third party cannot check it. That is a concrete
reason to push for the protocol layer.

## 4. Client verification ladder

Some client checks run all the time and some run on demand. This section orders them and
says how each result reaches a wallet that has to act on it.
[The comparison procedure](#25-comparison-procedure) gave the per-block comparison, and
[Commitment format and Nostr transport](#3-commitment-format-and-nostr-transport) gave
the object being compared.

### 4.1 The ladder

The client runs four checks, ordered by cost. The design calls the ordered list a ladder.

| Check | Trigger | Catches | Cost |
|---|---|---|---|
| **1. Commitment tracking** | Always on | Root divergence between servers, and chain contradiction: a height still contested six blocks later ([Chain agreement](#46-chain-agreement)) | One relay subscription; ~144 events/day/server |
| **2. Self-consistency** | Client fetches block *B* | Served ≠ committed. A policy contradiction, only a warning in v1 because v1 policies are unsigned. A hole inside the retention window ([Comparison procedure](#25-comparison-procedure), step 1) | Hashing `n` leaves. Microseconds |
| **3. Gap filling** | The self-consistency check found gaps, **before it can finish** | Whether a permitted gap is real | One targeted request |
| **4. Attribution** | Commitment tracking found divergence | *Which* server lied, and about what | Needs prevouts, so it is the expensive check |

**Gap filling runs inside the self-consistency check, not after it.** This is the one
place where reading the table top to bottom misleads.
[The comparison procedure](#25-comparison-procedure) fills gaps *before* the root is
recomputed, and the recomputation is what the self-consistency check actually catches. A
gap nobody can fill leaves the root uncomputed and the block *unresolvable*, never clean.
Building the two as strictly sequential stages rebuilds the hole the comparison procedure
closed. That is why the comparison procedure says the design depends on this order.

Commitment tracking runs for blocks the client has not scanned, and while the client is
idle. **Detection is separate from scanning**, so evidence builds up continuously and an
alarm can fire before the user opens the wallet.

### 4.2 Detection needs no node; attribution does, and may be deferred

A light client can detect a problem on its own, and can hand attribution to someone with
a node later.

Attribution here means deciding which of two disagreeing servers lied. A server that
contradicts its own signatures needs no attribution, because its own statements name it.
An in-window hole needs no outside chain fact either. The server signed both its tip and
the block's height, and those two values put the block inside the window. The client
needs a chain fact only to reject a gap that the signed values place outside the window
([Comparison procedure](#25-comparison-procedure)).

Attribution needs prevouts, so a full node or a third-party API. This does not force a
node onto the wallet, for two reasons.

**The privacy cost is near zero.** The servers choose the disputed transaction set, not
the user. It is whatever two indexers publicly disagreed about. Querying those txids
reveals interest in a public dispute, not in the user's payments.

**Attribution is not urgent.** Two signed roots cannot be denied and do not decay. A
client with no node records the evidence and hands the verdict to anyone who has one,
later or never.

> **A light client detects. An auditor attributes.**

### 4.3 Union for tweaks; k-of-N belongs on filters

The client scans every tweak any server committed to, and saves any k-of-N rule for
filters.

The tension between omission and commission from
[Scope and threat model](#1-scope-and-threat-model) shows up here as a direct conflict.
Omission wants the **union** across servers, and commission wants the **intersection**.
They act at different stages, which resolves it.

- Computing candidate outputs from tweaks is local and free: one EC multiplication, no
  network. So take the **union (1-of-N)**. A tweak in *any* server's committed set is
  scanned. This is what defeats omission, at no privacy cost.
- The leak is in fetching block data, which happens on a *filter* match. Whoever controls
  filter distribution can force a match. So a k-of-N rule belongs on **filters**, not
  tweaks.

v1 does not commit to filters, so that k-of-N rule is an unverified best effort. It is a
note, not a claim ([Attacks explicitly out of scope](#15-attacks-explicitly-out-of-scope)).

**The same gap matters for omission, and the union does not close it.** The union
assumes that once a tweak is scanned, the server answers honestly about the outputs: the
filter, the UTXO list and `outputs_short`. A server can hide a payment there as silently
as in the tweak list. A wallet on BlindBit v1 skips a block without error when the served
filter does not match. v1 does not check this ([Limits of v1](#limits-of-v1)).

The construction extends to part of the output data. Adding each transaction's taproot
output keys to its entry keeps Served ⊆ Canonical, because the keys come from the block
alone. Committed output keys cover the new-UTXO filter and `outputs_short`. v2 plans this
change. A false spent flag in `/utxos` stays outside it. Whether an output is spent
depends on later blocks, so the flag cannot enter a per-block canonical set, and it
remains a named limit after v2.

### 4.4 The primary output is coverage, not alarms

Canary reports a state for every block range it looked at. It does not only raise alarms.

An alarm that never fires looks like a product that does nothing. The checks produce
something continuous and visible instead: **per-block-range scan coverage.**

| Coverage state | Code and on-screen label | Meaning |
|---|---|---|
| **Verified** | `verified`, *Checked* | The recomputed root matched the signed root, with no gap to fill. It is qualified by *how*. **By cross-check**: another server's root agreed. **By tripwire**: a planted assertion came back ([Coverage integration and cost](#54-coverage-integration-and-cost)). **By own record**: one server's served list matches its own signature, and nothing checks that the record itself is complete. Under total collusion only the tripwire form says anything about completeness. It means the tweak list was checked, never that payments were ([Limits of v1](#limits-of-v1)). [v1 formats](2026-09-30-v1-formats.md) gives the reason codes |
| **Resolved** | `resolved`, *Checked, gap filled* | Some positions came as hashes or had to be filled before the root was recomputed, and then the root matched. For example, another server supplied an entry, or the client computed it from a payment it declared |
| **Unresolvable** | `unresolvable`, *Can't be checked* | The client could not recompute the root, so there is no verdict. The usual cause is a gap outside the retention window that nobody can fill ([Comparison procedure](#25-comparison-procedure)). It is neither a pass nor an accusation |
| **Unverified** | `unverified`, *Not checked* | There is no signed record to check against. For example, the server signs nothing, has not indexed the block yet, or did not answer. The data is still used, and it feeds the union ([Union for tweaks](#43-union-for-tweaks-k-of-n-belongs-on-filters)), but nothing about it is checked ([Comparison procedure](#25-comparison-procedure), step 0) |
| **Disputed** | `disputed`, *Servers disagree* | Roots diverge. Two named servers, one of them lying, not yet attributed ([Acting on alarms](#45-acting-on-alarms)) |
| **Compromised** | `compromised`, *Data withheld* | Attributed. One named server, one named block |

*Disputed* and *Compromised* are separate states because
[Acting on alarms](#45-acting-on-alarms) keeps them separate. Root divergence names two
servers without saying which lied. Collapsing that into a single alarm is exactly how an
attacker gets an honest server excluded.

**Mapping from the comparison procedure.** The comparison procedure returns three
terminal states for one `(server, block)`. Coverage aggregates them across ranges and
adds two that comparison never produces. *Clean* becomes **Verified** where no gap
existed and **Resolved** where one was filled. *Unresolvable* carries across unchanged.
*Omission detected* becomes **Compromised**. **Unverified** comes from step 0 and
**Disputed** from step 5, and neither is a terminal state of the per-block procedure.
Both step 0 cases that stop before comparison map to **Unverified**. Where the server
signed commitments for neighbouring blocks but not this one, the block also carries a
warning, the reason `no_record_for_block` in [v1 formats](2026-09-30-v1-formats.md). v1
does not accuse on it.

That determines what the wallet displays:

> **A balance computed over blocks that could not be verified is a lower bound, not a
> balance.**

A wallet with unresolvable ranges says so, instead of printing a confident number.

**How coverage reaches the user.** There are two paths, and only one of them works for a
wallet that does not know Canary exists:

| Consumer | Mechanism |
|---|---|
| A Canary-aware wallet, or `canary status` and `canary ui` | Reads the coverage state and displays it. In v1 this is the only path |
| **Unmodified wallet** | It cannot display what it cannot see. Enforcement is the v2 proxy ([Proxy, not observer](#62-proxy-not-observer)), which **refuses Compromised and Disputed blocks**, so the wallet never receives a balance built on them |

The refusal, not the display, answers "a wallet that ignores the alarm"
([Attacks explicitly out of scope](#15-attacks-explicitly-out-of-scope)). Coverage is not
always on screen. For an unmodified wallet it lives in `canary status`, a log the wallet
never reads ([Proxy, not observer](#62-proxy-not-observer)). v1 has no proxy, so v1 does
not close this gap. The proxy does not refuse *unverified* data either. That rule would
refuse every block from today's servers, which publish no commitments.

### 4.5 Acting on alarms

An alarm names a server and a block. Only a server that contradicts its own signatures is
safe to act against automatically, and then only by down-ranking it. Root divergence
never triggers automatic action. v1 records every alarm as a finding and excludes no
server.

An alarm is a fact about a server and a block, and v1 records it as a finding. Canary
keys each finding by the entry's position when it knows the position, and by the txid
otherwise. Keying on the position keeps one id when a later run recovers an entry that an
earlier run could not. Canary keeps findings and copies them forward from run to run.

It drops a finding automatically in one case only: the local Core node no longer has the
block's header, as when a regtest chain is wiped and mined again. A reorg does not drop a
finding, because Core keeps the headers of blocks that left its best chain. Evidence
files stay on disk either way. [v1 formats](2026-09-30-v1-formats.md) gives the exact id.

**Excluding a misbehaving server automatically is itself a way to attack.** If a third
party can induce the detection, it can knock out honest servers and leave the victim
with the attacker's. So the two alarm types get different treatment:

| Alarm | Attributable? | Automatic action |
|---|---|---|
| Self-consistency failure | Yes: S's own signature against S's own data | Safe to down-rank automatically |
| Root divergence | No: it names two servers without saying which lied | **None** until attribution settles it |

This asymmetry is why attribution is a separate check, not an action taken directly on
divergence.

### 4.6 Chain agreement

Canary does not assume a chain before it compares. It reports chain disagreement the same
way it reports other disagreement, and it needs one chain fact from outside the indexers.

Two servers committing to different block hashes at the same height are on different
chain tips. That is a fork, not an omission. Reporting it as one would be the loudest
possible false positive.

Standard SPV does not work where Canary runs. SPV keeps a header chain, 80 bytes per
block, and trusts the one with the most proof-of-work. Signet is the first public network
Canary targets ([Non-goals](#16-non-goals)). v1 itself is built and tested on regtest
only, which is local and trusted by construction (table below). A BIP-325 signet gets
its integrity from a challenge signature in the coinbase, not from accumulated work.
Difficulty is trivial, and a laptop can outrun the real chain. A client trusting
most-work on signet can be handed a chain in which the disputed block does not exist.
That turns a real omission into "reorg" and defeats step 2 of
[What a negative result proves](#53-what-a-negative-result-proves). Asserting a security
property that does not hold is worse than asserting none, because a reader builds on it.

| Network | Chain integrity from |
|---|---|
| mainnet | Accumulated proof-of-work. Standard SPV, and it works |
| **signet** | The BIP-325 challenge signature in the coinbase. **Not** work |
| regtest | Nothing. Single-operator and local, so it is trusted by construction ([Regtest, not signet](#72-regtest-not-signet)) |

**How much depends on this, precisely.** Less than it first looks.
[The comparison procedure](#25-comparison-procedure) keys comparison on block *hash*. So
two servers arguing about the contents of hash `B` cannot reach for the reorg excuse,
because they are talking about the same block by construction. What is exposed is
*chain membership*: whether `B` is in the chain at all. That matters in two places, step
2 of [What a negative result proves](#53-what-a-negative-result-proves) and the coverage
ranges in [Coverage](#44-the-primary-output-is-coverage-not-alarms), and nowhere else.

#### Chain agreement is an output, not an input

The chain is not a dependency Canary needs before it can compare. It is the same problem
Canary already solves. Several parties assert something, they can disagree, and the
disagreement is either transient or permanent. **Reorgs resolve. Lies persist.**

A server following a fabricated chain has to sign commitments for it if it wants its
blocks checked. The client pulls a signed commitment from the server for every block it
fetches ([Two channels, two jobs](#34-two-channels-two-jobs)). A server that declines
leaves those blocks Unverified, with the warning from
[Comparison procedure](#25-comparison-procedure) step 0 where it signed their
neighbours. Neither outcome is a pass.
[The commitment object](#33-the-commitment-object) uses append-only kinds, so a server
cannot withdraw a commitment once published. A fabrication that the server does sign
lands in the public feed, keyed by height and hash. A height where two servers name
different hashes is **contested**. Contested and transient is a reorg, and Canary ignores
it. Contested past six confirmations is a signed statement about the chain contradicted
by another signed statement. That is a heavier accusation than omission. It costs
nothing new to detect, because the commitment already carries both the height and the
hash.

This argument has a gap in v1, because v1 refuses nothing. A server can decline to sign
for the fabricated blocks. They then read Unverified, not checked, but the fabrication
also stays out of the public feed, where convergence would catch it. For those blocks
only the anchor below helps. The [Decision log](../decisions.md) records the stronger
argument this replaced.

It also puts chain-contradiction detection at roughly six block intervals, not one. That
fits the [security claim](#14-security-claim): timing depends on the attack.

#### The anchor, for when convergence is unavailable

Convergence needs two servers. With one server, or under total collusion, chain
membership cannot be derived from the indexer set at all. The attacker controls every
input and can simulate any world. That follows from what the client can know, not from
a design flaw. The honest response is to name the outside fact Canary needs, instead of
pretending it needs none:

> **Canary needs one chain fact it did not learn from an indexer.**

There are three ways to supply it, and v1 takes the first:

| Source | Cost | Trust required |
|---|---|---|
| **The user's own Core node**, where one is configured | Free. blindbit-oracle already requires Core v30+, so anyone running the full stack has one | None. It is their node |
| **A manually pinned recent `(height, hash)`** | Free | The pin, obtained out of band. It follows the model [Identity](#36-identity) already chose for indexer keys, stated as a limitation |
| **BIP-325 signet solution validation** | Two to three days, and it needs every txid in the block | **None at all**, which is the point |

v1's `canary check` requires `--core-rest`, so v1's outside chain fact is the user's Core
node. The pin stays in the design for after v1. The frozen v1 command line has no flag
for it ([v1 formats](2026-09-30-v1-formats.md)).

The third source is the correct answer, and it is specified here so it can be built. It
is not a v1 commitment. Validation strips the signet solution from the coinbase, and
recomputes the merkle root and so the block hash. It builds BIP-325's BIP-322-style
`to_spend` and `to_sign` pair, and runs a script engine against the signet challenge.
The result checks itself, so the data may come from an untrusted indexer: a malicious
server cannot forge the signet signer's signature. That keeps
[Detection needs no node](#42-detection-needs-no-node-attribution-does-and-may-be-deferred)
true. Signet blocks are small enough that fetching them whole is cheap. It is not part
of v1. Until it lands, the single-server case rests on the Core node or the pin, and
[What a negative result proves](#53-what-a-negative-result-proves) says so.

**Consequence for the packages:** the `headers` package
([Packages and frozen interfaces](#63-packages-and-frozen-interfaces)) is not an SPV
chain. It stores `(height, hash)` observations drawn from the commitment feed and the
anchor, with the contested-past-six-confirmations rule on top.

### 4.7 Evidence artifact

With a receipt, the evidence file lets anyone check an accusation offline. Without one,
it proves only that the server signed a commitment containing the entry.

One file, **offline-verifiable**: `canary verify <file>` needs no network.
[v1 formats](2026-09-30-v1-formats.md#6-the-evidence-file) defines the file,
`canary-evidence/1`: its fields, its name and the order in which `canary verify` checks
it. This section says only why the file holds what it holds.

The file carries:

- the server's signed record for the block;
- the receipt;
- the exact bytes the server served;
- the left-out entry;
- a Merkle proof that the entry is in the signed root, about 350 bytes
  ([Merkle tree](#32-merkle-tree)).

**The file carries what the server served.** A commitment and a proof alone show that the
server committed to the entry. They do not show that the server withheld it, and anyone
could build such a file against an honest server.

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

This file is the demo. It is also what would go with a bug report or a public
disclosure. An accusation nobody can check independently is worth little.

## 5. Canary tripwire

The tripwire checks for a payment the client already knows exists. It is the check of
last resort. It is also the only check that survives *all* queried indexers colluding
([The equivocation insight](#13-the-equivocation-insight)), because the client's
knowledge comes from outside the indexer system entirely.

### 5.1 Generalized statement

The tripwire is not "send yourself money." It is:

> **Assert that a payment exists in block B, then check whether each indexer reports it.**

The assertion has two sources:

| Source | Cost | What it gives |
|---|---|---|
| **Self-payment** | A real fee | Everything. The client made the transaction, so it holds the prevouts and computes the canonical leaf. It builds the missing-leaf proof and attributes with no node and no auditor ([What a negative result proves](#53-what-a-negative-result-proves)) |
| **A txid the payer disclosed** | Free | **Detection only.** *Does server S report txid X in block B* needs no prevouts. Attribution does. With no prevouts there is no tweak, so no leaf and no [evidence artifact](#47-evidence-artifact) until a block source turns up |

BIP-352 already allows for notifications sent outside the chain, and accepting them is
cheap. Two limits travel with the feature.

**It does not inherit the self-payment's node-free attribution.** That exception in
[What a negative result proves](#53-what-a-negative-result-proves) rests entirely on the
client having made the transaction. A bare txid supplies no prevouts. So the client
cannot compute the tweak, cannot build the left-out entry, and cannot produce an artifact
anyone else can check.

**It is useless against the attacker in [Attacks in scope](#12-attacks-in-scope), by
construction.** A sender hiding a payment from you does not hand you its txid. A sender
who does disclose one has to serve that txid honestly, or be caught at once by an
assertion it created itself. So disclosed txids give free coverage against any indexer
that is *not* the discloser. That case is real and common, because the payer and the
indexer are usually unrelated. They add nothing against the one adversary that section
names as most likely. They add to the self-payment path and do not replace it.

### 5.2 Indistinguishability

The tripwire works only if an indexer cannot tell a probe from a real payment. Chain data
does not give it away; metadata can.

As [Attacks in scope](#12-attacks-in-scope) shows, an attacker cannot identify a victim's
self-payment from chain data. That is the tripwire's foundation. What remains is
metadata:

| Leak | Mitigation | In v1? |
|---|---|---|
| **Periodic timing.** A probe every 6 blocks is easy to whitelist | Poisson scheduling, with exponential gaps between probes. It is memoryless, so the last probe reveals nothing about the next | v2 ([roadmap F25](../roadmap/2026-09-30-feature-roadmap.md)) |
| **Distinctive value.** A repeated or round amount | Randomized, non-round values | v2 ([roadmap F25](../roadmap/2026-09-30-feature-roadmap.md)) |
| **Broadcast and query correlation.** Broadcasting, then querying that block at once | Broadcast over a different path from the one used to query indexers | Documented |
| **Funding linkage.** Spending a UTXO the adversary sent, so it sees the victim transact | Fund probes from UTXOs the adversary does not know about, where possible. **Not fully solvable** | Stated limitation |

The v1 tripwire is one declared payment. The user makes a payment and names it to
`canary check` with `--expect`. v1 has no scheduler and picks no values, so the first two
mitigations wait for v2.

**The honest ceiling.** A passed tripwire proves the server served *that one tweak*. It
is not proof of global honesty, and it says nothing about the output data for that
payment ([Limits of v1](#limits-of-v1)). Against blanket degradation it is measurable.
An attacker dropping a fraction `p` is caught by `k` probes with probability
`1-(1-p)^k`, so ten probes catch a 20% degradation 89% of the time. Against a targeted
single-transaction omission, it helps only if the attacker cannot tell the probe apart.

### 5.3 What a negative result proves

A missing payment becomes an accusation only after the innocent explanations are ruled
out, and what it proves depends on where the entry went missing.

Rule out the innocent explanations first:

1. **Not yet indexed.** Wait until the server's declared height passes B's, plus margin.
2. **Reorg.** `B` must be in the chain Canary believes in
   ([Chain agreement](#46-chain-agreement)). With two or more servers, that is
   convergence: a height still contested six blocks later is not a reorg. With one
   server, it rests on the anchor in [Chain agreement](#46-chain-agreement). A client with
   neither a node nor a pin cannot finish this step. The tripwire then returns
   *unresolvable*, not an accusation.
3. **Never confirmed.** The same check.

After those, it is omission. And:

> **The tripwire is the one check where a light client attributes without a node.**

[Detection needs no node](#42-detection-needs-no-node-attribution-does-and-may-be-deferred)
holds that detection needs no node but attribution does. The tripwire is the exception.
The client *made the transaction*, so it holds the prevouts and computes the canonical
entry itself, with no auditor. What the negative result proves depends on where the entry
went missing. v1 treats three cases differently ([v1 formats](2026-09-30-v1-formats.md)):

| Where the entry is missing | v1 result | Provable to others? |
|---|---|---|
| The signed record contains the entry, and the list leaves it out inside the retention window | The ordinary omission. The client fills the gap with the entry it computed, and the evidence file notes that the tripwire found it | Yes, with a receipt. It is the standard evidence file ([Evidence artifact](#47-evidence-artifact)) |
| The signed record itself leaves the entry out | Always an accusation. No spent check applies, because the record commits to the full canonical set whether or not outputs are spent ([The canonical set](#22-the-canonical-set)) | No. The evidence file carries an inclusion proof, and v1 has no way to prove that an entry is absent from a root. The user knows, and nobody else can confirm it from Canary's files |
| The list carries only the entry's hash, or marks it absent outside the retention window | An accusation only when the local Core node shows one of the payment's taproot outputs unspent, at or above the server's declared dust threshold. Then pruning cannot explain the gap | No. The evidence file has no way to show an output unspent |

[v1 formats](2026-09-30-v1-formats.md) gives the reason code for each case.

**One qualifier.** In the full design the entry needs no node, because the wallet holds
the prevouts of its own transaction. v1 has no wallet in the path, so `canary check`
reads the declared payment from the local Core node. Step 2 above also needs a chain fact
from outside the indexer set. Under total collusion that fact cannot come from the
indexers, by definition ([Chain agreement](#46-chain-agreement)). So the tripwire
attributes without an auditor *given an anchor*: a Core node, a pin, or eventually the
signet solution check. Lacking all three, a negative result is still recorded, and the
server's signed record and receipt still stand. It becomes an accusation the moment an
anchor is available, because signed evidence does not decay.

### 5.4 Coverage integration and cost

A passed tripwire marks one block as verified for one server. Probes cost a fee each, so
the user's budget limits them.

A passed tripwire verifies one block for one server, so
[coverage](#44-the-primary-output-is-coverage-not-alarms) records how a block was
verified: **by cross-check**, **by tripwire** or **by own record**. Under total collusion
only the tripwire form says anything about completeness.

> The tripwire is the only part of Canary with a marginal monetary cost. **The strongest
> check is bought one transaction fee at a time.**

In the full design, a user budget limits probes, not a fixed schedule. v1 sends no probes
of its own. Its tripwire is one payment the user declares
([Indistinguishability](#52-indistinguishability)).

Disclosed txids ([Generalized statement](#51-generalized-statement)) are free. A user
receiving real payments gains tripwire coverage at no cost. That coverage counts only
against servers other than the payer who disclosed the txid, and only as detection. On a
test network every probe is free. That is what makes [the demo](#8-demo) possible: send a
payment, have a deliberately malicious indexer drop it, and watch Canary name it.

The tripwire is the one path whose delay is not a block interval. The client already
knows the txid and the block. So once the server has indexed that height, its own query
bounds the delay: seconds, not the block interval in the
[security claim](#14-security-claim). That holds for the tripwire alone, not for the
other checks.

## 6. Components, interfaces, ownership

Canary v1 ships two programs, and the full design adds a sidecar. This section also
fixes the Go interfaces and says what the BIP-352 library does for them.

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
| `canary` | CLI: `canary status`, `canary verify <file>`, `canary probe` |
| `blindbit-oracle` (fork) | Indexer with `--commit`: computes the canonical set, publishes commitments, signs receipts |

### 6.2 Proxy, not observer

**Status: v2.** v1 has no proxy ([Binaries](#61-binaries)). This section records the
design the proxy will follow, amended 2026-09-30.

A sidecar can sit **beside** the wallet, querying on its own while the wallet stays
unchanged. Or it can sit **in the data path**, where the wallet points at it instead of
the indexer. Canary is a proxy, for three reasons:

1. The wallet is unmodified. blindbitd was archived on 2025-08-14. The realistic clients
   today are blindbit-scan, a headless Go scanner, and Dana through its spdk library.
   Both speak the BlindBit v1 HTTP API, and each points at the proxy by changing one
   server URL.
2. Observer behaviour comes free with proxy mode, and the reverse does not.
3. **It closes "a wallet that ignores the alarm"**
   ([Attacks explicitly out of scope](#15-attacks-explicitly-out-of-scope)). A component
   in the data path can refuse to serve a block. An observer can only write to a log the
   wallet never reads.

**A reverse proxy for BlindBit v1.** The proxy passes every route through unchanged and
intercepts only the tweak routes, `/tweaks/{height}` and `/tweak-index/{height}`. Both
are keyed by height. The proxy resolves each height to a block hash from its chain anchor
([Chain agreement](#46-chain-agreement)) and runs the comparison on the hash, because
Canary compares blocks by hash. Answering 404 for every route except `/tweaks` would make
every v1 client fail at its first `/info`, `/block-height` or `/filter` request. The
routes passed through carry output data that Canary does not yet check
([Limits of v1](#limits-of-v1)), so the proxy never labels them as checked.

**What the proxy refuses.** It refuses **Compromised** and **Disputed** blocks. It does
not refuse *Unverified* data. Today's servers publish no commitments, so every block they
serve is Unverified, and refusing it would refuse all of them. The proxy passes
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

These are the frozen Go interfaces the components build against. Each comment names the
section that explains it.

```go
// canonical: the reference implementation. A pure function. See "The canonical set".
type Network uint32 // the P2P message-start magic, as in "Merkle tree"

type Leaf struct {
    TxID  [32]byte // internal byte order ("Merkle tree")
    Tweak [33]byte // compressed SEC
}

type PrevoutSource interface {
    Prevout(op wire.OutPoint) (*wire.TxOut, error)
}

func Set(net Network, blk *wire.MsgBlock, pv PrevoutSource) ([]Leaf, error)

// commit: Merkle tree, tagged hashes, promotion on odd nodes. See "Merkle tree".
type Proof struct {
    Index    uint32     // position in canonical order
    N        uint32     // set size, bound into the root, so a proof cannot be replayed
    Siblings [][32]byte // bottom-up
}

func Root(net Network, blockHash [32]byte, leaves []Leaf) [32]byte
func Prove(leaves []Leaf, i uint32) (Proof, error)
func VerifyProof(net Network, blockHash, root [32]byte, leaf Leaf, p Proof) bool

// policy: see "Policy declaration", including the bridge to today's servers.
type Policy struct {
    Network          Network
    StartHeight      uint32
    PrunesSpent      bool
    DustThresholdSat uint64
    DustConfigurable bool
}

func FromBlindBitInfo(r io.Reader) (Policy, error)

// feed: Nostr. See "The commitment object" and "Two channels, two jobs".
type Commitment struct {
    Network     Network
    BlockHash   [32]byte
    BlockHeight uint32
    N           uint32
    Root        [32]byte
    PolicyRef   [32]byte // event id of the policy declaration in force
    Author      [32]byte // Nostr pubkey of the signer
}

func (c Commitment) ToEvent(sk [32]byte) (nostr.Event, error)
func FromEvent(e nostr.Event) (Commitment, error)

type Feed interface {
    Subscribe(ctx context.Context, authors [][32]byte) (<-chan Commitment, error)
    // Batched on purpose: NIP-01 offers no range query, so a range fetch is one
    // filter over block hashes the client already knows. See "The commitment object".
    Get(ctx context.Context, author [32]byte, blockHashes [][32]byte) ([]Commitment, error)
}

// wire:     the response format ("Wire model") and receipts: Receipt, VerifyReceipt ("Receipts")
// headers:  (height, hash) observations and the contested-past-6 rule. NOT SPV ("Chain agreement")
// ladder:   the four checks and the coverage state machine ("Client verification ladder")
// evidence: artifact construction and offline verification ("Evidence artifact")
// tripwire: expected-payment assertions; the Poisson scheduler is v2 ("Canary tripwire")
```

Everything above compiles as written. No interface above is still open. `Feed.Get` is
batched because the block hash sits in the indexed `b` tag
([The commitment object](#33-the-commitment-object)). The `headers` package is
deliberately **not** an SPV chain ([Chain agreement](#46-chain-agreement)).

The original plan froze these interfaces on day 2, not at the end of week 1. On its
28-day clock, spending the first quarter before parallel work began was not affordable.

### 6.4 The BIP-352 library supplies the primitives — and what that costs

`canonical` wraps go-bip352's primitives. That saves most of the hard work and limits
what differential testing can prove.

**The import path is `github.com/setavenger/go-bip352`, package `bip352`, v0.1.8.**
Verified 2026-09-08 against the published module. This matters more than a naming
detail. The older `github.com/setavenger/gobip352` path is v0.1.4, and it does **not**
export `ExtractEligibleVins` or `ExtractPubKey`. Its own README says input eligibility is
out of scope. Every claim in this section about saved work is a claim about `go-bip352`.
Pointing `go.mod` at the old path silently removes the eligibility layer and leaves it to
be written by hand.

Signatures, verbatim from `go doc`:

```go
func ExtractEligibleVins(vins []*Vin) ([]*Vin, error)  // deep-copies; sets the Taproot flag
func ExtractPubKey(vin *Vin) ([]byte, TypeUTXO)        // no error; check TypeUTXO != Unknown
func ComputeInputHash(vins []*Vin, publicKeySum [33]byte) ([32]byte, error)
func TaggedHash(tag string, msg []byte) [32]byte       // confirmed BIP-340 construction
var NumsH = []byte{...}                                // the 32-byte x-only NUMS point
```

[The Merkle tree](#32-merkle-tree) depends on `TaggedHash` being a real BIP-340 tagged
hash. It was checked against `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)`, not assumed.
`NumsH` is exported, so the NUMS-H corners in [The corners](#73-the-corners) can assert
against the library's own constant instead of a copied literal.

**A byte-order trap, exactly the one [Merkle tree](#32-merkle-tree) warns about.**
`bip352.Vin.Txid` is documented as *"the normal human-readable format"*: display order,
byte-reversed. `ComputeInputHash` and `FindSmallestOutpoint` both require it that way.
The leaf preimage pins the txid in **internal** byte order. So `canonical` converts at
the boundary, in one place, and the vectors ([Vector format](#74-vector-format)) pin the
result. Two representations of a txid in one package is how implementations silently
fork.

Two further behaviours are worth pinning, both verified by running them.
`ExtractEligibleVins` on an empty slice returns `(empty, nil)`, not `ErrVinsEmpty`. And
`ExtractPubKey` signals failure by returning `TypeUTXO == Unknown`, not an error.

So `canonical` is not "implement BIP-352." It is those primitives plus the
transaction-level rules (at least one taproot output, no SegWit v>1 input), plus ordering
and leaf construction. That removes most of the risk from the riskiest component.

**It also rules out a claim that would otherwise have been made carelessly.**
blindbit-oracle is by the same author and uses the same library. So differential testing
`canonical` against blindbit-oracle exercises **the wrapper, not the primitives**: both
would be wrong together. Real independence needs a different lineage, such as
silentiumd or the BIP's own vectors.

This exposes a real gap. **BIP-352 ships send and receive test vectors, but nothing for
the index-level canonical set**: eligibility per transaction, ordering and set
membership. [Testing](#7-testing-with-a-differential-edge-case-suite) fills that gap. It
is needed regardless, and it is a legitimate upstream contribution, not a hackathon
artifact.

One decision follows: **the indexer fork keeps blindbit-oracle's own computation path
instead of calling our `canonical` package.** Sharing the code would be convenient and
would make the differential test meaningless. v1 departs from this on purpose: its
reference indexer calls `canonical`, and [Binaries](#61-binaries) records what that
costs.

### 6.5 Ownership

v1 is built by one person plus Claude, decided 2026-09-30. The original plan split the
work three ways along the package lines above. The
[Decision log](../decisions.md#the-original-three-person-split) keeps that split.

One reason from it still holds. The protocol core goes to whoever can unblock the other
work fastest, because everything else consumes it. And the malicious indexer mode
belongs with the indexer: it is a configuration flag on code that owner already knows,
not a separate project.

### 6.6 Dependency order

The original four-week, three-person schedule no longer applies to v1, and the
[Decision log](../decisions.md#the-original-three-person-split) keeps it. Two of its rules
still hold for any later work.

**Configure an agreement harness correctly, or it tests nothing.** A harness that
compares `canonical` with blindbit-oracle across many signet blocks is the cheapest early
signal that `canonical` is wrong. But blindbit-oracle's default response is
policy-filtered. Diffing a filtered response against the canonical set produces the
false positives [The separation](#21-the-separation-committed-set-vs-served-set) exists
to prevent. Run blindbit-oracle with its full-index option (`tweaks_full_basic=1`;
confirm the flag name against the pinned version) and no dust threshold. That yields an
index comparable to the canonical set. It is a configuration line, not a fork.

**Attribution has two forms, and only one is on the critical path.** The tripwire's
node-free attribution ([What a negative result proves](#53-what-a-negative-result-proves))
comes with the tripwire, because there the client holds the prevouts for a transaction it
made itself. The general auditor form needs prevouts for someone else's transaction. It
is the stretch component in [Risks](#67-risks) and has no date.

### 6.7 Risks

These are the risks the original plan named, with how it meant to handle each.

| Risk | Mitigation |
|---|---|
| `canonical` subtly wrong | The agreement harness ([Dependency order](#66-dependency-order)), BIP vectors, and the edge-case suite ([Testing](#7-testing-with-a-differential-edge-case-suite)) |
| Core v30 unpruned signet fails to come up | Check it on the first day, not weeks later, because it gates all indexer work. v1 runs on regtest, so this applies to signet after v1 |
| Relay dependency | Run our own relay (`strfry` or `nostr-rs-relay`) beside public ones, in line with running everything locally |
| Auditor scope creep | **Not on the critical path.** The tripwire attributes without a node on the self-payment path ([What a negative result proves](#53-what-a-negative-result-proves)). The demo's detection uses the retention rule ([Comparison procedure](#25-comparison-procedure)). So the demo never needs the auditor. It is the stretch component |

## 7. Testing with a differential edge-case suite

Canary tests the canonical set with vectors built on regtest to hit BIP-352's unclear
eligibility rules on purpose, instead of hoping a chain holds one.

### 7.1 Three layers

Three layers of tests cover the canonical set, and only the middle one is new work.

| Layer | Covered by | Independent? |
|---|---|---|
| **A. Primitives.** The tweak from a given input set | BIP-352's `send_and_receive_test_vectors.json` | Yes. It is the specification |
| **B. Canonical set.** Which transactions, in what order | **Nothing. No vectors exist** | Not applicable |
| **C. Real-chain agreement.** `canonical` against blindbit-oracle over N blocks | The agreement harness ([Dependency order](#66-dependency-order)) | No. Both use `go-bip352` ([The BIP-352 library](#64-the-bip-352-library-supplies-the-primitives--and-what-that-costs)) |

Layer A is someone else's test, but it is the only independent check on our dependency,
so we run it. Layer C catches wrapper bugs but not primitive bugs, and it is the cheapest
early signal.

**Layer B is the work, and the contribution.** BIP-352 specifies index-level eligibility
in prose and ships no vectors for it.

Within the original four-week plan, the realistic independent lineages were the BIP
vectors (free), blindbit-oracle (wrapper level only), and **silentiumd if it runs
easily**. Core PR #28241 is a truly independent C++ lineage. But it is a closed PR
against an old tree, so it is named, not budgeted.

### 7.2 Regtest, not signet

The edge-case suite and the v1 demo both run on regtest.

Several corners need arbitrary scripts and control over what goes into a block. Nobody
outside the signet operators can mine on public signet. So building a corner there waits
on someone else's block template, and on non-standard transactions relaying. Regtest
gives instant blocks, arbitrary transactions, no faucet dependency, and reproducible CI.

> **Regtest for the edge-case suite, and for the v1 end-to-end demo. Signet comes after
> v1.**

The v1 demo moved to regtest on 2026-09-30.
[What the format dictates](#81-what-the-format-dictates) gives the reason.

v1 uses its own reference indexer ([Binaries](#61-binaries)), not blindbit-oracle. So
only one regtest check remains before building: Core's REST endpoints behave as expected
on regtest.

### 7.3 The corners

Each row is a place where two correct-looking implementations could disagree, with the
result the BIP text requires.

| Case | Construction | Expected |
|---|---|---|
| **NUMS-H script path** | P2TR with internal key *H*, spent via script path | Input **excluded**. If it is the only eligible input, the transaction is not eligible |
| **NUMS-H, parity flipped** | *H* as internal key, control block's parity bit flipped | Input **excluded**. Byte 0 is `leaf_version \| parity`, and bytes 1..33 are still *H*. This catches an implementation that compares the control block from byte 0, and so stops recognising *H* whenever parity or leaf version differs |
| **Ordinary script-path spend** | Random internal key *P* ≠ *H*, script path | Input **included**. Only *H* is excluded, not script-path spends in general |
| **Malleated P2PKH** | `<dummy> OP_DROP <sig> <pubkey>` | The public key **must** still be found. The BIP says MUST |
| **Uncompressed P2PKH key** | 65-byte public key | **Excluded.** Compressed and x-only keys only |
| **SegWit v>1 input** | Spend a v2 witness program | **Whole transaction excluded** |
| **Mixed input types** | P2TR + P2WPKH + P2PKH in one transaction | All three summed |
| **Taproot output, no eligible input** | P2WSH inputs only | Not eligible |
| **Eligible input, no taproot output** | P2TR in, P2WPKH out | Not eligible |
| **Coinbase** | Not applicable | Not eligible: null prevout |
| **`A_sum` = point at infinity** | See below | **Skip the transaction** |
| **`outpoint_L` ties** | Two inputs from the same txid, adjacent vouts | Tests serialization and endianness |

The infinity case looks unreachable and is not. Two taproot inputs cannot produce it,
because both lift to even Y. But take `a`, and let `P = aG` with even Y. Fund a **P2TR**
output to x-only `P`, and a **P2WPKH** output to the compressed encoding of `−P`
(private key `n−a`, prefix `0x03`). Spend both in one transaction. Then
`A_sum = P + (−P) = ∞`. Both keys are ours, and it is trivial on regtest.

This case is the most likely to find a real bug. Libraries commonly error, or silently
return a zero point, on addition to infinity, and nobody reaches it by accident.

**Expectations come from the BIP text, never from what our code does.** Take the
parity-flip row. Flipping parity changes byte 0 only, and an implementation reading
bytes 1..33 still sees *H* and still excludes the input. Had the row said *included*, a
correct implementation would fail it. "Fixing" the implementation to pass would then
introduce the exact bug the vector exists to catch. These vectors are meant to go
upstream ([Upstream, and expectations](#76-upstream-and-expectations)), so the expectation
column is the part that has to be right. The [Decision log](../decisions.md) records the
draft that had this row inverted.

### 7.4 Vector format

A vector is one JSON file that any implementation can run with no node and no network.

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

The **prevout map** makes a vector self-contained. It is exactly what a node would
otherwise supply.

`expected.root` means the vectors also test the tagged hashing and odd-node promotion of
[Merkle tree](#32-merkle-tree). So they cover the whole `canonical` + `commit` stack, not
eligibility alone, which makes them worth more to an adopter.

**CI is hermetic.** Generating vectors needs regtest and Core, and runs as a task during
development. The committed JSON runs under plain `go test` with no node and no network.
[testdata/vectors/README.md](../../testdata/vectors/README.md) describes the committed
files.

### 7.5 Property tests

Some properties are structural, and no fixed vector reaches them. Each row defends one
decision in [Merkle tree](#32-merkle-tree).

| Property | Defends |
|---|---|
| `VerifyProof(Root(L), i, Prove(L, i))` for all `i`, random `L` | Basic soundness |
| Permuting transaction order changes the root | Accidental sorting. [The canonical set](#22-the-canonical-set) chose transaction order on purpose |
| A root over `n` leaves never validates as a root over `n′ ≠ n` | Binding `n` into the root |
| `n ∈ {0, 1, 2, 3, 5, 2ᵏ, 2ᵏ+1}` | **Odd-node promotion**, where CVE-2012-2459-class bugs live, plus the `n = 0` and `n = 1` base cases |
| An internal node hash never validates as a leaf | The distinct leaf and node tags |

### 7.6 Upstream, and expectations

A disagreement between implementations goes to one of three places, and the vectors ship
whether or not they find a bug.

- **We are wrong.** Fix it, and keep the vector.
- **They are wrong.** Report it with the vector attached. A failing vector is a far better
  bug report than prose.
- **The BIP is ambiguous.** This is the valuable case. BIP-352 is actively maintained
  (version 1.1.1, 2026-04-16, added a test vector), so an index-level vector contribution
  may well be accepted upstream.

**Expectations, so a quiet suite does not read as a failed one.** The likely outcome is
zero to two real bugs. The suite is the contribution either way. *"We tested this against
N implementations and they agree"* is a legitimate and reportable result. It answers how
we know the canonical set is right.

The work is time-boxed. The vectors ship whether or not they find anything.

## 8. Demo

The demo video shows the loss first, then the tool, then the limit, and never fakes a
frame. The 30 Sep amendment moved it to regtest, added a new first act and a longer
target, named the `--withhold-txid` switch, and added a neutral list of questions and
answers.

### 8.1 What the format dictates

BOSS Battle is asynchronous. The deliverable is a recorded video plus a repository that
has to read on its own. That fixes four things before any content decision:

1. **Nothing is faked.** A bad take is re-recorded, so no screen needs to be faked. The
   rule: every frame must come from a real run.
2. **Two kinds of reader, served separately.** Some people watch the video and never open
   the repository. Others open the repository and never finish the video. The video
   serves the first group, and
   [the repository path](#85-the-repository-path-for-readers-who-do-not-watch-the-video)
   serves the second. Neither depends on the other.
3. **The first twenty seconds state the problem**, because a viewer who has just started
   has no context yet.
4. **The target length is 3:15 to 4:30, and at least 180 seconds.** One competitor,
   QuietRelay, reports a 3-to-5-minute rule (180 to 300 seconds) from the organizers'
   private participant handbook, which we have not seen. A video in this range meets the
   rule if it holds, and costs nothing if it does not.

**The network is regtest.** v1 is built and tested on regtest only, and the video says so
on screen and says why. One person plus Claude builds the core loop in the final week. A
signet run would need a synced node and would wait on public block timing that nobody
controls. Regtest mines a block on command and needs no faucet. Anyone with Bitcoin Core
can repeat the run on one machine. The cost is real: the video cannot claim a run on a
public network. [Regtest, not signet](#72-regtest-not-signet) already uses regtest for
the edge-case suite.

### 8.2 Show the loss before the tool

The video shows the problem first and Canary second.

The narrative order is fixed, and it is not the architecture order. The problem is
invisible by construction, which is the whole project. So the video's first job is to
make the invisibility visible. Opening on a diagram or on Canary's own output asks the
viewer to take the problem on faith.

v1 has no wallet in the path ([Binaries](#61-binaries)). So act 1 shows the served data
directly: the chain holds the payment, and the indexer's response has no entry for it.

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

**The attack is already running in act 1. Act 2 reveals it; it does not apply it.** The
alternative is to open on a complete response, switch the flag on camera and watch the
entry disappear. That shows the change, but it spends fifteen seconds before the problem
appears, and it opens on a screen where nothing is wrong. The change worth the time is
act 3's: the same data, now producing an accusation.

**Cast the adversary as the sender**, as in [Attacks in scope](#12-attacks-in-scope).
The exchange that pays you is the indexer that tells you whether you were paid. One
adversary, one motive, one victim, and no third party brought in to make the plot work.

### 8.3 What is on screen: coverage or the artifact

The video shows both, at different acts, and they are not interchangeable.

| Output | Nature | Acts | Why there |
|---|---|---|---|
| **Coverage** ([Coverage](#44-the-primary-output-is-coverage-not-alarms)) | Continuous. The product | 5 | It is what Canary does when nothing is wrong, which is most of the time |
| **Evidence artifact** ([Evidence artifact](#47-evidence-artifact)) | Discrete. The event | 3, 4 | It is the accusation, and the only thing a third party can check |

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
5. **Nothing is cut inside a take.** Dead time between takes is cut. Timestamps stay
   visible so each cut is legible, and no output is fabricated or retyped.

### 8.5 The repository path, for readers who do not watch the video

A reader who never opens the video can check a real accusation from the README in under
a minute.

`evidence/` holds a real file from a real recorded run, not a hand-built fixture. The
README's first code block verifies it:

```
go run ./cmd/canary verify evidence/<file>.json
```

The first build downloads the Go module dependencies. So it needs a network connection,
unless the module cache already holds them or the modules are vendored. After that one
online build, verification needs no node, no network and no indexer. The target is under
60 seconds from opening the README to a result in the reader's own terminal. A CI test
verifies the same file, so a change that breaks it fails the build.

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

These are the questions a reviewer is likely to ask, answered plainly.

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
It cannot withdraw a published commitment, and each of its three choices meets a
different check. If it commits honestly and leaves a hole inside the retention window,
its own signed receipt shows the hole, and one server is enough. If it serves a wrong
entry, the recomputed root does not match its signature. If it commits to the smaller
set, any honest server's root differs, and the two servers stand as Disputed until
attribution names the liar. For a payment the client declared, the smaller set names the
server directly, because its own record leaves out the entry. The client knows, but v1
cannot prove it to others ([Canary tripwire](#5-canary-tripwire)). Two variants pass the
per-block check: serving the entry's hash under a declared pruning or dust policy, and
hiding the output data instead of the entry. [Limits of v1](#limits-of-v1) states both.

**Can't you run two indexers and diff what they serve?**
No. Honest indexers serve different sets, and BIP-352 permits it: "spent transactions
optionally can be skipped". A raw diff reports every such difference as an alarm. Canary
compares committed canonical sets instead
([Canonical tweak sets](#2-canonical-tweak-sets-and-policy-normalization)).

**What if every indexer colludes?**
Then comparing servers shows nothing. The tripwire still works, but only for payments the
client knows exist because it made them ([Canary tripwire](#5-canary-tripwire)).

**Does this need a full node?**
v1 does. `canary check` reads block hashes, the chain tip and declared payments from your
own Bitcoin Core node. The design's position is narrower. Detecting a problem needs no
node. A server that contradicts its own signatures is named without a node. A hole inside
the retention window needs no outside chain fact either, because the server signed both
its tip and the block's height. A chain fact is needed only to reject a gap that the
signed values place outside the window.

Deciding which of two disagreeing servers lied (attribution) needs prevouts, from a full
node or a third-party API. That can wait, because signed evidence does not expire
([Detection needs no node](#42-detection-needs-no-node-attribution-does-and-may-be-deferred)).
The tripwire attributes without a node, given one outside chain fact, because the client
made the transaction and holds its prevouts.

**Is a detected omission proof?**
Only with a receipt. The evidence file then carries the served bytes and the server's
signature over them, so anyone can check the omission offline. Without a receipt, the
client knows, and others can check only that the server committed to the entry
([Receipts](#38-receipts)).

**Does Canary stop fake entries?**
No. Canary covers hiding only. A server that adds fake entries (commission) is out of
scope ([Attacks explicitly out of scope](#15-attacks-explicitly-out-of-scope)).

**What does Verified mean?**
On screen it reads Checked. The block's tweak list was checked against a signed root. It
does not mean the block's payments were checked ([Limits of v1](#limits-of-v1)).

**Why regtest?**
Time and reproducibility, at the cost of not showing a run on a public network.
[What the format dictates](#81-what-the-format-dictates) gives the full reason.

---

## Appendix A. Prior art

These are the sources this document relies on, checked 2026-09-30. The full survey is in
[prior-art.md](../research/prior-art.md).

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
