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

## Current state — 2026-09-07

**Design phase. Nothing is implemented, and nothing should be until the design is
approved section by section.**

| | |
|---|---|
| Architecture | Approved (sidecar + 4-step ladder + Nostr transport) |
| §1 Threat model | Settled |
| §2 Canonical sets + policy normalization | Settled — data model is fixed, team interface named |
| §3 Commitment format + Nostr transport | Settled — commitment object, Merkle construction, event rules, receipts |
| §4 Client verification ladder | Settled — four rungs, coverage output, evidence artifact |
| §5 Canary tripwire | Settled — generalized to *expected payments*; §1.2 amended |
| §6 Components, interfaces, ownership | Settled — 3 binaries, proxy model, packages, ownership, risks |
| §7 Differential edge-case suite | Settled — regtest vectors, corners, property tests |
| §8 Demo | **Drafted in conversation, NOT approved, NOT written to the doc.** Key decisions captured below |

**Spec review run 2026-09-07 (`/code-review`). 15 defects found. 11 fixed, 4 open.**
The 8 editorial ones plus design defects 1, 2 and 3 are corrected in the doc. Four remain
and need a decision. Do not treat §1–§7 as final until they close.

Design doc: `docs/design/2026-09-06-canary-design.md`
Research + citations: `docs/research/prior-art.md`

## Spec review — 2026-09-07 — 11 FIXED, 4 OPEN

A `/code-review` pass over the full spec plus a self-review found 15 defects. The four
below are still open and must close before `writing-plans`, and before anyone codes
against §6.3.

### Design-level — OPEN. Need a decision, not just an edit

| # | Defect | Where |
|---|---|---|
| 4 | **§5.1's free out-of-band probe was overclaimed.** §5.3's node-free attribution needs *prevouts*, which the client has only because it made the transaction. Given a bare txid it cannot compute the tweak, build `missing_leaf`, or prove anything. And the §1.2 sender-attacker knows exactly which txid they disclosed and serves it honestly. "Strictly more useful" is wrong | §5.1, §5.3, §6.7 |
| 5 | **`dust_threshold_sat` is unverifiable in principle.** The leaf is `(txid, tweak)` and carries no output value, so a client can never check that a dust-justified gap was legitimate. Decide whether the field survives | §2.3, §2.2 |
| 6 | **Merkle root over an empty leaf set is undefined** — and it is the *most common* case on regtest, where most blocks hold no eligible transaction. §7.4's own example vector requires it; §7.5's property list starts at `n=1` | §3.2, §7.4 |
| 7 | **Multi-letter Nostr tags are not relay-indexed.** NIP-01 filters only single-letter tag names, so `block_hash` as a tag is not queryable and §6.3's `Feed.Get(author, blockHash)` cannot be served by a relay. Fix: carry the block hash in a single-letter indexed tag | §3.3, §6.3 |

### Design-level — FIXED 2026-09-07

| # | Defect | Fix applied |
|---|---|---|
| 1 | `headers` gave no security on signet | §4.6 rewritten. **The PoW claim is deleted** — a per-network table now says where integrity actually comes from (work on mainnet, the BIP-325 challenge signature on signet, nothing on regtest). The hole is narrower than it looked: §2.5 keys on block *hash*, so the reorg excuse is already unavailable for the comparison itself; only *chain membership* was exposed, in §5.3 step 2 and §4.4's ranges. Replaced by **chain agreement as an output, not an input** — a server on a fake chain must publish commitments for it (§2.5 step 0) and cannot withdraw them (§3.3), so a height still contested six blocks later is a signed chain contradiction, heavier than omission and free to detect. For the single-server case, §4.6 names the outside fact Canary requires: the user's own Core node, or a manually pinned `(height, hash)` per §3.6's precedent. **BIP-325 solution validation is specified but is NOT a v1 commitment** — week 3 if there is room. `headers` is no longer an SPV chain |
| 2 | §2.4's hashless-gap amendment opened a hole | The amendment's reasoning was right and the ordering was the bug. Retention *is* only an optimization: given a candidate leaf from anywhere, hashing it and recomputing the root proves it against the first server's own signature, so the second server is never trusted. What the amendment missed is that "nobody can supply the leaf" was a state the server chose, for free. Fixed in three places: §2.5 now **resolves gaps before recomputing the root**, and a block whose root was never recomputed is *unresolvable*, never clean; **tip tolerance governs effort and reporting, never verification**; and §2.4 makes hash retention **required inside a 144-block window**, near free because cut-through barely applies at the tip. Also: the response is now self-describing at length `n`, so truncation cannot read as a smaller block |
| 3 | §2.5 step 1 broke the tool-first layer | Step 0 now has three cases. A server that never commits → *Unverified*, accepted, feeds §4.3's union, caught only by the tripwire. A server that commits for neighbouring blocks but not this one → **refused**, because selective non-publication is the attack. **Evidence, not advertisement.** §0's tool-layer bullet now says what that layer actually is: union, `/info` policy, and the tripwire |

### Factual / editorial — FIXED 2026-09-07

All eight are corrected in the doc. Listed with what the fix was, so nobody re-opens them
or reverts a number back to the wrong one.

| # | Defect | Fix applied |
|---|---|---|
| 8 | Root preimage encodings undefined for `network` / `block_hash` | §3.2 now has a full encodings table. `block_hash` is internal byte order, same rule as `txid`. **`network` is the 4-byte P2P message-start magic**, not a private enum — BIP-325 derives a custom signet's magic from its challenge, so the magic keeps two signets distinct where an enum would merge them, and §2.7's first precondition depends on that. Read from `chaincfg.Params.Net`, pinned in CI by §7.4's regtest vectors. §3.3's enum gained regtest |
| 9 | §7.3's NUMS-adjacent vector inverted | Expectation flipped to **excluded** — parity lives in control-block byte 0, bytes 1..33 are still *H*. Added a second row (ordinary script-path spend, random *P* ≠ *H*, **included**) so the pair tests both over- and under-exclusion, plus a note in §7.3 explaining the inversion, since §7.6 ships these upstream |
| 10 | §3.7 storage wrong by ~7× | **~35 MB**, arithmetic written inline (≈965k blocks × 36 B). Added a note that the table is the pitch to indexers, so a skeptic recomputes it |
| 11 | §2.4's "no overhead at all"; n≈1500 vs n≈2000 | Overhead is honest now: 65 B per position vs 33 for a bare tweak, **roughly double**, unavoidable because a light client cannot supply the txid. **`n ≈ 2000` pinned everywhere**; §2.4's proof figures recomputed (352 B/proof, ~700 KB vs 130 KB of leaves) |
| 12 | README ladder described the pre-§2 design | Rewritten to §4.1's four rungs plus the tripwire, led by `Served ⊆ Canonical`, with the coverage framing and the *lower bound, not a balance* line. Status now §1–§7 + open corrections. Headline dropped "provable" (see #13) |
| 13 | §1.4 overclaimed non-repudiation and timing | Claim narrowed to "a detected event naming a server and a block", with two qualifiers travelling with it: **detection is not proof** (single-server omission needs §3.8 receipts, protocol layer only) and **timing depends on the attack** (rung 1 ≈ block interval; targeted omission surfaces at rung 2, on fetch). §1.2, §5.4, §8 and the README all aligned. §5.4 now states the tripwire's latency is bounded by its own query, not by a block interval |
| 14 | §2.6 stale on all three statements | Day-2 freeze, real `Set(net, blk, pv) ([]Leaf, error)` signature, regtest not signet |
| 15 | §4.4 "always on screen"; *Compromised* vs §4.5 | Split into **Disputed** (roots diverge, two named servers, unattributed) and **Compromised** (attributed, one named server) — six coverage states now. Added a table showing coverage reaches an unmodified wallet only through §6.2's refuse-in-path, not through a display |

Also closed, below the cap: `tripwire` assigned to Naman in §6.5, paired with `evidence`
per §5.3; rung 4 placed in week 3 in its tripwire form with the auditor form named as
§6.7's stretch; §6.3's literal `...` replaced with signatures that compile, plus an
explicit warning that `headers` and `Feed.Get` are known-open; `prior-art.md`'s
"normalise before comparing" marked superseded by §2.1 with the reason; doc header dated
`2026-09-06, revised 2026-09-07`. The rejected-as-half-right finding also landed: §6.6
now says to run blindbit-oracle with `tweaks_full_basic=1` and no dust threshold for the
week-1 gate.

### Original defect list, editorial half (kept for reference)

| # | Defect | Where |
|---|---|---|
| 8 | **Root preimage encodings undefined.** `n_le32` is pinned; `network` and `block_hash` are not — in the same table that pins txid byte order as a deliberate interop trap. And §3.3's enum is "signet / main" while every §7 vector is regtest | §3.2, §3.3 |
| 9 | **§7.3's NUMS-adjacent vector is inverted.** Flipping the control block's parity bit changes byte 0 only; bytes 1..33 still equal *H*, so a **correct** implementation *excludes* the input. The table says "included". A correct implementation fails this vector, and "fixing" it introduces the exact bug the vector exists to catch — and §7.6 ships these upstream | §7.3 |
| 10 | **§3.7 storage arithmetic wrong by ~6.5×.** 36 bytes × ~900k blocks = **32 MB**, not 5 MB. Still a fine adoption argument, but §2.1 designates this as the pitch to indexers and a skeptic recomputes it | §3.7 |
| 11 | **§2.4's "no overhead at all" is false.** 65-byte `(txid, tweak)` leaves are ~2× today's 33-byte tweak responses. Also §2.4 sizes a mainnet block at n≈1500 while §3.2 uses n≈2000 | §2.4, §3.2 |
| 12 | **README's ladder describes the pre-§2 design.** Step 2 is raw symmetric-difference diffing (the thing §2 exists to eliminate); step 3 claims "no full node required" against §4.2; step 4 is the un-generalized tripwire; step 1 conflates the 32-byte root with the ~200-byte event. README's status line also still says §1–§5 settled | README |
| 13 | **§1.4 overclaims twice.** *Non-repudiation* needs receipts, which §3.8 confines to the protocol layer, and §1.4's precondition does not mention them. *Timing* — "within one block interval" — is wrong for targeted omission, which is served≠committed and so surfaces only at rung 2, whose trigger is the client fetching the block. Rung 1 catches only cross-server root divergence. §5.4 ("thirty seconds") and §8 ("one block interval") also disagree | §1.4, §1.2, README |
| 14 | **§2.6 is stale on all three of its statements** — week-1 interface freeze (§6.3 says day 2), `CanonicalSet(block, prevouts) []Leaf` (§6.3 says `Set(net, blk, pv) ([]Leaf, error)`), and "constructible on signet" (§7.2 says regtest) | §2.6 |
| 15 | **§4.4's "coverage is always on screen" is impossible** under §6.2's unmodified wallet — coverage lives in `canary status`, which is the log-nobody-reads §6.2 dismisses. The real answer to §1.5 is §6.2's refuse-in-path. Separately, §4.4's *Compromised — named server* contradicts §4.5, where root divergence names two servers without saying which lied | §4.4, §4.5, §6.2 |

**Reviewer finding rejected as half-right:** the week-1 gate (§6.6) was flagged as raw
served-set diffing. Configuring blindbit-oracle with `tweaks_full_basic=1` and no dust
filter gives a full index comparable to `T_base`. The doc simply never says to do that —
a one-line fix, not a redesign, and it does not depend on Dev B's week-2 fork.

## §8 Demo — drafted, not approved, not in the doc

Presented in conversation and never approved; the design doc still says PENDING. Captured
here so it is not lost. Re-present for approval before writing it in.

- **Format drives it.** BOSS Battle is async, so the deliverable is a recorded video plus
  a repo read alone. Live-failure risk is nil (re-record), so nothing should be faked;
  the first 20 seconds carry everything.
- **Show the loss before the tool.** Five acts, ~2:30 — invisible loss (wallet reads
  0 sats while the explorer shows the payment) → one config line → detection → offline
  `canary verify` on a second machine, network off → **the honest limit**, closing on
  "accountable, not trustless" and showing an *unresolvable* range, the state that is
  deliberately not an accusation.
- **Cast the adversary as the sender** — the exchange pays *and* runs the indexer, per
  §1.2. One adversary, one motive, one victim.
- **Production rules:** show the attack being configured on screen (`--omit-tx`) or the
  missing payment reads as our bug; signet with visible timestamps and dead time cut;
  regtest fallback recorded in advance; our own relay visible.
- **Ship a real evidence artifact in the repo** so a judge runs `canary verify` in 30
  seconds without building anything — the shortest path from README to personally
  verifying an accusation.
- **Rehearse the CT question.** A knowledgeable judge asks "isn't this just Certificate
  Transparency?" — agree enthusiastically, then say what is new (the canonical-set and
  policy-normalization problem, which CT logs do not have). Disputing it looks defensive.

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
| **Nostr for commitment transport** | Free public signed bulletin board (**publication, not timestamping** — see mistake #7), no infrastructure for servers to run; clients subscribe to a relay instead of opening N connections, which also avoids leaking which blocks they care about |
| **Construct edge cases, don't scan for them** | Deliberately hit ambiguous BIP-352 eligibility rules rather than hoping a chain supplies one. **On regtest, not signet** (§7.2) — several corners need arbitrary scripts and controlled block composition, and we cannot mine on public signet. Signet is for the end-to-end demo only |
| **Commit to the canonical set, not the served set** | All legitimate indexer policy is *subtractive*, so `Served ⊆ Canonical`. Committing to the policy-free set lets storage policy stay free while accountability does not. §2.1 — this is the load-bearing idea of the whole design |
| **Run all indexers locally** | Never depend on a third-party public server being alive — that fragility is literally what the project is about |
| **`network` in the root preimage is the 4-byte P2P magic, not an enum** | BIP-325 derives a custom signet's magic from its challenge, so the magic separates two signets that an enum would merge — and §2.7's first precondition is that both servers index the same network. Read from `chaincfg.Params.Net`; §7.4's vectors pin it in CI. Decided 2026-09-07 while closing spec-review defect #8 |
| **Six coverage states, with *disputed* split from *compromised*** | §4.5 already ruled that root divergence names two servers without saying which lied. One combined alarm state is exactly how an attacker gets an honest server excluded. Decided 2026-09-07 while closing defect #15 |
| **Chain agreement is a Canary output, not a Canary input** | The chain is the same problem Canary already solves: parties assert, they disagree, and the disagreement is transient or permanent. Reorgs resolve; lies persist. Reusing the commitment feed costs nothing, where an SPV chain cost a component and bought nothing on signet. Decided 2026-09-07 closing defect #1 |
| **The 144-block hash-retention window is a protocol constant, not a policy field** | A server allowed to declare its own window declares zero, which is the hole verbatim. Decided 2026-09-07 closing defect #2 |
| **BIP-325 solution validation is specified but not committed for v1** | It is the only anchor needing no trust, and it is 2–3 days plus every txid in the block. Week 3 if there is room; until then the single-server case rests on a node or a pin, and §5.3 says so. Decided 2026-09-07 closing defect #1 |

**Superseded:** the original dossier proposed OpenTimestamps anchoring. Nostr events
replace it. OTS may return in v2 to anchor the event chain.

## Framing discipline — this is not optional

**Canary does not make tweak sourcing trustless. It makes it accountable.**

Second framing decision, from §4.4: **the primary output is coverage, not alarms.** An
alarm that never fires looks like a product that does nothing. Coverage, per block range,
is continuous and
visible. Six states as of the 2026-09-07 corrections — verified / resolved / unresolvable
/ unverified / **disputed** / compromised, where *disputed* is unattributed root
divergence and *compromised* is attributed, because §4.5 keeps those apart. It also yields
the line worth leading with: *a balance computed over blocks you could not verify is a
lower bound, not a balance.*

Say this first — in the README, in the docs, in the first 30 seconds of the pitch. A
limitation volunteered reads as rigor; the same limitation extracted by a judge reads as
overclaiming. The security claim is conditional and must always be stated with its
condition: *given at least one honest indexer publishing commitments, and an uncensored
path to a relay carrying them.*

Related discipline: cite Certificate Transparency (RFC 6962) for the split-view
insight. We are applying it, not inventing it.

## Team

3 people, all Go-capable. **Interfaces freeze day 2** (§6.3 — end of week 1 is a quarter
of a 28-day clock spent before parallel work starts). Everyone runs the same signet node.

- **Naman** — `canonical`, `commit`, `feed`: the protocol core both other tracks consume.
  Then evidence artifact, demo, pitch
- **Dev B** — indexer fork: `T_base` at index time, commitment publishing, receipts, and
  the deliberately-malicious mode
- **Dev C** — `canaryd`: proxy, ladder, policy, headers, coverage, CLI

Dev B / Dev C are placeholders — replace with real names before the day-2 freeze, since
it changes who gets `headers` versus `policy`.

## Mistakes that will be tempting

1. **Diffing raw tweak sets.** It produces nothing but false positives. Honest indexers
   legitimately serve different sets — blindbit-oracle does cut-through and dust
   filtering, silentiumd indexes only transactions with unspent taproot outputs, and
   BIP-352 itself *blesses* cut-through. **Settled in §2:** compare committed canonical
   sets, never served sets. Read §2 before touching any comparison code.
2. **Claiming we solved commission attacks.** We did not. Injection-to-deanonymize is a
   different attack with the opposite structure; ephemeral Tor block fetching is the
   accepted answer. Our k-of-N rule raises the bar as a side effect — that is a note,
   not a claim.
3. **Reaching for mainnet.** Costs days, buys nothing the design needs.
4. **Building a wallet.** `blindbitd` is the wallet. Canary is a sidecar.
5. **Treating the research as durable.** `docs/research/prior-art.md` is dated and
   perishable — the entire project rests on the gap still being open. Re-verify before
   relying on it.
6. **Using a replaceable Nostr event kind.** Kinds 10000–19999 and 30000–39999 are
   overwritten in place. A server could retroactively publish a policy declaration after
   using it as cover and the original would vanish. Policy and commitment events are
   **regular kinds, append-only**. §3.3.
7. **Claiming Nostr gives us timestamping.** It gives us *publication*. `created_at` is
   self-asserted and backdatable; ordering comes from the block hash. §3.5.
8. **Auto-excluding a server that trips an alarm.** If a third party can induce the
   detection, auto-exclusion knocks out honest servers and leaves the victim with the
   attacker's. Only self-consistency failures are safely automatic; root divergence names
   two servers without saying which lied. §4.5.
9. **Making the indexer fork call our `canonical` package.** Convenient, and it makes
   the differential test vacuous. Keep the two computation paths independent. §6.4.
10. **Recomputing the root before resolving gaps.** It looks like the cheap ordering and
   it is the hole that made §2.4's hashless gap exploitable: a position returned as a
   hole makes the root uncomputable, so the block is silently never verified. Resolve
   first, recompute second, and never call a block clean whose root was not recomputed.
   §2.5.
11. **Treating `headers` as SPV.** Proof-of-work carries no integrity on signet; BIP-325
   puts it in the challenge signature. `headers` is a store of `(height, hash)`
   observations with a contested-past-six-confirmations rule, not a most-work chain.
   §4.6.
12. **Committing secrets.** `.gitignore` already covers `nsec*`, `*.key`, `*.pem`,
   `.env`, `blindbit.toml`, `bitcoin.conf`. We will handle Nostr signing keys and Core
   RPC config; keep them out.

## External facts worth not re-deriving

- **An indexer cannot identify which transactions pay a published SP address** — that
  needs the private scan key. So targeted omission requires out-of-band knowledge, and
  the party who always has it is the sender. Hence the motivating scenario: *the exchange
  that pays you is also the indexer that tells you whether you were paid.* §1.2 / §5.
- **BIP-352 v1.1.0 (Mar 2026)** states the withholding trust assumption itself.
- **Bitshala's BIP-352 guide (3 Aug 2026)** calls trustless tweak sourcing "the big one."
- **Core PR #28241** (SP index) closed unmerged Feb 2025. Its "consistency check" means
  test-vector validation, not client-side detection. No collision.
- **Delving thread 891** (Jun 2024) is the canonical light-client discussion. harding's
  three attacks are all *commission*. Omission was never separately analyzed.
- **blindbit-oracle v2** needs Bitcoin Core **v30+**, unpruned, REST enabled
  (`/rest/spenttxouts`, Core PR #32540). `/info` already advertises policy-ish feature
  flags — a natural place to hang a policy declaration.
- **gobip352 already has the primitives** — `ExtractEligibleVins`, `ExtractPubKey`
  (NUMS-H included), `ComputeInputHash`. `canonical` is those plus transaction-level
  rules, ordering and leaf construction. But blindbit-oracle is the same author on the
  same library, so differential testing against it exercises the wrapper, not the
  primitives. §6.4.
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
