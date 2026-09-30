# CLAUDE.md — working context for Canary

Read this first. It records decisions already made, so they are not reopened without the
user. It also names the mistakes that will be tempting to make.

---

## What this is

**Canary** detects when a BIP-352 silent-payments tweak indexer withholds data. Today a
light wallet cannot tell "nobody paid you" from "the server left your payment out". There
is no error and no symptom, and the loss is permanent.

Built for **BOSS Battle** (Bitshala), 7 Sep – 5 Oct 2026, Cypherpunk track. One winner
per track, $1,000.

- **Hard deadline: Monday 5 Oct 2026, 23:59 IST (18:29 UTC).** Aim to publish on Devfolio
  by 17:00 IST. A saved draft does not count; it must say Published.
- Results come out on 12 Oct 2026.

Repo: `github.com/Sky-walkerX/canary`. It stays **private** until submission, because
publishing early hands the idea to competitors. It goes public, with an MIT `LICENSE`,
on 5 Oct.

## Current state — 2026-09-30

**The design is approved and implementation is under way.** The approval gate passed on
8 Sep. Write code test-first, within the approved 30 Sep plan. Changes to the settled
design still need the user's approval.

**Source of truth for scope:** the approved plan at
`/Users/skywalker/.claude/plans/pasted-content-id-0f6e-refactor-all-compiled-engelbart.md`.
It lives outside the repo. The scored feature roadmap, with the v1 cut line and the v2
themes, is `docs/roadmap/2026-09-30-feature-roadmap.md`.

| Part | State on 30 Sep |
|---|---|
| Design doc, sections 1–8 | Settled on 8 Sep. The eight amendments below were approved on 30 Sep and applied to the doc the same day, under "Amendments of 2026-09-30". Exact byte layouts are in `docs/design/2026-09-30-v1-formats.md` |
| `canonical`, `commit`, `feed`, `policy`, `internal/testvector` | Built. On the evening of 30 Sep, `go test ./... -count=1` passed in all 7 packages on Go 1.26.4: 80 top-level tests, none failing. That count includes `wire` and `commit.ProveFromLeafHashes`, both added that day and not yet committed. Rerun the tests rather than trusting this count |
| `wire`, including `wire/receipt.go` | In progress. `wire/response.go` is written and its tests pass, not yet committed. `wire/receipt.go` is not written. **Finishing it is the next task** |
| `cmd/canary-indexer`, the reference indexer with `--withhold-txid` | Not started |
| `ladder`, minimal, applying the retention rule | Not started |
| `evidence` | Not started |
| `cmd/canary`: `check`, `verify`, `status`, `ui` | Not started |
| Tripwire, tweak check only | Not started |
| `internal/ui`, `cmd/site`, `cmd/verify-wasm` | Not started; a parallel Claude session builds them |
| `scripts/demo-regtest.sh` and the committed evidence file | Not started |

Also true on the morning of 30 Sep: six commits were not pushed, the repo had no
`LICENSE`, and no `bitcoind` was installed. CI runs `go vet` and `go test`, and has passed
on every pushed commit.

**Next task:** finish the `wire` package with receipts (`wire/receipt.go`), then the
reference indexer. The state-file and evidence-file JSON schemas were frozen on 30 Sep in
`docs/design/2026-09-30-v1-formats.md`, because the UI reads them. A change needs a
version bump and the user's approval.

- Design doc: `docs/design/2026-09-06-canary-design.md`
- Research and citations: `docs/research/prior-art.md`, re-verified 30 Sep
- Glossary: `docs/glossary.md`

## Decisions made 2026-09-30

These override anything older in this file. The sections from 7–8 Sep below are kept as
history until they move to `docs/decisions.md`.

| Decision | Why |
|---|---|
| **Team: one developer plus Claude** | The three-person split in the 8 Sep plans no longer applies. Parallel Claude sessions build the UI and the docs. When time runs short, the core detection loop wins |
| **Ship v1 by 5 Oct 23:59 IST, then keep building** | The roadmap holds the v2 themes: 13–25 Oct, BOSS Summit (26 Oct–1 Nov) and btc++ Seoul (5–6 Nov) |
| **Regtest for v1** | It needs no public server and no signet coins, and we can mine on demand. The demo video says why. Say "v1 is built and tested on regtest only", not "runs only on regtest": `canary check` accepts other networks and prints a notice that they are untested. Signet and mainnet come after v1 |
| **No daemon and no proxy in v1** | `canary check` writes a state file, and `canary ui` reads it. The proxy returns after v1, as a reverse proxy for the BlindBit v1 HTTP API |
| **The v1 reference indexer reuses `canonical`** | A deliberate, v1-only exception to mistake 9 below. It saves building a fork. The docs must say that v1 does not test two independent implementations against each other |
| **The output hole is named now and fixed in v2** | Canary's entry is `(txid, tweak)`. Wallets decide whether a payment exists from output data that Canary does not commit to: the BlindBit v1 filter and `/utxos`, or v2's `outputs_short`. So "Checked" means the tweak list was checked, never that payments were |
| **Cypherpunk track by default** | Add Freedom Stack only if the 7 Sep handbook allows it and the pitch has a genuine crossover |
| **UI: Go `html/template`, with the Safety Lamp identity** | No Node, no single-page app, and no server-sent events in v1. See the identity notes below |
| **Eight design amendments** | Listed below. They amend the settled design, and the design doc was updated to match on 30 Sep |

### The eight design amendments

1. **Retention rule, in the
   [comparison procedure](docs/design/2026-09-06-canary-design.md#25-comparison-procedure).**
   An entry left out entirely
   while the block is less than 144 blocks deep is an omission. Canary names the server
   and marks the block Compromised ("Data withheld"). Before this, the case ended as
   Unresolvable or Clean, so the demo's attack never produced an accusation.
2. **Receipts move into the core.** `wire/receipt.go` defines `Receipt`, its digest and
   `VerifyReceipt`. A receipt signs a version byte, the network, the resource type, the
   block hash, the request parameters, the server's tip height and hash, and a SHA-256 of
   the bytes served. The network stops a receipt from one chain passing on another. The
   resource type stops a later receipt for output data passing as one for a tweak list.
   It travels in an `X-Canary-Receipt` response header. The 178-byte layout is in
   section 3 of the v1 formats doc.
3. **The evidence file, `canary-evidence/1`,** carries the served bytes and the receipt.
   `canary verify` recomputes the result itself. Without a receipt it prints "inclusion
   only: you can be sure of this, you can't yet prove it to others."
4. **Named limits,** in the
   [out-of-scope list](docs/design/2026-09-06-canary-design.md#15-attacks-explicitly-out-of-scope)
   and [Limits of v1](docs/design/2026-09-06-canary-design.md#limits-of-v1), the README
   and demo act 5. There are three:
   - Output-side withholding: filters, UTXO lists and `outputs_short`.
   - The hash-only variant under a pruning policy. The block reads Checked, gap filled
     (`resolved`, reason `hash_retained`). A server that declares no filtering and still
     sends a hash gets a warning, reason `hash_without_policy`, never an accusation,
     because v1 policies are unsigned.
   - Reach: v1 is built and tested on regtest only.
5. **Demo changes.** The demo runs on regtest, and the video says why. Act 1 is restaged
   as "the served data lacks the entry", because v1 has no wallet in the loop. One
   competitor (QuietRelay) reports a 3-to-5-minute rule from the private handbook; target
   3:15–4:30, at least 180 s. The malicious switch is `--withhold-txid`, with visible help
   text.
   - Act 3b is the Servers disagree (`disputed`) branch. The attacker signs a record for
     the smaller list, and a second, honest indexer signs a different root. v1 detects
     Servers disagree; only staging the scene is optional.
   - Act 5 closes on a Can't be checked (`unresolvable`) range, not on a Not checked one.
6. **No daemon and no proxy in v1,** as above.
   [Proxy, not observer](docs/design/2026-09-06-canary-design.md#62-proxy-not-observer)
   also records that "refuse Unverified" is wrong. Today's servers publish no
   commitments, so that rule would refuse every block they serve.
   - The v2 proxy refuses Data withheld and Servers disagree blocks. Whether it also
     refuses Can't be checked blocks is an open v2 decision.
   - A server that signed records for the blocks on both sides of a block, but not that
     block, is no longer refused. The block reads Not checked, reason
     `no_record_for_block`, with a warning. It is never an accusation.
7. **The `network` Nostr tag holds the decimal network magic;** regtest is `3669344250`.
   `feed/commitment.go` is right, and the doc changes to match. Do not switch the tag to
   a display name, because a name would merge two custom signets.
8. **Default track: Cypherpunk only,** as above.

The prior-art and citation corrections of 30 Sep (SPCOMMIT, the BIP-352 quotes) are a
note, not an amendment. Use this numbering in every doc that lists the amendments.

### Format changes decided on the evening of 30 Sep

`docs/design/2026-09-30-v1-formats.md` is the source of truth for byte layouts, reason
codes, the state mapping and the CLI. Where the design doc or the roadmap disagrees with
it, they change. These three changes went into the formats doc itself:

1. **New warning reason `hash_without_policy`.** A server whose `/info` declares no
   filtering sent a position as a hash only. It shows as a warning, never an
   accusation, because v1 policies are unsigned.
2. **Declared-payment findings split in two.**
   - The server's signed record leaves the declared entry out: always an accusation,
     with no spent check. Nobody else can confirm it unless Canary can write an
     evidence file for it, and v1's format has none for this case.
   - The list carries only a hash for the declared entry, or marks it absent outside the
     retention window: an accusation only when Core
     shows one of the payment's taproot outputs unspent, since pruning could explain a
     spent one. It is not provable to others either, because the evidence format cannot
     show an output unspent.
3. **Status line.** `canary status` prints the formats doc's line, in UTC. The dashboard
   adds the viewer's local time and a relative age, such as "6 min ago".

Also settled: the v1 tripwire is one declared payment. Scheduled probes at random times,
with randomised amounts, are v2 (roadmap feature F25).

### UI identity: Safety Lamp

- Coal `#17160F` on limestone `#F5F3EC`. Dark mode uses `#121210`.
- Canary yellow `#F4E13A` is the brand colour and **never a state colour**. Text in the
  yellow family uses `#5E5700`.
- State colours must measure at least 4.5:1 contrast. Every state shows as glyph plus word
  plus colour, never colour alone.
- Fonts: self-hosted Atkinson Hyperlegible Next and Atkinson Hyperlegible Mono (OFL).
- Radii of 2–4px, flat surfaces, 1px rules. Only data moves, and the UI honours
  `prefers-reduced-motion`.
- Banned: gradients, glass, emoji, a hero plus three cards, stat tiles, pills, toasts for
  events, "!", "secure" and "trustless".
- One wording table, `copy.go`, feeds the CLI, the UI and the wasm build.

On-screen labels for the six coverage states. The meanings are the general ones from
section 8 of the v1 formats doc; each state's reason code gives the specific case.

| Design name | On-screen label | Meaning |
|---|---|---|
| Verified | Checked | The root recomputed over every position matched the signed record, and no position needed filling. The tweak list was checked, never the payments |
| Resolved | Checked, gap filled | As Checked, but some positions came as hashes or were filled before the root was recomputed |
| Unresolvable | Can't be checked | Canary could not recompute the root. Neither a pass nor an accusation |
| Unverified | Not checked | There was no signed record to check against. Nothing about the block was checked |
| Disputed | Servers disagree | Two servers signed different records for the same block hash, and Canary does not know which lied |
| Compromised | Data withheld | One named server left out an entry it had signed for, or left out the entry for a payment you declared |

Do not narrow these meanings to one example. Can't be checked also covers a signed record
with no readable list, and Not checked also covers a server that did not answer.

### Known defects in the 8 Sep plans, found 30 Sep

Fix these while building; do not copy the plan code as written.

- The fork plan's omitter serves an absent position. The sidecar plan's `Compare` turns
  that into Unresolvable or Clean, never an accusation. Amendment 1 fixes this.
- An omitter that serves the correct leaf hash instead of nothing passes the per-block
  check. The block reads Checked, gap filled (`resolved`, reason `hash_retained`). This
  is the hash-only limit in amendment 4.
- The planned evidence artifact proves only inclusion, while the planned CLI claims it
  proves omission. Amendment 3 fixes this.
- `VerifyReceipt` sat in the fork's `internal/` tree, where the client cannot import it,
  and the receipt digest did not bind the server's tip. Amendment 2 fixes both.
- Fork Task B2 reverses the txid twice.
- The planned proxy returned 404 for every route except `/tweaks`, and refused every
  Unverified block. Neither matters for v1, which has no proxy.
- `commit.Prove` accepts only full leaves, and the evidence path needs proofs from leaf
  hashes. `commit.ProveFromLeafHashes` was added on 30 Sep, with a test that it agrees
  with `Prove`.

## Spec review — 2026-09-07 — ALL 15 FIXED

*History from 7–8 Sep. Names, weeks and owners in this section and the three that follow
refer to the superseded three-person plan. They are not current assignments.*

A `/code-review` pass over the full spec plus a self-review found 15 defects. All fifteen
are now closed in the doc. Kept in full because the *reasoning* is the expensive part and
someone will want to reopen one of these.

### Design-level — FIXED 2026-09-08

| # | Defect | Fix applied |
|---|---|---|
| 4 | §5.1's free out-of-band probe was overclaimed | "Strictly more useful" deleted. §5.1's table now has a third column separating what each source *gives*: a self-payment attributes with no node because the client holds the prevouts; an out-of-band txid is **detection only**, since without prevouts there is no tweak, no `missing_leaf`, no §4.7 artifact. And it is unavailable against §1.2's attacker **by construction** — a sender hiding a payment does not disclose its txid, and one who does must serve it honestly or be caught by an assertion they created. Free coverage against indexers *other than* the discloser, which is common because payer and indexer are usually unrelated. §5.4 and §6.7 aligned |
| 5 | `dust_threshold_sat` is unverifiable in principle | **Field kept, demoted.** The leaf carries no value, so a client can never check a dust-justified gap — and does not need to, because **no verdict in §2.5 takes the threshold as an input**. A resolved gap needs no reason; an unresolved gap is *unresolvable* whatever was declared. It survives for two non-verification jobs: routing §2.5's effort budget, and creating a contradiction a rung-4 attributor (who holds the block, hence the values) can check. §2.3 also records **putting the value in the leaf as considered and rejected** — 8 bytes on every leaf to buy nothing |
| 6 | Merkle root over an empty leaf set undefined | `merkle_root(∅)` = **32 zero bytes**, outer root computed over it unchanged. No fourth tag, and safe because `n` is already bound into the preimage, so `n = 0` cannot collide with any `n ≥ 1` root for the same block. §3.2 also pins `n = 1` (the leaf hash itself). **An empty set is committed, not skipped** — skipping restores defect #2's hole wearing the phrase *"no commitment, because there was nothing to commit."* §7.5's property row now starts at `n = 0` |
| 7 | Multi-letter Nostr tags are not relay-indexed | Block hash moved to the single-letter **`b`** tag, the query key; `height`, `n`, `network`, `policy_ref` stay multi-letter, carried for readers not filters. §3.3 also records the consequence nobody had noticed: **NIP-01 has no range query at all** — tag filters have no range operators and `since`/`until` act on the untrusted `created_at` (§3.5). So `Feed.Get` became a **batch call** over block hashes the client already knows, chunked to the relay's limit. §6.3 has no known-open interfaces left |

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
a one-line fix, not a redesign, and it does not depend on the (since superseded) week-2
fork.

## Spec self-review — 2026-09-08 — 7 findings, all fixed

Run after §8 landed, per `superpowers:brainstorming`. Placeholder scan came back clean.
Seven findings, all corrected in place.

| Finding | Fix |
|---|---|
| **§4.1's ladder table quietly rebuilt defect #2's ordering.** *"Each rung runs only when the one above it says something"* put gap resolution **after** self-consistency completed. §2.5 fixes the opposite order and calls it load-bearing. Someone implementing from the table alone rebuilds the hole | Rung 3's trigger now reads *before rung 2 can finish*, followed by a paragraph stating that rung 3 runs **inside** rung 2 and that sequential stages restore the closed hole |
| **§5.4 asserted a split §4.4 did not make** — verified-by-cross-check versus verified-by-tripwire | §4.4's *Verified* row carries the qualifier now, and says only the tripwire form is reachable under total collusion |
| **§5.4 still said "live demo"**, contradicting §8.1, where the format is recorded and async and live-failure risk is explicitly zero | Now "§8's demo" |
| **§0 understated the wire cost ~6×.** "32 bytes per block per server" is the root — what is *compared*. The event is ~200 bytes, and §3.7 says so two sections later | §0 names both numbers. Same class as defects #10 and #11: a figure a skeptic recomputes |
| **§2.5's three terminal states and §4.4's six coverage states had no stated mapping** | §4.4 maps them: *Clean* → **Verified** or **Resolved**, *Omission detected* → **Compromised**, *Unresolvable* unchanged, and Unverified / Disputed have no per-block equivalent |
| **§8's long-lead items had no week.** §8.6 wants signet funding "weeks early" and repeated takes; §6.6 put the whole demo in week 4 | Signet funding moved into the week-1 gate, plus a note that week 4 is editing and pitch, not first takes |
| **§8's act 1 / act 2 sequencing was ambiguous** — is the flag applied on camera or revealed? | Pinned: already running in act 1, revealed in act 2. The alternative is recorded along with the reason it loses |

**Scope check:** one spec, three binaries, three owners. It does not need decomposing,
but `writing-plans` will likely produce more than one plan — the protocol core, the
indexer fork and the sidecar separate cleanly along §6.5's ownership lines.

## §8 Demo — written 2026-09-08

In the doc now, at §8. **Amendment 5 of 30 Sep changes four of the points below**, and
each one is marked. The rest still stand:

- **Async format decides the content.** Recorded video plus a repo that reads alone, so
  live-failure risk is zero, so **nothing may be faked** — a fake has no upside and total
  downside. Two judges with disjoint behaviour: one watches and never opens the repo, one
  opens the repo and never finishes the video. §8.5 serves the second.
- **Show the loss before the tool.** Five acts. Wallet at 0 while the explorer
  shows the payment → the one config flag → detection → offline `canary verify` with the
  network interface down → **the honest limit**, closing on an *unresolvable* range.
  *Amended 30 Sep:* the video no longer runs 2:45. One competitor (QuietRelay) reports a
  3-to-5-minute rule from the private handbook; target 3:15–4:30, at least 180 s. Act 1
  becomes "the served data lacks the entry", because v1 has no wallet in the loop. Act 5
  still closes on a Can't be checked (`unresolvable`) range.
- **Act 5 is not optional.** Ending on the boundary is the register this track is judged
  in, and *unresolvable* is the clearest artifact of the design's discipline.
- **The attack targets a txid, not an address**, because an indexer cannot select by
  address without the scan key (§1.2). An address filter would quietly concede the
  premise the threat model rests on.
- **Act 3b shows the other branch** — the attacker who commits to the omitted set is
  caught by rung 1 instead of rung 2. It is the answer to the only strong objection.
  *Amended 30 Sep:* act 3b is the Servers disagree (`disputed`) branch. The attacker
  signs a record for the smaller list, and a second, honest indexer's root differs. v1
  detects Servers disagree; only staging the scene is optional, and it is no longer the
  first cut.
- **Repo path: README to a personally verified accusation in under 60 seconds**, from a
  real artifact of a real run. *Amended 30 Sep:* publishing the events to public relays
  is a stretch goal in v1, so the event IDs may not resolve on a relay.
- ~~Regtest is the fallback, not the plan.~~ *Reversed 30 Sep:* regtest is the plan for
  v1, and the video says why.

## Implementation plans — written 2026-09-08

Spec approved by the user on 2026-09-08. `superpowers:writing-plans` produced
**three** plans in `docs/superpowers/plans/`. Their owner columns assumed a team of three,
which no longer applies. Status on 30 Sep:

| Plan | Tasks | Status on 30 Sep |
|---|---|---|
| `2026-09-08-canary-protocol-core.md` | 16 — `canonical`, `commit`, `policy`, `feed`, `wire`, vectors | Tasks 1–14 shipped. Task 15 (`wire`) and Task 16 (corner vectors and the generator) are open |
| `2026-09-08-canary-indexer-fork.md` | 8 — blindbit-oracle fork: commit, publish, receipts, `--omit-txid` | Not started. For v1, `cmd/canary-indexer` replaces the fork and reuses `canonical` |
| `2026-09-08-canary-sidecar.md` | 9 — `headers`, `ladder`, coverage, proxy, CLI | Not started. For v1, `canary check`, `verify`, `status` and `ui` replace it, with no proxy |

The 30 Sep plan governs v1 scope. Read the known defects listed near the top of this
file before reusing code from these plans.

### Verified against the real packages, not against documentation

Before writing a line of the plans, the external APIs were fetched and run:

- **`bip352.TaggedHash` is a genuine BIP-340 tagged hash**, checked against
  `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)`. §3.2's entire construction rests on
  this, so it was tested rather than assumed.
- **`ExtractPubKey` returns 33 bytes for P2WPKH/P2PKH/P2SH and 32 x-only bytes
  for P2TR**, and signals failure with `TypeUTXO == Unknown`, not an error. The
  caller must lift x-only keys to 33 bytes with an `0x02` prefix before summing.
- **The tweak chain is** `ExtractEligibleVins` → `ExtractPubKey` per vin → lift →
  `SumPublicKeys` → `ComputeInputHash(eligible, sum)` → `TweakPubkey(sum, hash)`.
  Argument order confirmed by running it.
- `ExtractEligibleVins([])` returns `(empty, nil)`, **not** `ErrVinsEmpty`.
- `Vin.Witness` is `[][]byte`, not `[][][]byte` (a docs summary got this wrong).
- `NumsH` is exported, so §7.3's corners assert against the library's constant.
- go-nostr: `Event{ID, PubKey string, CreatedAt, Kind int, Tags, Content, Sig}`,
  `Sign(hexSecretKey)`, `Filter{Kinds, Authors, Tags TagMap, Since, Until}`.

### Plan self-review — 2026-09-08 — 6 findings, all fixed

| Finding | Fix |
|---|---|
| **`Position` was defined in the fork's `internal/server`, and the sidecar imported it.** Go forbids importing another module's `internal/` tree — this would have compiled in the fork and broken the moment Plan C built | Moved to the core as the **`wire` package** (Plan A Task 15). Both binaries import it; neither owns it |
| **§2.5 step 5 and §4.3 had no task.** `Disputed` was a coverage state with no producer, and the union that defeats omission was unimplemented | Plan C **Task 9**: `CrossCheck` and `Union`, with tests that the union is never an intersection and is deterministic under Go's randomised map iteration |
| **§7.3's corner vectors had no task**, and `genvectors` was a stub that exited 1 | Plan A **Task 16**: a real generator over Core's `/rest/spenttxouts`, plus the four corners. The NUMS-H pair is deliberately a pair — §7.3's expectation was inverted once already, and §7.6 ships these upstream |
| **`RootFromLeafHashes` was bolted onto Plan A from inside Plan C** | Moved into Plan A Task 4, written beside `Root` with an agreement test so the two paths cannot drift |
| **`canary.EventLookup` was referenced and never defined**, and the signed event was published but never stored | Plan B Task 4 Step 4 stores the event before the relay fan-out, so a total relay outage still leaves the client a signature |
| **§3.6's manual pinning had no task** | Plan C Task 8 Step 4: `canaryd` refuses to start on an unpinned indexer pubkey. No trust-on-first-use |

## Process we are following

The design went through `superpowers:brainstorming`: context, questions, approaches,
design in sections with approval after each, a written spec, then `writing-plans`. The
user approved the spec on 8 Sep and the 30 Sep plan on 30 Sep. Implementation is now under
way.

- **Build within the approved plan, test-first.** The core loop uses test-driven
  development; the UI and docs run in parallel Claude sessions.
- **The approval gate still applies to design changes.** Do not change the settled design,
  or add scope beyond the 30 Sep plan, without the user's approval. The user asked to
  "design things one by one", so show each design change before it lands.
- **The core wins when time runs short.** The plan lists the cut order and what is never
  cut.

## Decisions made before 30 Sep — reopen only with the user

Rows marked *Amended 30 Sep* are overridden in part by the 30 Sep decisions above.

| Decision | Why |
|---|---|
| **Layered: tool first, protocol second** | The client-side differ works against indexers as they exist and needs nobody's cooperation. The signed-commitment extension is the upgrade, not the foundation |
| **Sidecar daemon**, not library-first, not a public observatory | The library falls out of it for free. An observatory protects nobody, and the public servers are decaying (see below). *Amended 30 Sep:* v1 has no daemon and no proxy. `blindbitd`, the wallet this row first named, was archived on 2025-08-14; the realistic unmodified clients are blindbit-scan and Dana/spdk over the BlindBit v1 HTTP API |
| **Go** | blindbit-oracle, silentiumd and go-bip352 are all written in Go |
| **Signet, not mainnet** | Mainnet needs an unpruned Core v30+ and days of initial sync. Nothing in the design requires mainnet. *Amended 30 Sep:* v1 is built and tested on regtest only; signet comes after v1 |
| **Nostr for commitment transport** | Free public signed bulletin board (**publication, not timestamping** — see mistake #7), no infrastructure for servers to run; clients subscribe to a relay instead of opening N connections, which also avoids leaking which blocks they care about |
| **Construct edge cases, don't scan for them** | Deliberately hit ambiguous BIP-352 eligibility rules rather than hoping a chain supplies one. **On regtest, not signet** (§7.2) — several corners need arbitrary scripts and controlled block composition, and we cannot mine on public signet. *Amended 30 Sep:* the v1 end-to-end demo also runs on regtest |
| **Commit to the canonical set, not the served set** | All legitimate indexer policy is *subtractive*, so `Served ⊆ Canonical`. Committing to the policy-free set lets storage policy stay free while accountability does not. §2.1 — this is the load-bearing idea of the whole design |
| **Run all indexers locally** | Never depend on a third-party public server being alive — that fragility is literally what the project is about |
| **`network` in the root preimage is the 4-byte P2P magic, not an enum** | BIP-325 derives a custom signet's magic from its challenge, so the magic separates two signets that an enum would merge — and §2.7's first precondition is that both servers index the same network. Read from `chaincfg.Params.Net`; §7.4's vectors pin it in CI. Decided 2026-09-07 while closing spec-review defect #8 |
| **Six coverage states, with *disputed* split from *compromised*** | §4.5 already ruled that root divergence names two servers without saying which lied. One combined alarm state is exactly how an attacker gets an honest server excluded. Decided 2026-09-07 while closing defect #15 |
| **Chain agreement is a Canary output, not a Canary input** | The chain is the same problem Canary already solves: parties assert, they disagree, and the disagreement is transient or permanent. Reorgs resolve; lies persist. Reusing the commitment feed costs nothing, where an SPV chain cost a component and bought nothing on signet. Decided 2026-09-07 closing defect #1 |
| **The 144-block hash-retention window is a protocol constant, not a policy field** | A server allowed to declare its own window declares zero, which is the hole verbatim. Decided 2026-09-07 closing defect #2 |
| **BIP-325 solution validation is specified but not committed for v1** | It is the only anchor needing no trust, and it is 2–3 days plus every txid in the block. The single-server case rests on a node or a pin, and §5.3 says so. Decided 2026-09-07 closing defect #1. *Amended 30 Sep:* not in v1 at all. v1 is built and tested on regtest only, where it does not apply |

| **`dust_threshold_sat` stays, as a declaration and never as a proof input** | It cannot be verified — the leaf has no value — but nothing needs it to be: a resolved gap needs no reason and an unresolved one is *unresolvable* regardless. It earns its place routing effort and creating a contradiction rung 4 can check. Value-in-the-leaf rejected: 8 bytes per leaf to buy nothing. Decided 2026-09-08 closing defect #5 |
| **The empty set is committed, not skipped; `merkle_root(∅)` is 32 zero bytes** | `n = 0` is the *common* case on regtest, not a corner. Skipping would restore defect #2's hole under a new name. Zeros are safe because `n` is bound into the outer preimage. Decided 2026-09-08 closing defect #6 |
| **Block hash lives in the single-letter `b` tag, and `Feed.Get` is batched** | NIP-01 indexes single-letter tag names only, and offers **no range query at all** — no range operators on tags, and `since`/`until` act on the `created_at` we already refuse to trust. Batching hashes the client already knows is the only shape a relay can serve. Decided 2026-09-08 closing defect #7 |
| **Out-of-band txids are detection, never attribution** | Attribution needs prevouts, which only the payer and the transaction's author hold. And the §1.2 attacker never discloses a txid it is hiding, so the free probe is worth most against indexers unrelated to the payer — real, common, and not what §1.2 warns about. Decided 2026-09-08 closing defect #4 |

**Superseded:** the original dossier proposed OpenTimestamps anchoring. Nostr events
replace it. OTS may return in v2 to anchor the event chain.

## Framing discipline — this is not optional

**Canary does not make tweak sourcing trustless. It makes it accountable.**

Second framing decision, from
[coverage, not alarms](docs/design/2026-09-06-canary-design.md#44-the-primary-output-is-coverage-not-alarms):
**the primary output is coverage, not alarms.** An alarm that never fires looks like a
product that does nothing. Coverage, per block range, is continuous and visible. Six
states as of the 2026-09-07 corrections — verified / resolved / unresolvable / unverified
/ **disputed** / compromised, where *disputed* is unattributed root divergence and
*compromised* is attributed, because
[Acting on alarms](docs/design/2026-09-06-canary-design.md#45-acting-on-alarms) keeps
those apart. It also yields the line worth leading with: *a balance computed over blocks you could not verify is a
lower bound, not a balance.*

Say this first — in the README, in the docs, in the first 30 seconds of the pitch. A
limitation volunteered reads as rigor; the same limitation extracted by a judge reads as
overclaiming. The security claim is conditional and must always be stated with its
condition: *given at least one honest indexer publishing commitments, and an uncensored
path to a relay carrying them.*

Related discipline: cite Certificate Transparency (RFC 6962) for the split-view
insight. We are applying it, not inventing it.

Added 30 Sep:

- **We are not first.** SPCOMMIT (Rob Segers) has published tweak-list commitments for
  mainnet since 1 Sep 2026. Cite it next to RFC 6962. Canary's claim is narrower: a check
  at the client, one block at a time; filtered responses that leave explicit, signed
  gaps; and coverage states, evidence files and tripwires. Never write that filtering
  stays "checkable" without the condition. A hole inside the 144-block window names the
  server. A hole further back that nobody fills ends as Unresolvable. An entry sent as a
  hash passes the per-block check and reads Checked, gap filled (amendment 4). If the
  server declares no filtering, that raises a `hash_without_policy` warning, never an
  accusation. Under a declared pruning policy, only a tripwire on a payment you made
  catches it, and only while Core shows one of that payment's outputs unspent.
- **"Checked" covers the tweak list, not payments.** State the output hole wherever
  coverage is shown or claimed. SPCOMMIT v2 already commits to output prefixes.
- **Know versus prove.** The victim can know a single server withheld data. Proving it to
  someone else needs a signed receipt. Never write "proves" without that condition.
- **Disputed is not compromised.** Disputed means two named servers disagree and nobody
  knows which lied. Compromised means one server is shown to have withheld data. Never
  write "Canary tells you which server lied" without that distinction.

## Team

**One developer plus Claude**, decided 30 Sep. The developer drives the core detection
loop, test-first, with Claude. Parallel Claude sessions build the UI and the docs, and the
developer reviews them. Merges go through `main` one at a time.

The 8 Sep plans assumed three people, with separate owners for the core, the indexer
fork and the sidecar. That split no longer applies. The plan budgets about 50–55 hours of
the developer's time before 5 Oct, and the core loop alone needs 45–60 hours of work.

## Mistakes that will be tempting

1. **Diffing raw tweak sets.** It produces nothing but false positives. Honest indexers
   legitimately serve different sets — blindbit-oracle does cut-through and dust
   filtering, silentiumd indexes only transactions with unspent taproot outputs, and
   BIP-352 itself *blesses* cut-through. **Settled in
   [Canonical tweak sets](docs/design/2026-09-06-canary-design.md#2-canonical-tweak-sets-and-policy-normalization):**
   compare committed canonical sets, never served sets. Read that section before touching
   any comparison code.
2. **Claiming we solved commission attacks.** We did not. Injection-to-deanonymize is a
   different attack with the opposite structure; ephemeral Tor block fetching is the
   accepted answer. Our k-of-N rule raises the bar as a side effect — that is a note,
   not a claim.
3. **Reaching for mainnet.** Costs days, buys nothing the design needs.
4. **Building a wallet.** Canary checks what servers send; the wallet belongs to someone
   else. `blindbitd` was archived on 2025-08-14, so it is no longer the wallet to target.
   The realistic unmodified clients speak the BlindBit v1 HTTP API: blindbit-scan
   (headless Go, runs on regtest) and Dana through spdk. v1 has no proxy in front of
   either.
5. **Treating the research as durable.** `docs/research/prior-art.md` is dated and
   perishable — the entire project rests on the gap still being open. Re-verify before
   relying on it.
6. **Using a replaceable Nostr event kind.** Kinds 10000–19999 and 30000–39999 are
   overwritten in place. A server could retroactively publish a policy declaration after
   using it as cover and the original would vanish. Policy and commitment events are
   **regular kinds, append-only**. See
   [The commitment object](docs/design/2026-09-06-canary-design.md#33-the-commitment-object).
7. **Claiming Nostr gives us timestamping.** It gives us *publication*. `created_at` is
   self-asserted and backdatable. Each event is tied to a block by the block's hash, and
   order comes from the chain, never from `created_at`. See
   [What we do not trust about Nostr](docs/design/2026-09-06-canary-design.md#35-what-we-do-not-trust-about-nostr).
8. **Auto-excluding a server that trips an alarm.** If a third party can induce the
   detection, auto-exclusion knocks out honest servers and leaves the victim with the
   attacker's. Only self-consistency failures are safely automatic; root divergence names
   two servers without saying which lied. See
   [Acting on alarms](docs/design/2026-09-06-canary-design.md#45-acting-on-alarms).
9. **Making the indexer fork call our `canonical` package.** Convenient, and it makes
   the differential test vacuous. Keep the two computation paths independent. See
   [The BIP-352 library](docs/design/2026-09-06-canary-design.md#64-the-bip-352-library-supplies-the-primitives--and-what-that-costs).
   **v1-only exception, decided 30 Sep:** the v1 reference indexer, `cmd/canary-indexer`,
   reuses `canonical` on purpose. The docs must say so, and v1 must not claim to test two
   independent implementations. Any later fork of a real indexer follows the rule.
10. **Recomputing the root before resolving gaps.** It looks like the cheap ordering and
   it is the hole that made the hashless gap in the
   [wire model](docs/design/2026-09-06-canary-design.md#24-wire-model) exploitable: a
   position returned as a hole makes the root uncomputable, so the block is silently never verified. Resolve
   first, recompute second, and never call a block clean whose root was not recomputed.
   See [Comparison procedure](docs/design/2026-09-06-canary-design.md#25-comparison-procedure).
11. **Treating `headers` as SPV.** Proof-of-work carries no integrity on signet; BIP-325
   puts it in the challenge signature. `headers` is a store of `(height, hash)`
   observations with a contested-past-six-confirmations rule, not a most-work chain.
   See [Chain agreement](docs/design/2026-09-06-canary-design.md#46-chain-agreement).
12. **Committing secrets.** `.gitignore` already covers `nsec*`, `*.key`, `*.pem`,
   `.env`, `blindbit.toml`, `bitcoin.conf`. We will handle Nostr signing keys and Core
   RPC config; keep them out.
13. **Saying "Checked" means the payments were checked.** It means the tweak list was
   checked. A server can serve the right tweak and drop the output a wallet matches
   against, and v1 passes it. This is the output hole, named now and fixed in v2.
14. **Claiming Canary is the first to commit to tweak lists.** SPCOMMIT has done it on
   mainnet since 1 Sep 2026. Canary's differences are listed in the framing section.
15. **Citing BIP-352 as saying an indexer can withhold data.** It never says that, in
   any version. It says trustless tweak sourcing is "still an open question". The
   withholding wording is Bitshala's guide. See the external facts below.

## External facts worth not re-deriving

- **An indexer cannot identify which transactions pay a published SP address** — that
  needs the private scan key. So targeted omission requires out-of-band knowledge, and
  the party who always has it is the sender. Hence the motivating scenario: *the exchange
  that pays you is also the indexer that tells you whether you were paid.* See
  [Attacks in scope](docs/design/2026-09-06-canary-design.md#12-attacks-in-scope) and
  [Canary tripwire](docs/design/2026-09-06-canary-design.md#5-canary-tripwire).
- **BIP-352 never mentions an indexer withholding data**, in any version. A footnote says
  "It is still an open question as to how Bob can source the 33 bytes per transaction in
  a trustless manner". Appendix A, on light clients, is "out of scope for the current BIP
  ... to motivate further research". Both are in every revision since the file's first
  commit (15 Jan 2024).
  v1.1.0 (2 Mar 2026) only added the recipient limit `K_max`; the current version is
  1.1.1. Verified 30 Sep across all 34 revisions of the file.
- **Bitshala's BIP-352 guide (3 Aug 2026)** calls trustless tweak sourcing "the big one"
  and says "A light client that accepts tweak data from a server has no way to detect
  omission." Source: `x.com/bitshala_org/status/2084131259375296785`. This, not the BIP,
  is where the withholding wording comes from.
- **SomberNight** (Electrum maintainer) described the attack in `cake_wallet#2395`
  (17 Jul 2025): "I presently do not see a way how to fix this while using cut-through."
  Cake closed it as not planned. Canary answers part of it: holes inside the 144-block
  window become attributable, but hash-only withholding under a cut-through policy still
  reads Checked, gap filled (amendment 4).
- **The index-server spec** (`silent-payments/BIP0352-index-server-specification`) asks
  "How does a wallet know all tweaks were received for a given block request?"
- **SPCOMMIT is live prior art.** Rob Segers (`bitsagarob`, silentpayments.net) has
  published tweak-list commitments for mainnet since 1 Sep 2026. He posted the spec to
  bitcoin-dev on 2 Sep
  (`gnusha.org/pi/bitcoindev/6871d475-fbd4-4455-954d-20a369fba471n@googlegroups.com`).
  Optech #422 (11 Sep) described it without the name. It is a flat
  SHA-256 hash chain over the unfiltered list. Only the chain head is signed, posted every
  6 hours as a Nostr kind-1 note. v2 also covers `outputs_short` and spent outputs. No
  Merkle tree, no inclusion proofs, no network binding. Its author says a client given a
  filtered response "cannot check the subset for completeness". No wallet-side verifier
  was found on 30 Sep. Relay retention of its notes is poor except on nostr.mom.
- **tweak-service-auditor** (`silent-payments` org, Python) compares raw tweak lists from
  rbitcoin, BlindBit gRPC, Cake's electrs and Core. It runs on the operator's side, after
  the fact, with no signatures.
- **Live evidence for comparing committed lists, not served ones (30 Sep).** For mainnet
  block 969,300, silentpayments.dev returned 220 tweaks (full index) and 184 (filtered
  endpoint), and Cake's server returned 141. All 141 are in the 220.
- **Core PR #28241** (SP index) closed unmerged Feb 2025. Its "consistency check" means
  test-vector validation, not client-side detection. No collision.
- **Delving thread 891** (Jun 2024) is the canonical light-client discussion. harding's
  three attacks are all *commission*. Omission was never separately analyzed. A post on
  24 Sep 2026 by Segers adds measurements only.
- **blindbit-oracle v2** needs Bitcoin Core **v30+**, unpruned, REST enabled
  (`/rest/spenttxouts`, Core PR #32540). `/info` already advertises policy-ish feature
  flags — a natural place to hang a policy declaration. **v2 deprecates the HTTP data
  API in favour of a gRPC `OracleService`**, except `/info`. Five deprecated HTTP routes
  still run, but none matches the v1 API. The v1 branch still serves the v1 HTTP API
  (`/block-height`, `/tweaks`, `/tweak-index`, `/filter/*`, `/utxos`, `/spent-index`).
- **Clients, as of 30 Sep.** `blindbitd` was archived on 2025-08-14. blindbit-scan is a
  headless Go scanner on BlindBit v1 HTTP that supports regtest: the realistic unmodified
  client for a regtest demo. Dana (via spdk) also speaks v1 HTTP, but its released app is
  mainnet only. BlindBit Desktop speaks v2 gRPC and offers no regtest. v1 HTTP
  `/tweaks` returns bare 33-byte tweaks with no txid and no block hash.
- **Frigate** (Sparrow 2.5+) offers only `blockchain.silentpayments.subscribe`, which
  takes the wallet's scan private key. It serves no tweaks. **Cake's electrs** serves
  `blockchain.tweaks.subscribe` with no block hashes, applies cut-through, and has no
  integrity mechanism. From a light client without a full node, only a tripwire can check
  either. With a full node, a user can re-scan Frigate's blocks, and tweak-service-auditor
  already compares Cake's lists against Core.
- **shroud-indexer** (`github.com/CypherCommons/shroud-indexer`, MIT, TypeScript) began
  as `Bitshala-Incubator/silent-pay-indexer` and now lives under CypherCommons. It backs
  the Shroud wallet. Its JSON API is `/transactions/hash/{hash}` and
  `/transactions/height/{h}`; txids and block hashes are display-order hex, sorted by
  txid. It applies no dust limit and no cut-through, and publishes no commitments. Anmol
  Sharma, Bitshala's engineering head, wrote most of its commits; no source names him a
  judge. Say "Bitshala-incubated", not "Bitshala's own". Three code-reading findings (an
  empty HTTP 200 for unknown blocks, a varint bug at 253 or more transactions, and a
  first-opcode check that drops bare-multisig spends) are unconfirmed until run.
- **The BIP-352 library is `github.com/setavenger/go-bip352`, package `bip352`, v0.1.8** —
  **not** `gobip352`. Verified 2026-09-08 against the published module. The old
  `gobip352` path is v0.1.4 and does **not** export `ExtractEligibleVins` or
  `ExtractPubKey`; its README says eligibility is out of scope. Pointing `go.mod` at the
  old path silently deletes the eligibility layer. It has `ExtractEligibleVins`,
  `ExtractPubKey` (NUMS-H included), `ComputeInputHash`, a real BIP-340 `TaggedHash`, and
  an exported `NumsH`. `canonical` is those plus transaction-level rules, ordering and
  leaf construction. But blindbit-oracle is the same author on the same library, so
  differential testing against it exercises the wrapper, not the primitives. See
  [The BIP-352 library](docs/design/2026-09-06-canary-design.md#64-the-bip-352-library-supplies-the-primitives--and-what-that-costs).
- **`bip352.Vin.Txid` is display byte order**, and the leaf preimage in
  [Merkle tree](docs/design/2026-09-06-canary-design.md#32-merkle-tree) is internal byte order. Convert at the boundary, in one place. This is that section's stated trap with a real
  instance behind it.
- **Signet SP faucet**: `https://silentpayments.dev/faucet/signet/` — removes the need
  for a counterparty when demonstrating receipt. Not needed for v1, which is built and
  tested on regtest only.
- **`bitcoin.silentium.dev` stopped serving the API.** On 6 Sep the public indexer named
  in the light-client docs redirected to a parked page returning HTTP 200 with an
  identical 533-byte body for every path. A client pointed at it then got no error and no
  payments. On 30 Sep it returned an HTTP 301 redirect; that check did not follow the
  redirect. Useful as both a motivating example and a warning about demo dependencies.

## Conventions

- Design docs: `docs/design/YYYY-MM-DD-<topic>.md`
- Commit messages explain *why*, not just what. Trailer:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- Work on `main` for now; branch when parallel tracks start.
