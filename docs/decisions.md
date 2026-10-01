# Decision log

Why Canary is built the way it is, newest first. Each entry gives the date, the decision
and the reason. The [design document](design/2026-09-06-canary-design.md) holds the rules
as they stand now, and [v1 formats](design/2026-09-30-v1-formats.md) holds the exact
bytes. This file records how they got there, so nobody reopens a decision without knowing
what it cost the first time.

Terms are defined in the [glossary](glossary.md). Entries dated before 30 Sep mention
weeks, owners and a team of three. Those refer to the original plan, which no longer
applies: since 30 Sep, one developer builds Canary with Claude.

Some older entries use the design's names for the four client checks. In plain terms:
comparing signed roots across servers, checking one server's list against its own record,
filling gaps, and working out which of two servers lied.

---

## 1 October 2026: plain-language pass over the design

The design document was rewritten in plain language. No rule, number, byte layout or
decision changed, with two exceptions that bring it in line with the
[v1 formats](design/2026-09-30-v1-formats.md), which win where the two disagree:

| Change | Why |
|---|---|
| **v1's outside chain fact is the user's Core node only.** The pinned `(height, hash)` stays in the design, for after v1 | The frozen v1 command line requires `--core-rest` and has no pin flag. The design had said v1 takes both |
| **The v2 proxy refuses Compromised and Disputed blocks, and whether it refuses others is open.** The word "only" was dropped | The design's own proxy section lists two refusals still open for v2: Can't be checked blocks, and a missing record between two signed ones. "Only" settled a question that is still open |

The history the design carried moved here:

- The three-person ownership table and the four-week schedule are now under
  [The original three-person split](#the-original-three-person-split). The design keeps
  the two rules from them that still apply.
- One earlier draft said Canary commits to tweaks because that is where omission is
  silent. That was wrong. A server can hide a payment in the output data just as
  silently, which is why v1 names output-side withholding as a limit.
- Receipts were added while the design worked out the union across servers, which asked
  what Canary can prove to others, not only what it can detect.
- The design's other "an earlier draft said" passages were already recorded below. They
  cover the retention hole, the order of filling and recomputing, the SPV claim, the
  refusal rules, the storage figure, the inverted NUMS-H vector, and the evidence file
  that proved inclusion only.

## 30 September 2026, evening: changes to the v1 formats

The formats doc became the source of truth for byte layouts, reason codes, the state
mapping and the command line. Where the design document or the roadmap disagrees with it,
they change. Three changes went into the formats doc itself, before any program wrote
those formats, so no version number changed.

| Decision | Why |
|---|---|
| **A new warning, `hash_without_policy`.** A server whose `/info` declares no filtering sent a position as a hash only | Nothing the server signed declares its policy in v1, so the contradiction rests on unsigned data. It is a warning, never an accusation |
| **Declared-payment findings split in two.** If the server's signed record leaves the declared entry out, that is always an accusation, with no check on whether the outputs are spent. If the list carries only a hash, or marks the entry absent outside the retention window, that is an accusation only in one case. Core must show one of the payment's taproot outputs unspent | A record commits to every entry in the block, spent or not, so no policy explains a gap in the record. A gap in the list can be honest pruning when the outputs are spent. Neither finding is provable to others in v1: the evidence format has no claim for a missing entry, and cannot show an output unspent |
| **Status line.** `canary status` prints the formats doc's line in UTC. The dashboard adds the viewer's local time and a relative age, such as "6 min ago" | A terminal log reads best in one fixed time zone. A person glancing at a dashboard wants their own time and how stale the result is |
| **The v1 tripwire is one declared payment.** Scheduled test payments at random times and amounts wait for v2, roadmap feature F25 | v1 has no scheduler and picks no amounts. The single declared payment is enough for the demo's detection scene |

## 30 September 2026: the v1 plan

The user approved the plan for v1 on 30 Sep. It lives outside the repo, at
`~/.claude/plans/pasted-content-id-0f6e-refactor-all-compiled-engelbart.md`. The
[feature roadmap](roadmap/2026-09-30-feature-roadmap.md) carries the scored features, the
cut line and the dates after v1.

### Decisions

| Decision | Why |
|---|---|
| **One developer plus Claude.** Parallel Claude sessions build the UI and the docs, and the developer reviews them. Merges go into `main` one at a time | The three-person split in the 8 Sep plans no longer applies. The plan budgets about 50 to 55 hours of the developer's time before 5 Oct, and the core loop alone needs 45 to 60 hours of work. When time runs short, the core detection loop wins |
| **Ship v1 by Monday 5 Oct 2026, 23:59 IST, then keep building** | The roadmap holds the later themes: 13 to 25 Oct, the BOSS Summit from 26 Oct to 1 Nov, and btc++ Seoul on 5 and 6 Nov |
| **Regtest for v1** | It needs no public server and no signet coins, and blocks are mined on demand. The demo video says why. The wording is "v1 is built and tested on regtest only", not "runs only on regtest", because `canary check` accepts other networks and prints a notice that they are untested. Signet and mainnet come after v1 |
| **No daemon and no proxy in v1.** `canary check` writes a state file, and `canary ui` reads it | A proxy in the wallet's path costs 22 to 26 hours. It returns after v1, as a reverse proxy for the BlindBit v1 HTTP interface |
| **The v1 reference indexer reuses `canonical`** | It saves 4 to 6 hours of building a separate path. It breaks the rule that the indexer computes entries independently, so the docs must say v1 does not test two independent implementations against each other. The rule applies again to any later indexer |
| **The output hole is named now and fixed in v2** | Canary's entry is a txid and a tweak. Wallets decide whether a payment exists from output data Canary does not commit to: the BlindBit v1 filter and `/utxos`, or v2's `outputs_short`. So "Checked" means the tweak list was checked, never that payments were. Output keys in the entry cost 6 to 10 hours the budget does not have |
| **Cypherpunk track by default** | Add Freedom Stack only if the 7 Sep handbook allows a second track, and only with a genuine crossover pitch |
| **The UI uses Go `html/template` and the Safety Lamp identity** | No Node, no single-page app and no server-sent events in v1. A single-page app was measured at 50 to 65 hours, and v1 has no daemon for it to talk to. The identity is below |
| **The state-file and evidence-file formats froze on 30 Sep** | The UI and the checker build against them in parallel. A change needs a version bump and the user's approval |

**The Safety Lamp identity:**

- Coal `#17160F` on limestone `#F5F3EC`. Dark mode uses `#121210`.
- Canary yellow `#F4E13A` is the brand colour and never a state colour. Text in the yellow
  family uses `#5E5700`.
- State colours measure at least 4.5:1 contrast. Every state shows as a symbol, a word and
  a colour together, never colour alone.
- Fonts are Atkinson Hyperlegible Next and Atkinson Hyperlegible Mono, self-hosted, under
  the OFL.
- Corners have radii of 2 to 4 px, surfaces are flat, and rules are 1 px. Only data moves,
  and the UI honours `prefers-reduced-motion`.
- Banned: gradients, glass effects, emoji, a hero with three cards, stat tiles, pills,
  toasts for events, exclamation marks, "secure" and "trustless".
- One wording table, `copy.go`, feeds the CLI, the UI and the WebAssembly checker.

### The eight design amendments

These changed the settled design, so they needed the user's approval, which came with the
plan. The design document applied them the same day, under
[Amendments of 2026-09-30](design/2026-09-06-canary-design.md#amendments-of-2026-09-30).
Every doc that lists them uses this numbering.

1. **The retention rule.** An entry left out entirely while its block is less than 144
   blocks below the server's signed tip is an omission. Canary names the server and marks
   the block Data withheld. Before this, the case ended as Can't be checked or as Checked,
   so the demo's attack never produced an accusation
   ([Comparison procedure](design/2026-09-06-canary-design.md#25-comparison-procedure)).
2. **Receipts move into the core.** The `wire` package defines the receipt, its digest and
   its check. A receipt signs a version byte, the network, the resource type, the block
   hash, the request parameters, the server's tip height and hash, and a SHA-256 of the
   bytes served. The network stops a receipt from one chain passing on another. The
   resource type stops a later receipt for output data passing as one for a tweak list.
   It travels in an `X-Canary-Receipt` header, and its 178-byte layout is in
   [v1 formats](design/2026-09-30-v1-formats.md#3-the-receipt). The code moved because the
   client must check receipts, and Go does not let one module import another's
   `internal/` packages.
3. **The evidence file**, `canary-evidence/1`, carries the served bytes and the receipt.
   `canary verify` recomputes the result itself. Without a receipt it prints "inclusion
   only: you can be sure of this, you can't yet prove it to others." The earlier file held
   only the commitment and a proof. That shows the server signed for an entry, not that
   it left the entry out, and anyone could have built one against an honest server.
4. **Named limits,** in the design's
   [out-of-scope list](design/2026-09-06-canary-design.md#15-attacks-explicitly-out-of-scope)
   and [Limits of v1](design/2026-09-06-canary-design.md#limits-of-v1), the README and the
   demo's last act. There are three:
   - Output-side withholding: filters, UTXO lists and `outputs_short`.
   - The hash-only variant under a pruning policy. The block reads Checked, gap filled,
     with state `resolved` and reason `hash_retained`. A server that declares no
     filtering and still sends a hash gets a `hash_without_policy` warning, never an
     accusation, because v1 policies are unsigned.
   - Reach: v1 is built and tested on regtest only.
5. **Demo changes.** The demo runs on regtest, and the video says why. Act 1 becomes "the
   served data lacks the entry", because v1 has no wallet in the loop. One competitor,
   QuietRelay, reports a 3-to-5-minute rule from the private handbook, so the target is
   3:15 to 4:30 and at least 180 seconds. The withholding switch is `--withhold-txid`,
   with visible help text.
   - Act 3b is the Servers disagree branch. The attacker signs a record for the smaller
     list, and a second, honest indexer signs a different root. v1 detects Servers
     disagree; only staging the scene is optional.
   - Act 5 closes on a Can't be checked range, not on a Not checked one.
6. **No daemon and no proxy in v1.** The design's
   [Proxy, not observer](design/2026-09-06-canary-design.md#62-proxy-not-observer) also
   records that "refuse Unverified" is wrong. Today's servers publish no commitments, so
   that rule would refuse every block they serve.
   - The v2 proxy refuses Data withheld and Servers disagree blocks. Whether it also
     refuses Can't be checked blocks is an open v2 decision.
   - A server that signed records for the blocks on both sides of a block, but not that
     block, is no longer refused. The block reads Not checked, reason
     `no_record_for_block`, with a warning. It is never an accusation.
7. **The `network` Nostr tag holds the decimal network magic;** regtest is `3669344250`.
   `feed/commitment.go` was right, and the design text changed to match. A display name
   would merge two custom signets.
8. **Default track: Cypherpunk only,** as above.

**A note, not an amendment.** The same day corrected the prior art and the quotes. It
changed no design rule.

- The README, the prior-art file and CLAUDE.md all said BIP-352 v1.1.0 states that an
  indexer can withhold data. No revision of the BIP says that. v1.1.0 only added a
  recipient limit. The withholding wording comes from Bitshala's guide.
- SPCOMMIT, live on mainnet since 1 Sep 2026, is now cited as prior art. Canary cannot
  claim to be first with tweak-list commitments.
- `blindbitd`, the wallet the design first targeted, was archived on 2025-08-14. The
  realistic unmodified clients are blindbit-scan and Dana, over the BlindBit v1 HTTP
  interface.

### Defects found in the 8 September plans

Found on 30 Sep while checking whether the plans could produce the demo. Fix these while
building. Do not copy the plan code as written.

- The indexer plan's withholding switch serves an absent position, and the sidecar plan's
  comparison turns that into Can't be checked or Checked, never an accusation.
  Amendment 1 fixes this.
- A withholding server that serves the correct entry hash instead of nothing passes the
  per-block check. The block reads Checked, gap filled. This is the hash-only limit in
  amendment 4.
- The planned evidence file proves only inclusion, while the planned CLI claimed it proves
  omission. Amendment 3 fixes this.
- The receipt check sat in the indexer's `internal/` tree, where the client cannot import
  it, and the receipt did not sign the server's tip. Amendment 2 fixes both.
- The indexer plan reverses the txid twice when it builds entries.
- The planned proxy returned 404 for every route except `/tweaks`, and refused every
  Unverified block. Neither matters for v1, which has no proxy.
- `commit.Prove` accepts only full entries, and the evidence path needs proofs built from
  entry hashes. `commit.ProveFromLeafHashes` was added on 30 Sep, with a test that it
  agrees with `Prove`.

### Where the work stood on the morning of 30 Sep

The protocol core was built: `canonical`, `commit`, `feed`, `policy` and the test-vector
format, with 67 tests passing. Six commits were not pushed, the repo had no `LICENSE`, and
no `bitcoind` was installed. CI ran `go vet` and `go test` and had passed on every pushed
commit.

## 8 September 2026: the implementation plans

The user approved the design on 8 Sep. The design was built the brainstorming way:
context, questions, approaches, the design in sections with the user's approval after
each, a written spec, then plans. The user had asked to "design things one by one".

Three plans came out of it, in `docs/superpowers/plans/`. Their owner columns assumed
three people. Their status on 30 Sep:

| Plan | Scope | Status on 30 Sep |
|---|---|---|
| `2026-09-08-canary-protocol-core.md` | 16 tasks: `canonical`, `commit`, `policy`, `feed`, `wire`, test vectors | The first 14 tasks shipped. `wire` and the corner vectors with their generator were still open |
| `2026-09-08-canary-indexer-fork.md` | 8 tasks: a blindbit-oracle fork that commits, publishes, signs receipts and can omit a txid | Not started. For v1, `cmd/canary-indexer` replaces the fork and reuses `canonical` |
| `2026-09-08-canary-sidecar.md` | 9 tasks: `headers`, the checks, coverage, the proxy and the CLI | Not started. For v1, `canary check`, `verify`, `status` and `ui` replace it, with no proxy |

The 30 Sep plan governs v1 scope. Read the defects listed above before reusing plan code.

### The original three-person split

The 8 Sep plan assumed three people, four weeks, signet and a blindbit-oracle fork. Since
30 Sep one developer builds v1 with Claude, on regtest, with no proxy and no fork. The
design's Ownership and Dependency order sections held this record until 1 Oct.

| Owner | Scope |
|---|---|
| Naman, the protocol core | `canonical`, `commit`, `feed`. Then `tripwire` and `evidence` together, because the tripwire is what produces an evidence file with no node. Then the demo and the pitch |
| The indexer owner | The indexer fork: the canonical set at index time, commitment publishing, receipts, and the deliberately malicious mode |
| The sidecar owner | `canaryd`: the proxy, `ladder`, `policy`, `headers`, coverage and the CLI |

The indexer and sidecar owners were placeholders, never filled with names. The malicious
mode went to the indexer owner because it is a configuration flag on code that owner
already knew. The protocol core went to whoever could unblock the other two fastest.

The schedule was coarse on purpose. The detailed plan was the planning step's output.

| Phase | Gate |
|---|---|
| **Days 1–2** | Signet, Core v30 and blindbit-oracle running for all three. **Interfaces frozen** |
| **Week 1** | `canonical` agreeing with blindbit-oracle across ~1000 signet blocks. `commit`. A Nostr round trip. **Fund the signet UTXOs the signet demo needed** |
| **Week 2** | Commitments published end to end. Commitment tracking and the self-consistency check. Coverage. The proxy passing `blindbitd` traffic |
| **Week 3** | Tripwire, evidence and `canary verify`, the malicious mode, gap filling and attribution. The edge-case suite. If there was room, the BIP-325 signet solution check |
| **Week 4** | Demo, hardening, documentation, pitch. **Feature freeze 1 October**, four days before the deadline |

- **Interfaces froze on day 2, not at the end of week 1.** On a 28-day clock, the first
  quarter could not go by before parallel work began. Days 1 and 2 had all three people
  writing type definitions with no logic behind them. Everything after ran in parallel
  against stubs.
- **The week-1 gate mattered most.** Did `canonical` and blindbit-oracle produce the same
  set across 1000 signet blocks? It was a cheap harness, the start of the differential
  suite, and the earliest signal that `canonical` was wrong. It needed blindbit-oracle's
  full-index option and no dust threshold, and it did not wait on the indexer track.
- **Two demo tasks had a lead time longer than week 4.** Signet funding had to exist
  before the faucet stopped existing, so it moved into week 1. Recording had to start as
  soon as the end-to-end path worked, in week 3, so week 4 was editing, not first takes.
  The v1 demo runs on regtest, so the first task no longer applies.
- **Attribution had two forms.** The tripwire's node-free form landed in week 3 with the
  tripwire. The general auditor form was the stretch component and had no week.
- **The risk table** said to bring up Core v30 unpruned on signet on day 1, not in week 2,
  because it gated everything the indexer track did.
- **A day-1 check** was to confirm that blindbit-oracle accepts regtest. v1 uses its own
  reference indexer, so only the check that Core's REST endpoints behave on regtest
  remains.

**The library APIs were checked by running them, before any plan was written.** A docs
summary had already got one type wrong. The verified facts, such as the tagged-hash
construction and the tweak call chain, are in CLAUDE.md under external facts.

### Plan review: six findings, all fixed

| What was wrong | What changed |
|---|---|
| The per-position type lived in the indexer fork's `internal/server`, and the sidecar imported it. Go forbids importing another module's `internal/` tree, so it would have compiled in the fork and broken when the sidecar built | It moved to the core, as the `wire` package. Both binaries import it, and neither owns it |
| The union across servers and the cross-server root comparison had no task. Servers disagree was a state with nothing producing it | The sidecar plan gained a task for both, with tests that the union is never an intersection and stays deterministic under Go's random map order |
| The corner test vectors had no task, and the vector generator was a stub that exited with status 1 | The core plan gained a task: a real generator over Core's `/rest/spenttxouts`, plus the four corners. The NUMS-H vectors stay a pair, because their expectation was inverted once already and they are meant to go upstream |
| The sidecar plan added `RootFromLeafHashes` to the core from outside | It moved into the core plan, next to `Root`, with a test that the two paths agree |
| An event lookup was referenced and never defined, and the signed event was published but never stored | The indexer stores the event before sending it to relays, so a total relay outage still leaves the client a signature |
| Pinning each server's key by hand had no task | The sidecar refuses to start when a server's key is not pinned. There is no trust on first use |

## 8 September 2026: spec self-review, seven findings

Run after the demo section landed. A scan for placeholders came back clean. All seven
findings were fixed in place.

| What was wrong | What changed |
|---|---|
| The ladder table rebuilt the order the review had just removed. "Each check runs only when the one above it says something" put gap filling after the per-block check had finished. The comparison procedure requires the opposite order, and someone building from the table alone would have rebuilt the hole | The gap-filling row now runs before the per-block check can finish. A paragraph says gap filling runs inside that check, and that separate sequential stages bring the hole back |
| The tripwire section relied on a split the coverage section did not make, between Verified by cross-check and Verified by tripwire | The Verified row now carries that qualifier, and says only the tripwire form means anything when every server colludes |
| The tripwire section still said "live demo", while the demo section says the format is recorded and asynchronous, with no risk of a live failure | It now says "the demo" |
| The summary understated the cost on the wire by about 6 times. "32 bytes per block per server" is the root, the part compared. The event is about 200 bytes, as the cost section says | The summary names both numbers. This is the same kind of error as the storage and overhead figures below: a number a skeptic recomputes |
| The comparison procedure's three outcomes and the six coverage states had no stated mapping | The coverage section maps them. Clean becomes Verified or Resolved, Omission detected becomes Compromised, Unresolvable stays, and Unverified and Disputed have no per-block equivalent |
| The demo's long-lead tasks had no week. Signet funding was needed weeks early, and takes need repeating, yet the dependency order put the whole demo in week 4 | Signet funding moved into the week-1 gate, and week 4 became editing and pitch, not first takes. Superseded on 30 Sep, when the demo moved to regtest |
| It was unclear whether the withholding flag is switched on during act 1 or revealed in act 2 | It is already running in act 1 and revealed in act 2. The alternative is recorded, with why it loses |

**Scope check.** One spec, three binaries and three owners did not need splitting. The
planning step was expected to produce more than one plan, along the ownership lines, and
it produced three.

## 8 September 2026: the demo

Written into the design's [Demo](design/2026-09-06-canary-design.md#8-demo) section.
Amendment 5 of 30 Sep changed four of these points, and each change is marked.

- **The asynchronous format decides the content.** The deliverable is a recorded video
  plus a repo that reads on its own, so a live failure cannot happen, so nothing may be
  faked. A fake has no upside and total downside. There are two kinds of judge. One
  watches and never opens the repo, and the other opens the repo and never finishes the
  video. The repo path serves the second.
- **Show the loss before the tool.** The video has five acts. It opens on the wallet at 0
  while the explorer shows the payment. Then come the one config flag, the detection, and
  an offline `canary verify` with the network down. It ends on the honest limit, closing
  on a Can't be checked range.
  *Changed 30 Sep:* the video no longer runs 2:45. The target is 3:15 to 4:30 and at
  least 180 seconds. Act 1 becomes "the served data lacks the entry", because v1 has no
  wallet in the loop. Act 5 still closes on a Can't be checked range.
- **Act 5 is not optional.** Ending on the boundary suits the track, and Can't be checked
  shows the design's discipline more clearly than anything else.
- **The attack targets a txid, not an address.** An indexer cannot select by address
  without the scan key. An address filter would quietly concede the premise the threat
  model rests on.
- **Act 3b shows the other branch.** The attacker who signs a record for the smaller list
  is caught by the cross-server comparison instead of the per-block check. It answers the
  one strong objection. *Changed 30 Sep:* act 3b is the Servers disagree branch. The
  attacker signs a record for the smaller list, and a second, honest indexer's root
  differs. v1 detects Servers disagree, and only staging the scene is optional.
  *Open, for the user to settle:* the 8 Sep plan made act 3b the first cut if the video
  ran long. The CLAUDE.md of 30 Sep said it is no longer the first cut, while the amended
  design still makes it the first cut.
- **The repo path takes a reader from the README to an accusation they checked
  themselves in under 60 seconds,** using a real file from a real run. *Changed 30 Sep:*
  publishing the events to public relays is a stretch goal for v1, so the event ids may
  not resolve on a relay.
- ~~Regtest is the fallback, not the plan.~~ *Reversed 30 Sep:* regtest is the plan for
  v1, and the video says why.

## 8 September 2026: four review findings closed, and what they decided

These four came from the 7 Sep spec review and were fixed a day later.

| What was wrong | What changed |
|---|---|
| **The free probe from a disclosed txid was overclaimed.** The tripwire section called a txid disclosed by the payer "strictly more useful" than a payment you made yourself | That phrase is gone. The tripwire's source table now says what each source gives. A payment you made names the server with no node, because you hold the outputs it spent. A disclosed txid gives detection only. Without the spent outputs there is no tweak, no missing entry and no evidence file. It is also useless against the sender who is hiding a payment, by construction. That sender does not disclose the txid, and a sender who does must serve it honestly or be caught. It still gives free coverage against servers other than the one that disclosed it, which is common, because payer and server are usually unrelated ([Generalized statement](design/2026-09-06-canary-design.md#51-generalized-statement)) |
| **`dust_threshold_sat` cannot be verified.** An entry carries no amount, so a client can never check a gap excused by dust | The field stays, demoted. No outcome of the comparison takes the threshold as an input. A filled gap needs no reason, and an unfilled one is Can't be checked whatever the server declared. The field keeps two jobs that are not verification. It tells a client how hard to work on a gap, and it creates a contradiction that an auditor holding the block, and so the amounts, can check ([Policy declaration](design/2026-09-06-canary-design.md#23-policy-declaration)) |
| **The Merkle root of an empty list was undefined** | The tree root of an empty list is 32 zero bytes, and the outer root is computed over it unchanged. No fourth hash tag is needed. It is safe because `n` is bound into the outer hash, so an `n` = 0 root cannot collide with any other root for the same block. For `n` = 1, the tree root is the entry's own hash. The property tests now start at `n` = 0 |
| **Multi-letter Nostr tags are not indexed by relays** | The block hash moved to the single-letter `b` tag, which is the query key. `height`, `n`, `network` and `policy_ref` stay multi-letter, for readers rather than filters. NIP-01 also has no range query at all. Tag filters have no range operators, and `since` and `until` act on `created_at`, which Canary does not trust. So fetching records became a batch call over block hashes the client already knows, split to the relay's limit. No interface was left open |

Decisions made while closing them:

| Decision | Why |
|---|---|
| **`dust_threshold_sat` stays, as a declaration and never as an input to proof** | It cannot be verified, and nothing needs it to be. Putting the amount in the entry was considered and rejected: 8 bytes on every entry, plus a rule for which taproot output counts, to buy nothing |
| **An empty list is committed, not skipped** | `n` = 0 is the common case on regtest, not a corner. Skipping it would reopen the hashless-gap hole under a new excuse: "no commitment, because there was nothing to commit" |
| **The block hash lives in the `b` tag, and record fetches are batched** | NIP-01 indexes single-letter tags only and offers no range query. Batching hashes the client already knows is the only shape a relay can serve |
| **A disclosed txid gives detection, never attribution** | Attribution needs the spent outputs, which only the payer and the transaction's author hold. The sender hiding a payment never discloses its txid, so the free probe is worth most against servers unrelated to the payer. That case is real and common, and it is not the attack the threat model warns about |

## 7 September 2026: spec review

A code-review pass over the full spec, plus a self-review, found 15 problems. All 15 were
closed by 8 Sep. They are kept in full because the reasoning is the expensive part, and
someone will want to reopen one of them.

### Design problems fixed on 7 Sep

| What was wrong | What changed |
|---|---|
| **The header store gave no security on signet.** The design said Canary keeps its own header chain, verified by proof-of-work like standard SPV. On signet, integrity comes from the BIP-325 challenge signature, not from work, and a laptop can outrun the real chain | The proof-of-work claim is gone. A per-network table now says where integrity comes from: work on mainnet, the challenge signature on signet, nothing on regtest. The hole was narrower than it looked. Comparison is keyed on block hash, so "it was a reorg" was never available as an excuse for the comparison itself. Only whether a block is on the chain at all was exposed, in the tripwire's negative result and in coverage ranges. The fix makes chain agreement an output. A server on a fake chain must sign records for it and cannot withdraw them, so a height still contested six blocks later is a signed contradiction about the chain. With one server, Canary names the outside fact it needs: your own Core node, or a manually pinned height and hash. Checking BIP-325 signet signatures is specified but not promised for v1. The header store is no longer an SPV chain ([Chain agreement](design/2026-09-06-canary-design.md#46-chain-agreement)). The 30 Sep amendments weakened the "must sign" argument, because v1 refuses nothing, and the design says what replaces it |
| **An earlier amendment that day, dropping hash retention, opened a hole.** It argued that keeping hashes is only an optimization. That was right: given a candidate entry from anywhere, hashing it and recomputing the root proves it against the first server's own signature, so a second server is never trusted. What it missed is that "nobody can supply the entry" was a state the server could choose, for free. A position sent as nothing made the root impossible to compute, and the order of the checks then let the block pass | Three changes. The comparison fills gaps before it recomputes the root, and a block whose root was never recomputed is Can't be checked, never clean. How lenient a client is near the chain tip decides effort and reporting, never verification. And servers must keep at least each entry's hash for 144 blocks, which costs almost nothing because cut-through barely applies near the tip. The list also became self-describing at length `n`, so a truncated list cannot pass as a smaller block ([Wire model](design/2026-09-06-canary-design.md#24-wire-model)) |
| **The first comparison step broke the design's own tool-first layer.** It refused any block without a commitment, which would refuse every block from unmodified blindbit-oracle | The step now has three cases. A server that never commits is accepted as Unverified, feeds the union, and only the tripwire can catch it. A server that commits for neighbouring blocks but not this one was refused, because selective non-publication is the attack: evidence, not advertisement. The summary now says what the tool-first layer is: the union across servers, the `/info` policy and the tripwire. *Changed 30 Sep:* v1 refuses nothing, and that middle case reads Not checked with a warning |

### Factual and editorial problems fixed on 7 Sep

Each is listed with its fix, so nobody reopens it or puts a wrong number back.

| What was wrong | What changed |
|---|---|
| **The root's hash input left two encodings undefined.** The entry count's encoding was pinned, but `network` and `block_hash` were not, in the same table that flags txid byte order as a deliberate interop trap. The network list also said "signet / main" while every test vector was regtest | The [Merkle tree](design/2026-09-06-canary-design.md#32-merkle-tree) section now has a full encodings table. `block_hash` uses internal byte order, like `txid`. `network` is the 4-byte P2P message-start magic, read from `chaincfg.Params.Net` and pinned in CI by the regtest vectors. The network list gained regtest |
| **The test vector next to the NUMS point was inverted.** Flipping a control block's parity bit changes byte 0 only, and bytes 1 to 33 still equal the NUMS point H, so a correct implementation excludes the input. The table said "included". A correct implementation would have failed the vector, and "fixing" it would have added the exact bug the vector exists to catch. These vectors are meant to go upstream | The expectation is now "excluded". A second row, an ordinary script-path spend with a random key other than H, expects "included", so the pair catches both over- and under-exclusion. A note in [The corners](design/2026-09-06-canary-design.md#73-the-corners) explains the inversion |
| **The storage figure was wrong by about 6.5 times.** The draft said 5 MB. At 36 bytes for each of about 900,000 blocks, the answer is about 32 MB. Still a fine argument for adoption, but the cost table is the pitch to indexers, and a skeptic recomputes it | The figure is about 35 MB, with the arithmetic written out: about 965,000 blocks × 36 bytes. A note says why the arithmetic is shown ([Cost](design/2026-09-06-canary-design.md#37-cost)) |
| **"No overhead at all" was false, and two sections sized a mainnet block differently.** A 65-byte entry is about twice today's 33-byte tweak. One section used `n` ≈ 1,500 and another `n` ≈ 2,000 | The overhead is now stated honestly: a 65-byte entry, 66 bytes per position with its kind byte, against 33 for a bare tweak, roughly double. It cannot be avoided, because a light client cannot supply the txid. `n` ≈ 2,000 is used everywhere, and the proof figures were recomputed: 352 bytes per proof, about 700 KB of proofs against a list of about 130 KB |
| **The README described the checks from before the canonical-set design.** Its step 2 diffed raw served lists, the thing the design exists to avoid. Step 3 claimed no full node was needed, against the design. Step 4 was the old, narrow tripwire. Step 1 confused the 32-byte root with the 200-byte event. Its status line said only sections 1 to 5 were settled | The README was rewritten to the design's checks plus the tripwire, led by "served is a subset of canonical", with coverage and the lower-bound sentence. The headline dropped "provable", for the reason in the next row |
| **The security claim overclaimed twice.** Non-repudiation needs receipts, which the design then kept to the protocol layer, and the claim's condition did not mention them. "Within one block interval" is wrong for targeted omission, which shows up only when the client fetches that block. The cross-server check catches only diverging roots. The tripwire section said "thirty seconds" and the demo section said "one block interval" | The claim now reads "a detected event naming a server and a block", with two qualifiers attached. Detection is not proof: one server's omission needs receipts. Timing depends on the attack: diverging roots show up in about one block interval, and targeted omission shows up when the client fetches the block. The tripwire's delay is bounded by its own query ([Security claim](design/2026-09-06-canary-design.md#14-security-claim)) |
| **A section on what the design fixes for the team was stale on all three of its statements.** It said interfaces freeze at the end of week 1, where the packages section says day 2. It gave an old function signature. It said the corner cases could be built on signet, where the testing section says regtest | All three were corrected: the day-2 freeze, the real `Set(net, blk, pv) ([]Leaf, error)` signature, and regtest |
| **"Coverage is always on screen" was impossible, and Compromised contradicted the alarm rules.** An unmodified wallet cannot show coverage. It lives in `canary status`, which is the log nobody reads that the proxy section dismisses. The real answer is the proxy refusing blocks. Separately, "Compromised, named server" contradicted [Acting on alarms](design/2026-09-06-canary-design.md#45-acting-on-alarms), where diverging roots name two servers without saying which lied | The state split in two: Disputed, where roots diverge and two named servers stand unattributed, and Compromised, where one named server is attributed. That makes six coverage states. A table now shows that coverage reaches an unmodified wallet only through the proxy's refusal, not through a display |

**Smaller fixes, below the cap.** The tripwire was assigned to the protocol-core owner,
paired with evidence files, since the tripwire is what produces a file with no node.
Attribution was placed in week 3 in its tripwire form, with the general auditor form
named as a stretch. The packages section's literal `...` was replaced with signatures
that compile, plus a warning that the header store and record fetching were still open.
The prior-art file's "normalise before comparing" was marked superseded, with the reason.
The design header was dated "2026-09-06, revised 2026-09-07".

**A reviewer finding rejected as half right.** The review flagged the week-1 gate as raw
diffing of served lists. Running blindbit-oracle with `tweaks_full_basic=1` and no dust
filter gives a full index, comparable to the canonical set. The design simply never said
to do that. It was a one-line fix, not a redesign, and it did not depend on the indexer
fork planned for week 2, since superseded. The dependency-order section now says it.

### Decisions made while fixing them

| Decision | Why |
|---|---|
| **`network` in the root's hash input is the 4-byte P2P magic, not an enum of Canary's own** | BIP-325 derives a custom signet's magic from its challenge, so the magic keeps two signets apart where an enum would merge them. Comparison assumes both servers index the same network, so that distinction matters. The code reads it from `chaincfg.Params.Net`, and the regtest vectors pin it in CI |
| **Six coverage states, with Disputed split from Compromised** | Diverging roots name two servers without saying which lied. One combined alarm state is exactly how an attacker gets an honest server excluded |
| **Chain agreement is something Canary reports, not something it assumes** | The chain is the same problem Canary already solves. Parties assert, they disagree, and the disagreement is either transient or permanent. Reorgs resolve, and lies persist. Reusing the record feed costs nothing, where an SPV chain cost a component and bought nothing on signet |
| **The 144-block retention window is a fixed protocol rule, not a policy field** | A server allowed to declare its own window declares zero, which reopens the hole exactly |
| **BIP-325 signature checking is specified but not promised for v1** | It is the only chain anchor that needs no trust, and it costs 2 to 3 days plus every txid in the block. Until it lands, a single server's case rests on a Core node or a pin. *Changed 30 Sep:* not in v1 at all. v1 is built and tested on regtest only, where it does not apply |

## Before 7 September 2026: the architecture

The architecture was approved as a sidecar, a sequence of client checks and Nostr
transport, before the spec review.

| Decision | Why |
|---|---|
| **Layered: tool first, protocol second** | The client-side checker works against servers as they exist and needs nobody's cooperation. Signed commitments are the upgrade, not the foundation |
| **A sidecar daemon,** not a library first and not a public observatory | The library falls out of a sidecar for free. An observatory protects nobody, and the public servers are decaying. *Changed 30 Sep:* v1 has no daemon and no proxy. `blindbitd`, the wallet this first targeted, was archived on 2025-08-14, and the realistic unmodified clients are blindbit-scan and Dana over the BlindBit v1 HTTP interface |
| **Go** | blindbit-oracle, silentiumd and go-bip352 are all written in Go |
| **Signet, not mainnet** | Mainnet needs an unpruned Bitcoin Core v30 or later and days of initial sync, and nothing in the design needs mainnet. *Changed 30 Sep:* v1 is built and tested on regtest only, and signet comes after v1 |
| **Nostr carries the commitments** | It is a free, public, signed bulletin board, and servers run no extra infrastructure for it. It gives publication, not timestamping. Clients subscribe to a relay instead of opening a connection per server, which also avoids revealing which blocks they care about |
| **Construct edge cases instead of scanning for them** | Building transactions that hit the unclear BIP-352 eligibility rules beats hoping a chain holds one. They are built on regtest, not signet. Several need arbitrary scripts and control over what goes into a block, and nobody outside the signet operators can mine on public signet ([Regtest, not signet](design/2026-09-06-canary-design.md#72-regtest-not-signet)). *Changed 30 Sep:* the v1 demo also runs on regtest |
| **Commit to the canonical set, not the served set** | All legitimate server policy only removes entries, so what a server serves is always a subset of the canonical set. Committing to the unfiltered set leaves storage policy free while keeping servers accountable. The whole design rests on this ([The committed set and the served set](design/2026-09-06-canary-design.md#21-the-separation-committed-set-vs-served-set)) |
| **Run every indexer locally** | Never depend on a third-party public server being alive. That fragility is what the project is about |
| **Nostr instead of OpenTimestamps** | The original proposal anchored commitments with OpenTimestamps. Nostr events replaced it. OpenTimestamps may return in v2, to anchor the chain of events |
