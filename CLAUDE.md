# CLAUDE.md — working context for Canary

Read this first. It holds the current state, the rules, the decisions in force and the
verified external facts. The reasons behind older decisions, the review history and the
plan status live in [docs/decisions.md](docs/decisions.md). Reopen none of them without
the user.

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
- **Team: one developer plus Claude** (decided 30 Sep). The developer drives the core
  detection loop test-first with Claude. Parallel Claude sessions build the UI and the
  docs, and the developer reviews them.

Repo: `github.com/Sky-walkerX/canary`. It stays **private** until submission, because
publishing early hands the idea to competitors. It goes public on 5 Oct. The MIT
`LICENSE` is already committed.

## Current state on 2026-10-01

**The design is approved and implementation is under way.** The approval gate passed on
8 Sep. Write code test-first, within the approved 30 Sep plan.

**Source of truth for scope:** the approved 30 Sep plan. It is private to the developer
and is not in the repo. In the repo, the scored feature roadmap,
`docs/roadmap/2026-09-30-feature-roadmap.md`, carries the v1 cut line and the v2 themes.

**Every part of the v1 detection loop is built and tested, and on 1 Oct it ran end to end
on a real Bitcoin Core v31.1.0 node in regtest mode.** The tests still use a synthetic
chain, which `internal/core/coretest` builds in Go and serves the way Core's REST
interface does.

| Part | State on 1 Oct |
|---|---|
| Design doc, sections 1–8 | Settled on 8 Sep. The eight amendments of 30 Sep are applied, under "Amendments of 2026-09-30". Exact byte layouts are in `docs/design/2026-09-30-v1-formats.md` |
| `canonical`, `commit`, `feed`, `policy`, `internal/testvector` | Built and tested. `feed` has a relay client, but v1's checker fetches records over HTTP from each server and uses no relay |
| `wire`: tweak list and signed receipts | Built and tested. The receipt signs the server's tip. Every inside-or-outside decision about the retention window goes through `wire.InsideRetentionWindow` |
| `cmd/canary-indexer` and `internal/indexer`, with `--withhold-txid` | Built and tested |
| `ladder`: per-block states and reasons, gaps filled before the root | Built and tested |
| `evidence`: `canary-evidence/1` files and offline verify | Built and tested |
| `cmd/canary`: `check`, `verify`, `status`, `ui` | Built and tested. `check --expect` is the v1 tripwire, tweak check only |
| `internal/ui`, the local dashboard (`canary ui`) | Built and tested. `go run -tags uidev ./cmd/canary-uidev` shows it on sample data |
| `cmd/site`, the public site generator | Built and tested. It copies the browser checker into the site's hashed asset folder. With `-evidence` it publishes that file and a copy with one proof hash flipped, which fails at the inclusion step |
| `cmd/verify-wasm`, the browser checker | Built and tested. At `d52477d` on Go 1.26.4, `make wasm` gives 8,679,120 bytes raw (8.68 MB), 2.66 MB at gzip -9. Run in Node, it gives "Checks out." for the committed evidence file and makes no network call |
| End-to-end gate, `TestGate` in `cmd/canary/gate_test.go` | Passes. Two reference indexers on a 209-block synthetic chain, one withholding a taproot payment. `canary check` names the server, block and txid; the evidence file verifies in a process the operating system cuts off from the network (run on macOS; the Linux version runs in CI on ubuntu-latest amd64 and has passed on every push since it landed in `6c95886`; not run on Linux arm64); six one-byte tamperings each fail at their step; the dashboard shows the finding |
| A run on a real Bitcoin Core regtest node | Done on 1 Oct: `scripts/demo-regtest.sh --act5` on Core v31.1.0. Block 351 held five taproot payments. The withholder, key `db614560…`, left `ad56b9bb…e21e` out of its served list while signing it into its record. `canary check` over blocks 0 to 351, both servers pinned and the payment declared, gave 351 Checked · 1 Data withheld and named the withholder. Act 5: block 201 checked with the withholder alone reads Can't be checked, `gap_unfilled`, no accusation. Records came over HTTP; nothing went to Nostr relays. Output, state files and logs are in `docs/runs/2026-10-01` |
| The committed real evidence file and its CI test | Done. `evidence/omission-regtest-351-ad56b9bb-db614560.json`, 2,722 bytes, SHA-256 `aea26b9b…9710`. `TestCommittedEvidenceChecksOut` in `evidence/committed_test.go` verifies every committed `omission-*.json`. CI passed on `2679bc4`, the commit that added it, and on every push since |
| Recorded-run pages and README screenshots | Done. `go run ./cmd/site` reads `docs/runs` and builds pages for the 1 Oct run from its state files. The screenshots in `docs/media` come from that run |
| Video, public deploy | Not done. The site builds and serves locally; deploying it needs `npx wrangler login` first |

Tests on 1 Oct, at `d52477d`: `go test ./... -count=1` passed in all 19 packages on Go
1.26.4, and again with `-race`. That is 413 top-level tests, one of them a fuzz test with
four seeds, and 791 passing cases with subtests. Recount before quoting; other tracks
merge into `main`. Everything up to `d52477d` is pushed, and CI passed on every push of
1 Oct.

**Next tasks:**

1. Deploy a preview of the site once `npx wrangler login` is done. Keep it noindex until
   submission.
2. Record the video, following `docs/submission/video-script.md`. Its setup repeats the
   1 Oct run's steps, so heights and counts match; txids, keys and the file name do not.
3. Submit on Monday 5 Oct, following `docs/submission/checklist.md`. Publish on Devfolio
   by 17:00 IST.

Where things are:

- Design: `docs/design/2026-09-06-canary-design.md`
- Exact formats, reason codes, state labels and CLI: `docs/design/2026-09-30-v1-formats.md`
- Reader docs: `docs/how-canary-works.md`, `docs/faq.md`, `docs/glossary.md`
- Decision history: `docs/decisions.md`
- Research and citations: `docs/research/prior-art.md`, re-verified 30 Sep
- The recorded run of 1 Oct: `docs/runs/2026-10-01`, with its evidence file in `evidence/`
- The submission pack (Devfolio fields, video script, final-day checklist):
  `docs/submission/`
- The 8 Sep plans in `docs/superpowers/plans/` are superseded for v1 by the 30 Sep plan.
  Their status and known defects are in `docs/decisions.md`

## Rules

Each rule says what not to do and why. The positive target follows where it helps.

### Process

- **Don't change the settled design, or add scope beyond the 30 Sep plan, without the
  user's approval.** The approval gate still applies to design changes. The user asked to
  "design things one by one", so show each design change before it lands.
- **Don't write core code before its test,** because the core loop is built test-first.
- **Don't let UI or docs work slow the core loop.** When time runs short, the core wins.
  The plan lists the cut order and what is never cut.
- **Don't change the state-file or evidence-file JSON without a version bump and the
  user's approval,** because the UI and the checker build against them in parallel.
- **Don't follow the design doc or the roadmap where they disagree with the formats
  doc.** The formats doc is the source of truth for byte layouts, reason codes, the state
  mapping and the CLI. The others change to match it. Report a real problem in the
  formats doc instead of editing it.
- **Don't copy code from the 8 Sep plans as written,** because they carry known defects:
  the retention hole, the hash-only pass, an inclusion-only evidence file, the receipt
  check in `internal/`, a double txid reversal in the indexer plan, a proxy that 404s
  every route but `/tweaks`, and `commit.Prove` needing full leaves.
  [docs/decisions.md](docs/decisions.md#defects-found-in-the-8-september-plans) lists them.
- **Don't trust a recorded test count.** Rerun the tests.
- **Don't renumber the eight design amendments.** Every doc that lists them uses the
  numbering in [docs/decisions.md](docs/decisions.md#the-eight-design-amendments).

### Claims and wording

- **Don't call Canary trustless.** It makes tweak sourcing *accountable*. Say that first,
  in the README, the docs and the first 30 seconds of the pitch. A limit volunteered reads
  as rigour; the same limit extracted by a judge reads as overclaiming.
- **Don't state the security claim without its conditions:** *given at least one honest
  indexer publishing commitments, and an uncensored path to a relay carrying them.*
- **Don't present Canary as an alarm box.** The primary output is coverage, per block
  range, because an alarm that never fires looks like a product that does nothing. Lead
  with the line *a balance computed over blocks you could not verify is a lower bound,
  not a balance.*
- **Don't write "Checked" as if payments were checked.** It means the tweak list was
  checked. A server can serve the right tweak and drop the output a wallet matches
  against, and v1 passes it. State this output hole wherever coverage is shown or
  claimed; it is named now and fixed in v2.
- **Don't write "proves" without the receipt condition.** The victim can know a single
  server withheld data. Proving it to someone else needs a signed receipt, and some v1
  findings have no evidence format at all.
- **Don't write "Canary tells you which server lied".** Servers disagree (`disputed`)
  names two servers and nobody knows which lied. Data withheld (`compromised`) names one
  server shown to have withheld data.
- **Don't call Can't be checked a pass or an accusation.** It means Canary could not
  recompute the root.
- **Don't narrow a state's meaning to one example.** Can't be checked also covers a signed
  record with no readable list, and Not checked also covers a server that did not answer.
  Use the labels in the formats doc: Checked; Checked, gap filled; Can't be checked; Not
  checked; Servers disagree; Data withheld. The glossary's
  [States](docs/glossary.md#states) entry maps each label to its code and design name.
- **Don't claim Canary is first, or SPCOMMIT's second implementation.** SPCOMMIT has
  published tweak-list commitments for mainnet since 1 Sep 2026. Cite it next to RFC 6962.
  Canary's claim is narrower: a check at the client, one block at a time; filtered
  responses that leave explicit, signed gaps; and coverage states, evidence files and
  tripwires.
- **Don't cite Certificate Transparency as anything but the source of the split-view
  insight.** Canary applies RFC 6962's idea; it did not invent it.
- **Don't write that filtering stays "checkable" without the conditions.** A hole inside
  the 144-block window names the server. A hole further back that nobody fills is Can't be
  checked. An entry sent as a hash passes as Checked, gap filled (amendment 4). If the
  server declares no filtering, that raises a `hash_without_policy` warning, never an
  accusation. Under a declared pruning policy, only a tripwire on a payment you made
  catches it, and only while Core shows one of that payment's outputs unspent.
- **Don't cite BIP-352 as saying an indexer can withhold data.** It never says so, in any
  version. It calls trustless tweak sourcing "still an open question". The withholding
  wording is Bitshala's guide.
- **Don't claim Canary solves commission.** Injection to deanonymize is a different attack
  with the opposite structure, and short-lived Tor block fetching is the accepted answer.
  The k-of-N rule raises the bar as a side effect; that is a note, not a claim.
- **Don't claim Nostr gives timestamping.** It gives publication. `created_at` is
  self-asserted and can be backdated. Each record is tied to a block by its hash, and
  order comes from the chain.
- **Don't claim relay publication, a deployed site or a video that has not happened.** The
  1 Oct run fetched every record over HTTP from its server and published nothing to Nostr
  relays. Check the current-state table before writing about any of the three.
- **Don't say v1 "runs only on regtest".** Say "v1 is built and tested on regtest only",
  because `canary check` also accepts mainnet and prints a notice there. It refuses
  signet (decided 1 Oct). When you describe the tests, say they use a synthetic chain;
  the one real Core run is the recorded run of 1 Oct.
- **Don't claim v1 tests two independent implementations.** Its reference indexer reuses
  `canonical`, and the docs must say so.
- **Don't make a claim the roadmap rejects,** such as amounts, a score, "provably
  key-free" or "Bitshala's own indexer". The list is under "Claims we won't make" in the
  roadmap.
- **Don't break the house style** in comments, errors and human-facing text. Aim for about
  20 words per sentence, active voice, named links instead of "§" references, and no plan
  or task numbers. Error strings read `<pkg>: <what failed>: <detail>`. Avoid
  "trustless", "secure", "guarantee" and exclamation marks.

### Design and code

- **Don't compare raw served tweak lists.** Honest servers legitimately serve different
  sets: blindbit-oracle does cut-through and dust filtering, silentiumd indexes only
  transactions with unspent taproot outputs, and BIP-352 itself allows cut-through. Raw
  diffs produce nothing but false positives. Compare signed canonical sets. Read
  [Canonical tweak sets](docs/design/2026-09-06-canary-design.md#2-canonical-tweak-sets-and-policy-normalization)
  before touching any comparison code.
- **Don't recompute the root before filling gaps.** A position sent as nothing makes the
  root uncomputable, so the block silently never gets checked. Fill first, recompute
  second, and never call a block clean whose root was not recomputed. The retention rule
  is the one step that names a server before the root is recomputed. See
  [Comparison procedure](docs/design/2026-09-06-canary-design.md#25-comparison-procedure).
- **Don't use a replaceable Nostr event kind.** Kinds 10000–19999 and 30000–39999 are
  overwritten in place, so a server could publish a policy after using it as cover and the
  original would vanish. Policy and record events are regular kinds, append-only. Records
  are kind 1352. See
  [The commitment object](docs/design/2026-09-06-canary-design.md#33-the-commitment-object).
- **Don't exclude a server automatically when it trips an alarm.** If a third party can
  induce the detection, exclusion knocks out honest servers and leaves the victim with the
  attacker's. Only self-consistency failures are safe to act on automatically. See
  [Acting on alarms](docs/design/2026-09-06-canary-design.md#45-acting-on-alarms).
- **Don't make an indexer fork call `canonical`.** It is convenient and makes the
  differential test vacuous; keep the two computation paths independent. See
  [The BIP-352 library](docs/design/2026-09-06-canary-design.md#64-the-bip-352-library-supplies-the-primitives--and-what-that-costs).
  The v1 reference indexer, `cmd/canary-indexer`, reuses `canonical` on purpose, as a
  v1-only exception decided 30 Sep. Any later fork of a real indexer follows the rule.
- **Don't treat `headers` as SPV.** Proof-of-work carries no integrity on signet; BIP-325
  puts it in the challenge signature. `headers` stores `(height, hash)` observations with
  a contested-past-six-confirmations rule. See
  [Chain agreement](docs/design/2026-09-06-canary-design.md#46-chain-agreement).
- **Don't key blocks by height.** Compare, fetch and name blocks by hash, and map height
  to hash with the local Core node, because one height can name different blocks on two
  chains.
- **Don't mix byte orders.** Hash preimages and binary formats use internal order; JSON,
  URLs and Nostr tags use display order. Convert at the boundary, in one place, because
  mixed orders give different roots for identical data.
- **Don't switch the `network` tag to a display name.** It holds the decimal network
  magic, and a name would merge two custom signets.
- **Don't let a server declare its own retention window.** 144 blocks is a protocol
  constant, because a server allowed to choose declares zero.
- **Don't skip the record for an empty block.** `merkle_root(∅)` is 32 zero bytes.
  Skipping would hand a server the excuse "there was nothing to commit".
- **Don't learn a server's key from `/info`.** Pin each pubkey by flag. Trust on first use
  hands the key to anyone who can intercept one request.
- **Don't build a wallet.** Canary checks what servers send; the wallet belongs to someone
  else. The realistic unmodified clients speak the BlindBit v1 HTTP API: blindbit-scan
  (headless Go, runs on regtest) and Dana through spdk. v1 has no proxy in front of
  either.
- **Don't reach for mainnet.** It costs days and buys nothing the design needs.
- **Don't treat the research as durable.** `docs/research/prior-art.md` is dated and
  perishable, and the project rests on the gap still being open. Re-verify before relying
  on it.
- **Don't commit secrets.** `.gitignore` covers `nsec*`, `*.key`, `*.pem`, `.env`,
  `blindbit.toml` and `bitcoin.conf`. Keep Nostr signing keys and Core RPC config out.
  The reference indexer uses a throwaway key; only its pubkey is published.

## Decisions in force

Each has its full reason, and its history, in [docs/decisions.md](docs/decisions.md).

| Decision | In short |
|---|---|
| Accountable, not trustless | Detection names a server and a block, under the two conditions above |
| Commit to the canonical set, serve any subset | All honest policy only removes entries, so served ⊆ canonical. Storage policy stays free, and accountability does not |
| Tool first, protocol second | The checker works against servers as they are; signed records are the upgrade |
| Coverage, not alarms, with six states | Disputed is split from Compromised, because root divergence does not say which server lied |
| Go | blindbit-oracle, silentiumd and go-bip352 are all Go |
| v1 is tested on regtest; the code accepts regtest and main; signet after v1 (1 Oct) | Regtest needs no public server or coins and mines on demand, so the demo and every test run there. There is no mainnet demo. `canary check` accepts main and prints a notice that v1 is tested on regtest only. It refuses signet, and so does the reference indexer, through `core.NetworkFromChain`. Core reports only the name "signet", and a custom signet takes its magic from its challenge. Guessing the default magic would check every record against the wrong network, and nothing would fail. Signet needs a flag that names the network, planned after v1. `TestCheckRefusesSignet` pins the refusal |
| After one verified record, nothing a server answers stops the run (1 Oct) | Canary decides after the record pass. Once one of a server's records verifies under its pin, its refused records and lists count like outages, and a failed or off-API `/info` leaves only its policy unknown. The run saves. A refused list reads Can't be checked, `list_not_served`, with a warning naming the server inside the window. A server whose `/info` answers as `canary-info/1` cannot stop the run either. Only a server that proves nothing stops it with exit code 5: no verified record, no usable `/info`, and an answer outside the API. That points to a wrong URL, and no finding in that run could name the server. It can still deny the run to cover another server; the formats doc lists that limit. `TestCheckWithholderCannotStopTheRun` and `TestCheckStopsForAServerThatProvesNothing` pin the rule. Stopping on anything less would hand a withholder a veto over its own accusation. Size is bounded too. A record whose `n` is not below its block's transaction count counts as no record (`TestCheckRecordClaimingMoreEntriesThanItsBlock`). A list is read to `4 + 66n` bytes at most, and a record to 4096 bytes, about six times an honest one. Only a record that passes the checks is kept, and a block's ladder result is dropped once the block is read (`TestCheckReadsNoRecordLongerThanTheLimit`, `TestRecordPassKeepsOnlyRecordsThatPassTheChecks`). So one server's records cost a run a few times what an honest server's do, never 1 MiB a block. A slow server can still stretch the run; the formats doc lists that limit too |
| No daemon and no proxy in v1 | `canary check` writes a state file, `canary ui` reads it. The v2 proxy targets BlindBit v1 clients and refuses Data withheld and Servers disagree blocks only |
| The v1 reference indexer reuses `canonical` | Saves 4–6 hours; the docs say v1 does not test independent implementations |
| The output hole is named now, fixed in v2 | The entry is `(txid, tweak)`; output keys join it in v2 |
| The eight amendments of 30 Sep | Retention rule, receipts in the core, the evidence file, named limits, demo changes, no proxy, decimal network tag, Cypherpunk track only |
| 144-block retention window, a protocol constant | A hole inside the window names the server (amendment 1) |
| Nostr for publication, kind 1352, block hash in the `b` tag | NIP-01 indexes single-letter tags only and has no range query, so record fetches are batched by block hash |
| `network` is the 4-byte P2P magic, decimal in the tag | Keeps two custom signets apart |
| Chain agreement is an output, not an input | Reorgs resolve, lies persist. v1's outside chain fact is the user's Core node or a pinned `(height, hash)`. BIP-325 validation is not in v1 |
| The empty set is committed; `merkle_root(∅)` is 32 zero bytes | `n` is bound into the outer root, so zeros cannot collide |
| Disclosed txids give detection, never attribution | Attribution needs the spent outputs, which only the payer holds |
| `dust_threshold_sat` is declared, never an input to proof | Entries carry no amounts, and no accusation rests on the declared threshold. Since 1 Oct the tripwire takes the threshold a valid receipt signs, always 0 for `canary check`. Only a list with no valid receipt falls back to the declared one, which can excuse an entry and never accuse. When it alone excuses a payment Core shows unspent, the server's `error` says so. `TestReceiptDustThresholdOutranksTheDeclaredOne` and `TestCheckSaysWhenOnlyTheDeclaredDustThresholdExcuses` pin it |
| Nothing between a server and Canary can make Canary accuse it (1 Oct) | Two reviews found ways around this, all closed test-first. A signed tip above Core's tip is never a false chain claim, because a lagging node looks the same as a lie. It reads `tip_unconfirmed`, and a false claim needs Core to hold another block at the signed height more than 6 below its tip (`TestLaggingCoreAccusesNobody`, `TestSignedTipAgainstCore`). The cost, stated in the formats doc: a withholder can sign a tip above Core's and turn an omission into Can't be checked, though a declared payment still names it. A receipt the pin signed for other bytes, block, network or dust means the list was changed on the way. It reads `list_not_served`, with no warning and no evidence (`TestListAlteredInTransitAccusesNobody`, `TestCheckListAlteredInTransitAccusesNobody`). An unsigned list is still judged on what arrived, so `--indexer` and `--core-rest` take https or plain http to this computer only, exit 2 otherwise, and no redirect may break that (`TestCheckTakesHTTPSOrPlainHTTPToThisComputer`). An unsigned list is accused only below depth 138 by Core's tip, or by a higher tip `/info` declares (`TestLaggingCoreAccusesNobodyWithoutAReceipt`). A sign of trouble that names nobody stays as the server's `error` (`TestCheckKeepsTheSignOfAnAlteredList`). One key pinned to two servers is refused |
| The v1 tripwire is the payments you declare with `--expect` | Scheduled probes at random times and amounts are v2 (roadmap F25) |
| Run every indexer locally; construct edge cases on regtest | Never depend on a public server being alive; public signet cannot be mined on demand |
| The committed evidence file lives in `evidence/`, beside the Go package; the run record lives in `docs/runs/2026-10-01` (1 Oct) | `TestCommittedEvidenceChecksOut` reads every `omission-*.json` beside the package, so a format change that breaks the judge path fails CI. The README, the site and the video name `evidence/<file>`, and `cmd/site -evidence` refuses a file outside that directory. The run's command output, state files and indexer logs sit in `docs/runs/2026-10-01`, with local paths removed. The run also holds a byte-identical copy of the evidence file in its own `evidence/`, and both state files name `"evidence_dir": "evidence"`. `canary ui` reads a relative `evidence_dir` against the state file's directory, so `go run ./cmd/canary ui --state docs/runs/2026-10-01/state.json` shows the finding checking out from a fresh clone (`TestUIShowsTheRecordedRunsEvidence`). `docs/runs/2026-10-01/README.txt` lists every edit to the raw output. It is `.txt` because `cmd/site` publishes only `.json`, `.txt` and `.log` from a run |
| UI: Go `html/template`, the Safety Lamp identity | Coal `#17160F` on limestone `#F5F3EC`, dark `#121210`. Canary yellow `#F4E13A` is the brand, never a state colour; yellow-family text is `#5E5700`. States show symbol, word and colour, at 4.5:1 or better. Atkinson Hyperlegible Next and Mono, self-hosted. One wording table, `copy.go`. The ban list is in decisions.md |

## External facts worth not re-deriving

- **An indexer cannot identify which transactions pay a published SP address.** That
  needs the private scan key. So targeted omission requires outside knowledge, and the
  party who always has it is the sender. Hence the motivating scenario: *the exchange
  that pays you is also the indexer that tells you whether you were paid.* See
  [Attacks in scope](docs/design/2026-09-06-canary-design.md#12-attacks-in-scope) and
  [Canary tripwire](docs/design/2026-09-06-canary-design.md#5-canary-tripwire).
- **BIP-352 never mentions an indexer withholding data**, in any version. A footnote says
  "It is still an open question as to how Bob can source the 33 bytes per transaction in
  a trustless manner". Appendix A, on light clients, is "out of scope for the current BIP
  ... to motivate further research". Both are in every revision since the file's first
  commit (15 Jan 2024). v1.1.0 (2 Mar 2026) only added the recipient limit `K_max`; the
  current version is 1.1.1. Verified 30 Sep across all 34 revisions of the file.
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
  Optech #422 (11 Sep) described it without the name. It is a flat SHA-256 hash chain
  over the unfiltered list. Only the chain head is signed, posted every 6 hours as a Nostr
  kind-1 note. v2 also covers `outputs_short` and spent outputs. No Merkle tree, no
  inclusion proofs, no network binding. Its author says a client given a filtered
  response "cannot check the subset for completeness". No wallet-side verifier was found
  on 30 Sep. Relay retention of its notes is poor except on nostr.mom.
- **tweak-service-auditor** (`silent-payments` org, Python) compares raw tweak lists from
  rbitcoin, BlindBit gRPC, Cake's electrs and Core. It runs on the operator's side, after
  the fact, with no signatures.
- **Live evidence for comparing committed lists, not served ones (30 Sep).** For mainnet
  block 969,300, silentpayments.dev returned 220 tweaks (full index) and 184 (filtered
  endpoint), and Cake's server returned 141. All 141 are in the 220. It was a one-off
  measurement. Only the counts were kept, not the URLs or responses, so the repo cannot
  reproduce it. Say so wherever it is quoted.
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
- **go-bip352 behaviour, verified by running it on 8 Sep**, not taken from documentation:
  - `bip352.TaggedHash` is a genuine BIP-340 tagged hash, checked against
    `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)`. The whole
    [Merkle tree](docs/design/2026-09-06-canary-design.md#32-merkle-tree) construction
    rests on it.
  - `ExtractPubKey` returns 33 bytes for P2WPKH, P2PKH and P2SH, and 32 x-only bytes for
    P2TR. It signals failure with `TypeUTXO == Unknown`, not an error. The caller must
    lift x-only keys to 33 bytes with an `0x02` prefix before summing.
  - The tweak chain is `ExtractEligibleVins` → `ExtractPubKey` per vin → lift →
    `SumPublicKeys` → `ComputeInputHash(eligible, sum)` → `TweakPubkey(sum, hash)`.
    Argument order confirmed by running it.
  - `ExtractEligibleVins([])` returns `(empty, nil)`, **not** `ErrVinsEmpty`.
  - `Vin.Witness` is `[][]byte`, not `[][][]byte`; a docs summary got this wrong.
  - `NumsH` is exported, so the NUMS-H corner vectors assert against the library's own
    constant.
  - go-nostr: `Event{ID, PubKey string, CreatedAt, Kind int, Tags, Content, Sig}`,
    `Sign(hexSecretKey)`, `Filter{Kinds, Authors, Tags TagMap, Since, Until}`.
- **`bip352.Vin.Txid` is display byte order**, and the leaf preimage in
  [Merkle tree](docs/design/2026-09-06-canary-design.md#32-merkle-tree) is internal byte
  order. Convert at the boundary, in one place. This is that section's stated trap with a
  real instance behind it.
- **Signet SP faucet**: `https://silentpayments.dev/faucet/signet/`. It removes the need
  for a counterparty when demonstrating receipt. Not needed for v1, which is built and
  tested on regtest only.
- **`bitcoin.silentium.dev` stopped serving the API.** On 6 Sep the public indexer named
  in the light-client docs redirected to a parked page returning HTTP 200 with an
  identical 533-byte body for every path. A client pointed at it then got no error and no
  payments. On 30 Sep it returned an HTTP 301 redirect; that check did not follow the
  redirect. Useful as both a motivating example and a warning about demo dependencies.

## Conventions

- Design docs: `docs/design/YYYY-MM-DD-<topic>.md`. Reader docs sit directly in `docs/`.
- New decisions go at the top of `docs/decisions.md`, with the date, the decision and the
  reason. This file keeps only the decisions in force.
- Commit messages explain *why*, not just what. Trailer:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- The UI and docs tracks work on their own branches in separate worktrees. Merges go into
  `main` one at a time.
