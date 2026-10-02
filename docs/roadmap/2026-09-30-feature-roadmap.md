# Canary roadmap: what ships by 5 October, and what comes after

Written Wednesday 30 September 2026. Canary is entered in BOSS Battle's Cypherpunk track, which closes **Monday 5 October 2026 at 23:59 IST (18:29 UTC)**.

The schedule follows the plan you approved on 30 September. The competitor research behind several choices is in [BOSS Battle competitors](../research/2026-09-30-competitors.md). The [glossary](../glossary.md) defines the project's terms, and [Words used in this document](#words-used-in-this-document) repeats the ones used most here.

## At a glance

Canary makes silent-payment index servers accountable, not trustless. Every claim below holds only under two conditions: at least one honest indexer publishes signed records, and you have an uncensored path to a relay that carries them.

| ID | Feature | Impact | Uniq. | Cx | Hours | Priority | Horizon |
|---|---|---|---|---|---|---|---|
| F01 | Reference indexer with a withholding switch | 9 | 7 | 8* | 12* | 1.03* | v1, minimum form, never cut |
| F02 | `canary check` against the server's signed record | 10 | 9 | 6 | 9* | 1.60 | v1, never cut |
| F03 | Receipts and an offline evidence file | 8 | 9 | 6 | 10* | 1.40 | v1, never cut; receipt checking is cut 7 |
| F04 | Self-payment tripwire, tweak only | 7 | 6 | 4* | 4* | 1.65* | v1, cut 6; output check v2 |
| F05 | One wording table for every result | 5 | 3 | 2 | 2 | 2.10 | v1 |
| F06 | Coverage view and the lower-bound sentence | 7 | 7 | 3* | 1.5* | 2.33* | v1 inside F16, cut 4 |
| F07 | Public site | 6 | 2 | 3* | 2* | 1.47* | v1†, pages beyond the checker are cut 1 |
| F08 | In-browser evidence checker | 8 | 8 | 6 | 3* | 1.33 | v1†, cut 3 |
| F09 | Regtest setup, demo harness, CI run | 8 | 4 | 5* | 5* | 1.28* | v1, automation is cut 5; CI run v2 |
| F10 | Offline-verify test | 3* | 5 | 2* | 0.5* | 1.90* | v1, inside F03 |
| F11 | The limits table | 6 | 4 | 1 | 1.5 | 5.20 | v1, never cut |
| F12 | Truth pass: design fixes, then citations | 6 | 1 | 3 | 3* | 1.33 | v1, never cut |
| F13 | README and submission package | 8 | 1 | 3 | 4.5* | 1.73 | v1, never cut |
| F14 | Video from the recorded run | 8 | 2 | 5 | 6* | 1.12 | v1, never cut |
| F15 | Servers disagree on a block's record | 5 | 7 | 4 | 5 | 1.45 | v1†: detected inside F02; the act 3b scene is optional |
| F16 | Local dashboard (`canary ui`) | 4 | 4 | 4* | 4* | 1.00* | v1 thin†, cuts 2 and 4; live v2 |
| F17 | In-path proxy for unmodified wallets | 7 | 9 | 8 | 22–26* | 0.98 | v2* |
| F18 | `canary why <txid>` | 6 | 8 | 6 | 8 | 1.13 | v2* |
| F19 | Adapters for live servers, shroud-indexer first | 6 | 7 | 6 | 7 | 1.07 | v2* |
| F20 | Alerts that don't cry wolf | 3 | 2 | 2 | 2 | 1.30 | v2* |
| F21 | "What protects my wallet today?" page and `canary doctor` | 5 | 7 | 3* | 3 | 1.93* | v2* |
| F22 | SPCOMMIT interop | 6 | 7 | 6 | 10 | 1.07 | v2* |
| F23 | Output keys in the entry (entry format v2) | 8 | 5 | 7 | 10 | 0.97 | v2, first after judging |
| F24 | Spend check for hash-only slots | 5 | 6 | 6 | 6 | 0.90 | v2 |
| F25 | Expected-payment inbox and self-payment probes | 5 | 6 | 7 | 14 | 0.77 | v2 |
| F26 | Canary on a home node | 4 | 3 | 6 | 14 | 0.60 | v2 |
| F27 | Block-level test vectors offered upstream | 5 | 6 | 5 | 8 | 1.08 | v2 |
| F28 | Spec proposal for the index-server spec | 6 | 5 | 3 | 3* | 1.87 | v2 |
| X1 | Shared wire format (added in review) | – | – | – | 1 | not scored | v1 |
| X2 | Command-line tool and state file (added in review) | – | – | – | 4 | not scored | v1 |

**How to read the table.**
- **Impact, Uniq. (uniqueness) and Cx (complexity)** are scores from 1 to 10. A complexity of 1 is an hour of writing; a 10 is a multi-day build with unknowns.
- **Hours** is the feature's size. It is not always your time, because Claude builds the interfaces and drafts the docs in parallel sessions.
- **An asterisk (\*)** marks a number or horizon that a reviewer corrected. Each feature's section says what changed and why.
- **A dagger (†)** marks a horizon that the approved plan changed. F07, F08 and F16 moved into v1 as parallel work. F15 moved into v1 because `canary check` already compares records across servers, so only its demo scene stays optional.
- **F16 and F07 are sized for less than the plan now asks.** Their hours were scored for a thin Overview-plus-Finding dashboard and a four-page site. The approved plan then added the error pages, the update bar and the design system. Claude builds that extra scope in parallel, and this document does not size it.
- **"Cut N"** is the feature's place in [the cut order](#cut-order-when-time-runs-short). "Never cut" items appear on that section's never-cut list.

**Where the numbers come from.** Three independent scorers rated every feature: a Bitshala-style judge, a senior Go engineer and a privacy advocate. Each number in the table is the median of their three. Two formulas turn the scores into a ranking:

```
value    = 0.6 × impact + 0.4 × uniqueness
priority = value ÷ complexity
```

For example, F02 has impact 10, uniqueness 9 and complexity 6. Its value is 0.6 × 10 + 0.4 × 9 = 9.6, so its priority is 9.6 ÷ 6 = 1.60.

A critic then checked the ranking, the hours and the claims, and a frontend reviewer checked the interface plans. Where a reviewer was right, the number changed, and the priority was recomputed from the corrected scores. The ratio orders only the optional v1 work and v2. Dependencies fix the order of the v1 critical path, and [How the scores work](#how-the-scores-work) explains why.

---

## 1. What this document is

This document lists the features Canary could build, scores each one, and turns the scores into a plan. The plan has two parts. v1 ships by the deadline. v2 continues after judging.

You made these decisions on 30 September, and the plan follows all of them. [Decisions made on 30 September](#decisions-made-on-30-september) lists them in full, including the design choices.
- Ship a strong v1 by 5 October, then keep building after judging.
- Work as one person plus Claude. Claude builds the interfaces and rewrites the docs in parallel sessions from day 1.
- Build both a public site and a local dashboard, on one design system.
- Rewrite everything a reader sees in plain language, starting with the reader-facing docs.
- When time runs short, the core detection loop wins over the interfaces.

### How the scores work

Each feature gets three scores, each on a scale of 1 to 10.

- **Impact.** How much the feature changes the outcome for users and for judges. A 10 means the project fails without it.
- **Uniqueness.** How far the feature is from what already exists, including SPCOMMIT (see [Someone already publishes tweak-index commitments](#21-someone-already-publishes-tweak-index-commitments-partly-true)). A 10 means nobody has anything like it.
- **Complexity.** How hard and risky the feature is to build. A 1 is an hour of writing. A 10 is a multi-day build with unknowns.

Two numbers come from those scores:

```
value    = 0.6 × impact + 0.4 × uniqueness
priority = value ÷ complexity
```

Three scorers rated every feature independently:
- a Bitshala-style judge: what a Cypherpunk judge would reward;
- a senior Go engineer: what the feature costs to build and what can go wrong;
- a privacy advocate: what the feature does for a person receiving payments.

Each scorer also estimated hours. For every number, hours included, the table shows the **median of the three**. The median ignores one outlier. That matters here, because the privacy scorer rates documentation low and the judge scorer rates it high.

Two reviewers then attacked the scores. The critic went after the ranking, the hours and the claims. The frontend reviewer checked the site and dashboard plans. Where a reviewer was right, the number changed. Changed numbers carry an asterisk (*) in the table, and each feature's section says what changed and why.

The priority ratio has one known flaw, so the plan does not follow it blindly. The ratio rewards cheap work. Writing tasks float to the top, and the reference indexer, which every other feature needs, sinks near the bottom. Following the ratio in order would spend the first eleven hours without producing a working demo. So the plan uses two rules:
- The v1 critical path is fixed by dependency and listed in the order work starts.
- The ratio orders everything else: the optional v1 items and all of v2.

### Words used in this document

The project [glossary](../glossary.md) has the full list. These are the terms this document leans on most.

- **Silent payment.** A Bitcoin payment made under BIP-352 to a reusable address. The address never appears on chain, so the receiver has to scan blocks to find payments.
- **Tweak.** A 33-byte value computed for each eligible transaction. A wallet needs tweaks to scan. Computing one needs the coins the transaction spent, which a light wallet doesn't have.
- **Light wallet.** A wallet with no full node of its own. It asks a server for tweaks.
- **Index server, or indexer.** The server that computes tweaks and hands them to light wallets.
- **Entry.** One transaction's pair of transaction id (txid) and tweak. A block's **full list** has an entry for every eligible transaction, with nothing filtered out.
- **Filtering.** Honest servers drop some entries on purpose. **Cut-through** drops transactions whose outputs are already spent. A **dust filter** drops small ones.
- **Signed record.** A server's signed statement of a block's full list, published before anyone asks for the block. Canary's records contain a Merkle root. The root is a 32-byte fingerprint of the whole list, and it lets anyone prove that one entry belongs to the list. The code calls a signed record a "commitment".
- **Hash-only slot, empty slot.** When a server leaves an entry out of a response, it can send the entry's hash in its place, or send nothing.
- **Retention window.** The most recent 144 blocks, about one day. A block is inside it while it sits less than 144 blocks below the server's signed tip. Inside the window, a server must keep at least the hash of every entry.
- **Receipt.** The server's signature over the exact bytes it sent you.
- **Evidence file.** One JSON file holding the signed record, the receipt, the bytes served and a proof. Anyone can check it offline.
- **Tripwire.** A payment you make to yourself. Canary then checks that each server reports it. In v1 it is one payment you declare with `canary check --expect`.
- **Coverage.** Canary's result for each block. There are six states: Checked; Checked, gap filled; Can't be checked; Not checked; Servers disagree; Data withheld. F05 defines them.
- **Regtest.** A private Bitcoin test chain that runs on your own computer.
- **Nostr relay.** A public server that stores signed messages, called events. Each event has a numeric type, called a kind. A copy on a relay proves that an event was published. It does not prove when.
- **BlindBit.** setavenger's open-source index server (blindbit-oracle) and its clients. Its version 1 HTTP interface is what the Dana wallet and the blindbit-scan client speak. Version 2 speaks gRPC.
- **Frigate.** The server behind Sparrow's silent-payments support. The wallet gives Frigate its scan key, and Frigate does the scanning.
- **SPCOMMIT.** Rob Segers' commitment scheme for tweak indexes, live on mainnet. [Someone already publishes tweak-index commitments](#21-someone-already-publishes-tweak-index-commitments-partly-true) covers it.
- **Byte order.** A txid or block hash has two byte orders. Hashes and Canary's entries use internal order; block explorers show display order, which is reversed. Canary converts once, at the boundary.

---

## 2. What changed since the design was written

### Where the repo stands (checked 30 September)

- **Built and tested:** `canonical`, `commit`, `feed`, `policy` and `internal/testvector`, about 3,100 lines. The morning check counted 67 passing tests. The shared wire format, `wire`, landed that evening. `go test ./...` then passed all 80 top-level tests in seven packages.
- **Not started:** the receipt, the indexer, `canaryd`, the command-line tool, evidence files, tripwires and any interface.
- **Broken:** `make vectors` points at a generator that does not exist, so it fails.
- **Missing tools:** there is no Bitcoin Core on this machine. Docker is installed, but its daemon is not running. There is no local relay.
- **Go versions:** `go.mod` says Go 1.24.1 and has no toolchain line. The laptop runs Go 1.26.4, and CI uses 1.24.
- **Repo state:** the repo is private and has no LICENSE. Six commits are unpushed. The README still says "Design phase. No code yet."

Seven suspected problems were checked against primary sources. Here are the results, in plain terms.

### 2.1 Someone already publishes tweak-index commitments (partly true)

Rob Segers runs silentpayments.net and posts on GitHub as bitsagarob. His scheme, SPCOMMIT, is live on mainnet.

**The timeline.**
- 2026-09-01 22:21 UTC: the first checkpoint on Nostr, at height 965089.
- 2026-09-02: the spec and five test vectors landed (commit 8023408d), the same day as his bitcoin-dev post.
- 2026-09-11: Bitcoin Optech #422 described the scheme. It never uses the name SPCOMMIT.
- 2026-09-21: the reference implementation went into the repo (commit d204e6db). That is when the source was published. The service had been running for three weeks.

**How it works.**
- Version 1 hashes each block's sorted tweak list with SHA-256.
- A parallel version 2 also covers each transaction's txid, its 8-byte output prefixes and the block's spent outputs.
- Each block's value is chained to the previous block's value. Only the head of the chain is signed.
- The head goes out as a Nostr note every 6 hours. There are 118 notes so far, all from one key. The latest was 2026-09-30 13:45 UTC, at height 969306.

**What it doesn't do.**
- It has no per-block signature, no inclusion proofs and no network identifier.
- It covers only the unfiltered list. Segers writes that a client given a filtered response "cannot check the subset for completeness". He also describes what the chain offers as "detection by third parties after the fact rather than verification by the client".

**Other findings.**
- A second, independent implementation already exists: bitsagarob/spcommit-checkpoint-startos, from 2026-09-02. It is a v1-only witness, it needs an archival node, and it calls itself "not a wallet or a scanner". No second publisher appears on the four relays queried.
- No wallet-side verifier was found. That is absence of evidence only, because GitHub code search indexes these repos poorly.
- Relays keep these notes poorly. relay.damus.io held none of Segers' notes, relay.primal.net held 2, and nos.lol held about 3 days' worth. Only nostr.mom held the whole month.

**What this changes.** Canary cannot claim to be first with tweak-index commitments, first to use Nostr for them, or first with the "trust me becomes catch me" framing. Canary's real differences are:
- per-block signed records with proofs;
- records a client can check against a filtering server, inside the 144-block retention window;
- checks that run inside the wallet.

Only the first of these exists in code today.

Sources: github.com/bitsagarob/silentpayments-measurements (SPCOMMIT.md, FILTERS.md, LIGHT-CLIENT-PROTOCOL-DRAFT.md); bitcoinops.org/en/newsletters/2026/09/11/; the bitcoin-dev post of 2026-09-02 (gnusha.org/pi/bitcoindev); live relay queries on 30 September.

### 2.2 Canary misses a server that hides the output instead of the tweak (confirmed)

Canary's entry is (txid, tweak). But every wallet Canary could sit in front of decides whether a payment exists from *output* data the server supplies:
- **spdk and Dana** match against the server's new-UTXO filter, then read its UTXO list and skip any entry marked spent.
- **blindbit-lib, BlindBit's version 2 client library,** matches against each transaction's 8-byte output prefixes.

A sender who also runs the indexer knows the output it created. It can serve the correct tweak and drop the output from any one of those places. The signed record stays honest, so every check in v1 passes, and Canary would call the block Checked while the wallet missed the payment. A BIP-352 change, bips PR #2134, warns that hiding one output can also hide later outputs from the same sender.

What did not hold up:
- BlindBit's honest dust filter works per transaction, not per output, so it drops the tweak too and Canary sees the gap.
- blindbit-oracle PR #56 is a real output-level filter that anyone can trigger after the fact. But it is open, unmerged, off by default and limited to BlindBit version 2.
- The honest, deployed example of output-level filtering is Cake's electrs fork. Its source default is 1,000 sats, and the value actually deployed is unknown.
- Against BlindBit v1, the hole is adversarial or a bug. It is not honest policy.

Sources: cygnet3/spdk `scanners/local/src/scanner.rs`; setavenger/blindbit-lib `proto/indexing_server.proto`; blindbit-oracle PRs #56 and #61; cake-tech/electrs `schema.rs`; bitcoin/bips PR #2134; this repo's `canonical/canonical.go`.

### 2.3 The wallet the design names is archived (partly true)

- blindbitd was archived on 2025-08-14. It also needs an Electrum server.
- blindbit-oracle version 2 deprecates its HTTP data interface by policy. In code, it still serves five deprecated HTTP data routes, and none of them matches version 1's shapes.
- Three live client families exist today:
  - Dana, through spdk, speaks BlindBit v1 HTTP and defaults to silentpayments.dev. Its released app is mainnet-only.
  - BlindBit Desktop speaks gRPC only and offers no regtest.
  - blindbit-scan is a headless v1 HTTP client that runs on regtest, with Electrum optional. The suspicion missed this one entirely.
- As planned, the proxy returns 404 for everything except `/tweaks`, so every v1 client would break on its first call.
- The indexer plan targets BlindBit version 2, which no v1 wallet can use.

Sources: `gh api` archive status for setavenger/blindbitd; blindbit-oracle `internal/server/README.md` and `run.go`; cygnet3/dana; setavenger/blindbit-desktop; setavenger/blindbit-scan; this repo's sidecar plan.

### 2.4 Submission rules (partly true)

**Confirmed by the Devfolio API:**
- The deadline is Mon 5 Oct 23:59 IST.
- Registration closed on 28 Sep at 23:59 IST.
- Results come on 12 Oct at 14:00 IST.
- Teams have 1 to 3 people.
- Each of the three tracks has one $1,000 prize.
- "Save draft" and "Publish" are separate actions.

**The form** asks for media, the problem the project solves, challenges, technologies, and a note on track fit. It takes a YouTube, Vimeo or Loom link and shows no length limit.

**Not confirmed:**
- The "3 to 5 minute video" and "video link near the top of the README" rules come from one competitor's repo (QuietRelay). It attributes them to a participant handbook and a private organizer email of 21 September.
- Weekly progress logs appear only as that competitor's hedge. No source requires them.
- No rule requiring a public repo or a LICENSE was found.
- Several entrants submitted videos under 3 minutes. Dossier's runs 74 seconds.

The real rules are in the 7 September email to registered participants.

Sources: api.devfolio.co/api/hackathons/boss-battle; ToukoUrsin/quiet-relay `docs/DEMO.md`; EazyHood/relay-evidence `docs/eligibility.md`; Bitshala's posts on X of 7 and 15 September.

### 2.5 The repo misquotes BIP-352 (confirmed)

On 30 September, the README, prior-art.md and CLAUDE.md all said that BIP-352 v1.1.0 states the trust assumption that an indexer can withhold data. That is false.

- **No revision says it.** None of the 34 revisions of the BIP has ever mentioned withholding.
- **What v1.1.0 did.** It came out on 2026-03-02 and added only a per-group recipient limit. The current version is 1.1.1, which added one test vector.
- **What the BIP does say** has been in the text since the first draft:
  - a footnote: "It is still an open question as to how Bob can source the 33 bytes per transaction in a trustless manner";
  - the introduction calls light-client support "an area of open research";
  - Appendix A is "out of scope… to motivate further research".
- **Where the withholding wording actually comes from:**
  - Bitshala's guide of 3 August 2026: "A light client that accepts tweak data from a server has no way to detect omission."
  - SomberNight's cake_wallet#2395, July 2025: "what if the server lies by omission?" and "I presently do not see a way how to fix this while using cut-through."
  - The index-server spec asks the same question: "How does a wallet know all tweaks were received for a given block request?"

Sources: bitcoin/bips `bip-0352.mediawiki` history (permalink at 3a10b5b5f0); x.com/bitshala_org/status/2084131259375296785; cake-tech/cake_wallet#2395; silent-payments/BIP0352-index-server-specification.

### 2.6 The plans can't produce the demo's central scene (partly true: six problems, not five)

- **Withholding is never reported.** The planned withholding switch leaves an empty slot. The planned check never turns an empty slot into an accusation. It says "unresolvable" when nothing fills the slot, and "clean" when another source fills it. So the demo's main scene could not happen. The design itself never says what an empty slot inside the window means.
- **A variant passes outright.** A server can send the entry's correct hash instead of an empty slot. Under a declared filtering policy, the planned check calls the block clean.
- **Verify proves less than it prints.** The planned `canary verify` ignores the receipt and stores no served bytes, yet it prints "and served a set omitting it". Anyone who holds a block could build a passing accusation against an honest server.
- **The client can't check receipts.** The receipt-checking code sits in the indexer's internal package, which the client cannot import. No plan says how a receipt reaches the client.
- **The window can't be checked offline.** Receipts don't sign the server's tip, so a stranger cannot check the window without chain data.
- **The network tag disagrees with the design.** The code writes the network's 4-byte magic number in decimal, while the design says the tag carries a display name. The code is right, and the design text should change.
- **The proxy refuses everything.** The planned proxy refuses every block that has no signed record. Today, that is every block from every running server.

Corrections to the suspicion:
- The planned tripwire *does* report withholding for your own payment when your node anchors the chain.
- No gap filler exists in any plan.
- `commit.Prove` needs every entry, so it cannot build a proof from a response that contains hash-only slots.

Sources: `docs/superpowers/plans/2026-09-08-canary-sidecar.md` (the comparison at lines 599–724, the evidence file and verify at 1321–1461, the proxy at 1995–2004); `docs/superpowers/plans/2026-09-08-canary-indexer-fork.md` (the switch at 1606–1612, receipts at 1360–1419); `feed/commitment.go:82`; `commit/proof.go:25`.

### 2.7 shroud-indexer is a good adapter target (partly true)

**What held up.**
- It is MIT-licensed TypeScript. It moved from Bitshala-Incubator to CypherCommons, an organization created 2026-05-29. The accurate description is "Bitshala-incubated, now under CypherCommons".
- The Shroud wallet reads it through the JSON endpoint `/transactions/range`. From the binary endpoints, it uses only `/silent-block/latest-height`.
- The indexer does no dust filtering and no cut-through, so its served list should match the full list.
- It supports regtest. Signet is not an accepted config value.

**What was wrong.**
- The binary routes are `/silent-block/height/{h}` and `/silent-block/hash/{hash}`, not the ones the research named.
- Calling it "Bitshala's own" outright goes further than any source does.

**Found by reading code, not by running it:**
- a varint bug in the binary format for blocks with 253 or more transactions;
- an eligibility check that looks only at the first opcode, which drops transactions spending bare multisig.

**Behaviour a client must handle:**
- An unknown or unindexed block returns HTTP 200 with an empty list.
- Txids arrive in display byte order.

Sources: github.com/CypherCommons/shroud-indexer (controllers, `common.ts`, `indexer.service.ts`, `storage.service.ts`); CypherCommons/shroud `modules/SilentPaymentIndexer.ts`; bitshala.org/about.

### Summary

| Suspicion | Result | What held up | What did not |
|---|---|---|---|
| Someone already publishes tweak-index commitments | Partly true | Live on mainnet since 1 Sep; spec 2 Sep; Optech 11 Sep | 21 Sep is when the source was published, not when the service launched; Optech never names it; a second implementation already exists |
| Canary misses output-side withholding | Confirmed | Every wallet Canary could front decides from output data Canary doesn't commit to | BlindBit's honest dust filter is per transaction; PR #56 is unmerged, opt-in and v2-only |
| blindbitd is archived and v2 dropped HTTP | Partly true | Archived 14 Aug 2025; v2 deprecates HTTP by policy | v2 still serves five HTTP data routes, none in v1's shape; blindbit-scan was missed |
| Submission needs a 3–5 min video, a README link and weekly logs | Partly true | Deadline, form fields, Publish separate from Save draft | Video length and README link come from one competitor's report of a private email; weekly logs are unsourced; no repo or licence rule was found |
| The repo misquotes BIP-352 | Confirmed | No revision ever mentions withholding | Nothing |
| Five defects in the plans | Partly true | Five real defects plus one piece of doc drift | The tripwire does report withholding for your own payment; no gap filler exists anywhere |
| shroud-indexer is an easy adapter target | Partly true | Unfiltered, regtest-capable, with a JSON endpoint the wallet uses | The route names and "Bitshala's own" were wrong; two bugs come from reading code, not running it |

---

## 3. Scored features

This is the same data as [At a glance](#at-a-glance), grouped by when the work happens. An asterisk (*) marks a number or horizon that changed after review, and a dagger (†) marks a horizon that the approved plan changed. "Pinned" means the item is mandatory, so the priority ratio does not rank it. Hours are the feature's size. [The v1 cut line and schedule](#5-the-v1-cut-line-and-schedule) explains where Claude builds work in parallel, which lowers your own hours.

| ID | Feature | Impact | Uniq. | Cx | Hours | Priority | Horizon |
|---|---|---|---|---|---|---|---|
| | **v1 critical path, in the order work starts** | | | | | | |
| F13 | README and submission package | 8 | 1 | 3 | 4.5* | 1.73 | v1, pinned |
| F12 | Truth pass: design fixes, then citations | 6 | 1 | 3 | 3* | 1.33 | v1, pinned |
| F09 | Regtest setup, demo harness, CI run | 8 | 4 | 5* | 5* | 1.28* | v1, automation cut 5; CI run v2 |
| X1 | Shared wire format (added in review) | – | – | – | 1 | pinned | v1 |
| F01 | Reference indexer with a withholding switch | 9 | 7 | 8* | 12* | 1.03* | v1, minimum form* |
| F02 | `canary check` against the server's signed record | 10 | 9 | 6 | 9* | 1.60 | v1, pinned |
| F03 | Receipts and an offline evidence file | 8 | 9 | 6 | 10* | 1.40 | v1, pinned; receipt checking cut 7 |
| F10 | Offline-verify test | 3* | 5 | 2* | 0.5* | 1.90* | v1, inside F03 |
| X2 | Command-line tool and state file (added in review) | – | – | – | 4 | pinned | v1 |
| F05 | One wording table for every result | 5 | 3 | 2 | 2 | 2.10 | v1 |
| F04 | Self-payment tripwire, tweak only | 7 | 6 | 4* | 4* | 1.65* | v1*, cut 6; output check v2 |
| F11 | The limits table | 6 | 4 | 1 | 1.5 | 5.20 | v1, pinned |
| F14 | Video from the recorded run | 8 | 2 | 5 | 6* | 1.12 | v1, pinned |
| | **v1, detected inside F02; only the demo scene is optional** | | | | | | |
| F15 | Servers disagree on a block's record | 5 | 7 | 4 | 5 | 1.45 | v1†; act 3b scene optional |
| | **v1 interfaces, built in parallel, first to be cut** | | | | | | |
| F06 | Coverage view and the lower-bound sentence | 7 | 7 | 3* | 1.5* | 2.33* | v1, inside F16; cut 4 |
| F16 | Local dashboard (`canary ui`) | 4 | 4 | 4* | 4* | 1.00* | v1 thin†; cuts 2 and 4; live v2 |
| F07 | Public site | 6 | 2 | 3* | 2* | 1.47* | v1†; pages beyond the checker cut 1 |
| F08 | In-browser evidence checker | 8 | 8 | 6 | 3* | 1.33 | v1†; cut 3 |
| | **After judging, by priority** | | | | | | |
| F21 | "What protects my wallet today?" page and `canary doctor` | 5 | 7 | 3* | 3 | 1.93* | v2* |
| F28 | Spec proposal for the index-server spec | 6 | 5 | 3 | 3* | 1.87 | v2 |
| F20 | Alerts that don't cry wolf | 3 | 2 | 2 | 2 | 1.30 | v2* |
| F18 | `canary why <txid>` | 6 | 8 | 6 | 8 | 1.13 | v2* |
| F27 | Block-level vectors offered upstream | 5 | 6 | 5 | 8 | 1.08 | v2 |
| F19 | Adapters for live servers, shroud-indexer first | 6 | 7 | 6 | 7 | 1.07 | v2* |
| F22 | SPCOMMIT interop | 6 | 7 | 6 | 10 | 1.07 | v2* |
| F17 | In-path proxy for unmodified wallets | 7 | 9 | 8 | 22–26* | 0.98 | v2* |
| F23 | Output keys in the entry (entry format v2) | 8 | 5 | 7 | 10 | 0.97 | v2, first after judging |
| F24 | Spend check for hash-only slots | 5 | 6 | 6 | 6 | 0.90 | v2 |
| F25 | Expected-payment inbox and self-payment probes | 5 | 6 | 7 | 14 | 0.77 | v2 |
| F26 | Canary on a home node | 4 | 3 | 6 | 14 | 0.60 | v2 |

---

## 4. The features, in priority order

The v1 critical path comes first, in the order work starts, followed by F15, whose detection ships inside F02. The optional v1 interfaces follow in build order. The v2 items come last, ordered by priority score.

### 4.1 v1 critical path

#### F13 · README and submission package

**Scores.** Impact 8, uniqueness 1, complexity 3, hours 4.5* (0.5 on Wednesday, the rest from Thursday to Monday), priority 1.73. v1, pinned.

**What it is.** Two halves: the admin on Wednesday, and the README and submission from Thursday to Monday.

Wednesday, 30 minutes:
- Start the Devfolio draft. You registered before registration closed on 28 September, but no draft exists yet. Save draft and Publish are separate actions, and only a published entry counts.
- Push the six unpushed commits.
- Find the 7 September email to registered participants, which carries the "problem statements, evaluation criteria, and hackathon details", or its Discord post. Until you have it, every rule except the deadline and the form fields rests on a competitor's paraphrase.

Thursday to Monday:
- **The README, in plain words.** Claude drafts it in Track C on Thursday and adds the real run's numbers on Sunday. You review it on Monday. It runs in this order:
  - the video link in the first lines;
  - what Canary does;
  - "accountable, not trustless", with its condition;
  - what works and what doesn't yet;
  - numbers from the real run: tests passing, bytes per block, blocks checked, time to detection;
  - the limits table;
  - the verify path;
  - prior art: SPCOMMIT, RFC 6962 and the corrected BIP citation;
  - a note that AI assisted the work.
- **Repo steps.** Add an MIT LICENSE. Make the repo public. Tag the submitted commit.
- **Devfolio fields.** Media, the problem, challenges, technologies, and the track-fit note.
  - The track-fit note answers "privacy or reliability?". Canary makes the privacy-keeping setup, where the server never sees your scan key, safe enough to be the default.
  - The alternative is a remote scanner like Frigate. It learns every payment and can still withhold one.
- **Press Publish,** not Save draft, before 17:00 IST.

**Use cases.**
- A judge who never finishes the video reads the README, builds once, and reaches a checked accusation within a minute.
- A judge scoring completeness finds a plain table of what is built and what is planned, with numbers taken from a real run.
- The reported organizer preference for a video link near the top is met, without anyone having to claim it as a rule.

**Why it matters.** A private repo with no LICENSE, whose README says "No code yet", scores near zero with a judge who reads the repo, whatever the code does.

**Depends on.** The admin half depends on nothing. The README half needs F11, F12 and the video link from F14.

**Risks.**
- Weekly progress logs are not a sourced rule. Never backfill them. At most, add a dated build log generated from git history.
- Enter Cypherpunk only by default. Add Freedom Stack only if the 7 September handbook allows it, and only with a genuine crossover pitch.
- The "under a minute" claim must include first-build compile time. Time it.

**Score rationale.** Impact scores 9, 8 and 2 (median 8): the judge and engineer scorers see it as the biggest risk if skipped, and the privacy scorer sees no effect on users. Uniqueness is 1. The critic split the feature into Wednesday's admin and Monday's writing. The approved plan then moved the README draft to Thursday, in Track C. The critic also pinned it as mandatory instead of ranking it, because uniqueness shouldn't rank hygiene. Hours fall from 5 to 4.5.

#### F12 · Truth pass: fix the design and the citations first

**Scores.** Impact 6, uniqueness 1, complexity 3, hours 3*, priority 1.33. v1, pinned. Claude does all of it in Track C on Wednesday and Thursday, and you review it.

**What it is.** One pass that corrects every claim that [What changed since the design was written](#2-what-changed-since-the-design-was-written) refuted. The design half comes first, because the code depends on it. The design had been marked final, so each change needed your approval. You gave it with the plan on 30 September.

Design changes, approved on 30 September:
- **The empty-slot rule.** An empty slot inside the 144-block window means the server withheld an entry it signed for, and Canary names the server.
- **Receipts.** Receipts sign the server's tip height and tip hash.
- **The network tag** carries the network's 4-byte magic number in decimal. The design text changes to match the code.
- **Claim wording.** Claims narrow from "omission" to "tweak omission".
- **Remove a false line.** Delete the claim that tweaks are "where omission is silent".
- **Match the demo to the code.** Rewrite the demo's third scene to describe what the code will actually do. Rewrite the answer to "why not sign the omitted list?" the same way.
- **Video length.** The target moves from 2:45 to between 3:15 and 4:30.
- **CLAUDE.md.** It stops naming blindbitd as the wallet, and its status lines match the code.

Citation fixes, in the same pass:
- **Credit SPCOMMIT** next to RFC 6962 (Certificate Transparency).
- **Replace the BIP-352 misquote.** The README and prior-art.md said BIP-352 v1.1.0 "states the trust assumption directly". CLAUDE.md said it "states the withholding trust assumption itself". Search each file for `v1.1.0` to find every copy. Use the BIP's real footnote, the Bitshala guide and SomberNight's issue instead. Add an ellipsis where prior-art.md skips text.
- **Attribute the quotes correctly.** "One canonical per-block set" comes from Segers' mailing-list post. "Trust me into catch me" comes from his protocol draft.
- **Say that Optech #422 never uses the name SPCOMMIT.**

Nothing in this pass waits for Monday. The README takes the real run's numbers on Sunday (F13), and Monday's final wording check reads the citations once more.

**Use cases.**
- A judge who read Optech #422 finds SPCOMMIT already credited, in a comparison table.
- A judge who knows BIP-352 finds the BIP's real footnote quoted, not a sentence the BIP never contained.
- You, writing `canary check` on Friday, read a design that says what an empty slot inside the window means.

**Why it matters.** Bitshala, which runs this hackathon, wrote the guide, and Optech covered SPCOMMIT. A misquote or a false "first" costs more than a missing feature, and anyone can check each one in a single click.

**Depends on.** Nothing. F02 and F03 depend on the design half.

**Risks.** The design doc is 1,425 lines long. Change only the lines that a verified finding contradicts.

**Score rationale.** Impact scores 8, 6 and 2 (median 6): the judge scorer weighs credibility heavily. The critic split the feature into a design half and a citation half, and pinned it. The critic put the citations on Monday; the approved plan moved both halves to Wednesday and Thursday, in Track C. Hours fall from 4 to 3, because the README rewrite (F13) absorbs part of the citation work.

#### F09 · Regtest setup, demo harness, and a CI run

**Scores.** Impact 8, uniqueness 4, complexity 5*, hours 5* in v1 (1 on Wednesday, 4 on Sunday), priority 1.28*. The setup and the harness are in v1. The CI run moves to v2.

**What it is.** Three parts, split on the critic's advice.

- **Setup, 1 hour, Wednesday.**
  - `brew install bitcoin`, start a regtest node with REST enabled, and mine 200 blocks.
  - Check the version: the REST endpoint for spent outputs needs Bitcoin Core 30 or later.
  - Everything else waits on this.
- **Harness, 4 hours, Sunday.** One script, `scripts/demo-regtest.sh`, does the whole run:
  - start the node and two copies of the reference indexer: an honest one, and one running `--withhold-txid`;
  - pay a taproot address and mine a few blocks;
  - run `canary check` and write the evidence file.

  Its output is the recorded run. The video, the README's numbers and the committed evidence file all come from it. The optional act 3b scene (F15) and the staged Can't be checked range for the last scene each add their own setup, and only if they are built.
- **CI run, 2 hours, after judging.** An in-process variant, clearly labelled as a test. In v1, CI only checks the committed evidence file, which needs no node.

**Use cases.**
- A judge clones the repo and runs the script. It ends by naming the server, block and txid, and it leaves behind an evidence file that verifies.
- You re-shoot a video take in minutes, because the run is scripted.
- The README's numbers are copied from a real run, not typed by hand.

**Why it matters.** Every real artifact comes out of the harness. Without it, the video and the site show a run nobody can repeat.

**Depends on.**
- The setup depends on nothing. The indexer (F01) depends on it.
- The harness needs F01, F02 and F03, and F04 for the payment declared in the detection scene.

**Risks.**
- **The payment needn't be a silent payment.** Any Core-wallet payment to a taproot (bech32m) address lands in the full list. An indexer cannot tell it apart from a silent payment. Only a real receiving wallet would need an actual silent payment, and v1 has none. This removes the hardest step.
- **Don't mine 144 or more blocks** between the payment and the check. The empty slot would fall outside the window, and the accusation would disappear.
- **Keep bitcoind out of CI.** Running it there breaks the project's rule that tests need no node, so CI gets the in-process variant.
- **Keep signing keys out of git.** Use throwaway keys, never commit them, and publish only the public key.

**Score rationale.**
- Impact is the median of 8, 8 and 3, and uniqueness the median of 4, 3 and 4.
- The critic split the feature to break a cycle. The indexer needed bitcoind, which lived inside this feature, while this feature depended on the indexer.
- Complexity falls from 7 to 5, because two things came out: the setup moved out, and the payment no longer has to be a silent payment.
- Hours: 5 in v1, and the CI part's 2 move to v2.

#### X1 · Shared wire format (added in review; not scored)

**What it is.** The package that both the indexer and the client import for a served response. Each slot in a response is a full entry, a hash or empty. The protocol-core plan included it, but no feature list did. Hours: 1, on Wednesday.

**Why it matters.** The indexer, `canary check` and the evidence file all need it.

**Risks.** It must live in the shared core, not in the indexer's internal code, or the client cannot import it. The plans made that mistake once for this type and again for receipts.

#### F01 · Reference indexer with a visible withholding switch (minimum form)

**Scores.** Impact 9, uniqueness 7, complexity 8*, hours 12*, priority 1.03*. v1, minimum form.

**What it is.** A small Go program in this repo that plays an index server on regtest.
- It reads each block, and the coins the block spends, from the local Bitcoin Core node.
- It computes the block's full list of entries.
- It signs one record per block as a Nostr event of kind 1352. That is a regular kind, so a relay never overwrites an old record with a newer one. Relays may still drop events, so records are also stored locally.
- It stores each record locally and serves it at `GET /commitment/{blockhash}`.
- It serves each block's entries at `GET /tweaks/{blockhash}`, with a signed receipt in the `X-Canary-Receipt` response header.
- It describes itself at `/info`.
- It has one switch, `--withhold-txid <txid>`, the only one the [frozen v1 formats](../design/2026-09-30-v1-formats.md#the-withholding-switch) define. It marks one entry absent in what it serves, while the signed record stays honest.

Two demo setups are optional:
- Act 3b (F15) needs a mode that signs a record already missing the entry. The frozen formats don't define one, so it would be an additive flag, added only if the scene is built.
- The last scene's staged Can't be checked range needs an entry marked absent (no hash) in a block 144 or more blocks below the server's signed tip, so the reason is `gap_unfilled`. A hash would make the block read Checked, gap filled instead. No other server and no declared payment may supply that entry. [If you are ahead](#if-you-are-ahead) lists it.

Left out of the minimum form:
- a filtering mode;
- the BlindBit v1 routes a real wallet would need;
- relay publishing. v1 fetches records over plain HTTP.

**Use cases.**
- A judge watching the video sees `--withhold-txid <txid>` typed on screen and listed in `--help`. The missing entry reads as an attack the team staged, not as a bug in Canary.
- A judge reading `--help` sees that the attack targets a txid, not an address. An indexer cannot find a receiver's payments without the scan key, but a paying exchange knows its own txid. The threat model stays honest.
- An index-server operator curls the endpoint and sees what records cost. A root is about 36 bytes per block, about 35 MB for the chain's roughly 965,000 blocks. A signed event is about 690 bytes per block, about 666 MB for all blocks (965,000 × 690 bytes). The 1 Oct run's record for block 351 is 691 bytes.

**Why it matters.** Every check except the tripwire needs a server that publishes per-block records. No live server publishes Canary's records, so without this indexer there is nothing to catch.

**Depends on.** The F09 setup, the wire format (X1), and the receipt type. The receipt type is built first, inside F03's hours.

**Risks.**
- **Independence.** The project's own rule says the indexer must not reuse Canary's `canonical` package, because then a test comparing the two would prove nothing. Keeping the two paths separate costs another 4 to 6 hours. You decided on 30 September that the minimum form reuses `canonical`. The docs therefore say plainly that the v1 comparison isn't independent.
- **Txid byte order.** Hashes use internal byte order, and explorers show display order. One reviewer suspected that the indexer plan reverses txid byte order twice. Nobody confirmed it. Pin txid order with a test.

**Score rationale.**
- Impact is the median of 9, 9 and 5; the privacy scorer notes that no real user runs this indexer.
- Uniqueness is 7, because SPCOMMIT already runs a committing server. The new parts are per-block records, receipts and the switch.
- The critic's corrections:
  - The original 14 hours only held for a minimum form. The full version as first written would take 20 hours or more: an independent tweak path, a filtering mode, and the BlindBit v1 routes with their filter.
  - The original estimate also left out the wire format and bitcoind.
- With the scope now set to the minimum form, complexity rises from 7 to 8 and hours are 12.

#### F02 · `canary check`: each block against the server's own signed record

**Scores.** Impact 10, uniqueness 9, complexity 6, hours 9*, priority 1.60. v1, pinned.

**What it is.** For each block, Canary fetches two things from the server: its signed record, and what it serves (full entries, hash-only slots and empty slots). It then:
1. fills whatever gaps it can;
2. recomputes the fingerprint;
3. compares it with the signed fingerprint.

It fills gaps *before* it recomputes, never after.

An empty slot inside the 144-block window means the server withheld an entry it signed for. Canary then names the server, the block and the txid.

A server that filters honestly can still be checked, within a limit. Inside the most recent 144 blocks, it must send the hash of every entry it drops, so Canary can check the block against the signed root. Older blocks can be checked only if the server kept the hashes or another source supplies the entries. Otherwise they read Can't be checked.

The 9 hours cover:
- the retention-window rule, with the block height and the server's tip passed into the comparison;
- fetching signed records over HTTP (the existing `feed` package only talks to relays);
- pinning the server's public key with a flag, with no trust on first use;
- binding each height to a block hash from your own node, because Canary keys every block by its hash, never by its height;
- the `check` command and its exit code.

**Use cases.**
- **Regtest demo.** An honest server and a withholding server run side by side. `canary check` prints "withholder left out an entry it had signed for: block 205, txid 01982d71…7c16.", exits with code 1, and marks the honest server's blocks Checked.
- **A reviewer's question.** A BIP-352 reviewer asks SomberNight's question: "I presently do not see a way how to fix this while using cut-through." The answer is a design and a command, for blocks inside the retention window. In v1, unit tests cover the filtering case. No filtering server runs in the demo.
- **Operator CI.** An indexer operator runs the check in CI against their own regtest server. A release that serves less than it signed then fails before shipping.

**Why it matters.** Checking a filtered response when it arrives, at least inside the retention window, is the thing SPCOMMIT's author says his scheme cannot do. This is accountability, not trustlessness: it only works with a server that publishes records.

**Depends on.** F01, F12's design changes, X1.

**Risks.**
- **The planned version never reported withholding.** It returned "unresolvable" when no second source existed, and "clean" when a second source filled the gap. The retention rule fixes this. Add a test that fails without it.
- **Hash-only withholding.** A server that *declares* cut-through can send the correct hash in place of the entry, and the block reads Checked, gap filled, with the reason `hash_retained`. A server whose `/info` declares no pruning and does the same gets a warning, reason `hash_without_policy`. It is never an accusation, because v1 policies are unsigned. F11 names this limit, and F24 fixes it.
- **Checked means less than it sounds.** It means the scan entries matched, never that your payments were found. See F11.
- **Raw comparisons.** Show a raw comparison only as quoted research, with its date. On 30 September, three live answers for mainnet block 969300 held 220, 184 and 141 entries: silentpayments.dev's two endpoints and Cake's server. It was a one-off measurement, and only the counts were kept. A raw diff cannot tell filtering from withholding. That is why Canary compares against signed records instead.

**Score rationale.** Judge 10/9, engineer 10/9, privacy 6/8. The critic raised hours from 7 to 9 for the parts listed above, which the original estimate left out. Complexity stays at 6.

#### F03 · Signed receipts and an evidence file anyone can check offline

**Scores.** Impact 8, uniqueness 9, complexity 6, hours 10*, priority 1.40. v1, pinned.

**What it is.** When `canary check` catches withholding, it writes one JSON file in the versioned format `canary-evidence/1`. The file holds:
- the server's signed record;
- its signed receipt over the exact bytes it served;
- those bytes;
- a Merkle proof that the missing entry is in the signed record.

`canary verify` rebuilds the result from those parts with no network. It runs eight steps in this order, and stops at the first failure ([v1 formats, the evidence file](../design/2026-09-30-v1-formats.md#what-canary-verify-recomputes-in-order)):
1. the file reads cleanly, with no unknown fields;
2. the signed record's id and signature are valid;
3. the record's signer is the accused key;
4. the record names the file's block and network;
5. the Merkle proof carries the entry to the signed root;
6. the receipt verifies under the same key and covers the served bytes;
7. the served list has the length the record states, and the entry's position does not carry it;
8. an empty position sits inside the window, measured against the tip the server signed.

Steps 1 to 5 need no receipt. The file carries no stored result, and verify rejects any field it does not know, so it prints only what it recomputes. Without a receipt, it stops after step 5. It then prints "Inclusion only: you can be sure of this, you can't yet prove it to others." Such a file shows what the server signed, not what it served.

The 10 hours:
- 3 for the receipt type in the shared core, including the tip;
- 5 for the file and verify;
- 1 for a proof builder that works from hashes, because `commit.Prove` needs every entry;
- 1 for tamper tests, no-receipt tests and F10.

**Use cases.**
- A judge who never watches the video builds once online, turns off the network, and runs `canary verify` on the committed file. Every check passes, and the output names the server, block and txid.
- A reviewer flips one byte of the proof. Verify fails and names the check that broke. Adding a result field makes the file unreadable, because verify rejects unknown fields and recomputes everything.
- A victim attaches the file to an issue on the server's repo. Both signatures come from the operator's own key, so the operator cannot claim the file was made up.

**Why it matters.** Detection is not proof. A signed record on its own shows only that the server committed to an entry. It doesn't show that the server then served a list without it. The receipt closes that gap. Other entrants export files that only agree with themselves. Here, the accused party signed both halves.

**Depends on.** F02, F01 signing receipts, X1, F12's design changes.

**Risks.**
- **The planned verify was forgeable.** It checked only the record's signature and the proof, and printed a claim it never checked. Test the fix by building exactly that forged file and confirming verify rejects it.
- **A server can overstate its signed tip.** That puts the empty slot outside the window by the server's own signed values. `canary check` then tests the tip against your Core node. If Core contradicts it, Canary accuses the server of a false chain claim, but writes no evidence file, so the finding is not provable to others. F11 says so.
- **Offline verify needs no node.** Canary writes an evidence file only when the server's own signed tip and height put the block inside the window. Those signed values settle the question without chain data.
- **Fresh clones aren't offline-ready.** A fresh clone must download modules first. Say "build once online, then verify offline", or ship release binaries.
- **Format freeze.** The file format and the state-file schema were frozen on 30 September in [v1 formats](../design/2026-09-30-v1-formats.md). Generate the committed example last, from the final run.

**Score rationale.** Judge 8/8, engineer 9/9, privacy 5/9. The critic raised hours from 8 to 10. The receipt type with the tip, the hash-based proof builder and the tests were all missing from the estimate. Both this feature and F01 also claimed the receipts, so in practice nobody owned them. They sit here now.

#### F10 · Offline-verify test

**Scores.** Impact 3*, uniqueness 5, complexity 2*, hours 0.5*, priority 1.90*. v1, inside F03's hours.

**What it is.** One test that runs `canary verify` while every network dial fails. The README's "verifies offline" claim links to it.

**Use case.** A judge asks whether offline verification is real. The README points to the test.

**Why it matters.** Every claim the README makes needs a test behind it.

**Depends on.** F03.

**Risks.**
- The original feature also included a traffic test showing that no request carries a scan key, an address or a watched txid. Canary v1 never holds a scan key or an address, so that test would prove nothing yet. It returns in v2, once Canary talks to real servers.
- Don't call Canary "provably key-free". Block-level fetches still reveal which blocks a wallet cares about, such as its starting height. Name that leak instead of claiming there is none.

**Score rationale.** The critic cut impact from 5 to 3 and hours from 3 to 1. This document books half an hour for the one remaining test. Complexity falls to 2, because the feature is now a single test.

#### X2 · Command-line tool and state file (added in review; not scored)

**What it is.** The `canary` binary, with `check`, `verify`, `status` and `ui`, as [v1 formats, the CLI](../design/2026-09-30-v1-formats.md#9-the-cli) defines them.
- `check` writes a state file holding per-block coverage.
- `status --json` prints the state file.
- The wording table (F05) is built in.

The state file's JSON shape was frozen on Wednesday 30 September, in [v1 formats, the state file](../design/2026-09-30-v1-formats.md#8-the-state-file). The dashboard and the site's recorded-run page both read it, and Claude builds them in parallel from Thursday. Hours: 4.

**Why it matters.** The original list had a view of coverage (F06), but nothing that computed coverage or wrote it down.

**Depends on.** F02, F03.

**Risks.** Any change to the schema after Wednesday breaks the dashboard and the site.

#### F05 · One wording table for every result

**Scores.** Impact 5, uniqueness 3, complexity 2, hours 2, priority 2.10. v1. It lives in `internal/ui/copy.go`, and Claude builds it on Thursday with the design system.

**What it is.** One Go table. For each coverage state it holds a label, a one-line meaning, what to do next, and what the state does not prove. The CLI, the dashboard, the site and the checker all read this table, so the terminal and the browser never disagree on camera. Two earlier drafts proposed different labels. The reviewers reconciled them into this set.

[v1 formats, the state file](../design/2026-09-30-v1-formats.md#states-and-on-screen-labels) is the source of truth for the labels, their meanings and the reason codes. Track B builds `copy.go` from it, not from this summary:

| State | Plain meaning | What it does not prove |
|---|---|---|
| Checked | The entries you got match what the server signed. | That the outputs your wallet matches against were served honestly. |
| Checked, gap filled | Some positions came as hashes, or were filled from another source, before Canary recomputed the root. Everything matched. | That the server's reason for leaving them out was real. |
| Can't be checked | Canary could not recompute the root. For example, an entry was left out outside the window and no source could supply it. | That anyone cheated, or that the block passed. It is neither a pass nor an accusation. |
| Not checked | There is no signed record to check against. For example, the server publishes none, hasn't indexed the block yet, or didn't answer. | Anything, either way. |
| Servers disagree | Two servers signed different records for the same block. | Which one is wrong. |
| Data withheld | A server left out an entry it was bound to include. Either it signed a record containing the entry and served a list without it, or it left out the entry for a payment you declared. | That the entry was a payment to you. |

Rules that go with the table:
- Under Data withheld, add "You can prove this to others" only when the evidence file carries a receipt that verifies. Otherwise, write: "You can be sure of this. You can't yet prove it to others."
- A server that published records for the blocks around this one but not for this block shows as Not checked, with the reason `no_record_for_block` and a warning. The warning is not an accusation.
- Never use these words in any label: proven, safe, secure, trustless, seamless, timestamped. No exclamation marks.

**Use cases.**
- A user sees: "Can't be checked: blocks 212–214. Canary could not recompute the signed root for them. A payment in them could be missing from what your wallet shows. This does not mean anyone cheated."
- A user with two servers sees "Servers disagree about block 207. This does not show which is wrong." and keeps both servers.

**Why it matters.** The coverage states are the product. If a user reads Servers disagree as Data withheld, they drop an honest server, and an attacker who can trigger that can knock out honest servers. If a user reads Checked as "safe", they are told more than Canary knows.

**Depends on.** The list of states. The critic removed the dependency on F02 itself.

**Risks.** Labels can drift between surfaces. Run a lint over the templates for the banned words.

**Score rationale.** All three scorers gave 5, 3, 2 and 2. The critic flagged three of the earlier labels:
- "Caught withholding" sounds like proof even when there is no receipt.
- "Recovered" suggests recovered funds.
- "Not checked yet" implies a later check. For a server that never publishes records, that check never comes.

#### F04 · Self-payment tripwire (tweak only)

**Scores.** Impact 7, uniqueness 6, complexity 4*, hours 4*, priority 1.65*. v1 checks the tweak only; the output check follows after judging. It is cut 6: if it isn't passing by Sunday 20:00, it becomes a named limit.

**What it is.** You tell Canary about a payment you made to yourself in block B, with `canary check --expect TXID[@BLOCKHASH]`. The v1 tripwire is that one declared payment. Scheduled probes at random times and amounts come in v2 (F25). You hold the coins the payment spent, so Canary can compute the entry itself. Canary fetches block B's whole served list, the same request any wallet makes, never a query for one txid. It then checks that each server reports the entry. Your own Bitcoin Core node confirms that the transaction is in block B. That confirmation is what lets Canary name a server instead of only raising a worry.

What Canary concludes depends on what the server signed and served ([v1 formats, reasons](../design/2026-09-30-v1-formats.md#reasons)):
- **The record carries the entry, and the list marks it absent inside the window.** This is an ordinary omission, reason `absent_in_window`. The declared payment supplies the missing entry, so `canary check` can write an evidence file.
- **The signed record itself leaves the entry out.** Canary accuses the server, Data withheld, reason `expected_payment_not_in_record`, with no spending check. A record commits to every entry in the block, spent or not. The finding is not provable to others unless an evidence file can be built, and `canary-evidence/1` has no claim for this case.
- **The list carries only the entry's hash, or marks it absent outside the window.** Canary accuses, reason `expected_payment_not_in_list`, only when Core shows one of the payment's taproot outputs unspent, at or above the server's declared dust threshold. Then pruning cannot explain the gap. Otherwise nobody is accused, because pruning could explain it.

**Use cases.**
- **The video's detection scene.** In act 3, the declared payment supplies the entry that the withholding server left out. Canary recomputes the root and names the server, the block and the txid.
- **A record signed without your payment.** A server signs a record that already leaves your entry out. A check against that server alone sees nothing wrong, because it serves exactly what it signed. The tripwire catches it: your transaction is in block B, and the server's signed record for B doesn't contain it.
- **The case the project was built for.** The exchange that pays you also runs your indexer. Your self-payments look like its payments, so hiding the payments it chooses risks hiding a probe.

**Why it matters.** It is the only check that still works when every server colludes. It also answers the first question an expert asks: "Why wouldn't the attacker just sign the omitted list?" A second committing server shows such a record as Servers disagree (F15), which names both servers. The tripwire is the only v1 check that names the one that lied.

**Depends on.** F01, F02's fetch path, and your own node as the chain anchor. Showing the signed-record case on camera also needs the record-omitting mode that F15 describes.

**Risks.**
- Against a server with no receipts, the result is detection for you, not proof for others. The signed-record case is never provable to others in v1.
- Before accusing, rule out three cases: not yet indexed, unconfirmed, and removed by a reorg.
- If the tripwire fetched only the block holding the probe, the request would reveal which block you care about. Fetch the same range the wallet fetches.
- A txid the payer tells you, without the coins it spent, gives detection only. Canary can't build the entry, so there is no evidence file. And the attacker in this story never tells you the txid it's hiding.

**Score rationale.**
- **Scores kept.** Impact is the median of 7, 7 and 8. Uniqueness is the median of 6, 6 and 7.
- **Output check moved to v2.** The original feature also promised an output check. It would look for a match in the served filter, an unspent entry in the UTXO list, or the 8-byte prefix. The critic pointed out that the v1 indexer serves none of those. That half can't run until a server serves output data (F17, F19) or the entry covers outputs (F23).
- **Scope, hours, complexity.** The scope narrowed to the tweak, so hours fall from 6 to 4, and complexity falls from 5 to 4.
- **New dependency.** The critic added one: F15's attribution runs through this feature.

#### F11 · The limits table

**Scores.** Impact 6, uniqueness 4, complexity 1, hours 1.5, priority 5.20. v1, pinned. Claude drafts it from Wednesday, and you finish it on Monday.

**What it is.** One table of what Canary v1 does not check, shared by the README, the site and the video's last scene. It opens with the condition every claim depends on: at least one honest server publishing signed records, and an uncensored path to wherever they are published. It also says what "Checked" means: the tweak list was checked, never that payments were checked.

The rows below are the planned content. The final wording depends on what ships.
- **Output-side withholding.** A server serves the right tweak and drops the output your wallet matches against, from its filter, its UTXO list or its 8-byte prefixes. Every v1 check passes. Fix: F23.
- **Hash-only withholding under a filtering policy.** A server that declares cut-through sends the right hash instead of the entry. v1 reads the block as Checked, gap filled, with the reason `hash_retained`. A server whose `/info` declares no pruning and does the same gets a warning, reason `hash_without_policy`, and never an accusation, because v1 policies are unsigned. Only the tripwire catches the variant: for your own payment, when Core shows an output unspent (reason `expected_payment_not_in_list`). Fix: F24.
- **A server that signs a record already missing the entry.** A check against that server alone can't see this. A second committing server catches it as Servers disagree, which names both servers but not the liar (F15). The tripwire names the liar for your own payments, as a finding you can't yet prove to others. If F04 slips, the row says the tripwire is not in v1.
- **Fake entries added to steer your wallet.** Out of scope. Canary looks for missing data, not added data.
- **Every server colluding, with no tripwire.**
- **Built and tested on regtest only.** No live server publishes Canary's records or speaks its API today, so v1 cannot check a live server, even through the tripwire.
- **A server that declines to answer is warned about, not accused.** Skipping one block's record between signed neighbours gives Not checked, reason `no_record_for_block`, with a warning. So does signing a record and then refusing the list inside the window. Nothing the server signed shows the refusal.
- **Detection is not proof without a receipt.** A gap excused by a signed tip that your node contradicts is accused. It is not provable to others, because checking it needs a node.
- **Nostr gives publication, not timestamps.**
- **Which blocks you fetch reveals your wallet's age.**

**Use cases.**
- An expert judge asks, "What if the server keeps the tweak and drops the output?" The first row answers it and names the fix.
- A judge asks, "Why not mark the withheld entry as pruned?" The hash-only row answers it.

**Why it matters.** A limit the team volunteers reads as rigor. The same limit dragged out by a judge reads as overclaiming. The first two rows are the first attacks an index-server author would try.

**Depends on.** Nothing, to start. Finish it last, because its content depends on whether F04 and the receipts ship.

**Risks.** The table must not credit a fix that didn't ship. The original draft named F04's output check as the answer to the first row. That check isn't in v1, so the row must not mention it.

**Score rationale.** Impact scores 8, 6 and 4 (median 6). Complexity 1 from all three scorers. The critic pinned the table as mandatory rather than ranking it.

#### F14 · Video, 3 to 5 minutes, from the recorded run

**Scores.** Impact 8, uniqueness 2, complexity 5, hours 6*, priority 1.12. v1, pinned.

**What it is.** A recording of the harness run, at least 180 seconds long, with a target of 3:15 to 4:30. The scenes:
1. **The missing entry.** Your node shows the transaction in block H. The server's list for block H doesn't have it.
2. **The switch.** `--withhold-txid`, shown in `--help`.
3. **The catch.** `canary check` names the server, block and txid. The server's record is honest, and its served list has an empty slot inside the window. Narrate exactly that. The design's version of this scene, "recompute and find a mismatch", is not what happens.
4. **The other branch (act 3b).** The attacker now signs a record that already leaves the entry out. A second, honest indexer signs the full list for the same block. The two roots differ, and coverage reads Servers disagree, naming both servers and not the liar. `canary check` detects this in v1. Only staging the scene is optional, because it needs a record-omitting mode the frozen formats don't define (F15).
5. **Offline verify.** `canary verify` runs on the evidence file with the network off.
6. **The limits.** The limits table, then a Can't be checked range in `canary status`: signed data Canary could not check, which is neither a pass nor an accusation. The range is staged as the first item under [If you are ahead](#if-you-are-ahead).

Say on camera that the video runs on regtest and why. Say that AI assisted the work.

**Use cases.**
- A judge who only watches sees the loss before the tool, and an honest ending.
- A retake takes minutes, because the run is scripted.

**Why it matters.** Judging is asynchronous, so nothing can be faked. The video carries the story for the judge who never opens the repo.

**Depends on.** F09's run, and F16 if it ships. The critic removed the dependency on the browser checker, because the verify scene uses the command line.

**Risks.**
- **No wallet for scene 1.** The design's first scene showed a wallet at zero, and there is no wallet to show:
  - blindbitd is archived;
  - blindbit-scan needs routes that v1 doesn't serve;
  - Dana's released app is mainnet-only.

  Scene 1 is restaged as "the served list lacks the entry". A minimal scanner would cost about 3 hours and edge toward building a wallet, which the project rules out.
- **The length rule is unconfirmed.** One competitor (QuietRelay) reports a 3-to-5-minute rule from the private handbook and an organizer email of 21 September. Meet it, since that costs nothing, but don't cite it as a rule. Target 3:15 to 4:30, and confirm the runtime is at least 180 seconds.

**Score rationale.**
- Impact is 8; nine of the 21 Cypherpunk entries already have a video.
- Uniqueness is 2.
- Hours fall from 7 to 6, on the critic's estimate.

#### F15 · Servers disagree on a block's record

**Scores.** Impact 5, uniqueness 7, complexity 4, hours 5, priority 1.45. v1†. Detection ships inside F02. Only the staged demo scene, act 3b, is optional. F15 is not on the critical path.

**What it is.** A committing indexer signs a record that leaves the entry out, then serves exactly that list, so a check against it alone finds nothing. A second, honest committing indexer signs the full list for the same block hash. Canary sees two different signed roots. It reports Servers disagree, reason `records_differ`, names both servers in a `disagree` finding, and drops neither. The block becomes Data withheld only when a payment you declared shows which server left it out.

`canary check` already compares roots across servers, as the last step of every check, so detection costs nothing extra in v1. The 5 hours now buy the staged scene. It needs a second indexer mode that signs a record already missing the entry. The frozen v1 formats define only `--withhold-txid`, so that mode would be an additive flag, added only if the scene is built.

**Use cases.**
- A judge asks why an attacker would sign an honest record. Act 3b shows the other choice caught.
- A user with two servers sees the disagreement and keeps both.

**Why it matters.** It keeps disagreement apart from proof, which stops a third party from getting an honest server excluded.

**Depends on.** F01 (a second instance, plus the record-omitting mode for the scene), F02, and F04 for attribution. The critic added the F04 dependency.

**Risks.**
- "Both branches lose for the attacker" overclaims, because the hash-only and output-side variants lose nothing.
- In v1, a `disagree` finding has no evidence file, because `canary-evidence/1` carries only the omission claim. Label it detection.
- Run act 3b without `--expect` for the hidden payment. With it, the tripwire names the liar: Data withheld, reason `expected_payment_not_in_record`, outranks Servers disagree, so the scene would not show the disagreement.
- Never exclude a server automatically.

**Score rationale.** Scores unchanged. The first draft of this roadmap moved F15 to v2 to make room, with the tripwire covering the scene instead. The approved design keeps act 3b as this branch, and the v1 formats already detect it. So only the staged scene stays optional.

### 4.2 v1 interfaces, built in parallel

Claude builds everything in this section in a parallel session from Thursday, and you review it. Until a real run exists, the pages render only watermarked sample data, behind a build tag the release binary never uses. These features are also the first to go when time runs short. [The cut order](#cut-order-when-time-runs-short) drops them before any part of the core loop.

#### F06 · Coverage view and the lower-bound sentence

**Scores.** Impact 7, uniqueness 7, complexity 3*, hours 1.5*, priority 2.33*. v1. It is drawn inside the dashboard (F16), so the two ship together, or are cut together at cut 4.

**What it is.** The view has:
- one row per server;
- one cell per block, showing the block's state by shape, colour and word;
- a range table beside it, which is the accessible version.

Go draws the view as SVG, one shape per run of blocks.

Whenever any block isn't Checked, a fixed sentence sits under the view: "12 blocks couldn't be checked. A payment in them could be missing from what your wallet shows, so treat its balance as a lower bound." When some of those blocks read Data withheld or Servers disagree, which Canary did check, the sentence opens "12 blocks are not Checked." instead, with the same second sentence. It says a payment could be missing, never that one is. This is the line worth leading with. A balance computed over blocks you couldn't check is a lower bound, not a balance.

The view shows no BTC amount:
- v1 has no link to a wallet;
- entries carry no value;
- Canary never holds a scan key.

**Use cases.**
- A user sees how many blocks were actually checked. A progress bar would only have said "done".
- The video's last scene closes on a visible Can't be checked range.
- Two servers sign different records for the same block. The cell reads Servers disagree and names both servers.

**Why it matters.** An alarm that never fires looks like a product that does nothing, but coverage is always visible. None of the silent-payment wallets studied (Cake, Dana, BlindBit, Sparrow) shows whether its server was honest. The closest thing is mempool.space's block audit, which shows "Unknown" rather than a fake pass.

**Depends on.** X2, F05.

**Risks.**
- Draw only real run data.
- No 0-to-100 score.
- Without the in-path proxy (F17), coverage is only a view and protects nothing. The page says so.

**Score rationale.** Judge 7/7, engineer 7/7, privacy 6/8. The frontend reviewer replaced the planned single-page app with server-rendered Go templates. In that setup, the view is one template and one test, so complexity falls from 4 to 3 and hours from 5 to 1.5.

#### F16 · Local dashboard (`canary ui`)

**Scores.** Impact 4, uniqueness 4, complexity 4*, hours 4*, priority 1.00*. A thin version ships in v1†, built by Claude in a parallel session. Pages beyond Overview and Finding are cut 2, and the whole dashboard is cut 4. The live version comes in v2.

**What it is.** A `canary ui` subcommand, not a daemon. It reads the state file that `canary check` wrote and serves read-only pages on 127.0.0.1.
- **Overview:** a one-sentence summary, the lower-bound sentence, the coverage view, counts, open findings and the servers.
- **Finding:** what happened, what it proves, the verify report, and the evidence file to download.
- **Blocks pages:** the coverage view with its range table, and one page per block. These go first if a day slips (cut 2).
- **Error and empty pages:** a 404, a 500 with an error ID, "No check yet" with the command to run, an unreadable state file, and a stale-results banner.
- **An update bar:** while the tab is visible, the page checks the state file every 5 seconds and offers "New results. Reload". It never contacts any outside server.

The status line uses the same words as `canary status`, from [v1 formats, the CLI](../design/2026-09-30-v1-formats.md#canary-status): "Last check 2026-10-03 08:32 UTC · blocks 0–212 · regtest · canary 0.1.0 (abc1234)". The dashboard changes only the time. It prints your local time instead of UTC, followed by a relative age: "Last check 2026-10-03 14:02 IST (6 min ago) · blocks 0–212 · regtest · canary 0.1.0 (abc1234)". Every page carries a regtest badge.

**Use cases.**
- In the video, the terminal and the dashboard share the frame at least once and use the same words.
- A user whose server was caught opens the Finding page and downloads the evidence file.
- A user opens the dashboard before running any check and sees the exact command to run.

**Why it matters.**
- You chose to have a dashboard.
- The track asks projects to "make the private path the easy path", and a terminal-only tool doesn't do that.
- The dashboard is what appears in the video.

**Depends on.** X2, F05 and the real run. The reviewer reversed the original order. The dashboard comes first, and the site reuses its templates.

**Risks.**
- Bind to 127.0.0.1 only.
- Reject other Host headers, which blocks DNS rebinding.
- Send a CSP header.
- Make zero external requests, and self-host the fonts.
- Show no "Protecting" badge, no "running" light and no "Stop using this server" button. v1 isn't in the wallet's path, and it doesn't run continuously.
- Keep sample data behind a dev-only build tag with a SAMPLE DATA watermark. The release binary must not be able to render it.

**Score rationale.**
- **Impact is low.** The scores were 4, 3 and 5; judges rarely run local tools.
- **Hours and complexity.** The reviewer's architecture uses Go templates, no Node build and no live updates. That puts hours at about 4, including the shared styles, and lowers complexity from 5 to 4.
- **Why it's scheduled anyway.** The priority is low, but you chose the dashboard, and the high-scoring F06 lives inside it.
- **Your time.** Claude builds the pages in a parallel session from Thursday, so your own time is about an hour of wiring and review.
- **Scope added after scoring.** These sizes were scored for a thin dashboard: Overview plus Finding. The approved plan then added the Blocks pages, the error and empty pages, the update bar, and a design system with self-hosted fonts and SVG symbols. Claude builds that extra scope in parallel, and it is not sized here.

#### F07 · Public site on the same design system

**Scores.** Impact 6, uniqueness 2, complexity 3*, hours 2*, priority 1.47*. v1†: Claude builds it in a parallel session from Friday. It goes public only after you press Publish on Monday. Pages other than the checker page are the first cut.

**What it is.** `go run ./cmd/site` renders the dashboard's templates into a static site with four pages:
- a home page that opens on the evidence checker (F08), followed by the plain explanation, the limits and "run it yourself";
- one long page on how it works;
- a recorded-run page;
- a 404 page.

The checker comes preloaded with the real evidence file and a labelled tampered copy. The site deploys to Cloudflare Pages with `npx wrangler pages deploy`, which needs you to log in to wrangler. It carries `noindex` until submission.

**Use cases.**
- A judge on a phone opens the site from the Devfolio link and sees the real run's coverage and finding.
- The recorded-run page shows the dashboard as it stood at the end of the real run, under a banner that can't be dismissed: "Recorded run, not live."

**Why it matters.** The strongest rivals, Dossier and RelayJoin, win partly on a page a judge can open in 20 seconds. Canary has nothing to click yet. [BOSS Battle competitors](../research/2026-09-30-competitors.md) has the details.

**Depends on.** F16's templates and the real run.

**Risks.**
- **The recorded run must be exact.** Render the recorded-run page only from the byte-identical state file the real run wrote, committed next to the evidence file. Show the file's SHA-256 and the commit. Use absolute times only.
- **Fonts.** Use Atkinson Hyperlegible Next and Atkinson Hyperlegible Mono, self-hosted: 52 KB, matching metrics, and a slashed zero. *Superseded 2 October 2026: the design uses Geist and JetBrains Mono. See [decisions](../decisions.md).*
- **Colour.** Use a canary yellow at about 55° hue, such as #F4E13A. Avoid #F5C518, which is IMDb's brand yellow and sits right next to Binance's. On light backgrounds, give the yellow an ink outline: without one, its contrast is only 1.2–1.5:1. *Superseded 2 October 2026: the brand is canary amber `#FFC174` on a dark-first ground. See [decisions](../decisions.md).*
- **State symbols.** Draw the six state symbols as SVG, not as Unicode characters, which render differently from one platform to the next.

**Score rationale.** Impact 6. Uniqueness 2, because every competitor has a site. The scored 8 hours assumed a separate JavaScript workspace. With the shared Go templates it's about 2 hours, and complexity falls from 5 to 3. That size was scored for a four-page site. The approved plan then added the preloaded checker, the recorded-run page with its SHA-256, and the wrangler deploy. Claude builds that extra scope in parallel, and it is not sized here.

#### F08 · In-browser evidence checker

**Scores.** Impact 8, uniqueness 8, complexity 6, hours 3*, priority 1.33. v1†: Claude builds it in a parallel session on Saturday. It is cut 3, and it ships only if Wednesday's WebAssembly build check passes.

**What it is.** The same `canary verify` code, compiled to WebAssembly and put on the site. A judge drops in an evidence file, or clicks the real one. Their own browser checks it and says in plain words what it shows. A labelled tampered copy ("field `proof[2]`, one byte flipped") shows exactly which check fails.

**Use cases.**
- A judge with no Go installed clicks the real file and watches each check pass.
- An accused operator loads the file and sees which signature and which slot the claim rests on.
- A reader drops in a file someone posted on a forum.

**Why it matters.** It turns "verify this yourself" into a single click. When the file carries a receipt, everything the page checks was signed by the accused party.

**Depends on.** F03's verify, and the site (F07).

**Risks.**
- **Unproven build.** Nobody has yet built `canary verify`'s dependencies for WebAssembly. `feed` pulls in the go-nostr relay pool, bytedance/sonic and coder/websocket. Wednesday's 15-minute build check decides whether this feature is possible at all. The size budget is about 3 MB compressed.
- **Toolchain mismatch.** `wasm_exec.js` must match the compiler, and `go.mod` has no toolchain line: CI runs 1.24 and the laptop runs 1.26. Pin the toolchain before you publish a hash.
- **No reproducibility claim yet.** The page says which commit and Go version built it. Don't claim a reproducible build until two machines produce the same file.
- **Upload claim.** Say "your file is never uploaded" only on a static host with no server functions, and only after a test confirms zero requests.

**Score rationale.** Impact 8, uniqueness 8. The reviewer's architecture drops the Web Worker and the build tooling, so hours fall from 7 to 3 (2.5, plus the build check). Complexity stays at 6, because of the unproven build.

### 4.3 After judging, by priority score

#### F21 · "What protects my wallet today?" page and `canary doctor`

**Scores.** Impact 5, uniqueness 7, complexity 3*, hours 3, priority 1.93*. v2*.

**What it is.** A dated page that asks which wallet and server you use, then says honestly what Canary can and can't do for that setup. Later, a `canary doctor` command probes the setup directly.

**Use cases.**
- A Sparrow user learns that Frigate holds their scan key and returns matches, not tweaks, so Canary can't check it.
- A blindbit-scan user learns their client could sit behind Canary's proxy once F17 exists.
- A BlindBit Desktop user learns it speaks gRPC only.

**Why it matters.** Commitments can't protect most people receiving silent payments today. The framing rules say to state that first.

**Depends on.** Nothing. The critic removed the dependency on F05.

**Risks.**
- The Frigate and Cake facts come from source reading on 30 September. No independent check covered them.
- Date every claim.

**Score rationale.** The critic moved this to v2, because v1 protects none of the wallets it would list. In v1, one row of the limits table covers the point. Complexity rises from 2 to 3, since every wallet fact needs checking.

#### F28 · Spec proposal for the index-server spec

**Scores.** Impact 6, uniqueness 5, complexity 3, hours 3*, priority 1.87. v2.

**What it is.** A short standalone spec covering:
- per-block signed records;
- hash-only slots;
- the retention window;
- receipts that sign the tip.

It proposes one optional endpoint for the silent-payments index-server spec. The proposal goes to Delving thread 891, with credit to SPCOMMIT.

**Use cases.**
- The index-server spec's own question gets a runnable answer: "How does a wallet know all tweaks were received for a given block request?"
- An operator adds the endpoint and keeps filtering.
- SomberNight's cut-through question gets a reply with code attached.

**Why it matters.** It is how Canary outlasts the hackathon: as a format other servers speak.

**Depends on.** F01. F03's receipts must sign the tip first.

**Risks.**
- The spec repo has been quiet since May 2026, so also post to Delving and tag setavenger and bitsagarob.
- Name the output gap, or reserve room for F23.
- Say "accountable", not "trustless".

**Score rationale.** The critic took this out of the v1 ranking. It has no effect on 5 October, and the design doc already serves as the spec. Extracting a SPEC.md takes about an hour. With the posts, it comes to about 3 hours instead of 5.

#### F20 · Alerts that don't cry wolf

**Scores.** Impact 3, uniqueness 2, complexity 2, hours 2, priority 1.30. v2*.

**What it is.** When a block's state changes, Canary sends a notification through a channel you choose. The wording never pushes you to drop a server.

**Use cases.**
- "Data withheld: indexer X, block H. Evidence saved."
- A Nostr direct message: "Servers disagree about block H. Keep both."
- A daily digest instead of one ping per event.

**Why it matters.** An alarm nobody sees protects nobody.

**Depends on.** F05, and a long-running daemon, which v1 doesn't have.

**Risks.**
- A Nostr direct message tells relays that your key received a message at that moment.
- Never exclude a server automatically.
- Never present a relay's timestamp as the time something happened.

**Score rationale.** The frontend reviewer moved even the `--on-alert` hook to v2, because every alert channel assumes a daemon.

#### F18 · `canary why <txid>`

**Scores.** Impact 6, uniqueness 8, complexity 6, hours 8, priority 1.13. v2*.

**What it is.** You give Canary a txid that someone says they sent. Canary says which of these cases applies:
- the transaction was never eligible;
- it isn't confirmed;
- the server's stated filter explains its absence;
- the server left it out;
- the server served it and the wallet missed it.

**Use cases.**
- A payer spent through a script path whose internal key is the special unspendable key BIP-352 excludes. No server could ever have reported it.
- A Dana user learns their own dust setting hid the payment.
- The hidden self-payment on regtest comes back as Data withheld, with an evidence file.

**Why it matters.** "Where's my money?" is the moment real users run into this problem, and wallets answer with silence today. Known cases include cake_wallet #1564 and #2395, and Sparrow's silent-skip fixes in 2.5.4 and 2.5.5.

**Depends on.** F04, F05.

**Risks.**
- A declared filter can't be verified, because entries carry no value. Say "consistent with the server's stated filter", never "dropped for dust".
- Fetching the coins a transaction spent from a public explorer leaks the txid.
- The "wallet missed it" case needs the scan key, and uses it only on your machine.

**Score rationale.** Unchanged.

#### F27 · Block-level test vectors offered upstream

**Scores.** Impact 5, uniqueness 6, complexity 5, hours 8, priority 1.08. v2.

**What it is.** Test vectors that fix which transactions an index must include, and in what order. They cover:
- the empty block;
- the unspendable-key pair;
- script-path and mixed-input cases;
- a bare-multisig spend next to an eligible input.

Canary runs them against independent servers, then offers them to BIP-352, the index-server spec and tweak-service-auditor.

**Use cases.**
- shroud-indexer's maintainers get a failing vector for the first-opcode check, plus a varint bug report, once both have been run.
- tweak-service-auditor gains vectors built from Core data, with txids attached.

**Why it matters.** The vectors keep their value even if nobody adopts Canary's records. They answer the question "how do you know your full list is right?"

**Depends on.** F01, the missing vector generator (`make vectors` is broken), and bitcoind.

**Risks.**
- Both shroud findings come from reading code. Run them before filing anything.
- Runs against blindbit-oracle only test the shared library, since the two have the same author.
- Ship the unspendable-key vectors as a pair. Their expectation was inverted once before.
- An earlier draft said shroud-indexer is built on Bitshala's silent-pay library. No source establishes that. Say only that it's TypeScript.

**Score rationale.** Unchanged.

#### F19 · Adapters for live servers, shroud-indexer first

**Scores.** Impact 6, uniqueness 7, complexity 6, hours 7, priority 1.07. v2*.

**What it is.** Read-only connectors for servers people already run. The first reads shroud-indexer's `/transactions/hash/{hash}`, the JSON data the Shroud wallet actually uses. That endpoint returns every eligible transaction, unfiltered. Canary compares it, entry by entry, with a committing server's signed record for the same block hash. BlindBit v2 and Cake's electrs follow, with tripwire-only coverage.

**Use cases.**
- A Shroud tester points Canary at shroud-indexer on regtest. Any gap is either withholding or a known eligibility difference.
- A Cake user's coverage view says plainly that only the tripwire applies.

**Why it matters.** Integrate rather than rebuild. shroud-indexer is the Bitshala-incubated server behind the Shroud wallet.

**Depends on.** F02, F04, and Core 23 or later over RPC. The Docker image works.

**Risks.**
- Txids arrive in display order. Reverse them once, at the boundary.
- Results are sorted by txid, not by position in the block.
- An unindexed block returns HTTP 200 with an empty list, so check `/silent-block/latest-height` first.
- The first-opcode check drops bare-multisig spends. Explain that false gap; don't hide it.
- Shroud signs nothing, so the result is detection, never Data withheld.
- Describe the server as "Bitshala-incubated, now under CypherCommons".

**Score rationale.** Unchanged. It takes 5 to 8 hours end to end.

#### F22 · SPCOMMIT interop

**Scores.** Impact 6, uniqueness 7, complexity 6, hours 10, priority 1.07. v2*.

**What it is.** Three pieces, in order:
1. A Go port of SPCOMMIT's version 1 hash that passes its published vectors.
2. A checker that recomputes the blocks between two checkpoints from unfiltered data, then chains them to the published head.
3. Optionally, the indexer publishes SPCOMMIT-compatible heads as a second visible publisher.

**Use cases.**
- A judge who knows SPCOMMIT finds a passing test.
- A live mainnet window is checked.
- A second publisher appears on the relays.

**Why it matters.**
- It turns the project that got to the protocol idea first into an ally.
- No wallet-side verifier of SPCOMMIT has been found.
- SPCOMMIT's version 2 covers the output prefixes that Canary's entries lack.

**Depends on.** F12's credit. It also needs your decision on mainnet.

**Risks.**
- **Mainnet only.** SPCOMMIT's chain starts at height 709655.
- **Nothing per block to fetch.** No per-block values are published.
- **Trust in the previous head.** A window check trusts the previous head. Checking from the start means recomputing from height 709656 on an archival node.
- **Relays don't index the tags.** Checkpoints use multi-letter tags that relays don't index, so filter by author instead.
- **Frame the claim as "first wallet-side consumer found".** "Second implementation" is already taken.

**Score rationale.** The critic moved even the 2-hour vector port out of v1. Unless the published vectors carry raw tweak lists, which is unchecked, the port needs mainnet block data, and it does nothing on regtest.

#### F17 · In-path proxy for unmodified wallets

**Scores.** Impact 7, uniqueness 9, complexity 8, hours 22–26*, priority 0.98. v2*.

**What it is.** `canaryd` sits between a wallet and its server as a reverse proxy.
- It passes every route through.
- It intercepts `/tweaks/{h}` and `/tweak-index/{h}`, and honours their `dustLimit` parameter.
- It serves the union of several servers' answers.
- It refuses a block only when the block is Data withheld or Servers disagree. Whether to refuse Can't be checked blocks is an open v2 decision.

The first target is BlindBit v1 HTTP: blindbit-scan, then Dana built from source. A front end for Cake comes later.

**Use cases.**
- blindbit-scan on regtest points at `canaryd`. A withheld block makes it wait, with a visible reason, instead of recording no payment.
- If one server drops a payment and another serves it, Dana still finds the payment, and Canary records who left it out.

**Why it matters.** A warning in a log protects nobody. A component in the data path does. Serving the union defeats a single withholding server without anyone's cooperation.

**Depends on.**
- F02, F05 and F11.
- An indexer that speaks the BlindBit v1 routes, another 6 to 10 hours.
- A blindbit-oracle v1-branch server upstream.

**Risks.**
- **Bare tweak lists.** v1's `/tweaks` returns bare lists of tweaks, with no txids and no block hash. So:
  - compare the lists as multisets;
  - bind each height to a hash from your own node;
  - fetch the unfiltered list for checking.
- **Unchecked data.** Filters and UTXO lists pass through unchecked. That is the output-side hole, so label them.
- **Blocks without records.** Pass Not checked blocks through with a coverage header. Refusing them would refuse every block from today's servers.
- **The union cuts both ways.** It widens exposure to fake entries, the opposite of requiring servers to agree. State that.

**Score rationale.** Scores unchanged. Hours rise from 16 to 22–26, because the server behind the proxy has to speak BlindBit v1, and F01's hours don't cover that.

#### F23 · Output keys in the entry (entry format v2)

**Scores.** Impact 8, uniqueness 5, complexity 7, hours 10, priority 0.97. v2, first after judging.

**What it is.** A new, versioned entry format. Each entry also binds its transaction's taproot output keys, either full keys or the 8-byte prefixes that BlindBit v2 and SPCOMMIT v2 already use.

**Use cases.**
- A BlindBit v2 server runs PR #56's reuse filter, and someone funds the victim's key a second time. The output disappears but the tweak stays. v1 passes this case. v2 flags the missing output inside a signed block.
- For BlindBit v1 clients, every committed key in a checked entry must match the served filter. The filter never gives false negatives, so a miss proves the filter is bad.
- Output-level filters, like PR #56 or Cake's per-output dust filter, become declared gaps that someone can be held to.

**Why it matters.** It closes the hole that [the output-hole check](#22-canary-misses-a-server-that-hides-the-output-instead-of-the-tweak-confirmed) confirmed in Canary's own design, and experts look for that hole first. Output keys come from the block alone, so the rule "a server may leave entries out for a stated reason, but never add one" still holds at the output level.

**Depends on.** F02, F03.

**Risks.**
- It changes the entry tag, the fingerprint, the vectors, the wire format and the indexer, and entries lose their fixed width. Budget 6 to 10 hours or more.
- It is cheapest now, while only `canonical`, `commit` and the test vectors use the entry. Every package built on the entry raises the cost. You decided on 30 September to name the hole in v1 and fix it here.
- The spent flag in a UTXO list still can't be checked without a spend index.
- Match SPCOMMIT v2's format. Don't invent a third one.
- Recompute the storage figure in public.

**Score rationale.** Scores are unchanged. The ratio understates this feature because its complexity is high. It still goes first after judging: it fixes a confirmed hole, and every week of waiting makes it cost more.

#### F24 · Spend check for hash-only slots

**Scores.** Impact 5, uniqueness 6, complexity 6, hours 6, priority 0.90. v2.

**What it is.** A server that declares a filtering policy may send a hash-only slot near the tip. Before Canary accepts that gap, it checks that the transaction's outputs really are spent. The check uses your own node, or a second source that supplies the entry.

**Use cases.**
- A cut-through server hides a payment by sending the right hash. Canary finds the output unspent and flags the gap.
- A second committing server supplies the entry, which shows that the first server's gap had no valid reason.

**Why it matters.** Without this check, the hash-only variant reads as Checked, gap filled. For that variant, the design's claim that "serving less is caught" is false.

**Depends on.** F02.

**Risks.** The server's own spent-index comes from the server being checked. Spend data must come from your node or from another server. No plan has a task for this check yet.

**Score rationale.** Unchanged.

#### F25 · Expected-payment inbox and self-payment probes

**Scores.** Impact 5, uniqueness 6, complexity 7, hours 14, priority 0.77. v2.

**What it is.** Two new sources of expected payments.
- An inbox collects txids from payers: a donor's encrypted Nostr note, an invoice reply, or a sender's payment notification.
- Scheduled self-payments go out at random times and amounts, within a monthly fee budget. Your wallet signs each one.

**Use cases.**
- A maintainer puts a "tell me you donated" box next to their address.
- A Dana user sets a 5,000-sat monthly budget for probes.

**Why it matters.** It needs no cooperation from any server. Probes are the only check that still works when every server colludes. Ten probes catch a server that drops 20% of payments about 89% of the time (1 − 0.8¹⁰).

**Depends on.** F04, F20.

**Risks.**
- A bare txid gives detection only.
- Canary never holds spending keys.
- Probes paid from coins an adversary sent you reveal the probes to that adversary.
- Probes don't help against Frigate, which holds your scan key and can recognise your own spends.
- The notification formats are still drafts.
- On mainnet, every probe costs a real fee.

**Score rationale.** Unchanged.

#### F26 · Canary on a home node

**Scores.** Impact 4, uniqueness 3, complexity 6, hours 14, priority 0.60. v2.

**What it is.** Canary packaged for Umbrel, Start9 or a plain Linux box running next to Bitcoin Core. A phone wallet reaches it over the home network or Tor. The node supplies the chain anchor and the spent coins.

**Use cases.**
- A Dana user in a café points Dana at their home Canary's onion address.
- An Umbrel owner installs Canary from the app store.

**Why it matters.** Phone wallets can't run a sidecar. Home-node users already run the node that naming a server requires.

**Depends on.** F17, F06.

**Risks.**
- A StartOS package of an SPCOMMIT witness already exists, so Canary would not be first on StartOS.
- Tor adds latency to every scan.
- The scan key is never stored without explicit opt-in.

**Score rationale.** Unchanged.

---

## 5. The v1 cut line and schedule

This section follows the plan you approved on 30 September. Where that plan and the first draft of this roadmap differ, the plan wins. The biggest change is timing. Claude builds the interfaces and rewrites the docs in parallel sessions from the first day, instead of waiting for the core to work. The core still wins when time runs short, because the interfaces are the first things cut.

### Decisions made on 30 September

These answers replace the open questions in the first draft. The design document and CLAUDE.md are being updated to match them.

**How the work runs**
- Ship v1 by 5 October, then keep building after judging.
- The team is one person plus Claude.
- Build a public site and a local dashboard, on one design system.
- Rewrite the reader-facing docs first.
- Build the interfaces and the docs in parallel sessions. When time runs short, the core loop wins.

**Design choices for v1**
- **The v1 indexer reuses `canonical`.** The project's rule says the indexer and the checker compute entries on separate paths, so that comparing them proves something. v1 breaks that rule to save 4 to 6 hours, and the docs say so plainly. The rule applies again in v2.
- **The output hole is named now and fixed in v2.** The v1 entry stays (txid, tweak). The limits table (F11), the README and the video's last scene all name the hole. F23 fixes it, first after judging.
- **Regtest.** The demo runs on regtest, and the video says why. No signet node is synced or funded, and nothing in the design needs a public network.

**Design amendments approved with the plan**

These change the design, so they needed your explicit approval. The numbering follows the plan.
1. **The retention rule.** Suppose a server leaves an entry out while its block is less than 144 blocks below the server's signed tip. Canary treats that as withholding and names the server: Data withheld. Before this change, the case ended as Can't be checked or Checked.
2. **Receipts move into the shared core.** A receipt signs the block hash, the request parameters, the server's tip height and hash, and a digest of the bytes served. It also signs a format version, the network and the resource type, so it cannot be replayed on another chain or for other data ([v1 formats, the receipt](../design/2026-09-30-v1-formats.md#3-the-receipt)). It travels in an `X-Canary-Receipt` header.
3. **The evidence file** (format `canary-evidence/1`) carries the served bytes and the receipt. `canary verify` recomputes the result itself. Without a receipt it prints "Inclusion only: you can be sure of this, you can't yet prove it to others."
4. **Named limits.** The design's out-of-scope section, the README and the video's last scene name three limits. They are output-side withholding, hash-only withholding under a filtering policy, and v1 being built and tested on regtest only. "Checked" means the tweak list was checked, never that payments were checked.
5. **Demo changes.** The demo runs on regtest. Scene 1 becomes "the served list lacks the entry", because v1 has no wallet to show. The video runs 3:15 to 4:30. It keeps act 3b, the Servers disagree branch, if that scene is built. The switch is named `--withhold-txid`, with visible help text.
6. **No daemon and no proxy in v1.** `canary check` writes a state file, and `canary ui` reads it. The proxy comes in v2 as a BlindBit v1 reverse proxy (F17). The design also records that refusing every Not checked block is wrong, because it would refuse every block from today's servers.
7. **The network tag.** The Nostr `network` tag holds the network's magic number in decimal. The code is right, and the design text changes to match it.
8. **Default track: Cypherpunk only.** Add Freedom Stack only if the 7 September handbook allows it, and only with a genuine crossover pitch.

The citation and prior-art fixes in F12 are a note, not an amendment. They correct quotes and credit, and they change no design rule.

### Four tracks

| Track | Who does it | What |
|---|---|---|
| A. Core loop | You and Claude, test-first | The critical path: wire format, receipts, reference indexer, `canary check`, the evidence file and `canary verify`, the CLI and state file, the tripwire, the harness |
| B. Interfaces | Claude in a parallel session; you review | The design system and wording table, the dashboard (`canary ui`), the public site, the in-browser checker |
| C. Docs | Claude in a parallel session; you review | Citation fixes, glossary, how-it-works page, README, design doc pass, CLAUDE.md, FAQ, video script |
| D. Submission | You | Devfolio draft and fields, the 7 September handbook, pushing, the video, LICENSE, public repo, tag, Publish |

Changes from Tracks B and C merge into `main` one at a time.

### What ships by Monday 5 October

**Track A, in build order**
1. X1: the shared wire format.
2. F03, part 1: the receipt type in the shared core, plus a proof builder that works from hashes.
3. F01: the reference indexer, minimum form, with `--withhold-txid`.
4. F02: `canary check`. It fills gaps first, then recomputes the fingerprint, and it applies the retention rule.
5. F03, part 2, with F10: the evidence file, `canary verify`, and the offline and tamper tests.
6. X2: the `canary` CLI with `check`, `verify`, `status [--json]` and `ui`. The state-file schema was frozen on Wednesday in [v1 formats](../design/2026-09-30-v1-formats.md), because the interfaces depend on it.
7. F04: the tripwire, tweak check only. A plain taproot payment from the Core wallet is enough, so no silent-payment send is needed.
8. F09: `scripts/demo-regtest.sh`, the end-to-end run. The committed evidence file comes from its final run, and a CI test verifies it.

**Track B:** F05 and the design system first, then F16 with F06, then F07, then F08.

**Track C:** F12 and F11 drafts first, then the glossary, the how-it-works page, the README draft (F13), the FAQ and the video script.

**Track D:** F13's admin half, F14, and pressing Publish.

**Not in v1:**
- F17 through F28;
- F15's staged scene, unless you are ahead. F15's detection is in v1, inside F02;
- F09's harness run in CI (CI checks only the committed evidence file);
- F10's traffic test;
- F04's output check.

### Hours

By the scored estimates, Track A adds up to about 45 hours:

```
wire 1 + indexer 12 + check 9 + receipts and evidence 10
  + CLI and state file 4 + setup and harness 5 + tripwire 4 = 45 hours
```

Submission work adds about 10.5 hours: 4.5 for the README and submission, and 6 for the video. The total of about 55.5 hours sits at the top of your 50 to 55 hour budget. Reviewing Claude's work on Tracks B and C costs extra time on top. There is no buffer inside the days, so the cut order is the buffer.

### Day by day

| Day | Track A (you and Claude) | Tracks B and C (Claude; you review) | Gate or cut point |
|---|---|---|---|
| **Wed 30 Sep, evening** | Devfolio draft; find the 7 September handbook; push the unpushed commits. `brew install bitcoin`, then mine regtest to 200 blocks. Wire format. Freeze the state-file and evidence schemas. 15-minute WebAssembly build check | Save the research files; this roadmap and the competitor analysis; the truth pass; the design amendments | The node is mining by 22:00, or setup moves to Thursday |
| **Thu 1 Oct** | Receipt type in the core; reference indexer | B: design tokens, fonts, state symbols, the wording table, and the dashboard on watermarked sample data. C: glossary, how-it-works, README draft | The indexer serves a signed record and a list for every block |
| **Fri 2 Oct** | Receipts on every response, `--withhold-txid`, a byte-order test; `canary check` with the retention rule | B: site pages, error and empty states, the update bar. C: design doc pass, Go comment cleanup | 22:00: does `canary check` name the server? If not, make cuts 1 to 3 |
| **Sat 3 Oct** | Evidence file and `canary verify`, with offline and tamper tests; the CLI and state file | B: the in-browser checker on the real verify code. C: CLAUDE.md, FAQ, the decision log, status headers on the old plans | **Gate:** a real evidence file verifies with the network off |
| **Sun 4 Oct** | `status --json`; the harness and the recorded run; the tripwire, tweak only; commit the final evidence file | B: point the dashboard at the real state file; the recorded-run page; accessibility, 360 px width, both themes; a `noindex` preview deploy. C: README numbers from the run, video script | Harness past 15:00: skip dashboard polish. Tripwire not passing by 20:00: it becomes a named limit |
| **Mon 5 Oct** | Review the drafts; record and edit the video; LICENSE, public repo, tag | A final wording check across every page and doc | **Published on Devfolio by 17:00 IST.** The site goes public after publishing; stop work on it at 21:00 |

Notes on the days:
- **Wednesday's two checks.** The node check needs `bitcoin-cli -regtest getblockcount` to print 200 or more. The spent-outputs REST endpoint needs Bitcoin Core 30 or later, so check the version too.
- **Sunday's run.** Never mine 144 or more blocks between the payment and the check. The empty slot would fall outside the window, and the accusation would disappear.
- **Monday's fallbacks.** If nothing is recorded by 13:00, record the terminal only, in one take. If you aren't published by 16:30, stop everything else and publish.
- **Monday's clock.** 17:00 IST is 11:30 UTC. Keep 21:00 to 23:59 IST free for emergencies only. A saved draft does not count as an entry.

### Cut order when time runs short

Cut in this order:
1. **Site pages other than the checker page.**
2. **Dashboard pages other than Overview and Finding.**
3. **The in-browser checker (F08).** A judge can still verify the evidence file from the command line.
4. **The dashboard (F16, with F06).** The video shows the terminal instead.
5. **Harness automation.** Record a manual run of the same commands, and say so in the README.
6. **The tripwire (F04).** It becomes a named limit in the limits table. The detection scene still works, because the honest server's list supplies the withheld entry.
7. **Receipt checking in `canary verify`.** Verify then prints "inclusion only", and the README says: "You can be sure of this. You can't yet prove it to others."

Cuts 1 to 4 mostly save your review time, because Claude builds those parts. Cuts 5 to 7 save core hours.

Never cut:
- the reference indexer and its switch;
- `canary check` naming the server;
- the evidence file and offline verify;
- the limits table and the citation fixes;
- a video of at least 3 minutes;
- the README, LICENSE and public repo;
- pressing Publish.

The interfaces go first, even though you chose them, and that order is deliberate. Judges score a working catch. An interface drawn over a run that never happened is worth nothing. Both interfaces continue after judging, as [v2: after judging](#6-v2-after-judging) describes.

### If you are ahead

Add these to Track A, in order:
1. A staged Can't be checked range for the last scene, about 2 hours. The last scene closes on it. It needs a server that marks an entry absent (no hash) in a block 144 or more blocks below its signed tip, so the reason is `gap_unfilled`; a served hash would read Checked, gap filled instead. No other server and no declared payment may supply that entry.
2. Publishing the run's signed records to two relays that are known to keep events. Nobody has checked whether relays accept kind 1352. Until this is done, the README must not say the records can be found on a public relay.
3. Act 3b's staged scene (F15). It needs a record-omitting mode on a second indexer copy, as an additive flag. The detection itself needs no new code.

---

## 6. v2: after judging

### Dates that matter

| Date | Event |
|---|---|
| Mon 5 Oct, 23:59 IST | Submission deadline |
| 6–11 Oct | Judging |
| Mon 12 Oct, 14:00 IST | Results |
| 26 Oct – 1 Nov | BOSS Summit, Jaipur. It asks people to "Bring your work… demos, prototypes". Apply at luma.com/bitshalaboss. |
| 5–6 Nov | btc++ Seoul, privacy edition, with a prize pool of 2.5M sats |

The summit and btc++ dates come from the research notes and were not re-checked today.

### During judging, 6–11 October

- **Keep the submitted state fixed.** Link the submission tag from Devfolio and from the README, and do new work on a branch until results are out. No rule on this was found either way. Working on a branch sidesteps the question.
- **Publish the recorded run's records** to two relays that are known to keep events, such as nostr.mom plus one more. Fetch them back with `feed.Get`, then check again before 12 October.
- **Extract SPEC.md** from the design doc. This is F28's first hour.
- **Decide on mainnet.** Mainnet is needed for F22's live check, and the project rule says no mainnet.

### Theme 1: close the holes v1 names (13–25 Oct, before the summit)

- **F23: output keys in the entry, first.** This also unlocks F04's output check against a server that serves filters or UTXO lists.
- **F24: spend check for hash-only slots.**

F15 left this list, because v1 already detects Servers disagree inside F02.

Goal for the summit: the first two rows of the limits table move from "not checked" to "checked".

### Theme 2: interfaces (13–25 Oct)

- **F08: the in-browser checker.** Build it if it was cut from v1. Either way, pin the Go toolchain, and publish the WebAssembly file's hash only after two machines produce the same build.
- **F07: the full site.** Restore any pages cut from v1, and add a docs section. Use a docs framework only once about ten pages actually exist.
- **F16: the live dashboard.** This waits for `canaryd`, which F17 builds. v1 already has a polling update bar. v2 adds Nostr-signed release announcements, the alerts in F20, the Activity page, and browser tests in CI.
- **F21: the "What protects my wallet today?" page.** Every claim on it carries a date.

### Theme 3: reach real wallets and servers (from mid-October)

- **F17: the in-path proxy, BlindBit v1 first.** This is the version to show at the summit: blindbit-scan on regtest, unmodified, pointed at `canaryd`.
- **F19: the shroud-indexer adapter.** It is the most relevant integration for the Bitshala audience.
- **F22: SPCOMMIT interop,** if you approve mainnet.
- **After the summit:** F18 (`canary why`), F20 (alerts), F25 (inbox and probes) and F26 (home node), in roughly that order.

### Theme 4: upstream and standing (before 26 Oct)

- **F28:** post the spec proposal to Delving thread 891 and to the index-server spec, crediting SPCOMMIT. Tag setavenger and bitsagarob.
- **F27:** run the block-level vectors, then offer them upstream. Take the two shroud-indexer findings to its maintainers only after they reproduce.

### btc++ Seoul, 5–6 November

Check its rules on prior work before you plan to enter. A small, new piece built during the event is the safe shape. One option is the tripwire adapter for Cake and Frigate users from F19 and F25, since it works against servers people actually run.

### Housekeeping, whenever there is slack

- F09's CI run: an in-process variant, clearly labelled as a test.
- F10's traffic test: no request may carry a scan key, an address or a watched txid. Add it once Canary talks to real servers.
- Fix or remove the broken `make vectors` target.
- Add a toolchain line to `go.mod`.
- Update the status lines in CLAUDE.md and the design doc.

---

## 7. Things we decided not to do, and why

### Claims we won't make

- **"First" with tweak-index commitments, with Nostr for them, or with "catch me".** SPCOMMIT was live on 1 September, and Optech covered it on 11 September.
- **"BIP-352 v1.1.0 states the withholding assumption."** No revision of the BIP says it. v1.1.0 added a recipient limit.
- **"Canary is SPCOMMIT's second implementation."** One already exists. If Canary interoperates with SPCOMMIT, the honest claim is "first wallet-side consumer found".
- **"Bitshala's own indexer" for shroud-indexer.** No source supports it. The accurate description is "Bitshala-incubated, now under CypherCommons".
- **"Committing honestly and serving less is caught," as a general claim.** It is false for the hash-only variant.
- **Honest BlindBit dust filtering as the example of the output hole.** BlindBit filters per transaction. Cake's electrs is the honest example.
- **"Cake's dust line is 546 sats."** The source default is 1,000 sats, and the deployed value is unknown.
- **"Cake has the largest base of silent-payment receivers."** This is unverified.
- **A relay copy "confirming the team didn't mint it".** A relay copy shows that something was published. It does not show who made it or when.
- **"At least 0.0421 BTC" or "a hidden payment of 0.0150 BTC to you."** v1 has no wallet link, entries carry no value, and Canary has no scan key.
- **A 0-to-100 score or a letter grade.** Neither has a check behind it that anyone could re-run.
- **"Provably key-free."** Block fetches still reveal which blocks you care about.

### Targets we dropped

- **blindbitd as the wallet.** It was archived on 2025-08-14 and needs an Electrum server.
- **BlindBit Desktop behind the proxy.** It speaks gRPC only and offers no regtest.
- **A proxy that returns 404 for everything but `/tweaks` and refuses every block without a record.** It would break every v1 wallet. It would also refuse every block from every server running today.
- **shroud-indexer's binary routes.** The wallet doesn't read them, and they have a varint bug at 253 or more transactions.
- **An SPCOMMIT mainnet cross-check before 5 October.** No per-block values are published, and mainnet conflicts with the regtest decision.
- **Checking served filters against full blocks.** Fetching every block defeats the purpose of a light wallet.
- **Mainnet or signet for v1.** There is no node, no time to sync one, and no time to fund one.

### Build choices we rejected for v1

- **A filtering mode in the reference indexer.** It would demonstrate the hash-only bypass on camera. Unit tests cover the filtering case instead.
- **A minimal scanner for the first scene.** It costs about 3 hours and drifts toward building a wallet, which the project rules out.
- **An independent tweak path in the indexer.** It costs 4 to 6 hours. You decided on 30 September that the v1 indexer reuses `canonical`, and the docs say so.
- **Output keys in the entry before the deadline.** That is 6 to 10 hours the budget doesn't have.
- **Frontend tooling.** v1 has no daemon, so nothing live exists for an app to talk to. Each of these adds build or upkeep cost, and several return in v2:
  - a pnpm workspace, a Vite and Preact single-page app, committed build output, and generated TypeScript types;
  - server-sent events, a service worker, browser notifications and webhooks;
  - a JSON error catalogue, and a 20-page docs site with search;
  - settings and expected-payment forms;
  - a Web Worker for the checker, and a fixture mode in the shipped binary;
  - Playwright or axe in CI.
- **Visual identity choices.**
  - IMDb's yellow #F5C518; Canary uses a canary yellow near 55° hue instead.
  - Unicode state symbols; Canary uses SVG.
  - A bird logo, unless it survives one 45-minute attempt and still reads as a 16 px favicon.
  - Overpass with IBM Plex Mono; Canary uses Geist and JetBrains Mono. *Superseded 2 October 2026, which changed the pair from Atkinson Hyperlegible Next and Mono.*
  - Uppercase letter-spaced labels, "01 / 02 / 03" steps, big-number tiles, bento grids, pill badges, and a "hook, then three steps" landing page.

### Process choices

- **A 2:45 video with act 3b, the Servers disagree branch, as the first cut.** That length falls below the reported 180-second floor.
- **Backfilled weekly progress logs.** At most, a dated build log generated from git history.
- **Entering more than one track without asking the organizers.**
- **Automatically excluding a server that trips an alarm.** If a third party can trigger the alarm, it can use it to knock out honest servers. This project rule stays.
- **Changing the submitted repo after the deadline without a tag.**