# BOSS Battle competitors

Gathered on 30 September 2026, five days before BOSS Battle closes on Monday 5 October at 23:59 IST (18:29 UTC). This is a snapshot. Entrants can change their projects until the deadline, so treat every count here as dated.

The [feature roadmap](../roadmap/2026-09-30-feature-roadmap.md) records what Canary changed because of this research. The [glossary](../glossary.md) defines Canary's own terms.

---

## 1. What this is and how it was gathered

This is a survey of every published BOSS Battle project, written to answer two questions. Who is Canary really up against in the Cypherpunk track? And what do the strongest entries do that Canary did not?

**Sources.**
- **Devfolio's public API** listed all 68 published projects, with their tracks, taglines, tags, links and videos.
- **GitHub** gave repo history, commit counts, CI runs and code. Where a project had a live demo, the research probed it with plain HTTP requests.
- **Primary sources** for the ecosystem: the BIP-352 text and history, the SPCOMMIT repo, relay queries, Bitcoin Optech, and the repos of the servers and wallets involved.

**Method.** Claude gathered this on 30 September in three steps, across two research runs.
1. **Triage.** Every one of the 68 projects got a short review. It recorded the project's tracks, what it does, how much real code it has and how good its interface is. It also rated how close the project is to Canary's problem, and how likely it is to beat Canary. The [appendix](#appendix-all-68-projects) lists all 68.
2. **Deep dives.** Thirteen projects got a close read of their code, docs and interface. Where possible, the reviewer checked claims directly: transactions on a block explorer, CI runs, live demos. [The Cypherpunk contenders](#3-the-real-cypherpunk-contenders-ranked) profiles the eight entered in Cypherpunk, and [Other deep-dived entries](#other-deep-dived-entries-freedom-stack) the five that are not.
3. **Second checks.** Any finding that would change Canary's plan was checked again against primary sources. Where the second check corrected the first, this document uses the correction and says so.

**Limits of this survey.**
- Devfolio's search index carries no description text. "Nobody else works on silent-payment servers" rests on names, taglines, tags and repos.
- Some findings come from reading code, not running it. Those say so.
- Relevance and threat scores are judgement calls, each on a scale of 0 to 5. Threat is 0 for any project not entered in Cypherpunk, since only Cypherpunk entries compete with Canary for its prize.
- Nobody on the Canary side knows who the judges are. [Judging research](#8-judging-research) separates what is public from what is inferred.

**Canary's own state on 30 September, for fairness.** Canary had a tested Go library: about 3,100 lines in five packages, with 67 passing tests and CI when this research ran. By that evening the shared wire format had landed too, and `go test ./...` passed all 80 top-level tests. It had no binary, no interface, no video and no end-to-end run. Its README still said "Design phase. No code yet." The repo was private and had no LICENSE. Every comparison below was made against that state.

---

## 2. The field at a glance

| | Count |
|---|---|
| Published projects | 68 |
| Entered in Cypherpunk / Freedom Stack / Machine Money | 21 / 24 / 20. A project can pick several tracks, and 16 picked more than one |
| Entered in no track | 25, mostly school or AI projects unrelated to Bitcoin |
| Code: substantial / moderate / thin / none | 14 / 13 / 22 / 19 |
| Has any interface | 47 |
| Interface rated polished / decent | 6 / 5. The polished six: Dossier, RelayJoin, MeCuadra, AXI, QuietRelay, NostrPulse |
| Has a video | 17 by Devfolio's own video field. The triage found 20 video links in total |

**Cypherpunk on its own, 21 entries:**
- **Substantial code:** 6. Five are on topic: Dossier, RelayJoin, MeCuadra, LeakCheck and Luma Wallet. The sixth, ChronicleAI, is an Ethereum project last pushed on 13 August, before the hackathon started.
- **Moderate code:** 6. **Thin:** 5. **None:** 4.
- **Video:** 9 of the 21.
- **Theme:** most entries are TypeScript web apps on the idea "see what your wallet leaks".
- **Silent payments:** no other entry builds silent-payment infrastructure. MeCuadra and AXI use the words "silent payments", but their code does not follow BIP-352.

The track is thin at the bottom, with four or five finished, honest entries at the top. Nobody else works on Canary's problem. On 30 September, several of those finished entries beat Canary on everything a judge could see without reading code.

---

## 3. The real Cypherpunk contenders, ranked

This ranking orders entries by how likely each is to beat Canary for the Cypherpunk prize. The threat score comes from the triage. Most head-to-head results depend on one condition: whether Canary ships a working, visible run by 5 October. On 30 September, the top four each beat Canary on anything a judge could click.

### 1. RelayJoin: highest threat (4 of 5)

**What it is.** Payjoin while the receiver is offline. In a payjoin, the receiver adds one of its own coins to the payment, which breaks a common chain-analysis guess. RelayJoin carries the payjoin messages over Nostr as encrypted, single-use "gift wraps", so the receiver doesn't need to be online. It is written in Rust by one builder, with 31 commits between 10 and 22 September.

**Strengths.**
- **It works, and the evidence checks out.** Two payjoins are confirmed on mutinynet, a public signet, and both txids resolve on its explorer.
- **Its tests and CI are real.** It has about 46 unit tests, and every one of its last 15 CI runs passed.
- **A replay site.** The team recorded a real run and turned it into a static page with play controls and captions. A judge sees what looks like a live demo without running anything. A script generates the 2-minute video from the same replay, so the site and the video can't disagree.
- **The plainest copy in the field.** A gift wrap is "a locked note". The randomized timestamp is "deliberately fake".
- **An honest status table** that separates "Built" from "Verified live", with CI run IDs, event IDs and block heights.
- **An honest threat model** that names what it doesn't solve, plus a prior-art section.

**Weaknesses.**
- The technique is known. The project itself credits five earlier attempts.
- No stock wallet can pay one of its payment requests yet, so only its own tools can use it.
- It has no Tor and no padding. Relays see IP addresses, and message size leaks the input count. The threat model admits both.
- Its Nostr evidence links used a 7-day expiry, so they stopped working around 29 September, before judging.
- No pushes since 22 September.

**Compared with Canary.** RelayJoin is finished and proven. Canary works on a newer problem, one the organizers' own guide calls open. Both use Nostr: RelayJoin for private messages, Canary as a public noticeboard. Canary needs one sentence saying why its records are public on purpose. RelayJoin sets the bar for what "shipped" and "evidence first" look like.

### 2. Dossier: high threat on presentation (4 of 5)

**What it is.** A browser-only tool. You paste a Nostr public key, and it builds the surveillance file an analyst could assemble from public data. Then it offers one-click fixes that you sign with your own Nostr browser extension (NIP-07). It is entered in Cypherpunk and Freedom Stack.

**Strengths.**
- **Anyone can try it in 20 seconds.** Example buttons load well-known accounts, and each result has a shareable link. The research ran it live and got a full report in about 18 seconds.
- **A strong identity.** It looks like a case file, with lettered exhibits and a cover sheet, in light and dark themes with self-hosted fonts.
- **Results per source.** It talks to each relay separately and verifies every signature. Its coverage table tells "the relay held the deletion request and ignored it" apart from "the relay never received it".
- **A streaming log** shows each step while it runs.
- **Honest limits and ethics.** A plain Limits section, and third parties stay pseudonymous until you prove you are the subject.
- **Good hygiene.** No backend, a strict content security policy, and every data source can point at your own infrastructure.

**Weaknesses.**
- Three commits, all on 27 September, so the build history can't be seen.
- It works on Nostr first. It reaches Bitcoin only through Lightning payments and addresses posted in notes.
- Its findings are heuristics, such as a time zone accurate to about an hour, not proofs.
- It can be pointed at anyone's key, and it shows that person's data to whoever runs it.
- Its tests are thin: 7 test blocks, none covering the relay client or the fixes. It has no 404 page and no error boundary.
- It may be judged mainly in Freedom Stack.

**Compared with Canary.** Dossier wins by a wide margin on how easy it is to try. Canary's case rests on substance and on fit with base-layer Bitcoin privacy, and it only counts if Canary ships a page a judge can click.

### 3. LeakCheck: high threat on rigor (4 of 5)

**What it is.** A local Python tool that reads a PSBT, an unsigned transaction file, before you broadcast it. It plays a chain-analysis observer and runs 12 well-known heuristics blind. Then it scores each guess against what your wallet knows about its own inputs and change.

**Strengths.**
- **Well tested.** About 150 test functions, and CI passed on every run.
- **Credible fixtures.** Its sample transactions come from Sparrow's own wallet code, run headlessly.
- **Tests enforce its privacy claims.** One test blocks every network socket and runs every sample through the tool. Others check that built pages contain no URLs and that the server listens on localhost only.
- **Honest wording built in.** Every report ends with a fixed sentence: "X of Y checks applied … not proof of privacy." It never says clean, safe or private.
- **Easy to launch.** It has a command line, a local web page, and double-click launchers for Mac, Windows and Linux.
- **Hardened input handling,** including fuzzing and guards against memory-exhaustion bugs in its parsing library.

**Weaknesses.**
- The heuristics are textbook. The new part is scoring the observer's guess against the wallet's truth.
- It rejects silent-payment outputs outright.
- You have to export and paste a PSBT by hand.
- No video, no screenshots, an empty Devfolio description, and an unbranded interface that shows raw rule IDs.
- It was built over about 36 hours on 27 and 28 September. Its Mac and Windows launchers are untested, by its own table.

**Compared with Canary.** LeakCheck matches Canary's honest style exactly, so Canary cannot win on "we state our limits" alone. It has to win on the problem. LeakCheck is the bar for privacy claims backed by tests.

### 4. Veil: moderate to high threat (3 of 5)

**What it is.** A privacy check for choosing which coins to spend. You label coins by where they came from. Veil proposes a spend that avoids linking sources, and Bitcoin Core builds and signs it.

**Strengths.**
- **A hosted demo a judge can click in 10 seconds.** It shows the same payment two ways: "a typical wallet" scores 0, Veil scores 90, and Veil's version is cheaper. The demo labels its node as simulated.
- **Plain reasons.** Every finding comes with a one-sentence reason, and good findings show alongside warnings.
- **A clear split of work.** Core builds and signs; Veil only decides, then re-scores the transaction Core actually built.
- **Fits existing tools.** It uses Sparrow-compatible labels and exports PSBTs for hardware wallets.
- **Its pitch quotes the track brief**: "make the private path the easy path".

**Weaknesses.**
- The "0" comes from a baseline Veil wrote itself, which spends the smallest coins first. It is not Bitcoin Core's real coin selection. The hosted page labels this honestly; the Devfolio pitch does not.
- The penalty weights are arbitrary, and the category already exists in Sparrow and Wasabi.
- The documented local setup fails: the RPC username differs in case between two config files.
- No video and no CI. Three commits within 50 minutes on 26 September.

**Compared with Canary.** Veil's story needs no background, while Canary's needs "tweak server" explained first. Canary should copy Veil's side-by-side frame. It should not copy the self-written baseline.

### 5. MeCuadra: moderate threat (2.5 of 5)

**What it is.** A polished barter marketplace in two languages. Its privacy comes from people swapping goods without paying at all.

**Strengths.**
- **It looks finished:** a live site, a 2:15 video, screenshots, a logo and dark mode.
- **A worked example with named people.** Ana in Lisbon swaps a folding bike for Bruno's camera. It turns the threat model into a story.
- **A clear privacy table** with one row per property.
- **An interactive zero-knowledge demo page** that needs no setup.
- **One file for judges** with the problem, the example, limits, a demo script and a pitch for each track.

**Weaknesses, found by reading the code.**
- Most of the code predates the hackathon. The repo was created on 18 August.
- Its "Silent Payments" code does not follow BIP-352.
- Its zero-knowledge badge can be forged, because the verifier never checks the signed ratings.
- Its ratings table is readable by anyone with the app's public access key, which exposes who rated whom.
- Its "Cashu stamp" is a server-side keyed hash with a fallback secret. The Cashu library is never imported.
- It has no tests and no CI.

**Compared with Canary.** MeCuadra wins with a judge who only clicks around. It loses badly with any reviewer who knows BIP-352.

### 6. AXI: low to moderate threat (2 of 5)

**What it is.** A polished multi-page site entered in all three tracks. It combines a marketplace, escrow, encrypted Nostr chat and a Cashu wallet.

**Strengths.**
- A deployed live demo, with every main route working.
- Encrypted Nostr chat that works, and a Cashu wallet with a free test faucet, so a judge gets test sats in one click.
- A key is created on first visit, so a judge installs nothing.
- A plain headline and a four-step escrow walkthrough.

**Weaknesses.**
- Its silent-payment math does not follow BIP-352, and nothing in the app sends or scans a silent payment.
- Its escrow enforces nothing: the payer can spend at any time, while the landing copy says the opposite.
- Its zero-knowledge badge can never turn green on the live site.
- It stores escrow state in a replaceable Nostr event kind, so a later event overwrites the release record.
- Two commits and no tests. Its Machine Money pitch contains text that reads like a pasted chatbot reply.

**Compared with Canary.** AXI is a threat through looks only.

### 7. Luma Wallet: low to moderate threat (1.5 of 5)

**What it is.** A mobile web wallet in which an AI agent buys things over Lightning, RGB and L402. Every payment needs your approval, tied to the exact payment details, and spending limits apply. It is mainly a Machine Money entry.

**Strengths.**
- Real end-to-end RGB-over-Lightning settlement on regtest, backed by structured before-and-after evidence files.
- A carefully reasoned money-safety core. Each approval is bound to a hash of the exact payment, duplicates are blocked, and failures fail closed.
- A progressive web app with good offline, loading and error states.
- Honest labels on what is simulated.

**Weaknesses.**
- Its Cypherpunk case is about authorization, not privacy.
- Every agent turn sends the user's purchase intent to OpenAI.
- The evidence files were written by the author, so a judge has to take them on trust.
- The video runs 12 minutes. It runs on regtest and localhost only, and it has no CI.

### 8. Wallet Server Path Diversity: a latent threat (2 of 5)

**What it is today.** A README and nothing else: one commit on 9 September. It proposes a simulator showing how an Electrum light wallet's choice of servers could concentrate on one network operator.

**Why it still matters.**
- Its README is the clearest non-expert explanation in the field, in exactly the plain voice Canary wants.
- Its fix reuses something Bitcoin Core already ships (ASMap), which makes it look adoptable.
- Its author contributes to ASMap and maintains a live, tested dashboard with most of the pieces the simulator needs. A polished entry could appear in the last few days.

The research recommended re-checking its last push between 3 and 5 October.

### The rest of the track

The other Cypherpunk entries have thin or no code, or sit far from Canary's problem: CypherStack, BlockShield AI, SatoshiTrace, Satoshi Sentinel, PrivaVend, Bitcoin Privacy Assistant, NostrCast, SatFlow DVM, CampusPilot AI and ChronicleAI. ShadowSync, Spectra and Stegashareus have no code at all. The [appendix](#appendix-all-68-projects) has a line on each.

---

## 4. Overlaps with Canary's space

None of these entries works on silent-payment servers. Each overlaps with one part of Canary's approach.

| Entry (track) | What overlaps | What it lacks that Canary aims for |
|---|---|---|
| Relay Evidence (Freedom Stack) | An evidence report on one Nostr event, per relay. Seven named outcomes, and "What this report cannot prove" in every report | Its evidence is its own local record, "not a signed receipt". Canary's evidence is signed by the server it accuses, when the receipt ships |
| QuietRelay (Freedom Stack) | Exports an evidence file. Its verifier recomputes every decision, so an edited result fails even if the file's digest is recomputed | "Self-verifiable, not externally attested", in its own words. Nobody outside signs it |
| W-TVC Protocol (Machine Money, Freedom Stack) | A signed record published on Nostr and checked by a client: the same shape as Canary | It used a replaceable event kind and trusted Nostr's self-reported `created_at` time. Its Nostr code was deleted on 17 September, but the pitch still describes it |
| Bitcoin Reliability Labs (Freedom Stack) | An adversarial test harness with JSON and HTML evidence. Its PSBT lab includes silent-payment scenarios | A developer tool. It says it is "not a chain scanner" and protects no end user |
| Dossier (Cypherpunk, Freedom Stack) | Results attributed to each source, and two failure types kept apart that a simple view would merge | Heuristic findings, with nothing signed |
| ShadowSync Agent (Machine Money, Cypherpunk) | Framed around what leaks between a light wallet and its server | The repo is empty |

The two evidence tools, Relay Evidence and QuietRelay, show that "honest limits plus offline verification" is not unique to Canary. Canary's difference is who signs the evidence.

### Other deep-dived entries (Freedom Stack)

Five of the thirteen deep dives went to entries outside Cypherpunk. None of them competes with Canary for its prize. They are the field Canary would meet if it also entered Freedom Stack, which [Entering more than one track](#entering-more-than-one-track) weighs. The research ran none of them locally. These points come from reading their code and docs, and from loading their live sites where they had one.

**QuietRelay** (Freedom Stack)
- **What it is.** A local workbench for Nostr relay operators. It replays signed events through a relay's admission policy and shows which get admitted, held or rejected, and why. An optional local relay checks those predictions against real replies.
- **Strengths.** Its evidence verifier recomputes every decision, so an edited result fails even when the file's digest is recomputed. The README states the exact counts a fixed run should produce, so a judge can check them. It has a 3:33 captioned video recorded from the real app, dated QA notes at three screen widths, and a distinct visual identity.
- **Weaknesses.** Its evidence is "self-verifiable, not externally attested", in its own words. Everything runs locally on made-up fixture identities. It has 21 tests and no CI, and much of its text is 7 to 10 px, which is hard to read on a real screen. It was built in about two days, mostly in one commit, with AI assistance and a synthetic video voice, both disclosed.
- **Compared with Canary.** QuietRelay is the model for a README whose claims a judge can check. Canary's difference is that the accused server signs the evidence, once the receipt ships.

**NostrPulse** (Freedom Stack, Machine Money)
- **What it is.** A web app with three parts: a 0 to 100 trust score for any Nostr key, Cashu tips, and a server that caps what an AI agent may pay.
- **Strengths.** It has the easiest evaluation path in the field: a live site, a 4-minute video and a published npm package. Its README has a numbered "Happy path for judges", with the result to expect at each step. Two buttons on its home page contrast a real account with a bot clone in about 5 seconds. The Cashu tipping works against a public test mint, and a relay page measures latency for real.
- **Weaknesses, found by reading the code on 30 September.** Its headline benchmark figures, such as "100% interception, 0% false positives", have no script behind them. A "5/5 Relays" status indicator is a fixed string, and a simulated attack always returns "BLOCKED". A home-page leaderboard labelled as live ranks seed data first. Tip receipts count toward the score without their signatures being checked. It has no tests and no CI.
- **Compared with Canary.** NostrPulse shows how much a guided judge path is worth. It also shows the one thing Canary must never do: a status light that is always green is exactly what Canary exists to expose.

**Relay Evidence** (Freedom Stack)
- **What it is.** A small command-line tool. You give it one signed Nostr event and a list of relays. It asks each relay for the event once, then writes a report that sorts each answer into one of seven named outcomes.
- **Strengths.** Real generated reports are committed, so a judge can read the output on GitHub without installing anything. Every report ends with "What this report cannot prove". Its 33 tests run against real local servers, inspect every outgoing message, and check that no content or key goes out. Simulated fixtures say so inside the files themselves.
- **Weaknesses.** Its evidence stays with its maker: "a local record of observations, not a signed receipt", in its own words. The scope is one event at one moment. It has two commits, six minutes apart on 9 September, and no video, CI or interactive interface. Its copy hedges so often that the point gets buried.
- **Compared with Canary.** Its report has the shape of Canary's evidence file without the server's signature. Canary should copy its committed reports and its outgoing-message test, and avoid its hedging.

**Bitcoin Reliability Labs** (Freedom Stack)
- **What it is.** Two developer test labs from one builder, under one name. Cashu Fault Lab injects faults into ecash payments, such as lost responses, duplicates and crashes, then checks 18 rules. PSBT Interop Lab passes one PSBT through several pinned Bitcoin libraries and compares each handoff, including silent-payment scenarios on regtest.
- **Strengths.** It has the most working code in the field: two published npm tools, versioned releases, and large CI runs against real mints and Lightning on regtest. One command runs a real scenario, writes evidence and cleans up. Missing evidence is recorded as "not observable" and never counted as a pass. Its sites have a themed 404 page, search and a written design QA pass, and its video runs 3:46 with chapters.
- **Weaknesses.** Both repos were created in July, and most of their commits predate the hackathon. Two unrelated products share one submission, with an empty Devfolio description. The READMEs are dense with jargon. It protects no end user, and calls itself "not a chain scanner". The video uses an AI-generated voice, which it discloses. Its latest scheduled CI runs were red, from a dependency audit only.
- **Compared with Canary.** It sets the bar for "shipped". Its "not observable" state matches Canary's rule that Can't be checked is never a pass.

**W-TVC Protocol** (Machine Money, Freedom Stack)
- **What it is.** A Rust tool that commits AI model weights to a 32-byte digest, signs it with a BIP-340 key and records it in a local hash-chained ledger. Its `verify` command can recompute the digest from weights on disk.
- **Strengths.** One command, `tvc demo`, runs the whole story offline and ends on the catch: one weight out of 96 changes, and the registry rejects it. It has 98 tests, careful Merkle and hashing code, and verify output that always says what it did not check. A README section separates what is real from what is scaffolding.
- **Weaknesses.** Its headline claim, catching an AI provider that swaps models behind an API, is not built. The zero-knowledge layer and the Nostr publisher were deleted on 17 September, but both Devfolio pitches still describe them. It has no video, no CI and no interface.
- **Compared with Canary.** It has Canary's shape: a signed commitment that a client checks. Its deleted Nostr code used a replaceable event kind and trusted Nostr's self-reported `created_at` time, which are the two choices Canary's design rejects. Its one-command demo is worth copying.

### Entering more than one track

The platform allows it: 16 of the 68 projects picked more than one track, including Dossier and RelayJoin. Two things are unknown. Nobody knows whether one project can win two prizes. And nobody knows whether the private criteria sent on 7 September say anything about it.

Freedom Stack's brief is about systems whose useful properties don't depend on trusting their operator. That is close to Canary's thesis, and Canary uses Nostr. But the research judged Freedom Stack the stronger field, with PactAgent, ecashmesh, NostrPulse, QuietRelay and Bitcoin Reliability Labs. And entering all three tracks reads as unfocused.

**Decision (30 September):** Canary enters Cypherpunk only by default. It adds Freedom Stack only if the 7 September handbook allows it, and only with a genuine crossover pitch. The [roadmap's decisions](../roadmap/2026-09-30-feature-roadmap.md#decisions-made-on-30-september) record this.

---

## 5. What the strongest entries do that Canary did not

Each row names a practice, who does it well, and what Canary changed because of it. The feature IDs link to the [feature roadmap](../roadmap/2026-09-30-feature-roadmap.md).

| What they do | Who does it | What Canary changed |
|---|---|---|
| Something to try in under a minute, with no setup | Dossier's example buttons, RelayJoin's replay site, the hosted demos of Veil and NostrPulse | A public site whose home page is the evidence checker (F07, F08). It comes preloaded with the real evidence file and a labelled tampered copy |
| A video of 2 to 4 minutes, with chapters and an honest limits section | RelayJoin, QuietRelay (3:33), NostrPulse (about 4 minutes) | The video targets 3:15 to 4:30, at least 180 seconds, and keeps the limits scene (F14) |
| A README status that is true, with evidence behind it | RelayJoin's "Built" vs "Verified live"; LeakCheck's validation table | A "what works / what doesn't yet" table with numbers from the real run (F13) |
| Real output committed to the repo | Relay Evidence and QuietRelay commit real reports | The harness commits the final evidence file, and a CI test verifies it (F09). The site shows the recorded run with its SHA-256 (F07) |
| A verifier that recomputes results instead of trusting them | QuietRelay | `canary verify` ignores any stored result and prints its own (F03) |
| Missing evidence never counted as a pass | Bitcoin Reliability Labs' "not observable" state | Canary already had this: "Can't be checked" is neither a pass nor an accusation (F05) |
| Plain language first, protocol terms later | RelayJoin's "locked note"; Dossier's one plain sentence per section | A plain-language rewrite of every reader-facing doc, a glossary, and one wording table for every screen (F05) |
| A visual identity | Dossier's case file, RelayJoin's dark stage, QuietRelay's green rail on cream paper | A design system shared by the dashboard and the site, with its own identity (roadmap, Track B) |
| A guided path through the product | NostrPulse's "Happy path for judges"; QuietRelay's "useful loop" | A "Try it" section: build once online, then verify the committed evidence file offline (F13) |
| Complete interface states | RelayJoin's "stored on 2 of 3 relays"; a themed 404 at Bitcoin Reliability Labs | Error and empty pages for the dashboard: 404, 500 with an error ID, "No check yet", unreadable state, stale results (F16) |
| One-command runs | Bitcoin Reliability Labs' `doctor` and `demo`; W-TVC's `tvc demo`; LeakCheck's launchers | One script runs the whole regtest story (F09) |
| Privacy claims enforced by tests | LeakCheck's socket-blocking test; Relay Evidence's check of every outgoing message | A test runs `canary verify` while every network connection fails (F10). A traffic test waits for v2, because v1 holds no scan key to leak |
| A filled Devfolio card, a public repo and a license | Most finished entries | Devfolio fields with a track-fit note, an MIT LICENSE, a public repo and a tag (F13) |

**What Canary chose not to copy.**
- **A 0 to 100 score or a letter grade,** as Dossier and Veil use. Nobody could re-run a check that produces it.
- **A baseline the team wrote itself** to make the product look better, as in Veil's headline number.
- **Sample data under a "Live" label,** as NostrPulse shows. Canary's sample pages sit behind a build tag the release binary never uses, with a watermark.
- **Replaceable Nostr event kinds,** as W-TVC and AXI used. A replaceable event can be overwritten after the fact, so Canary's records use a regular, append-only kind.
- **Nostr events that expire,** as RelayJoin's did.
- **Entering all three tracks.**

The roadmap's [Things we decided not to do](../roadmap/2026-09-30-feature-roadmap.md#7-things-we-decided-not-to-do-and-why) has the full list.

---

## 6. Where Canary is stronger, and the conditions

Every point here holds only if Canary ships its core loop by 5 October. On 30 September, a judge could see none of them.

- **The organizers' own guide names the problem as open.** Bitshala's BIP-352 guide of 3 August 2026 lists "Trustless light client tweak sourcing. This is the big one." It adds: "A light client that accepts tweak data from a server has no way to detect omission." No other entry works on this.
- **It is the only silent-payment infrastructure entry.** The two entries that use the words, MeCuadra and AXI, get the protocol wrong.
- **The evidence is signed by the server it accuses.** QuietRelay and Relay Evidence both say their evidence is only self-consistent. The condition: this holds only when the receipt ships and verifies. Without a receipt, Canary's file shows what the server signed, not what it served, and Canary says so.
- **It can check a filtering server, inside a window.** Canary commits to the full, unfiltered list of entries. Inside the most recent 144 blocks, a filtering server must send the hash of every entry it drops, so the client can check the block against the signed root. Older blocks can be checked only if the server kept the hashes or another source supplies the entries; otherwise they read Can't be checked. Cut-through happens mostly deep in history, so against a single filtering server, most filtered blocks in a first full scan would read Can't be checked. That is a partial answer to the open question SomberNight raised (see [Where the problem is stated](#where-the-problem-is-stated)). A second condition: in v1, a server that declares a filtering policy can still hide an entry behind its correct hash, and the block reads Checked, gap filled. A server that declares no pruning and does the same gets only a warning, because v1 policies are unsigned. The roadmap names this limit and plans the fix (F24).
- **Its Nostr design is sounder.** Canary uses regular, append-only event kinds. It does not trust `created_at`, because Nostr gives publication, not timestamps. And it pins each server's key instead of trusting the first key it sees. W-TVC and AXI used replaceable kinds.
- **It has a development history.** By 30 September, Canary had 34 incremental commits between 6 and 10 September. On the evening of 30 September, all 80 of its top-level tests passed. Several rivals are single-day uploads. The flip side: nothing was pushed between 10 and 30 September.
- **It states each claim with its condition.** Canary is accountable, not trustless. Its claims hold only if at least one honest indexer publishes signed records, and the user has an uncensored path to a relay carrying them. It has no dual-use problem. In v1 it talks only to a local indexer and your own node. Once it talks to real servers and relays, the blocks it fetches reveal which blocks you care about, such as your wallet's starting height. The roadmap names that limit.

**Where Canary is weaker, stated plainly.**
- **It is not first with tweak-index commitments.** SPCOMMIT has run on mainnet since 1 September. See [SPCOMMIT](#spcommit).
- **The output hole.** Canary's entry is (txid, tweak). Wallets decide whether a payment exists from output data: filters, UTXO lists and 8-byte output prefixes. Canary v1 does not commit to that data. A server can serve the right tweak, drop the output, and pass every v1 check. SPCOMMIT's version 2 does cover output prefixes.
- **v1 is built and tested on regtest only,** and it sits in front of no real wallet. No live server publishes Canary's records.
- **Presentation.** Until the site, the video and the README land, the top four rivals look more finished.

---

## 7. Prior art in the ecosystem

### SPCOMMIT

SPCOMMIT is Rob Segers' commitment scheme for silent-payment tweak indexes. He runs silentpayments.net and posts on GitHub as bitsagarob. The details below were checked against primary sources on 30 September. They correct the first research pass on two points: when the service went live, and whether Optech used the name.

**Timeline.**
- **1 September 2026, 22:21 UTC:** the chain went live. The first checkpoint appeared on Nostr at height 965089.
- **2 September:** the spec and five test vectors landed in [bitsagarob/silentpayments-measurements](https://github.com/bitsagarob/silentpayments-measurements) (commit 8023408d). He announced it on the [bitcoin-dev mailing list](https://gnusha.org/pi/bitcoindev/6871d475-fbd4-4455-954d-20a369fba471n@googlegroups.com) the same day.
- **11 September:** [Bitcoin Optech #422](https://bitcoinops.org/en/newsletters/2026/09/11/) described the scheme. It never uses the name SPCOMMIT.
- **21 September:** the reference implementation was published (commit d204e6db). That date marks the source going public, not the service going live.

**How it works.**
- **Version 1** is a SHA-256 hash over each block's height, block hash (internal byte order), entry count and sorted tweaks. It covers only the unfiltered list: no dust limit and no cut-through.
- **Version 2** runs as a separate chain. For each transaction it covers the txid, the tweak and 8-byte output prefixes, sorted by txid, plus the block's spent-output list.
- **One chain, one signature.** Each block's value is hashed together with the previous block's, from a starting point at height 709655. Only the head of the chain is signed.
- **Publication.** The head goes out every 6 hours as an ordinary Nostr note (kind 1). By 30 September there were 118 notes, all from one key. The latest was at 13:45 UTC on 30 September, at height 969306.

**What it doesn't do.**
- It has no per-block signature, no inclusion proofs and no network identifier.
- A client given a filtered response "cannot check the subset for completeness", in Segers' own words.
- He describes what the chain offers as "detection by third parties after the fact rather than verification by the client".

**Other findings.**
- **A second implementation already exists:** [bitsagarob/spcommit-checkpoint-startos](https://github.com/bitsagarob/spcommit-checkpoint-startos), from 2 September. It checks version 1 only, needs an archival node, and calls itself "not a wallet or a scanner". No second publisher appeared on the four relays queried.
- **No wallet-side verifier was found.** That is absence of evidence only, because GitHub's code search indexes these repos poorly.
- **Relays keep these notes poorly.** relay.damus.io held none of them, relay.primal.net held 2, and nos.lol held about 3 days' worth. Only nostr.mom held the whole month. The lesson for Canary: store records locally, publish to several relays, and claim relay availability only after checking it.

**Compared with Canary.**

| | SPCOMMIT | Canary |
|---|---|---|
| Status | Live on mainnet since 1 September | v1, built and tested on regtest only |
| Structure | A flat hash per block, chained block to block | A Merkle tree per block, whose root also binds the network, the block hash and the entry count |
| Signing | Only the chain head, every 6 hours | One signed record per block |
| Proof that one entry is included | None | A Merkle inclusion proof |
| Servers that filter | Can't be checked | Inside the 144-block window, filtered entries arrive as hashes and are checked against the signed root. Beyond it, only if hashes were kept or another source fills the gap |
| Check in the wallet at fetch time | None found | The design's core. v1 checks each served list with `canary check`, outside the wallet. The in-path proxy is v2 (F17) |
| Output data | Version 2 covers 8-byte output prefixes | Not covered in v1: the output hole |
| History | The chain pins the order and all of history | Per-block records don't pin history |

**How Canary treats it.** Canary cites SPCOMMIT openly, next to Certificate Transparency ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)), whose split-view idea Canary applies. Canary does not claim to be first with tweak-index commitments, first to use Nostr for them, or first with the "trust me becomes catch me" framing. Interoperating with SPCOMMIT is a v2 feature (F22).

### tweak-service-auditor

[silent-payments/tweak-service-auditor](https://github.com/silent-payments/tweak-service-auditor) is a Python tool, active on 30 September. It compares the raw tweak lists served by rbitcoin, BlindBit's gRPC interface, Cake Wallet's electrs server and Bitcoin Core. It runs on the operator's side, after the fact, and nothing in it is signed.

Raw comparison has a known weakness: it cannot tell honest filtering from withholding. On 30 September, three live answers for mainnet block 969300 held 220, 184 and 141 entries. Those came from silentpayments.dev's two endpoints and Cake's server. It was a one-off measurement, and only the counts were kept. That noise is why Canary compares against signed records instead. The roadmap plans to offer Canary's block-level test vectors to this project (F27).

### The index-server specification

The silent-payments organization's [index-server specification](https://github.com/silent-payments/BIP0352-index-server-specification) asks the question Canary answers: "How does a wallet know all tweaks were received for a given block request?" Its tweak-server profile says "Service cannot be fully trusted — Users should be able to verify received data against other sources". Its data-integrity section says "Tweak data should be verifiable against full node data". The repo has been quiet since May 2026. The roadmap plans a proposal to it, crediting SPCOMMIT (F28).

### Where the problem is stated

- **BIP-352** never says that an index server can withhold data. A footnote says: "It is still an open question as to how Bob can source the 33 bytes per transaction in a trustless manner." Appendix A, on light clients, is "out of scope … to motivate further research". Both have been in the text since the first draft. Version 1.1.0 only added a per-group recipient limit. Canary's earlier docs misquoted this, and the truth pass fixes it.
- **Bitshala's BIP-352 guide** ([3 August 2026](https://x.com/bitshala_org/status/2084131259375296785)): "A light client that accepts tweak data from a server has no way to detect omission."
- **SomberNight,** the Electrum maintainer, in [cake_wallet#2395](https://github.com/cake-tech/cake_wallet/issues/2395) (July 2025): "what if the server lies by omission?" and "I presently do not see a way how to fix this while using cut-through."
- **Delving Bitcoin thread 891** (June 2024) is the main light-client discussion. Its attacks all involve servers adding data, not hiding it.

### The servers and wallets Canary would sit beside

- **blindbitd was archived** on 14 August 2025. The design had named it as the wallet.
- **blindbit-oracle version 2** deprecates its HTTP data interface in favour of gRPC.
- **The realistic unmodified clients** are [blindbit-scan](https://github.com/setavenger/blindbit-scan) and Dana (through spdk). blindbit-scan is a headless Go client that runs on regtest. Both speak BlindBit's version 1 HTTP interface.
- **Sparrow's server, Frigate,** takes the wallet's scan key and does the scanning itself. Canary's records can't check it. Only a self-payment tripwire, or a rescan with your own node, can.
- **Cake Wallet's electrs server** filters with cut-through and a dust limit, and has no integrity mechanism.
- **shroud-indexer** is the Bitshala-incubated indexer behind the Shroud wallet, now under CypherCommons. It is MIT-licensed TypeScript, does no filtering, and runs on regtest. Reading its code turned up two likely bugs: a length-encoding error for blocks with 253 or more transactions, and an eligibility check that drops bare-multisig spends. Nobody has run either yet. A read-only adapter is a v2 feature (F19).

---

## 8. Judging research

This section keeps three kinds of statement apart: what public sources say, what came second-hand, and what is inference. No public source names the judges, and this document does not guess.

### What public sources say

From [Devfolio's public API](https://api.devfolio.co/api/hackathons/boss-battle):
- **Deadline:** Monday 5 October 2026, 23:59 IST (18:29 UTC).
- **Registration** closed on 28 September at 23:59 IST.
- **Results:** 12 October at 14:00 IST.
- **Teams:** 1 to 3 people.
- **Prizes:** one $1,000 prize in each of the three tracks.
- **Judging** happens off the platform. The API lists no judges, and online judging is off.
- **Save draft and Publish are separate actions.** Only a published entry counts.
- **The form** asks for media (video or images), the problem the project solves, challenges, technologies and a track-fit note. It takes a YouTube, Vimeo or Loom link and shows no length limit.

Devfolio's terms require original work made during the event, and its code of conduct requires disclosing reused code.

On 7 September, Bitshala posted that registered participants had received "the problem statements, evaluation criteria, and hackathon details". Those went out privately. On 15 September, Bitshala reported "65 teams | 230+ builders".

### What came second-hand

- **Video length.** A "3 to 5 minute" rule and "keep the film link near the top of README" both come from one competitor's repo, QuietRelay's `docs/DEMO.md`. It cites a participant handbook and an organizer email of 21 September. The email appears to be a private reply to that participant. Several entrants submitted shorter videos, such as Dossier's 74 seconds, so the rule may not be widely known or enforced.
- **A rubric.** NostrPulse quotes slides from a private participant deck. One reads: "Show the numbers: benchmarks, adversarial results, the metric your approach moves." Others cover stating finished and unfinished work, and genuine crossover between tracks.
- **Weekly progress logs.** No source requires them. They appear only as one competitor's hedge.
- **Repo rules.** No rule requiring a public repo or a LICENSE was found.

Canary's response: the video will run at least 180 seconds, with a target of 3:15 to 4:30, and its link will sit near the top of the README. That costs nothing whether or not the rule is real. The real rules are in the 7 September email, and finding it is on the roadmap's Wednesday list.

### Inference

These points are the research's reading of indirect evidence. Treat them as guesses.
- **Devfolio's scoring factors are a weak signal.** The event's settings list Technicality, Originality, Practicality, Aesthetics and Wow-Factor. That is Devfolio's default list, and other events show the same one.
- **The track copy points at defaults.** The Cypherpunk track says strong entries "make the private path the easy path". A tool that only warns fits this less well than one in the data path.
- **Past winners at similar events had one working idea.** The research looked at six bitcoin++ hackathons in 2025. At the privacy edition in Riga, first place went to git-futz, a small tool that randomizes commit timestamps so they don't leak your time zone. At two events, the first-place project also won best design. Deep infrastructure also placed or earned mentions: block validation with Utreexo, and a fuzzer for Lightning implementations.
- **Tangible entries won Bitshala's earlier contest.** The research found one: a pitch contest in Goa in November 2025, where a made-in-India miner won and a feature-phone Bitcoin wallet came second. This was not re-checked.
- **What follows for Canary, as inference only:** a working catch on a recorded run beats an interface over sample data. A limit the team volunteers reads as rigor, while the same limit extracted by a reviewer reads as overclaiming.

---

## Appendix: all 68 projects

Generated from the triage data of 30 September. Projects are sorted by threat to Canary, then by relevance, then by name. Each name links to the project's Devfolio page. The deep dives sometimes saw more than the triage did. Veil's interface, for example, shows as unknown here, but its deep dive rated the live demo well.

- **Tracks:** CP is Cypherpunk, FS is Freedom Stack, MM is Machine Money. "None" means the project picked no track.
- **Code:** substantial, moderate, thin or none, judged from the linked repos.
- **UI:** polished, decent, basic, none, or unknown when the research could not load it.
- **Relevance:** overlap with Canary's problem, from 0 to 5.
- **Threat:** the chance of beating Canary for the Cypherpunk prize, from 0 to 5. It is 0 for any project outside Cypherpunk.

| Project | Tracks | What it is | Code | UI | Relevance | Threat |
|---|---|---|---|---|---|---|
| [Dossier](https://devfolio.co/projects/dossier-6fd9) | CP, FS | Paste a Nostr public key and it builds, in your browser, the surveillance file an analyst could assemble (location, sleep hours, DM partners, zap/Lightning money trail to on-chain funding txs, EXIF GPS, relays still serving deleted notes), then offers one-click fixes signed by your NIP-07 extension. | substantial | polished | 2 | 4 |
| [LeakCheck](https://devfolio.co/projects/leakcheck-4cb5) | CP | Local tool that reads your PSBT before you broadcast it, plays a chain-analysis observer, and tells you which of the observer's guesses (change output, common ownership, etc.) would be right. | substantial | basic | 2 | 4 |
| [RelayJoin](https://devfolio.co/projects/relayjoin-3aaf) | CP, FS | Asynchronous Payjoin (BIP78 semantics) carried over NIP-59 gift-wrapped Nostr events, so the receiver can be offline and no payjoin directory/OHTTP relay is needed. | substantial | polished | 2 | 4 |
| [Veil](https://devfolio.co/projects/bigocoder-a791) | CP | Pre-broadcast privacy coin control: scores a planned Bitcoin spend 0-100 against chain-analysis heuristics, then builds a more private version as a PSBT via Bitcoin Core. | moderate | unknown | 1 | 3 |
| [MeCuadra](https://devfolio.co/projects/mecuadra-8c8f) | CP, FS | P2P barter marketplace (no prices) with Bitcoin/Nostr key login, NIP-44 chat, Cashu anti-spam stamps, ZK reputation badges and 'Silent Payments-style' contact codes. | substantial | polished | 1 | 2.5 |
| [Wallet Server Path Diversity](https://devfolio.co/projects/wallet-server-path-diversity-f7b7) | CP | Proposes a tool that simulates how an Electrum light wallet picks its ~10 servers under the current /16 rule versus Bitcoin Core's ASMap, to show how much one network operator can see in each case. | none | none | 2.5 | 2 |
| [AXI](https://devfolio.co/projects/axi-ce18) | CP, FS, MM | Nostr peer-to-peer marketplace for goods and freelance services, with Cashu milestone escrow, NIP-44/59 encrypted chat, a client-side ZK reputation badge and BIP-352 silent-payment contact codes. | moderate | polished | 1 | 2 |
| [Luma Wallet](https://devfolio.co/projects/luma-0b41) | CP, MM | Mobile PWA wallet where an AI agent buys things over Lightning/RGB and L402. Every payment needs user approval tied to the exact payment details, and spending-policy limits apply. | substantial | decent | 1 | 1.5 |
| [Satoshi Sentinel](https://devfolio.co/projects/satoshi-sentinel-c925) | CP, FS, MM | Web app that analyzes pasted Bitcoin addresses, payment requests, URLs, Nostr events and suspicious messages and gives an AI-assisted, explainable scam/risk assessment. | moderate | decent | 1 | 1.5 |
| [SatoshiTrace](https://devfolio.co/projects/linkability-d555) | CP | Paste a Bitcoin address and see three chain-analysis heuristics (address reuse, common-input ownership, change linkage) run against it via mempool.space. | thin | unknown | 1 | 1.5 |
| [BlockShield AI](https://devfolio.co/projects/blockshield-ai-d8d1) | CP | Web app that analyses a Bitcoin address/tx with privacy heuristics, graph visualisation and an LLM 'Privacy Copilot' that explains the risks. | moderate | decent | 0.5 | 1.5 |
| [PrivaVend](https://devfolio.co/projects/privavend-26df) | CP, FS, MM | A Nostr NIP-90 AI data-vending machine paid with Cashu ecash, with NIP-44 encrypted results and local Ollama inference. | moderate | basic | 1 | 1 |
| [Spectra (VEILSTR)](https://devfolio.co/projects/spectra-c6c7) | CP | AI-powered analysis of a Nostr user's public activity (posting times, relays, interactions, writing style) to show how linkable their pseudonymous identities are. | none | unknown | 1 | 1 |
| [CypherStack](https://devfolio.co/projects/cypherstack-02e0) | CP, FS, MM | Client-side web app that computes trust scores for Bitcoin addresses, Nostr profiles and AI agents from public data, with a 'ZK proof' of score threshold. | thin | decent | 0.5 | 1 |
| [Satoshi Sentinel](https://devfolio.co/projects/satoshi-sentinel-93bd) | None | FastAPI + React address privacy scanner with 0-100 score, React Flow tx graph, Gemini copilot, Nostr alert publishing and a privacy 'academy'. | moderate | unknown | 0.5 | 1 |
| [ShadowSync Agent](https://devfolio.co/projects/shadowsync-agent-bde0) | CP, MM | Claims to monitor light-wallet/server sync for privacy leaks and give an AI-explained privacy score; the repo is empty. | none | none | 2 | 0.5 |
| [Bitcoin Privacy Assistant](https://devfolio.co/projects/bitcoin-privacy-assistant-2f89) | CP | Static web page that explains Bitcoin privacy risks to beginners and gives simple advice. | thin | basic | 1 | 0.5 |
| [Uncluster](https://devfolio.co/projects/uncluster-ca54) | FS | Pre-signing checker that flags common-input-ownership merges across labeled UTXO clusters, change script-type mismatches, round amounts and BIP-69 ordering, plus a scanner for Bitcoin addresses leaked in Nostr events, with a retro CRT-styled web console and Python CLI. | thin | decent | 1 | 0.5 |
| [Entropy Trace](https://devfolio.co/projects/entropy-trace-4a75) | None | Apparently a tool for tracing where randomness comes from (possibly wallet or key entropy). No links, description or track are given. | none | none | 0.5 | 0.5 |
| [NostrCast](https://devfolio.co/projects/nostr-street-135c) | CP, FS | Twitch-style live-streaming concept on Nostr, with Cashu NutZap tips that trigger on-stream effects. | thin | basic | 0.5 | 0.5 |
| [SatFlow DVM](https://devfolio.co/projects/satflow-dvm-8f36) | CP, FS, MM | Nostr NIP-90 Data Vending Machine that takes Bitcoin Script audit jobs, charges a Lightning invoice via LNbits, runs an LLM audit and returns the result encrypted with NIP-44. | thin | none | 0.5 | 0.5 |
| [Cypherpunk (ChronicleAI)](https://devfolio.co/projects/cypherpunk-80df) | CP | ChronicleAI: an AI on-chain monitoring desk that sells a $4.99/month subscription, routes revenue to a treasury, executes DeFi actions via KeeperHub and publishes proof; resubmitted under the name 'Cypherpunk'. | substantial | unknown | 0 | 0.5 |
| [Stegashareus](https://devfolio.co/projects/stegashareus-5eb0) | CP | Planned PyQt desktop app to hide BIP-39 seed phrases in JPEGs robust to chat-app recompression, with plausible deniability. | none | none | 0 | 0.5 |
| [Relay Evidence](https://devfolio.co/projects/relay-evidence-7cff) | FS | A CLI that takes one signed Nostr event and a relay list, checks the event locally, queries each relay for it, and writes a portable JSON/Markdown report that separates observations from explanations. | moderate | basic | 3.5 | 0 |
| [QuietRelay](https://devfolio.co/projects/quietrelay-5f23) | FS | Local Nostr relay policy workbench: replays signed events through Open/Quiet presets, shows what gets admitted, held or rejected, and runs a real loopback WebSocket relay to check predictions. | substantial | polished | 3 | 0 |
| [Bitcoin Reliability Labs](https://devfolio.co/projects/bitcoin-reliability-labs-3f55) | FS | Two fault-injection test labs: Cashu Fault Lab (payment delivery/recovery across Cashu and Nostr under crashes, loss, duplicates) and PSBT Interop Lab (compatibility across Bitcoin tools), both producing saved evidence. | substantial | unknown | 2.5 | 0 |
| [W-TVC Protocol](https://devfolio.co/projects/wtvc-protocol-964c) | FS, MM | Commits AI model weights to a 32-byte digest, signs it with a BIP-340 key, and publishes it as a Nostr event, so a payer can later check which model served an inference. The zkML proving layer is not built. | moderate | none | 2.5 | 0 |
| [ecashmesh](https://devfolio.co/projects/ecashmesh-def0) | FS | A Rust engine plus a React Native reference wallet that picks which ecash or payment source (Cashu mint, Fedimint federation, Lightning) to pay from, ranked on explicit evidence about fees, reliability, liquidity and freshness. | substantial | unknown | 1 | 0 |
| [Lifeboat](https://devfolio.co/projects/lifeboat-b947) | FS | Encrypts LND static channel backups with NIP-44, publishes them to several Nostr relays, and recovers channel funds from the 24-word seed alone. | thin | unknown | 1 | 0 |
| [NostrPulse](https://devfolio.co/projects/nostrpulse-869f) | FS, MM | Nostr web-of-trust reputation explorer with an anti-Sybil score, NIP-61 Cashu NutZaps, and an MCP server that puts spending caps on AI-agent payments. | substantial | polished | 1 | 0 |
| [PactAgent](https://devfolio.co/projects/pactagent-42ce) | FS, MM | Framework where AI agents discover each other on Nostr, sign service offers, fund Cashu escrow, exchange private work via NIP-59, verify completion and settle in ecash. | substantial | none | 1 | 0 |
| [ChainTrace](https://devfolio.co/projects/chaintrace-6e6b) | MM | Local-first FastAPI backend running chain-analysis heuristics (reuse, CIOH, change, timing, amount, peel chains) on a wallet's public history. | moderate | none | 0.5 | 0 |
| [AegisMCP](https://devfolio.co/projects/aegismcp-af9e) | None | A claimed safety tool for MCP (Model Context Protocol) tools. The GitHub repo is empty. | none | none | 0 | 0 |
| [AgentSats](https://devfolio.co/projects/agentsats-autonomous-ai-agent-economy-7cbc) | MM | AI agents discover each other over Nostr NIP-90 and pay each other in Lightning for research tasks. | thin | unknown | 0 | 0 |
| [Autonix](https://devfolio.co/projects/machine-money-461e) | MM | A demo where a Gemini agent hits an L402 paywall and a deterministic policy engine decides whether its Lightning wallet pays. | thin | unknown | 0 | 0 |
| [BlindVend](https://devfolio.co/projects/blindvend-77b4) | FS | Placeholder for a pay-per-prompt service in Go on Nostr. The repo contains only a title README. | none | none | 0 | 0 |
| [CampusPilot AI](https://devfolio.co/projects/campuspilot-ai-9791) | CP, FS, MM | College management app (attendance, notices OCR, study plans) with an AI assistant; no Bitcoin component. | moderate | unknown | 0 | 0 |
| [CIVIC AI](https://devfolio.co/projects/civic-ai-0ce5) | None | Civic issue reporting web app, unrelated to Bitcoin; demo link only. | none | unknown | 0 | 0 |
| [CivicOS](https://devfolio.co/projects/civicos-a053) | None | An AI municipal-services web app (Vercel-hosted) unrelated to Bitcoin. | none | unknown | 0 | 0 |
| [Dashboard-Final-Version](https://devfolio.co/projects/dashboardfinalversion-2a8b) | None | Streamlit YouTube analytics dashboard, unrelated to Bitcoin. | thin | basic | 0 | 0 |
| [DESIGN ARENA](https://devfolio.co/projects/design-arena-7999) | None | Competitive design-battle platform with AI jury feedback, Nostr login and Lightning reward payouts. | thin | unknown | 0 | 0 |
| [DialSats](https://devfolio.co/projects/dialsats-f446) | MM | An 'agentic Bitcoin wallet' with no links, repo, or description. | none | none | 0 | 0 |
| [Ecommerce website](https://devfolio.co/projects/ecommerce-website-e6ca) | None | Static HTML/CSS/JS storefront for a shop on GitHub Pages. No connection to Bitcoin. | thin | basic | 0 | 0 |
| [Fine Catch](https://devfolio.co/projects/fine-catch-c93a) | MM | AI tool that reads student-loan agreements, pulls out the fees, rates and penalties with evidence, and explains them. | thin | unknown | 0 | 0 |
| [GAYN1](https://devfolio.co/projects/gayn-f6eb) | None | General AI desktop assistant with tools, gesture recognition and activity analytics. | moderate | unknown | 0 | 0 |
| [Geo echo](https://devfolio.co/projects/geo-echo-dd87) | None | AI search app hosted on Google AI Studio; no repo, no Bitcoin component. | none | unknown | 0 | 0 |
| [Ghost Infrastructure](https://devfolio.co/projects/ghost-infrastructure-8ea6) | None | React/Leaflet map app for identifying neglected urban land with AI suggestions. | thin | unknown | 0 | 0 |
| [Infernous (Infernos)](https://devfolio.co/projects/nodus-426f) | MM | A Rust node that puts an L402 Lightning paywall in front of Ollama or any OpenAI-compatible model, so agents can pay sats per request with no accounts. | substantial | none | 0 | 0 |
| [JARVIS-AI](https://devfolio.co/projects/jarvisai-9c74) | None | Small Python voice assistant script. | thin | none | 0 | 0 |
| [MAKAUT NEXUS](https://devfolio.co/projects/makaut-nexus-1558) | None | Student study-tracking web app for a university (React Three Fiber, Framer Motion). | moderate | unknown | 0 | 0 |
| [Nostre 3D Visualizer](https://devfolio.co/projects/nostre-d-visualizer-a12f) | FS | Three.js 3D visualisation of Nostr protocol data. | thin | unknown | 0 | 0 |
| [Oncocare A personal oncology expert system](https://devfolio.co/projects/oncocare-a-personal-oncology-ecpert-system-625c) | None | A medical oncology risk expert system, unrelated to Bitcoin. The GitHub repo is empty. | none | none | 0 | 0 |
| [PUKart](https://devfolio.co/projects/pukarta-campus-market-place-1337) | None | Campus marketplace where students sell to each other (MERN stack, Google OAuth). No connection to Bitcoin. | moderate | unknown | 0 | 0 |
| [ResumeIQ - AI Resume Analyzer](https://devfolio.co/projects/resumeiq-ai-resume-analyzer-bc2e) | None | Single-HTML-file resume and GitHub profile analyzer using the Gemini API. | thin | unknown | 0 | 0 |
| [SaralGati](https://devfolio.co/projects/saralgati-9453) | None | Android simplified-launcher/assistant app for elderly users, unrelated to Bitcoin. | substantial | unknown | 0 | 0 |
| [SatsNav](https://devfolio.co/projects/beaconnostr-3fbc) | FS, MM | MCP server that gives AI agents Lightning route-finding, fee monitoring and NWC payments with spending limits. | none | unknown | 0 | 0 |
| [Sattle](https://devfolio.co/projects/splitsats-4d98) | FS | Bill-splitting app over Lightning. | none | unknown | 0 | 0 |
| [SATWISE AI](https://devfolio.co/projects/satwise-ai-87eb) | MM | Unclear AI + Bitcoin app (React/Flask/Solidity stack) with no pitch text. | thin | unknown | 0 | 0 |
| [School website](https://devfolio.co/projects/school-website-d28f) | None | A static school website. | thin | unknown | 0 | 0 |
| [SentinelScan](https://devfolio.co/projects/sentinelscan-d2cc) | None | AI scanner that flags scam smart contracts. | thin | basic | 0 | 0 |
| [Smart AI Backup and detection](https://devfolio.co/projects/smart-ai-backup-and-detection-6997) | None | Cloud storage management frontend, unrelated to Bitcoin. | none | unknown | 0 | 0 |
| [Smart Attendance Risk Predictor](https://devfolio.co/projects/smart-attendance-risk-predictor-88f7) | None | Tiny scikit-learn/Streamlit script predicting student attendance risk. | none | none | 0 | 0 |
| [StockSentinel](https://devfolio.co/projects/stocksentinel-674d) | FS | Next.js agent that alerts on tokenized-stock spreads via Binance Web3 API and optionally executes capped swaps. | thin | unknown | 0 | 0 |
| [Student Portfolio Website](https://devfolio.co/projects/student-portfolio-website-f2db) | None | Placeholder student portfolio page; only link is a template CodePen URL. | none | none | 0 | 0 |
| [Two-Level Game-Based Virtual Network Allocation](https://devfolio.co/projects/twolevel-gamebased-virtual-network-resource-allocation-239c) | None | Python/NetworkX academic project on virtual network embedding via game theory. | none | none | 0 | 0 |
| [Velra](https://devfolio.co/projects/velra-fc36) | MM | Rust tool that saves Claude Code's task state to SQLite before /compact and restores it afterwards. | substantial | none | 0 | 0 |
| [Venture mind](https://devfolio.co/projects/venture-mind-e1e7) | None | Placeholder entry named 'PromptShield AI': no description, links, video or track. | none | none | 0 | 0 |
| [ZapAgent](https://devfolio.co/projects/zapagent-a0a7) | None | A NIP-90 data-vending-machine agent that takes Nostr jobs, is paid via NWC zaps, runs Gemini, and shows a React dashboard. | thin | basic | 0 | 0 |
