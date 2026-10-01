# Devfolio fields

This page holds the text for every field of Canary's BOSS Battle entry on Devfolio.
Under each heading, an italic note says what the field is for. Everything after the
note is the text to paste.

Before you paste:

- Replace the two values still in [brackets]: the video link and the site address. The
  recorded run of 1 Oct filled every other bracket, from the files in
  [docs/runs/2026-10-01](../runs/2026-10-01/) and the committed evidence file.
- Some lines describe things that have not happened yet. Their note says which line to
  delete if it still has not happened. Never leave in a claim about a video, relay
  publication or a deployed site that did not happen.
- Recount the tests on 5 Oct, with the command in the
  [final-day checklist](checklist.md#before-1200-ist). The numbers below were measured on
  1 Oct.
- Press Publish, not Save draft. Only a published entry counts.

---

## Project name

Canary

## Tagline

*Under 80 characters. This one is 71. A shorter option, at 58 characters: "Holds
silent-payments servers to the tweak lists they sign".*

Names the silent-payments server that leaves out an entry it signed for

## Track

*Cypherpunk only, unless the 7 Sep handbook allows a second track. See
[Freedom Stack](#freedom-stack-only-if-the-handbook-allows-multi-track-entry) at the end.*

Cypherpunk

## Links

*Delete the site line if the site is not deployed.*

- Source: https://github.com/Sky-walkerX/canary, tag `v0.1.0`
- Video: [video link]
- Site with the in-browser evidence checker: [site URL]

## Media

*The video goes in the video field. If the form also takes images, use screenshots from
the recorded run only. Never use the sample-data dashboard, because its data comes from
no run.*

1. The terminal where `canary check` names the withholding server, block 351. The text
   is in [docs/runs/2026-10-01/check.txt](../runs/2026-10-01/check.txt).
2. The browser checker showing "Checks out." for the evidence file from the run:
   `docs/media/site-checker-real.png`.
3. The local dashboard's Overview for the same run: `docs/media/dashboard-overview.png`.

## The problem it solves

Silent payments let you publish one reusable address, and nobody watching the chain can
link the payments you receive. To find a payment, a light wallet asks a server for one
small value per transaction, called a tweak. The wallet combines each tweak with its own
key and looks for a match.

If the server leaves out the tweak for your payment, your wallet never finds it. It shows
the balance it would show if nobody had paid you. There is no error, no retry and nothing
to notice, and the payment stays invisible.

The receiver is the one hurt. The sender is the one best placed to do it. A server can't
tell which transactions pay you without your private scan key, but the sender knows its
own transaction. So an exchange that pays you, and also runs the server your wallet uses,
can hide its own payment and still hold a record that it paid.

Bitshala's own BIP-352 guide of [3 August 2026](https://x.com/bitshala_org/status/2084131259375296785)
names the gap: "A light client that accepts tweak data from a server has no way to detect
omission."

In technical terms, a BIP-352 light client receives per-transaction tweaks from an index
server and cannot tell a complete list from one with entries removed. Honest servers also
filter differently, through cut-through and dust limits. So comparing two servers' lists
raises false alarms and settles nothing.

Canary makes the server accountable for what it leaves out. For each block, a server
signs one record: the entry count and a Merkle root over the complete, unfiltered list of
`(txid, tweak)` entries. It may then serve less, but every entry it leaves out is a marked
gap. `canary check` recomputes the root from what the server sent, and names the server
and the block when the server's own signatures contradict each other. Servers must keep
at least each entry's hash for 144 blocks, about a day. So an empty gap in a recent block
names the server. A signed receipt over the served bytes turns that finding into an
evidence file anyone can check offline, in a terminal or in a browser.

Canary does not make tweak sourcing trustless. It makes it accountable. The claim holds
given at least one honest server publishing signed records, and an uncensored path to a
relay carrying them. Version 1 fetches records from each server over HTTP and uses no
relays yet.

## Challenges I ran into

**A citation that turned out false.** Our early docs said BIP-352 v1.1.0 states that an
index server can withhold data. On 30 September we read all 34 revisions of the BIP, and
none of them says it. Version 1.1.0 only added a limit on recipients. The withholding
wording came from Bitshala's guide. We fixed every copy, and now quote the BIP's real
footnote, which calls tweak sourcing for light clients "still an open question".

**Someone got there first.** The same research found SPCOMMIT. Rob Segers has published
tweak-list commitments for mainnet since 1 September, and Bitcoin Optech #422 described
the scheme without naming it. So Canary is not first. We cut every "first" claim and credited SPCOMMIT next
to Certificate Transparency. Our claim is now narrower. Canary checks each block at the
client. A filtered response marks every gap, inside a list whose length the server
signed. And Canary adds coverage states, evidence files and tripwires. We also say where
SPCOMMIT is ahead. It commits to output prefixes, and its hash chain fixes the order of
all history.

**A demo that could never accuse anyone.** Reviewing our own plans on 30 September, we
found that the central demo scene could not happen. The withholding server left an empty
slot. The planned check called that "unresolvable" when nothing filled it, and "clean"
when something did. Neither names a server, because an honest server that prunes old
blocks sends the same empty slot. The fix is a retention rule. Servers must keep at least
the hash of every entry for 144 blocks. A slot sent empty while the block sits less than
144 blocks below the server's own signed tip names the server. The receipt signs that
tip, so a stranger can check the window offline.

**A hole we chose to name, not fix.** Canary commits to each transaction's ID and tweak.
A wallet decides that a payment exists from output data the server also sends. So a
server can send the right tweak, drop the output, and Canary v1 still reads the block as
Checked. Closing that costs 6 to 10 hours we did not have before the deadline. Instead,
the README, the design and the video's last scene all name it. Checked means the tweak
list was checked, never the payments. Output keys in the entry are the first work after
judging.

**Hostile servers found routes we had missed.** Reviews on 1 October found five ways one
server could stop, stall or exhaust the run that would name it:

- It could answer "not found" for the one block it was hiding, which stopped the run
  before anything was saved.
- It could sign a chain tip too high for Bitcoin Core to look up, and Core's refusal
  stopped the run.
- It could sign a record claiming 200,000 entries and turn one block into 200,000
  findings. That run took over a minute, and the cost grew with the square of the count.
- It could pair any record with a 64 MiB list, which would take about 6.6 GB to decode.
- It could pad every record with a 1 MiB signed tag. At 600 blocks the run reached a
  2.19 GB heap, and it would have died before naming anyone.

Each route is now closed and pinned by a test, and the padded run peaks at 21 MB. One
route stays open, and the docs name it: a slow server can still stretch a run.

## Technologies used

*If the field takes tags, use the comma-separated line. If it takes text, use the list.*

Go, Bitcoin, BIP-352, Silent Payments, BIP-340, Schnorr signatures, Nostr, Bitcoin Core,
WebAssembly, html/template

- **Go**, tested on Go 1.26.4, for every part: the checker, the reference index server,
  the dashboard, the site generator and the browser checker.
- **BIP-352** through `github.com/setavenger/go-bip352` v0.1.8, for eligibility, the
  input hash and the tweak.
- **BIP-340 Schnorr signatures** through `btcec/v2`, for records and receipts.
- **Nostr** through `go-nostr`. Each record is a signed kind-1352 Nostr event.
- **Bitcoin Core's REST interface**, for block hashes, the chain tip and the outputs each
  transaction spends. The reference index server needs Core v30 or later for
  `/rest/spenttxouts`.
- **WebAssembly**, so the browser checker runs the same Go verify code as the terminal.
- **Go's `html/template`**, for the local dashboard and the static site. There is no
  JavaScript framework, and the site builds with Go alone.

Reused code, for the code of conduct: the Go libraries above, plus `goldmark` for the
site's Markdown, all used as published. The fonts are Atkinson Hyperlegible Next and
Mono, under the SIL Open Font License. The repo's first two commits, design notes, landed
on the evening of 6 September IST, before the event opened. The first code commit is from
9 September.

## Track fit: is this privacy or reliability?

*For the track-fit field.*

Privacy. The failure looks like a reliability bug, a payment that never shows up. But
today the way out costs privacy.

A light wallet has two choices now. It can keep its scan key and trust the server to
send every tweak. Or it can hand its scan key to a remote scanner, such as Sparrow's
Frigate server, which does the scanning for it. Bitshala's guide names the cost of each.
Private light-client scanning "means the server cannot see your outputs, not that it
cannot withhold them." And "a remote scanner can still withhold a transaction, and now it
knows everything as well."

A light wallet that can check its server lets the private model be the default: a server
that never sees your scan key. Without a check, a wallet that wants reliable payments has
a reason to hand its key over. The track asks entries to make the private path the easy
path. Canary is the check that makes the private path worth choosing.

Canary itself never sees your scan key. It does not hide which blocks you check, though,
and the docs list that as a limit.

## What works, and what doesn't yet

*For the description field, or after the problem field if the form has no description.
The second and third bullets come from the recorded run of 1 Oct, in
[docs/runs/2026-10-01](../runs/2026-10-01/).*

What works:

- The whole v1 loop is built and tested: a reference index server with a
  `--withhold-txid` switch, `canary check`, evidence files, `canary verify`,
  `canary status`, a local dashboard and a browser checker. One end-to-end test runs it
  on a synthetic regtest chain. `canary check` names the withholding server, the block
  and the txid, from that server's own signatures.
- On 1 October 2026, a run on Bitcoin Core v31.1.0 in regtest mode named the
  withholding server at block 351, txid
  `ad56b9bb4aa382fdaec664abc1dcaf57b0477905c5c17c2c7669d6212d5fe21e`. The server had
  left that payment out of the list it served, while its signed record for the block
  still included it. `canary check` over blocks 0 to 351 reported 351 Checked and
  1 Data withheld. A last check covered block 201 alone, with only the withholder. That
  block sat 150 blocks deep, past the 144-block window, and nothing could fill its gap.
  It read Can't be checked, which is neither a pass nor an accusation.
- That run's evidence file is committed at
  `evidence/omission-regtest-351-ad56b9bb-db614560.json`, and a CI test keeps it
  checking out. It checks out with `canary verify`, which needs no network, and with the
  browser checker's WebAssembly build.
- A one-byte change to an evidence file fails the check, at the step that covers that
  byte.

What doesn't yet:

- Canary v1 does not check output data. A server can send the right tweak and drop the
  payment's output, and the block still reads Checked.
- A server that declares a pruning policy can send just an entry's hash. The root still
  matches, so v1 cannot tell that from honest pruning.
- Version 1 is built and tested on regtest only, against its own reference index server.
  That server reuses Canary's code for computing entries, so v1 does not test two
  independent implementations. No deployed server speaks Canary's API yet.
- No relays yet. `canary check` fetches signed records from each server over HTTP. The
  recorded run published nothing to Nostr relays.
- The recorded run used one Bitcoin Core node on one computer, feeding both servers and
  the checker.
- No wallet in the loop. A finding reaches you only when you run `canary check`.
- When two servers disagree, Canary names both and cannot say which one lied. That
  finding, and a few others, have no evidence file in v1: you know, but cannot yet prove
  it to others.

## Numbers

*Measured on 1 Oct 2026 unless marked. Recount the tests before pasting.*

- **Tests:** 403 top-level tests, 782 passing cases with subtests, in 19 Go packages.
  None fail, with or without the race detector, on Go 1.26.4. One of them verifies the
  committed evidence file.
- **Code:** about 16,300 lines of Go, plus about 17,000 lines of tests.
- **End to end:** one test runs the whole v1 demo in one process, on a 209-block
  synthetic chain with two reference index servers. `canary check` takes about 0.2 s
  there.
- **Adversarial results:** six one-byte changes to an evidence file each fail at the step
  that covers that byte. Five hostile-server routes are each pinned by a test.
  `canary verify` also passes in a process that macOS cuts off from the network.
- **Memory bound:** Canary reads at most 4 KiB of a record, against 689 bytes for an
  honest one on regtest. It reads at most `4 + 66n` bytes of a list of `n` entries.
  Against a server that pads every record, a 600-block run peaks at 21 MB, against 16 MB
  for honest servers. Before that fix it reached 2.19 GB.
- **Browser checker:** 8.68 MB of WebAssembly, or 2.66 MB with gzip -9.
- **Cost to a server:** one signed record per block, 689 bytes on regtest, and one signed
  receipt per list it serves. It keeps 36 bytes per block long term, about 35 MB for all
  of mainnet history (965,000 blocks × 36 bytes).
- **Wire size:** a full list is `4 + 66n` bytes. A pruned entry costs 33 bytes as a
  hash, or 1 byte if it is left out.
- **Retention window:** 144 blocks, about one day at 10 minutes per block.
- **From the real run, 1 Oct 2026:** 352 blocks checked, 0 to 351, against two servers:
  351 Checked and 1 Data withheld. Block 351 holds five entries. The withholder's receipt
  covers the 269-byte list it served. The evidence file is 2,722 bytes, SHA-256
  `aea26b9bf54926af62eefe09b7fb7bd64540025b052001f52a41f77cac1b9710`. The run did not
  time `canary check`.

## AI assistance

*One sentence for the disclosure field, or the end of the description.*

One developer built Canary with Claude, Anthropic's AI assistant, which wrote much of the
code, tests and docs under the developer's direction and review.

## Freedom Stack, only if the handbook allows multi-track entry

*Paste this only if the 7 Sep handbook allows one project in two tracks. The default is
Cypherpunk only, and entering a second track without that rule reads as unfocused.*

Freedom Stack is about systems whose useful properties don't depend on trusting their
operator. Canary applies that to the server a light wallet depends on. Each server signs
what it indexed for every block. A client checks what the server serves against that
signature, with no trust in that server's word. Anyone can check an evidence file offline, in a terminal or a
browser, with no node, account or server. Records are Nostr events, so a server needs no
new infrastructure to publish them. Version 1 still fetches them over HTTP and uses no
relays. The limit stays in place. Canary needs at least one honest server and an
uncensored path to its records. It makes withholding detectable and attributable, not
impossible.
