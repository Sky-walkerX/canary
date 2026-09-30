# Prior art and gap analysis

**Compiled 2026-09-06. Re-verified 2026-09-30.** Each claim was checked against a primary
source on the date given next to it. The 30 Sep pass corrected two false citations and
added the prior art that appeared in September, most importantly SPCOMMIT. Re-verify
before relying on any of it. The gap this project addresses is a perishable fact.

Terms such as *tweak*, *commitment* and *cut-through* are defined in the
[glossary](../glossary.md).

---

## 1. The gap is recognised, and still open

Re-verified 2026-09-30.

- **BIP-352 leaves tweak sourcing open**, in text present in every revision since the
  file's first commit (15 Jan 2024). The current version is 1.1.1 (16 Apr 2026).
  - A footnote says: *"It is still an open question as to how Bob can source the 33 bytes
    per transaction in a trustless manner."*
  - The introduction says: *"light client support is considered an area of open
    research"*.
  - Appendix A, on light clients, says: *"While this is out of scope for the current BIP,
    it is included to motivate further research into this topic."*
  - No revision of the BIP mentions a server withholding or omitting data.
- **Correction (30 Sep).** An earlier version of this file said that BIP-352 v1.1.0
  (March 2026) introduced light-client approaches and stated the withholding assumption.
  Both statements were false. Appendix A has been in the file since its first commit.
  Version 1.1.0 only added the per-group recipient limit `K_max` (2,323). The withholding
  wording comes from Bitshala's guide, below.
- **Bitshala's BIP-352 guide** (3 Aug 2026,
  [x.com/bitshala_org](https://x.com/bitshala_org/status/2084131259375296785)) comes from
  the hackathon's organiser. Under open problems it says: *"Trustless light client tweak
  sourcing. This is the big one…"* It continues: *"A light client that accepts tweak data
  from a server has no way to detect omission. … Until it is solved, 'privacy-preserving'
  light client scanning means the server cannot see your outputs, not that it cannot
  withhold them."* The ellipsis marks text left out between the two sentences.
- **SomberNight**, the Electrum maintainer, opened
  [cake_wallet#2395](https://github.com/cake-tech/cake_wallet/issues/2395), "Missing funds
  when receiving silent payments", on 17 Jul 2025. He wrote: *"what if the server lies by
  omission? … the client will never learn about this, even after connecting to a
  different server"*. He also wrote: *"I presently do not see a way how to fix this while
  using cut-through."* Cake closed the issue on 18 Jul 2025 as not planned.
- **The silent-payments
  [index-server specification](https://github.com/silent-payments/BIP0352-index-server-specification)**
  asks: *"How does a wallet know all tweaks were received for a given block request?"* Its
  tweak-server profile says *"Service cannot be fully trusted"*. Its data-integrity section
  says *"Tweak data should be verifiable against full node data"*.
- **Bitcoin Optech #421** (4 Sep 2026) covered silent payments only for miner payouts in
  coinbase transactions.
- **Bitcoin Optech #422** (11 Sep 2026) covered SPCOMMIT, without using that name. It said
  Segers's server *"publishes per-block commitments over the sorted tweak set and
  checkpoints them to nostr every six hours, making omissions attributable after the
  fact"*. The 6 Sep version of this file said Optech had nothing on index integrity; that
  is no longer true.
- **Bitcoin Core PR #28241**, "Silent payment index (for light wallets and consistency
  check)" by Sjors, was **closed unmerged** on 2025-02-20. Its "consistency check" means
  validating the index against test vectors across mainnet, not detecting omission on the
  client. No collision. <https://github.com/bitcoin/bitcoin/pull/28241>

**Conclusion (30 Sep).** SPCOMMIT, below, makes omission detectable after the fact by
someone who runs a full node. We found no wallet or client that checks tweak data at the
moment it is fetched.

## 2. SPCOMMIT: the closest prior art

Added 2026-09-30. Sources: the
[silentpayments-measurements](https://github.com/bitsagarob/silentpayments-measurements)
repository (`SPCOMMIT.md`, `FILTERS.md`, the light-client protocol draft), the
[bitcoin-dev post](https://gnusha.org/pi/bitcoindev/6871d475-fbd4-4455-954d-20a369fba471n@googlegroups.com)
of 2 Sep 2026, Optech #422, and a live query of four Nostr relays.

**Who and when.** Rob Segers (GitHub `bitsagarob`) runs silentpayments.net.

- His commitment chain went live on mainnet on 1 Sep 2026. The first Nostr checkpoint was
  at 22:21 UTC, height 965,089.
- He published the specification, with v1 and v2 formats and five test vectors from real blocks, on
  2 Sep 2026. He announced it on bitcoin-dev the same day.
- He added the reference implementation, `commitments.js`, on 21 Sep 2026. That date marks
  when the source was published, not when the service started.
- A second implementation by the same author, the witness package
  `bitsagarob/spcommit-checkpoint-startos`, appeared on 2 Sep. It covers v1 only, runs on an archival Bitcoin Core node, and describes itself as
  "not a wallet or a scanner".

**How it works.**

- v1 is a SHA-256 over height, block hash, count and the block's tweaks, sorted as hex
  strings. It covers the unfiltered list: no dust limit and no cut-through.
- v2 is a separate, parallel chain. For each transaction, sorted by txid, it covers the
  txid, the tweak and `outputs_short`, the 8-byte prefixes of the output keys. It also
  covers the block's spent-output data.
- Each chain links blocks as `head(H) = sha256(head(H-1) || commitment(H))`, from a
  genesis at height 709,655.
- Only the chain head is signed. The operator posts it every 6 hours as a Nostr kind-1
  note tagged `t=silentpayments-tweak-index`. On 30 Sep we counted 118 such notes from one
  key, the latest at height 969,306.
- The format has no Merkle tree, no inclusion proofs and no network identifier.

**What its author says it does not do.** `FILTERS.md` says a client given a filtered
response *"cannot check the subset for completeness"*. It describes what the chain offers as
*"detection by third parties after the fact rather than verification by the client"*.

**What Canary adds.** These are design differences. The status table in the
[README](../../README.md) says which parts are built.

- **One signed event per block.** Each Canary commitment is its own signed Nostr event,
  found through the single-letter `b` tag that holds the block hash. A client can check one
  block without recomputing a chain from a checkpoint.
- **Proofs and binding.** Canary's root is a tagged-hash Merkle tree with inclusion proofs.
  The root also binds the network's 4-byte magic, the block hash and the entry count.
- **Filtered responses leave explicit, signed gaps.** A server serves a subset of the
  committed list. Each entry it leaves out is a marked gap in a list whose length and root
  it signed, and the client tries to fill the gaps from elsewhere. Three conditions apply:
  - A gap sent as nothing while the block is less than 144 blocks deep names the server.
  - A gap sent as nothing further back, which no other source fills, ends as *Can't be
    checked* (unresolvable).
  - A gap sent as the entry's hash passes the per-block check, and the block reads
    *Checked, gap filled*. If the server declares no filtering, Canary also raises a
    warning, never an accusation, because v1 policies are unsigned. Under a declared
    pruning policy, only a tripwire on a payment the user made catches it, and only
    while one of that payment's outputs is unspent; see
    [Limits of v1](../design/2026-09-06-canary-design.md#limits-of-v1).
- **A check at fetch time**, with coverage states, evidence files and tripwires on
  payments the user expects.

**Where SPCOMMIT is ahead.**

- **Outputs.** v2 commits to output-key prefixes and spent outputs. Canary's entry covers
  only the txid and the tweak. A server can serve the right tweak and drop the output, and
  Canary v1 would not notice. The served data would contradict SPCOMMIT v2's commitment.
- **History.** Its single chain head fixes the order of all history. Canary's separate
  per-block events do not.

**Relay retention is uneven.** On 30 Sep, damus returned none of Segers's notes, primal
returned 2, nos.lol held about 3 days, and only nostr.mom held the whole month. Canary
should store its own events and publish to several relays that are checked to keep them.

## 3. Other work on the same problem

Re-verified 2026-09-30.

- **[tweak-service-auditor](https://github.com/silent-payments/tweak-service-auditor)**
  (Python, silent-payments org, active on 30 Sep). It compares raw tweak lists across
  rbitcoin, BlindBit's gRPC server, Cake's electrs and Bitcoin Core. It runs on the
  operator's side, after the fact, and uses no signatures.
- **Frigate**, the server behind Sparrow 2.5 and later, offers only
  `blockchain.silentpayments.subscribe`. The wallet sends its scan private key and the
  server does the scanning. Frigate serves no tweaks. Bitshala's guide says of this model
  that *"a remote scanner can still withhold a transaction, and now it knows everything as
  well"*.

## 4. The canonical thread analysed the *opposite* attack

[Silent Payments: Light Client Protocol](https://delvingbitcoin.org/t/silent-payments-light-client-protocol/891),
Delving Bitcoin, May–June 2024. Participants: setavenger (protocol author), cygnet3,
josibake, harding.

harding (5 June 2024) laid out three attacks by malicious index servers. **All three are
commission attacks.** Each injects fake tweaks or filters so that the victim fetches a
block and reveals their network identity:

1. A fake payment to the victim's silent-payment address, with filters built only from it.
2. A legitimate tweak reused to build a filter for a transaction not in the block.
3. Dust sent to the target address, tracking who downloads the blocks containing it.

His conclusion on comparing several servers:

> "Downloading tweaks and filters from different servers doesn't help. Even if we can be
> sure the servers aren't colluding, whoever controls the filter distribution server can
> always force a match by lying."

**This is correct for commission and backwards for omission.**

| | Commission | Omission |
|---|---|---|
| Structure | A union attack: one liar is enough | An intersection attack: one honest source defeats it |
| Several servers | Do not help | Are exactly the defence |
| Agreed mitigation | Fetch blocks from random nodes over short-lived Tor connections | Does nothing: the client never learns to fetch the block |

The thread converged on the Tor block-fetching mitigation, and nobody analysed omission
separately. A later post on 24 Sep 2026, by Segers, adds measurements only. The BIP still
calls trustless tweak sourcing an open question, and Bitshala's guide still lists omission
as unsolved.

The thread raised an auditing approach and rejected it, because *"audits only tell you
that the server was honest in the past."* That objection applies to periodic audits by a
third party. It does not apply to per-block commitments that the client checks against
the data it was actually sent, which is what Canary does.

## 5. Why the naive version does not work

Honest indexers legitimately serve **different** tweak lists, so a raw comparison produces
nothing but false alarms.

- **blindbit-oracle** supports cut-through, which drops a transaction's tweak once all its
  taproot outputs are spent. On 6 Sep this was measured at about 38% of tweaks on mainnet.
  It also supports a configurable dust limit.
- **silentiumd** computes tweaks only for transactions with *unspent* taproot outputs, so
  it applies cut-through by default.
- **Live evidence, 30 Sep.** For mainnet block 969,300, silentpayments.dev returned 220
  tweaks from its full index and 184 from its filtered endpoint. Cake Wallet's server
  returned 141. All 141 appear in the list of 220. A raw comparison cannot tell whether
  the missing 79 were filtered or hidden.

Any workable design must therefore define a complete list for each block.

**Superseded on 2026-09-07.** This section first concluded that servers must declare their
policy and that responses must be *normalised before comparing*. That is the wrong shape.
Both policy filtering and dishonest hiding remove entries, so normalising two filtered
responses against each other cannot tell them apart. The design instead compares signed
commitments to the *complete* list and leaves the served lists alone; see
[the committed set and the served set](../design/2026-09-06-canary-design.md#21-the-separation-committed-set-vs-served-set).
The policy declaration survives, but as an excuse published in advance, not as an input to
a comparison.

**Useful consequence:** a server can commit when it indexes a block and prune afterwards.
The commitment survives at 36 bytes per block: a 32-byte root plus a 4-byte entry count.
An aggressively pruning server stays accountable for exactly what it dropped.

## 6. The ecosystem is mostly Go

Re-verified 2026-09-30 unless marked otherwise.

| Project | Language | Status | Role for Canary |
|---|---|---|---|
| [blindbit-oracle](https://github.com/setavenger/blindbit-oracle) | Go | Active, pushed 2026-09-24. v2 is a rewrite that needs Bitcoin Core v30 or later, unpruned, with REST. v2 serves a gRPC `OracleService` and deprecates its HTTP data API except `/info` | A reference server. The v1 branch still serves the BlindBit v1 HTTP API |
| [blindbitd](https://github.com/setavenger/blindbitd) | Go | **Archived on 2025-08-14.** Its README points to newer BlindBit programs | No longer a realistic client |
| [blindbit-scan](https://github.com/setavenger/blindbit-scan) | Go | Headless scanner, not archived. Speaks BlindBit v1 HTTP and supports regtest | The realistic unmodified client for a regtest demo |
| Dana / spdk | Dart and Rust | Dana v0.8.3 (10 Sep 2026) scans through spdk's BlindBit v1 HTTP backend. The released app is mainnet only; regtest needs a source build | A real wallet on the v1 API |
| Frigate | — | Sparrow's server. Takes the scan private key; serves no tweaks | Without a full node, only a tripwire can check it. With one, the user can re-scan the blocks themselves |
| Cake Wallet's electrs | Rust | Live. Serves `blockchain.tweaks.subscribe` with no block hashes, applies cut-through, has no integrity mechanism | Without a full node, only a tripwire can check it. With one, an operator can compare its lists against Core, as tweak-service-auditor does |
| [shroud-indexer](https://github.com/CypherCommons/shroud-indexer) | TypeScript | MIT. Began as Bitshala-Incubator/silent-pay-indexer; now under CypherCommons. Applies no dust limit and no cut-through | The indexer behind the Shroud wallet; publishes no commitments |
| [silentiumd](https://github.com/louisinger/silentiumd) | Go | Stale since 2025-01-04 | A second implementation. Staleness makes divergence *more* likely, which is useful |
| [go-bip352](https://github.com/setavenger/go-bip352) | Go | v0.1.8, verified 2026-09-08 | BIP-352 building blocks. **Renamed**: the old `gobip352` path is v0.1.4 and lacks the eligibility functions; see [the library section of the design](../design/2026-09-06-canary-design.md#64-the-bip-352-library-supplies-the-primitives--and-what-that-costs) |
| [BIP0352-light-client-specification](https://github.com/setavenger/BIP0352-light-client-specification) | — | Work-in-progress spec, checked 2026-09-06 | The light-client protocol Canary extends |

On 6 Sep, blindbit-oracle's `/info` endpoint advertised feature flags (`tweaks_only`,
`tweaks_full_basic`, `tweaks_full_with_dust_filter`,
`tweaks_cut_through_with_dust_filter`) and reported `"network": "signet"`. That endpoint
is a natural place for a policy declaration.

A silent-payments signet faucet exists at <https://silentpayments.dev/faucet/signet/>
(checked 6 Sep). Version 1 is built and tested on regtest only, so the faucet matters
only for later signet work.

## 7. Live infrastructure is decaying

`bitcoin.silentium.dev` is the public mainnet indexer named in the light-client
documentation. **By 6 Sep it no longer served the API.** On 6 Sep the domain redirected
to `access.silentium.dev`, an unrelated parked page:

```
/v1/chain-tip                  len=533 sha=4473e411def3
/v1/block/850000/scalars       len=533 sha=4473e411def3
/totally/fake/path             len=533 sha=4473e411def3
```

On 6 Sep every path, including ones that do not exist, returned the same 533-byte body
with HTTP 200. A client pointed at this host then got no error. It got a success response
and no payments. On 30 Sep the domain returned an HTTP 301 redirect. That check did not
follow the redirect, so what the target serves now is unknown.

**Design consequence:** do not build the demo on third-party public servers being alive.
Run every indexer locally, against a local regtest node.

## 8. Divergence hunting: construct, don't scan

Scanning mainnet for an ambiguous transaction would need an unpruned node and days of
initial sync. Instead, Canary constructs regtest transactions that deliberately hit each
ambiguous BIP-352 eligibility rule, and checks whether implementations agree. Regtest,
not signet, because several of these cases need arbitrary scripts and control over what
goes into a block, and nobody outside the signet operators can mine on public signet.

The richest known case: **script-path spends that use the NUMS point H as the internal
key** are excluded from the input set. A receiver detects this by checking whether the
taproot internal key in the control block equals H. This rule was contested during the
BIP's design: *"any exclusion of allowable inputs seems like a footgun"*. Handling it
correctly needs control-block parsing, which independent implementations can get wrong in
different ways.

Any disagreement found is a real interoperability bug worth reporting upstream. It also
turns the demo from "here is a mechanism" into "here is what it found".

---

## Sources

- BIP-352: <https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki>
- Bitshala BIP-352 guide, 3 Aug 2026: <https://x.com/bitshala_org/status/2084131259375296785>
- cake_wallet#2395: <https://github.com/cake-tech/cake_wallet/issues/2395>
- Index-server specification: <https://github.com/silent-payments/BIP0352-index-server-specification>
- SPCOMMIT and the light-client protocol draft: <https://github.com/bitsagarob/silentpayments-measurements>
- Segers on bitcoin-dev, 2 Sep 2026, "Silent payments light clients: measurements and index commitments": <https://gnusha.org/pi/bitcoindev/6871d475-fbd4-4455-954d-20a369fba471n@googlegroups.com>
- Bitcoin Optech #421: <https://bitcoinops.org/en/newsletters/2026/09/04/>
- Bitcoin Optech #422: <https://bitcoinops.org/en/newsletters/2026/09/11/>
- tweak-service-auditor: <https://github.com/silent-payments/tweak-service-auditor>
- Delving Bitcoin thread 891: <https://delvingbitcoin.org/t/silent-payments-light-client-protocol/891>
- Bitcoin Core PR #28241: <https://github.com/bitcoin/bitcoin/pull/28241>
- RFC 6962 (Certificate Transparency): <https://www.rfc-editor.org/rfc/rfc6962>
- blindbitd (archived): <https://github.com/setavenger/blindbitd>
- shroud-indexer: <https://github.com/CypherCommons/shroud-indexer>
- silentpayments.xyz, the BlindBit suite and silentiumd: see the table in section 6
