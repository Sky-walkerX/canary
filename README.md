# Canary

**A silent-payments light wallet cannot tell "nobody paid you" from "the server left
your payment out."** Canary is designed to check the tweak list a server sends against a
list that the same server signed and published for that block. When what the server sent
contradicts what it signed, Canary names the server and the block. Version 1 is due on
5 Oct 2026 and is still being built; the [status table](#status-30-september-2026) says
which parts work today.

Canary does not make tweak sourcing trustless. It makes it *accountable*, under the two
conditions in the [security claim](#security-claim).

New to silent payments? [How Canary works](docs/how-canary-works.md) walks through the
checks with a worked example. The [FAQ](docs/faq.md) answers the usual objections, and the
[glossary](docs/glossary.md) defines every term.

---

## Status (30 September 2026)

Canary is being built for [BOSS Battle](https://bitshala.org) (Bitshala), 7 Sep – 5 Oct
2026, Cypherpunk track. Version 1 is due on 5 Oct 2026 at 23:59 IST. One developer builds
it, working with Claude, Anthropic's AI assistant. Work continues after 5 Oct; the
[feature roadmap](docs/roadmap/2026-09-30-feature-roadmap.md) lists what comes next.

| Part | State | What it does |
|---|---|---|
| `canonical` | Built and tested | Computes a block's complete tweak list from the block and the outputs it spends |
| `commit` | Built and tested | Hashes that list into a Merkle root bound to the network, the block hash and the entry count, with inclusion proofs |
| `feed` | Built and tested | Turns a commitment into a signed Nostr event and back, and fetches events from relays by block hash |
| `policy` | Built and tested | Holds a server's declared filtering rules, and reads them from blindbit-oracle's `/info` |
| `internal/testvector` | Built and tested | Defines the test-vector file format; one vector, an empty block, exists so far |
| `wire` | Partly built | The tweak-list format a server sends is built and tested. Signed receipts are being built for v1 |
| Reference indexer | Being built for v1 | A small server that publishes commitments and can be told to withhold one transaction |
| `canary check`, `verify`, `status`, `ui` | Being built for v1 | The command-line checker and its local results page |
| Evidence files | Being built for v1 | A file that anyone can check offline |
| Tripwire | Being built for v1 | Checks whether a server reports a payment you know exists |
| Dashboard and public site | Being built for v1 | Shows results; the site hosts a checker for evidence files |

On the evening of 30 Sep, `go test ./...` passed in all 7 packages on Go 1.26.4: 80
top-level tests, none failing. GitHub Actions runs `go vet` and `go test` on every push,
and every run so far has passed. The last CI run was on 9 Sep. The `policy`, `feed`,
`internal/testvector` and `wire` code has not been pushed yet, so it has been tested
locally only.

Version 1 is built and tested on regtest only, a private local test network. `canary
check` will accept other networks, but prints a notice that v1 was not tested on them.
Nothing has been run against signet or mainnet servers.

## The problem

To receive silent payments (BIP-352) without downloading every block, a light wallet asks
a server for a [tweak](docs/glossary.md#tweak). A tweak is a 33-byte value per eligible
transaction, which the wallet combines with its own scan key. If the server leaves a
transaction out, the wallet never sees that payment. There is no error and no retry. The
wallet shows the same balance it would show if nobody had paid.

An indexer cannot tell which transactions pay a given silent-payment address, because
that needs the recipient's private scan key. So hiding one specific payment needs outside
knowledge of it. The party that always has that knowledge is the sender:

> **The exchange that pays you is also the indexer that tells you whether you were paid.**

Light wallets usually ship with a default server, often run by the wallet's vendor. When
the sender also runs that server, it holds a record showing it paid, and the recipient
sees nothing.

The gap is recognised, and it is still open:

- **BIP-352 leaves tweak sourcing open.** A footnote says: *"It is still an open question
  as to how Bob can source the 33 bytes per transaction in a trustless manner."* Its
  light-client appendix is *"out of scope for the current BIP"*. The BIP does not discuss
  a server withholding data.
- **Bitshala's BIP-352 guide** ([3 Aug 2026](https://x.com/bitshala_org/status/2084131259375296785))
  calls trustless tweak sourcing *"the big one"*. It says: *"A light client that accepts
  tweak data from a server has no way to detect omission."*
- **SomberNight**, the Electrum maintainer, described the attack in
  [cake_wallet#2395](https://github.com/cake-tech/cake_wallet/issues/2395) (July 2025).
  He wrote: *"I presently do not see a way how to fix this while using cut-through."*
- **The silent-payments
  [index-server specification](https://github.com/silent-payments/BIP0352-index-server-specification)**
  asks: *"How does a wallet know all tweaks were received for a given block request?"*

Sparrow 2.5.0 (May 2026) took a different route with its Frigate server. The wallet hands
its scan private key to the server, which does the scanning. That made scanning fast. The
wallet still depends on the server to report every payment, and the server now learns
them all, as Bitshala's guide points out.

## Prior art: SPCOMMIT, and what Canary adds

Canary is not the first to publish tweak-list commitments. Rob Segers's
[SPCOMMIT](https://github.com/bitsagarob/silentpayments-measurements), run by
silentpayments.net, has published them for mainnet since 1 Sep 2026. He posted the
specification to the
[bitcoin-dev mailing list](https://gnusha.org/pi/bitcoindev/6871d475-fbd4-4455-954d-20a369fba471n@googlegroups.com)
on 2 Sep. [Optech #422](https://bitcoinops.org/en/newsletters/2026/09/11/)
(11 Sep) described the scheme without using the name.

SPCOMMIT hashes each block's unfiltered tweak list and chains the hashes block to block.
It signs only the chain head, which the operator posts to Nostr every 6 hours as a kind-1
note. As of 30 Sep we found no wallet that checks it.

Canary adds three things. None of them is finished yet; the [status table](#status-30-september-2026)
says what exists.

- **A check at the client, one block at a time.** Each block gets its own signed Nostr
  event, found by block hash. A client can check one block without recomputing a chain.
  The event format is built (`commit`, `feed`); the client check is being built.
- **Filtered responses leave explicit, signed gaps.** A server may leave entries out
  under a policy it declared in advance. Each entry it leaves out is a marked gap in a
  list whose length and Merkle root the server signed. So the client knows exactly which
  entries it did not receive, and tries to fill them from other sources. SPCOMMIT's own
  notes say a client given a filtered response *"cannot check the subset for
  completeness"*. Canary does not fully solve that either. Three conditions apply:
  - A gap sent as nothing while the block is less than 144 blocks deep names the server.
  - A gap sent as nothing further back, which no other source fills, ends as *Can't be
    checked*.
  - A gap sent as the entry's hash passes the per-block check, and the block reads
    *Checked, gap filled*. If the server declares no filtering, Canary also raises a
    warning, never an accusation, because v1 policies are unsigned. Under a declared
    pruning policy, only a tripwire on a payment you made catches it, and only while one
    of that payment's outputs is unspent; see
    [what Canary does not do](#what-canary-does-not-do).
- **Coverage states, evidence files and tripwires**, described below.

SPCOMMIT is ahead in two ways. Its v2 format also commits to each transaction's output-key
prefixes and to the block's spent outputs, which Canary does not; see
[what Canary does not do](#what-canary-does-not-do). Its hash chain also fixes the order of
all history, which Canary's separate per-block events do not.

## How Canary works

This section describes the design in
[`docs/design/2026-09-06-canary-design.md`](docs/design/2026-09-06-canary-design.md). The
status table above says which parts exist. [How Canary works](docs/how-canary-works.md)
follows one block through every check. Version 1 is a command-line checker plus a
reference indexer. The design's proxy, which sits between a wallet and its servers, comes
after v1.

**The key idea: servers may leave entries out, but never add them.** Honest servers
filter differently. Some delete entries whose outputs are all spent ("cut-through"), and
some skip small payments. Comparing their answers directly therefore produces only false
alarms. On 30 Sep, two live servers returned three different lists for mainnet block
969,300. silentpayments.dev returned 220 tweaks from its full index and 184 from its
filtered endpoint, and Cake Wallet's server returned 141. All 141 appear in the list of
220, and a raw comparison cannot tell whether the missing 79 were filtered or hidden.

So each server signs a [commitment](docs/glossary.md#commitment) to the *complete,
unfiltered* list for every block, and serves whatever subset its policy allows. Two rules
follow:

- An entry a server sent that is not in its own signed list was made up.
- An entry in the signed list that the server did not send needs a reason declared in
  advance, and Canary tries to fill it from elsewhere.

The checks, cheapest first:

1. **Compare signed commitments across servers.** Each server publishes a signed Nostr
   event of about 200 bytes per block. It carries a 32-byte Merkle root over the block's
   complete list. If two servers sign different roots for the same block hash, at least
   one of them is lying. Canary cannot yet tell which, so it marks the block
   *disputed* and takes no automatic action.
2. **Check what you were sent, filling gaps first.** Canary rebuilds the root from what a
   server sent and compares it with the root that server signed. For an entry its policy
   pruned, a server may send the entry's 32-byte hash, or nothing at all.
   - A hash is enough to rebuild the root, so the block can pass without the full entry.
     This is the [hash-only limit](#what-canary-does-not-do).
   - For an entry sent as nothing, Canary tries to fill it from another source *before*
     it rebuilds the root. A block whose root was never rebuilt is never marked checked.
   - Servers must keep at least the hash of every entry for 144 blocks, about one day at
     10 minutes per block. If a server sends nothing for an entry while the block is less
     than 144 blocks deep, Canary names the server and marks the block *compromised*.
   - If an entry sent as nothing, outside the 144-block window, cannot be filled, the
     block is *unresolvable*. That is not a pass, and it is not an accusation.
   - If the rebuilt root differs from the signed one, the server sent data that
     contradicts its own signature. Canary names the server and marks the block
     *compromised*.
3. **Work out who lied.** Deciding which of two disagreeing servers lied means recomputing
   the complete list from the block and the outputs it spends. That needs a full node or
   another block source. A client without one keeps the signed evidence for someone who
   has one.
4. **The tripwire.** This check still works when every queried server colludes. You
   assert that a payment exists, because you sent it or because the sender gave you its
   transaction ID. Canary then checks whether each server reports it.
   - For a payment you sent yourself, Canary can compute the entry, because you hold the
     outputs your own transaction spent. It still needs one block hash it trusts from
     outside the servers. In v1 your own Bitcoin Core node supplies it.
   - If the server's signed record leaves that entry out, Canary names the server,
     whether or not the payment's outputs are spent.
   - If the server's list carries only the entry's hash, pruning could explain the gap.
     Canary then names the server only when your node shows one of the payment's taproot
     outputs unspent.
   - In both cases you know, but cannot yet prove it to others. v1's evidence file cannot
     show that a record lacks an entry, or that an output is unspent.
   - A transaction ID someone else gave you supports detection only, not naming a server.
   - A passed tripwire shows only that the server reported that one tweak.
   - In v1 the tripwire is one payment you declare to `canary check`, and it checks the
     tweak only, not the output data. Scheduled test payments at random times and
     amounts come after v1.

**The main output is coverage, not alarms.** An alarm that never fires looks like a
product that does nothing. Coverage is reported per block range, in one of six states:

| Design name | On-screen label | Meaning |
|---|---|---|
| Verified | Checked | The root rebuilt over every position matched the root the server signed, and no position needed filling. This covers the tweak list, not payments |
| Resolved | Checked, gap filled | As Checked, but some positions came as hashes or were filled before the root was rebuilt. For example, another server supplied an entry, or Canary computed it from a payment you declared. An entry sent only as a hash can still hide a payment; see the [hash-only limit](#what-canary-does-not-do) |
| Unresolvable | Can't be checked | Canary could not rebuild the root. For example, an entry sent as nothing outside the 144-block window that no source could fill, or a signed record with no readable list. Not a pass, and not an accusation |
| Unverified | Not checked | There was no signed record to check against. For example, the server publishes none, has not indexed the block yet, or did not answer. A server that signed the blocks on both sides of this one, but not this one, also gets a warning, never an accusation |
| Disputed | Servers disagree | Two named servers signed different roots for the same block hash; which one lied is unknown |
| Compromised | Data withheld | One named server left out an entry it had signed for, or left out the entry for a payment you declared. For example, it sent nothing for an entry inside the 144-block window, or its list contradicts its own signed root |

Coverage also gives the most useful single sentence about a light wallet's balance:

> **A balance computed over blocks you could not verify is a lower bound, not a balance.**

Servers publish commitments as signed Nostr events. Nostr is a public bulletin board, and
servers need to run no extra infrastructure to use it. Nostr gives *publication*, not
timestamping. An event's `created_at` field is self-asserted and can be backdated. So
Canary ties each event to a block by the block's hash, and takes order from the chain,
never from `created_at`.

## What Canary does *not* do

- **It does not make tweak sourcing trustless.** It makes it *accountable*. If every
  indexer you query colludes and you have planted no tripwire, you learn nothing.
- **It does not check output data.** Canary commits to each transaction's ID and tweak.
  Wallets decide whether a payment exists from output data the server also sends: the
  BlindBit v1 output filter and `/utxos` list, or v2's `outputs_short`. A server can send
  the right tweak and drop the output, and v1 would still report the block as Checked.
  "Checked" means the tweak list was checked, never that payments were checked. Committing
  to outputs is planned after v1.
- **It does not catch a hash-only entry under a pruning policy.** A server whose declared
  policy prunes spent entries may send just an entry's hash. The root still matches, so
  the block reads *Checked, gap filled*. If no other server sends the full entry, v1
  cannot tell this from honest pruning. Only a tripwire on a payment you made can, and
  only while your node shows one of that payment's outputs unspent. A server that
  declares no filtering and still sends a hash gets a warning, not an accusation,
  because v1 policies are unsigned.
- **It does not defend against commission**, meaning fake entries injected so that a
  client fetches a block and reveals its IP address. That is a different attack.
  Fetching blocks over short-lived Tor connections is the accepted answer there. Canary
  looks only for tweak-list entries that were hidden. The root check does reject a served
  entry that is missing from the server's own signed list, but that is a side effect,
  not a defence against this attack.
- **Version 1 is built and tested on regtest only**, against its own reference indexer.
  That indexer uses the same `canonical` package as the checker, so v1 does not test two
  independent implementations against each other.
- **It does not make scanning faster.** Frigate made scanning faster. Canary is about
  whether the data is complete, which is a separate question.
- **It is not a wallet**, not a new Bitcoin Core filter type, and not a succinct proof of
  correct indexing. That last one is the long-term answer and is listed as future work.

## Security claim

> Given at least one honest indexer publishing commitments, and an uncensored path to
> at least one relay carrying them, Canary converts omission from a silent, permanent
> failure into a detected event naming a server and a block.

Three qualifiers travel with the claim:

- **Omission here means a missing tweak-list entry.** Hidden output data is outside the
  claim; see [what Canary does not do](#what-canary-does-not-do).
- **Detection is not proof.** When two servers sign different roots for the same block
  hash, anyone can check both signatures, so the disagreement is provable. It does not
  show which server lied. A single server's omission is provable to others only when that
  server signs receipts over its responses. In v1 it also needs the server's signed
  record to include the entry that was left out. Against today's unmodified indexers,
  the victim knows but cannot prove it.
- **Timing depends on the attack.** Disagreement between servers shows up in the
  commitment feed, roughly one block interval after the block. Hiding one payment from
  one client shows up only when that client checks that block. In v1 there is no
  background service, so every check happens when you run `canary check`.

What each assumption buys:

| Assumption | What Canary can detect |
|---|---|
| One indexer, publishing commitments | That indexer sending you less than it signed for. Two exceptions: the hash-only case above, and an entry sent as nothing outside the 144-block window that no other source fills, which ends as *Can't be checked* |
| Several indexers, at least one honest | Also an indexer that signed for a list with the entry removed, because its root disagrees |
| All indexers colluding | Only what a tripwire finds, and only for payments you already know exist |

This is [Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)'s split-view
problem: a server showing different people different data. Certificate Transparency
answers it with gossip between clients. Canary answers it with public Nostr relays. The
full comparison with earlier work, including
[Delving Bitcoin thread 891](https://delvingbitcoin.org/t/silent-payments-light-client-protocol/891),
is in [`docs/research/prior-art.md`](docs/research/prior-art.md).

## Build and test

Canary needs Go 1.24.1 or later. The tests need no Bitcoin Core node, network access or
relay.

```
make help    # list the targets
make test    # go test ./...
make vet     # go vet ./...
```

## Repository layout

```
canonical/               the complete tweak list for one block
commit/                  Merkle root, commitment and inclusion proofs
feed/                    commitments as signed Nostr events, and a relay client
policy/                  a server's declared filtering rules
wire/                    the tweak-list format a server sends
internal/testvector/     the test-vector file format and its runner
testdata/                BIP-352 upstream vectors and Canary's own vectors
docs/*.md                how it works, the FAQ, the glossary and the decision log
docs/design/             the design document and the frozen v1 formats
docs/research/           prior art with citations, and the competitor analysis
docs/roadmap/            the scored feature roadmap, with the v1 cut line
docs/superpowers/plans/  the 8 September implementation plans
```

## License

The project will be released under the MIT license before submission on 5 Oct 2026. The
`LICENSE` file is not in the repository yet.
