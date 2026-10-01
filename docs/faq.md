# Questions and answers

The questions a reviewer who knows Bitcoin tends to ask, answered plainly. Terms link to
the [glossary](glossary.md). [How Canary works](how-canary-works.md) walks through the
checks with a worked example.

**Where it comes from:**
[Certificate Transparency?](#isnt-this-certificate-transparency) ·
[SPCOMMIT?](#how-is-this-different-from-spcommit) ·
[What BIP-352 says](#does-bip-352-say-a-server-can-withhold-data) ·
[Privacy or reliability?](#is-this-privacy-or-reliability)

**How it holds up:**
[Diffing two servers](#why-not-diff-two-servers) ·
[Committing honestly](#why-would-a-withholding-server-commit-honestly) ·
[Publishing at all](#why-would-a-server-publish-signed-records-at-all) ·
[Collusion](#what-if-every-server-colludes) ·
[Full node](#does-this-need-a-full-node) ·
[Servers disagree](#which-server-lied-when-servers-disagree) ·
[Dropping a server](#why-not-drop-a-server-automatically-when-it-trips-an-alarm)

**What it proves:**
[Proof](#is-a-detected-omission-proof) ·
[Checked](#what-does-checked-mean) ·
[Can't be checked](#what-does-cant-be-checked-mean) ·
[Amounts](#can-canary-tell-me-how-much-i-was-not-paid) ·
[Relay times](#does-a-copy-on-a-relay-prove-when-a-record-was-published)

**Scope and limits:**
[Output data](#what-about-the-output-data-wallets-actually-match-against) ·
[Fake entries](#does-canary-stop-fake-entries) ·
[Scan key](#does-canary-need-my-scan-key) ·
[Independent indexer?](#is-the-v1-reference-indexer-an-independent-implementation) ·
[Regtest](#why-regtest) ·
[Speed](#does-canary-make-scanning-faster) ·
[After v1](#what-comes-after-v1)

---

## Where it comes from

### Isn't this Certificate Transparency?

It applies Certificate Transparency's central idea, and cites
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) for it. The split-view problem is a
server showing different people different data. The answer is to make the server sign
one public statement that anyone can compare with what they were shown.

The difference is the data. A certificate log entry is whatever the log says it is. A
tweak list comes from a block by rules that honest servers apply differently, such as
[cut-through](glossary.md#cut-through), dust limits and start heights. Canary commits each
server to one unfiltered list per block and lets it serve less, with every gap marked.
Certificate Transparency has nothing like honest filtering, so it never needed that part.
The design covers this in
[The equivocation insight](design/2026-09-06-canary-design.md#13-the-equivocation-insight).

### How is this different from SPCOMMIT?

[SPCOMMIT](glossary.md#spcommit) came first, and Canary does not claim otherwise. Rob
Segers has published tweak-list commitments for mainnet with it since 1 Sep 2026. It
hashes each block's unfiltered list into a chain and signs only the chain head, every 6
hours. Its author writes that a client given a filtered response "cannot check the subset
for completeness". We found no wallet that checks SPCOMMIT's commitments, as of 30 Sep
2026.

Each server signs one record per block under Canary's format. A client fetches that
record by block hash and checks it each time it fetches that block. A filtered list keeps its signed length, and every entry left
out is an explicit gap. A gap sent as nothing inside the
[retention window](glossary.md#retention-window) names the server. Canary also reports
coverage states, writes evidence files and supports tripwires.

SPCOMMIT is ahead in two ways. Its v2 format commits to output prefixes and spent outputs,
which Canary v1 does not. Its chain also fixes the order of all history, which separate
per-block records do not.

### Does BIP-352 say a server can withhold data?

No, and no revision of it ever has. A footnote says "It is still an open question as to
how Bob can source the 33 bytes per transaction in a trustless manner." Its appendix on
light clients is "out of scope for the current BIP".

The withholding wording comes from elsewhere. Bitshala's BIP-352 guide of 3 Aug 2026
says "A light client that accepts tweak data from a server has no way to detect
omission." SomberNight, the Electrum maintainer, described the attack in
[cake_wallet#2395](https://github.com/cake-tech/cake_wallet/issues/2395) in July 2025.
The index-server specification asks "How does a wallet know all tweaks were received for
a given block request?" [Prior art](research/prior-art.md) gives the sources and dates.

### Is this privacy or reliability?

Privacy. The failure looks like a reliability bug, a payment that never shows up. The way
out today costs privacy.

A light wallet has two choices now. It can keep its [scan key](glossary.md#scan-key) and
trust the server to send every tweak. Or it can hand the scan key to a remote scanner,
such as Sparrow's Frigate server, which scans for it. Bitshala's BIP-352 guide names the
cost of each. For the first, it says "'privacy-preserving' light client scanning means the
server cannot see your outputs, not that it cannot withhold them." For the second, it
says "a remote scanner can still withhold a transaction, and now it knows everything as
well."

A light wallet that can check its server lets the private model, a server that never sees
your scan key, be the default. Without a check, a wallet that wants reliable payments has
a reason to hand the key over.

## How it holds up

### Why not diff two servers?

Honest servers serve different lists, and BIP-352 allows it: "spent transactions
optionally can be skipped". A raw diff reports every such difference as an alarm. On
30 Sep 2026, mainnet block 969,300 came back as 220 tweaks from one server's full index,
184 from its filtered endpoint and 141 from Cake Wallet's server. All 141 were among the
220, and a diff cannot tell whether the missing 79 were filtered or hidden.

Canary compares signed records of the complete list instead, and lets each server serve
less of it ([Canonical tweak sets](design/2026-09-06-canary-design.md#2-canonical-tweak-sets-and-policy-normalization)).

### Why would a withholding server commit honestly?

Once its records are on relays, it cannot take one back, because records use a regular
Nostr kind, which a later event cannot replace. v1 does not publish records to relays.
There, the state file and the evidence files keep the copy Canary fetched from the server.
Each choice left to the server meets a different check:

- **It signs the full list, then sends nothing for your entry inside the retention
  window.** Its own receipt shows the gap. One server is enough, and the evidence file
  lets anyone check it.
- **It signs the full list, then sends a wrong entry.** The recomputed root does not match
  its signature.
- **It signs a list without your entry.** Any honest server's root differs, and the block
  reads Servers disagree until someone holding the block works out which server lied. If
  you declared that payment as a [tripwire](glossary.md#tripwire), its own record names it
  as Data withheld. You know, but v1 cannot prove it to others.
- **It signs no record for that block.** The block reads Not checked. If the server signed
  the blocks on both sides, Canary adds a warning. v1 does not accuse on it, because a
  missing record carries no signature.

Two variants pass the per-block check. The server can send your entry's hash under a
declared pruning policy, or it can send the right entry and hide the payment's
[output data](glossary.md#output-data) instead.
[Limits of v1](design/2026-09-06-canary-design.md#limits-of-v1) states both.

### Why would a server publish signed records at all?

Canary cannot make it. A server that signs nothing gets Not checked on every block. In the
full design, the tripwire is the only check that still works against such a server. v1
speaks only its own reference indexer's API, so no deployed server works with it yet.

The cost to a server is small. It pays one signature and about 200 bytes per block. It
keeps 36 bytes per block afterwards, a 32-byte root and a 4-byte count. For all of
mainnet history that is about 35 MB, from roughly 965,000 blocks × 36 bytes. It may prune
entries freely once a block is 144 blocks deep. In return, an honest server can show that
it served everything it signed for.

### What if every server colludes?

Then comparing servers shows nothing. The [tripwire](glossary.md#tripwire) still works,
because your knowledge of the payment comes from outside the servers. It covers only
payments you know exist, such as one you made yourself.

### Does this need a full node?

v1 does. `canary check` reads block hashes, the chain tip and declared payments from your
own Bitcoin Core node, and it will not run without one.

The design's position is narrower: detection needs no node, and attribution does. A
server that contradicts its own signatures is named without a node. A gap inside the
retention window needs no outside chain fact either, because the server signed both its
tip and the block's height. A chain fact is needed only to reject a gap that the signed
values place outside the window.

Working out which of two disagreeing servers lied needs the block and the outputs it
spends, from a full node or a third-party service. That can wait, because signed records
do not expire
([Detection needs no node](design/2026-09-06-canary-design.md#42-detection-needs-no-node-attribution-does-and-may-be-deferred)).

### Which server lied when servers disagree?

Canary does not know, and says so. Two signed roots for the same block hash show that at
least one server lied. Anyone can check both signatures. Deciding which one lied means
recomputing the complete list from the block and the outputs it spends. That is why
Servers disagree is a separate state from Data withheld, which names one server.

### Why not drop a server automatically when it trips an alarm?

Because a third party could use that to knock out honest servers. If an attacker can
cause two servers to disagree, automatic exclusion leaves you with the attacker's server.
Only a server that contradicts its own signatures names itself.
[Acting on alarms](design/2026-09-06-canary-design.md#45-acting-on-alarms) gives the rule.

## What it proves

### Is a detected omission proof?

Only with a [receipt](glossary.md#receipt). The evidence file then holds the server's
signed record, the bytes it served and its signature over those bytes. Anyone can run
`canary verify` on it offline and see the contradiction.

Without a receipt, you know, and others can check only that the server signed for the
entry. `canary verify` then prints "Inclusion only: you can be sure of this, you can't yet
prove it to others." Some findings have no evidence file in v1 at all, such as a false
chain claim or a missing declared payment. Each finding records which kind it is.

Canary separates knowing from proving to others. You know whatever your own
`canary check` saw. Someone else can confirm a finding only from signed data they can
check themselves.

| Finding | You know | Others can check |
|---|---|---|
| Data withheld: an entry sent as nothing inside the window, with a receipt | Yes | Yes. `canary verify` checks the evidence file offline |
| The same, without a receipt | Yes | Inclusion only. The file shows that the server signed for the entry, not what it served |
| Servers disagree | Two named servers signed different roots | Both signatures are checkable, but they do not show which server lied. v1 writes no evidence file for it |
| Data withheld from a false chain claim, a missing declared payment, or a list of the wrong length | Yes | No. v1 has no evidence format for these |
| A warning | That a server behaved oddly | Nothing. A warning is not an accusation |

### What does "Checked" mean?

The block's tweak list matched a root the server signed. It does not mean the block's
payments were checked, because v1 does not check the
[output data](glossary.md#output-data) a wallet matches against. With one server, it also
does not show that the server's record itself was complete. A second server or a declared
payment tests that.

### What does "Can't be checked" mean?

Canary could not recompute the root. The usual cause is an entry sent as nothing outside
the retention window, which no other source could fill. It is neither a pass nor an
accusation. A balance computed over such blocks is a lower bound, not a balance.

### Can Canary tell me how much I was not paid?

No. Entries carry no amounts, Canary never holds your scan key, and v1 has no link to a
wallet. A finding names the transaction that was left out, not what it paid you.

### Does a copy on a relay prove when a record was published?

No. Nostr gives publication, not timestamping. An event's `created_at` time is whatever
the signer wrote, and it can be backdated. Canary ties each record to a block by the
block's hash and takes order from the chain.

## Scope and limits

### What about the output data wallets actually match against?

v1 does not check it, and this is the largest limit. Canary's entry is a txid and a
tweak. Once a wallet has a tweak, it decides whether a payment exists from output data
the server also sends. On BlindBit v1 that is the new-UTXO filter and the `/utxos` list
with its spent flag. On BlindBit v2 it is `outputs_short`, each transaction's 8-byte
output-key prefixes.

A sender who also runs the server knows the output it created. It can send the correct
tweak and drop the output, and Canary v1 still reads the block as Checked. Adding each
transaction's taproot output keys to its entry is planned for v2. That covers the filter
and `outputs_short`. A false spent flag stays out of reach, because whether an output is
spent depends on later blocks.

### Does Canary stop fake entries?

No. Canary looks for hiding only. A server that adds fake entries, for example to make a
wallet fetch a block and reveal its IP address, is running a different attack. Fetching
blocks over short-lived Tor connections is the accepted answer to it
([Attacks explicitly out of scope](design/2026-09-06-canary-design.md#15-attacks-explicitly-out-of-scope)).

### Does Canary need my scan key?

No. Canary checks entries per transaction and never learns which ones pay you. It does
not hide which blocks you ask about, though. The height range you check shows where your
wallet starts. The design pulls every record a server publishes from relays, which would
hide which records you check, and v1 does not do that yet. Fetching tweak lists still
shows a server which blocks you scan, even then.

### Is the v1 reference indexer an independent implementation?

No. It reuses Canary's own `canonical` package to compute each block's entries. When the
indexer and the checker agree, that tests the protocol, not two independent
implementations. A later indexer that computes entries on its own path would restore that
test.

### Why regtest?

Time and reproducibility. One person plus Claude builds the core in the final week before
5 Oct 2026. A signet run needs a synced node and waits on public block times that nobody
controls. Regtest mines a block on command and needs no faucet, and anyone with Bitcoin
Core can repeat the run on one machine. Several test cases also need arbitrary scripts and
control over what goes into a block, which nobody outside the signet operators has.

The cost is real. v1 cannot claim a run on a public network, and no deployed server speaks
its API yet. `canary check` accepts other networks and prints a notice that v1 was not
tested on them.

### Does Canary make scanning faster?

No. Frigate made scanning faster by taking the wallet's scan key. Canary asks a separate
question: whether the data a server sent is complete.

### What comes after v1?

The first work after judging closes the limits v1 names: output keys in the entry, and a
spend check for entries sent only as hashes. Then an in-path proxy for BlindBit v1
wallets, adapters for live servers, and publishing records to relays. The
[feature roadmap](roadmap/2026-09-30-feature-roadmap.md#6-v2-after-judging) has the order
and dates.
