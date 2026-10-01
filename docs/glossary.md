# Glossary

The terms used across Canary's docs, screens and code, in alphabetical order. Each entry
gives the plain meaning first. Where a screen shows the idea under its own label, the
entry names that label. Where the [design document](design/2026-09-06-canary-design.md)
uses a different name, the entry gives that too.

Exact byte layouts and JSON fields live in [v1 formats](design/2026-09-30-v1-formats.md).
For the whole system on one page, read [How Canary works](how-canary-works.md).

[Accountable](#accountable) · [Byte order](#byte-order) · [Canonical set](#canonical-set) ·
[Commitment](#commitment) · [Coverage](#coverage) · [Cut-through](#cut-through) ·
[Dust filter](#dust-filter) · [Entry](#entry) · [Event](#event) ·
[Evidence file](#evidence-file) · [Expected payment](#expected-payment) ·
[Finding](#finding) · [Gap](#gap) · [Inclusion proof](#inclusion-proof) ·
[Index server](#index-server) · [Light wallet](#light-wallet) ·
[Merkle root](#merkle-root) · [Nostr](#nostr) · [Omission](#omission) ·
[Output data](#output-data) · [Policy](#policy) · [Receipt](#receipt) ·
[Reference indexer](#reference-indexer) ·
[Regtest, signet and mainnet](#regtest-signet-and-mainnet) · [Relay](#relay) ·
[Retention window](#retention-window) · [Scan key](#scan-key) ·
[Signed record](#signed-record) · [Silent payments](#silent-payments) ·
[SPCOMMIT](#spcommit) · [States](#states) · [Tripwire](#tripwire) · [Tweak](#tweak) ·
[Tweak list](#tweak-list)

---

### Accountable

Canary's claim about index servers. A server that leaves out data it signed for gets
named, so hiding a payment stops being silent. This is weaker than trustless, because
you still rely on two conditions. At least one honest server publishes signed records,
and you have an uncensored path to a [relay](#relay) that carries them.

### Byte order

Txids and block hashes have two byte orders. Internal order is how the bytes sit inside
a serialized transaction or block header, and every hash Canary computes uses it. Display
order reverses the bytes, the way block explorers and `bitcoin-cli` print them. JSON, URLs
and Nostr tags use display order. Each Canary program converts in one place, because
mixing the two orders gives a different root for the same data.

Example: the internal-order txid `75d59e36…66ae` displays as `ae667139…d575`.

### Canonical set

The complete list of [entries](#entry) for one block, in transaction order, with nothing
filtered out. It includes every transaction BIP-352 makes eligible, and ignores the
optional rule that lets a server skip spent ones. It depends only on the block and the
outputs its transactions spend, so anyone with a full node can recompute it.

In the design: canonical set, written `T_base(block)` in older text. The roadmap calls it
the "full list".

### Commitment

The design document's name for a [signed record](#signed-record).

### Coverage

Canary's main output: a [state](#states) for every block checked, reported as ranges of
heights. An alarm that never fires looks like a tool that does nothing, so Canary reports
what it checked on every run. Coverage also supports the one sentence worth remembering
about a light wallet's balance. A balance computed over blocks you could not check is a
lower bound, not a balance.

On screen: the coverage strip and the range table on the dashboard's Blocks page.

### Cut-through

Honest filtering that drops a transaction's entry once all of its taproot outputs are
spent. BIP-352 allows it: "spent transactions optionally can be skipped". blindbit-oracle
offers it as an option, and silentiumd does it by default. Cut-through is one reason two
honest servers serve different lists for the same block.

In a server's [policy](#policy): `prunes_spent`. The design folds cut-through and
unspent-only indexing into that one flag, because a client sees the same result.

### Dust filter

Honest filtering that drops transactions whose taproot outputs all fall below a
threshold in satoshis. A server declares it as `dust_threshold_sat` in its
[policy](#policy), where 0 means none. Canary cannot verify the threshold, because an
entry carries no amounts, and no state depends on it. `canary check` always asks for the
unfiltered list.

### Entry

One transaction's pair of txid and [tweak](#tweak): 32 + 33 = 65 bytes. Canary hashes
each entry with the tag `canary/leaf/v1` to build the [Merkle root](#merkle-root). An
entry carries no amount and no output keys, which is why Canary v1 does not check
[output data](#output-data).

In the design: leaf.

### Event

A signed [Nostr](#nostr) message. Canary's [signed records](#signed-record) are events of
kind 1352. That is a regular kind, which relays keep as it was published. Canary never
uses a replaceable kind, since a server could then overwrite an old record in place. The
`b` tag holds the block hash in display order, and relays index it so a client can fetch
records by block hash. The event's `created_at` time is set by the signer and can be
backdated.

### Evidence file

A JSON file that lets anyone check a Data withheld [finding](#finding) offline, with
`canary verify` and no network. It holds the server's signed record, the
[receipt](#receipt), the exact bytes served, the left-out entry and an
[inclusion proof](#inclusion-proof). It stores no result. `canary verify` recomputes
everything from the signed data. Without a receipt, the file shows only that the server
signed for the entry, not that it left the entry out.

On screen: "Checks out", "Inclusion only: you can be sure of this, you can't yet prove it
to others.", "Does not check out" and "Can't read this file". Format: `canary-evidence/1`.
In the design: evidence artifact.

### Expected payment

A payment you declare to `canary check` so it can act as a [tripwire](#tripwire). Also
called a declared payment.

### Finding

A fact about a server and a block that Canary records and carries forward from run to
run. There are three kinds:

- **withheld** names one server and comes from a Data withheld result. It is an
  accusation.
- **disagree** names two servers and comes from a Servers disagree result. It says one of
  them lied, not which.
- **warning** names one server that did something an honest server would not, where
  nothing it signed shows it. It is not an accusation and changes no block's state.

Each finding records whether others can check it, in its `provable` field. On screen,
warnings end with "Not an accusation." In the design: alarm.

### Gap

A position in a [tweak list](#tweak-list) that does not carry the entry in full. The
server sends either the entry's 32-byte hash or nothing at all, which the formats call
`hash` and `absent`. Canary tries to fill every gap from another source before it
recomputes the root.

On screen: a block whose root matched after gaps reads "Checked, gap filled". In the
design: a position sent as nothing is a hole. The roadmap says hash-only slot and empty
slot.

### Inclusion proof

The sibling hashes that link one [entry](#entry) to a signed [root](#merkle-root). A
proof for a 2,000-entry block is 11 hashes of 32 bytes, 352 bytes in all. It shows that
the server signed for that entry without shipping the whole list.

In the design: Merkle proof. In the evidence file: the `proof` field.

### Index server

A server that computes the [entries](#entry) for each block and serves them to light
wallets. Examples are blindbit-oracle, Cake Wallet's electrs, shroud-indexer and Canary's
own [reference indexer](#reference-indexer). The docs also say indexer, or just server.

In the design: indexer.

### Light wallet

A wallet without its own full node. To receive silent payments it asks a server for
[tweaks](#tweak), because computing a tweak needs the outputs a transaction spent, and a
light wallet does not have them.

### Merkle root

A 32-byte hash over all of a block's [entries](#entry), built as a Merkle tree of
BIP-340 tagged hashes. Canary's root also binds the network, the block hash and the
entry count `n`, so nobody can reuse it for another block or another length. A block with
no entries still gets a root and a signed record.

On screen: "fingerprint", on detail pages only. In the design and the formats: root.

### Nostr

An open protocol for signed messages, passed around by [relays](#relay). Canary uses it
as a public bulletin board for [signed records](#signed-record). Nostr gives publication,
not timestamping. Canary orders records by block hash, never by the time an event claims.
In v1 each server hands out its own records over HTTP. Publishing them to relays comes
after v1.

### Omission

Leaving out data a client needed; here, an [entry](#entry) for a block. The docs also say
withholding or hiding. Canary looks for omission only. The opposite attack, commission,
adds fake entries, for example to make a wallet fetch a block and reveal its IP address.
Canary does not defend against commission.

### Output data

The data a wallet matches against, once it has a tweak, to decide whether a payment
exists. On BlindBit v1 that is the new-UTXO filter and the `/utxos` list with its spent
flag. On BlindBit v2 it is each transaction's 8-byte output-key prefixes, `outputs_short`.
Canary v1 commits to entries only, so a server can serve the right tweak, hide the
output, and the block still reads Checked. Adding output keys to the entry is planned for
v2. A false spent flag stays out of reach even then.

### Policy

A server's declared filtering: `prunes_spent`, `dust_threshold_sat`, `dust_configurable`
and a start height. Every field can only remove entries. In v1 the policy comes from the
server's unsigned `/info` response, so Canary uses it for display and warnings, never as
evidence.

In the design: policy declaration, which a server signs and cites by event id in the
record's `policy_ref` tag. v1 publishes no policy event, so `policy_ref` is 64 zeros.

### Receipt

The server's signature over one [tweak list](#tweak-list) and the request that produced
it. It is 178 bytes, sent as 356 hex characters in the `X-Canary-Receipt` response
header. It signs the network, the block hash, the dust threshold asked for, the server's
tip height and hash, and the SHA-256 of the exact bytes served. A signed record says what
exists in a block. A receipt says what the server gave you. With both, anyone can check
an omission.

### Reference indexer

`canary-indexer`, the small [index server](#index-server) that ships with v1 and runs on
regtest. It signs a record for every block, serves tweak lists with receipts, and has a
`--withhold-txid` switch that makes it leave one transaction out on purpose, for the
demo. It reuses Canary's own `canonical` package. So v1 does not test two independent
implementations against each other.

### Regtest, signet and mainnet

Bitcoin networks. Mainnet is the real one. Signet is a public test network where a
designated signer authorizes each block, so proof-of-work gives it no integrity. Regtest
is a private chain on your own machine, where you mine blocks on command.

Canary v1 is built and tested on regtest only. `canary check` accepts other networks and
prints a notice that v1 was not tested on them. Canary identifies each network by its
4-byte message-start magic, which keeps two custom signets apart. Regtest's magic is
`fabfb5da`, written 3669344250 in JSON and in Nostr tags.

### Relay

A server that stores and forwards Nostr [events](#event). A relay may drop, delay or
censor events, and relays differ in how long they keep them. The event's signature shows
who signed it. A relay's copy adds only that the event was published, not when.

### Retention window

A server's signed tip and the 143 blocks below it (depth 0 to 143), about one day at 10
minutes per block. Inside it, a server must keep at least the hash of every entry. So an
entry sent as nothing is an omission, and Canary names the server as Data withheld. The
window is a fixed rule of the protocol. No server can declare its own.

```
depth  = tip height − block height
inside = depth < 144
```

The tip height comes from the server's [receipt](#receipt), and the block height from its
[signed record](#signed-record). For a block at height 205 served with a signed tip of
212, the depth is 7, inside the window. That block leaves the window when the server's
tip reaches 205 + 144 = 349.

### Scan key

The private key a silent-payments recipient uses to find payments, by combining it with
each transaction's [tweak](#tweak). A server without your scan key cannot tell which
transactions pay you. Hiding one specific payment therefore takes outside knowledge of
it, which the sender has. Handing your scan key to a server lets it scan for you, and also
shows it every payment you receive.

### Signed record

A server's signed statement about one block: the entry count `n` and the
[Merkle root](#merkle-root) over the [canonical set](#canonical-set). It is a Nostr
[event](#event) of kind 1352, served at `GET /commitment/{blockhash}`. A server signs it
once, when it indexes the block, and never signs a second one for the same block. Two
records for one block from one key contradict each other.

In the design: commitment.

### Silent payments

The BIP-352 scheme for reusable payment addresses that never appear on chain. Each
payment goes to a fresh taproot output, derived from the recipient's address and the
sender's input keys. The recipient finds payments by scanning each eligible transaction
with its [scan key](#scan-key) and that transaction's [tweak](#tweak).

### SPCOMMIT

Rob Segers's commitment scheme for tweak indexes, live on mainnet since 1 Sep 2026. It
hashes each block's unfiltered tweak list into a chain, and signs only the head of the
chain, posted to Nostr every 6 hours. Its v2 also covers output prefixes and spent
outputs, which Canary v1 does not. [How Canary works](how-canary-works.md#prior-art)
compares the two.

### States

The six results Canary gives a block, one per block per run. A screen always shows a
state as its label, a symbol and a colour together.

| On screen | Code | Design name | Meaning |
|---|---|---|---|
| Checked | `verified` | Verified | The root recomputed over every position matched the server's signed root, and no position needed filling. The tweak list was checked, never the payments |
| Checked, gap filled | `resolved` | Resolved | As Checked, but some positions came as hashes or were filled from another source before the root was recomputed |
| Can't be checked | `unresolvable` | Unresolvable | Canary could not recompute the root. Neither a pass nor an accusation |
| Not checked | `unverified` | Unverified | There was no signed record to check against. Nothing about the block was checked |
| Servers disagree | `disputed` | Disputed | Two servers signed different roots for the same block hash. At least one lied, and Canary does not know which |
| Data withheld | `compromised` | Compromised | One named server left out an entry it had signed for, or the entry for a payment you declared |

Each state carries a reason code, such as `absent_in_window` or `hash_retained`.
[v1 formats](design/2026-09-30-v1-formats.md#reasons) lists them all.

The design's comparison procedure names three outcomes for one server and one block.
Clean becomes Checked or Checked, gap filled. Omission detected becomes Data withheld.
Unresolvable stays Can't be checked.

### Tripwire

A payment you know exists, declared so that Canary checks every server reports it. In
v1 you make a payment from your own Bitcoin Core wallet and pass `--expect TXID` to
`canary check`. Canary computes the payment's entry from your node. The tripwire still
works when every server colludes, and it covers only payments you know about. v1 checks
the entry only, not the payment's output data. Scheduled test payments at random times
and amounts come after v1.

In the design: tripwire, or expected payment. In the state file: `expected_payments`.

### Tweak

A 33-byte public key computed for each eligible transaction: the sum of its input public
keys, multiplied by a hash of that sum and its smallest outpoint. Computing it needs
the outputs the transaction spends, which a light wallet lacks, so the wallet asks a
server. The wallet then combines each tweak with its [scan key](#scan-key) to find its
own outputs.

### Tweak list

What a server returns for one block at `GET /tweaks/{blockhash}`. It holds exactly `n`
positions in canonical order after a 4-byte count. Each position carries the full entry,
the entry's hash, or nothing. With every position full, it is `4 + 66n` bytes, so 132,004
bytes at `n` = 2,000. A [receipt](#receipt) covers the exact bytes.

In the design: response, or served set.
