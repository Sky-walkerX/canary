# Test vectors

Each JSON file here is one self-contained test of Canary's canonical set. A vector holds a
whole block and every output its transactions spend, so any implementation can run it
with no node and no network.

BIP-352 ships vectors for the tweak of a given set of inputs. It ships none for the index
level: which transactions in a block are eligible, in what order, and what root they
produce. These vectors cover that level.

## How they run

`go test ./internal/testvector` loads every `*.json` file in this directory and runs it.
For each vector, the test:

1. decodes the block and builds the spent outputs from `prevouts`;
2. computes the canonical set with the `canonical` package;
3. compares the count with `expected.n` and each entry with `expected.leaves`;
4. computes the root with the `commit` package and compares it with `expected.root`.

Checking the root as well as the entries means a vector also tests the Merkle tree's
tagged hashes, its odd-node rule and the byte order of every hash input. CI runs these
files under plain `go test`, with no Bitcoin Core node and no network.

## Format

```json
{
  "name": "empty-block",
  "network": "regtest",
  "block": "<the whole serialized block, hex>",
  "prevouts": { "<txid>:<vout>": { "scriptPubKey": "<hex>", "value": 12345 } },
  "expected": {
    "n": 0,
    "leaves": [],
    "root": "<32 bytes, hex>"
  },
  "rationale": "<why this vector exists, in a sentence or two>"
}
```

| Field | Meaning |
|---|---|
| `name` | A short, unique name. It matches the file name |
| `network` | `main`, `signet` or `regtest`. The root binds the network's 4-byte magic, which the loader reads from btcd's `chaincfg` |
| `block` | The full serialized block, lowercase hex |
| `prevouts` | Every output the block's transactions spend. The key is `<txid>:<vout>`, with the txid in display order, the form Bitcoin Core's REST API uses. The value is in satoshis |
| `expected.n` | The number of entries in the canonical set |
| `expected.leaves` | Each entry as `<txid>:<tweak>`, in transaction order. The txid is in display order, and the tweak is the 33-byte compressed point in hex |
| `expected.root` | The root a signed record for this block would carry, in hex |
| `rationale` | Why the vector exists. A test fails if it is empty, because a vector nobody can explain is a vector nobody can fix |

The loader rejects unknown fields, so a misspelled field name fails the test instead of
leaving a value empty.

**Byte order.** JSON carries txids in display order, as block explorers print them. Every
hash input uses internal order. `Run` in `internal/testvector` does every conversion.
A txid written in the wrong order fails the vector before the root is checked. In a
prevout key it fails the prevout lookup, and in `expected.leaves` it fails the entry
comparison. The root check catches the other mistake: hashing code that uses the wrong
order gives a different root for the same data.

## What is here

| File | What it pins |
|---|---|
| `empty-block.json` | A regtest block holding only a coinbase. The canonical set is empty, so `n` is 0 and the Merkle root is 32 zero bytes. The outer root still binds the network, the block hash and `n`. An empty block is the common case on regtest, and a server still signs a record for it |

## Adding a vector

Nothing generates these files yet. `make vectors` prints a notice and exits with status 1.
The planned generator reads blocks and their spent outputs from a local regtest node
through Core's `/rest/spenttxouts`. Until it exists, a new vector is built by hand or by a
test, and its expected values come from the BIP-352 text, never from what the current
code outputs.

The design lists the corner cases the suite is meant to cover, such as the NUMS point
*H* in a script-path spend, a malleated P2PKH `scriptSig` and an input sum at the point
at infinity. See [The corners](../../docs/design/2026-09-06-canary-design.md#73-the-corners)
and [Vector format](../../docs/design/2026-09-06-canary-design.md#74-vector-format).
