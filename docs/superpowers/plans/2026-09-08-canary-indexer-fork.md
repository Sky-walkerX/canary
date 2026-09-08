# Canary Indexer Fork Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fork blindbit-oracle so it commits to the policy-free canonical set for every block, publishes that commitment as a signed Nostr event, serves a self-describing wire response, signs receipts, and can be told to omit a transaction on purpose.

**Architecture:** A thin accountability layer bolted onto blindbit-oracle's existing indexing loop. At index time the fork already holds the block and its prevouts, which is the only moment it can compute the canonical set — so the commitment is computed there, stored at 36 bytes per block, and published. Storage policy downstream stays entirely free.

**Tech Stack:** Go 1.24+, blindbit-oracle v2 (PebbleDB, Bitcoin Core v30+ REST), plus `commit` and `feed` from the protocol core.

**Spec:** [`docs/design/2026-09-06-canary-design.md`](../../design/2026-09-06-canary-design.md) — §2.1, §2.4, §3.2, §3.4, §3.7, §3.8, §6.1 and §8.4.

**Owner:** Dev B (§6.5). **Weeks 1–3** (§6.6).

**Depends on:** Plan A Task 1 (frozen interfaces), Task 4 (`commit.Root`), Task 12 (`feed.Commitment.ToEvent`). Work can start against Task 1's stubs on day 2.

## Global Constraints

- **The fork keeps blindbit-oracle's own computation path.** It may import the `canonical.Leaf` *type*, and it must **not** call `canonical.Set`. Sharing the computation would be convenient and would make the week-1 differential gate vacuous — both implementations would be wrong together (§6.4). This is the single most important rule in this plan.
- **Commit to `T_base`, not to what you store.** Every legitimate policy is subtractive, so the commitment is over the policy-free set including transactions the server is about to discard (§2.1). A server that commits to its filtered set is the equivocation case, not the honest case.
- **Retention:** leaf hashes are **required** for blocks within `W = 144` of the tip and optional beyond it. `W` is a protocol constant, never a configuration field — a server allowed to declare its own window declares zero (§2.4).
- **The wire response is self-describing at length `n`.** Every position is a full leaf, a 32-byte hash, or nothing, and the list is exactly `n` long. A merely shorter response is indistinguishable from a smaller block (§2.4).
- **The wire format lives in the core's `wire` package**, not under `internal/`. The sidecar decodes what this server encodes, and Go forbids importing another module's internal tree — defining it here would compile until the moment Plan C imported it.
- **Nostr kind 1352, regular range, append-only.** Never a replaceable kind (§3.3).
- **Never commit secrets.** The publisher's `nsec` comes from a file or environment variable, never from a flag in shell history and never from a committed config. `blindbit.toml` and `nsec*` are gitignored.
- **The malicious mode targets a txid, not an address.** An indexer cannot select by address — that needs the scan key it does not have. Targeting by txid is precisely the sender-attacker's capability, and an address filter would concede the premise the threat model rests on (§1.2, §8.4).

---

## File Structure

Paths are inside the blindbit-oracle fork.

| Path | Responsibility |
|---|---|
| `internal/canary/leaves.go` | Build `[]canonical.Leaf` from the indexer's **own** per-block computation |
| `internal/canary/store.go` | The 36-byte per-block record and the 144-block hash window |
| `internal/canary/publish.go` | Sign and publish the commitment; retry and relay fan-out |
| `internal/canary/receipt.go` | §3.8 receipts over `(request_params, response_digest)` |
| `internal/canary/omit.go` | The deliberately malicious mode, isolated in one file so it is auditable |
| `internal/server/commitment.go` | `GET /commitment/:blockhash` — §3.4's pull channel |
| `internal/server/tweaks_v2.go` | Builds §2.4's position list from stored state; the encoding itself is the core's `wire` package |
| `cmd/blindbit-oracle/flags.go` | `--commit`, `--canary-nsec-file`, `--canary-relays`, `--omit-txid` |

---

### Task 1: Fork, build, and run against regtest

**Files:**
- Create: `docs/canary-fork.md` in the fork
- Modify: `go.mod` in the fork

**Interfaces:**
- Consumes: nothing.
- Produces: a building fork with the protocol core available as a dependency.

- [ ] **Step 1: Fork and pin the upstream commit**

```bash
git clone https://github.com/setavenger/blindbit-oracle
cd blindbit-oracle
git checkout -b canary
git rev-parse HEAD > /tmp/upstream-base.txt
cat /tmp/upstream-base.txt
```

Record that hash in `docs/canary-fork.md` — every later claim about "what upstream does" is relative to it, and upstream moves.

- [ ] **Step 2: Add the protocol core as a dependency**

```bash
go mod edit -require=github.com/Sky-walkerX/canary@v0.0.0
go mod edit -replace=github.com/Sky-walkerX/canary=../canary
go mod tidy
```

The `replace` points at the sibling checkout so the two repositories move together during the build. It is removed only if the core is ever published.

- [ ] **Step 3: Write the guard test that keeps the differential suite honest**

This is the rule that is easiest to break by accident and hardest to notice: a tired engineer imports `canonical.Set` because it is right there, and the week-1 gate silently starts comparing the implementation against itself.

```go
// internal/canary/independence_test.go
package canary

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fork must compute its own canonical set. Importing canonical.Set would
// make the week-1 differential gate compare an implementation against itself
// (§6.4). The Leaf TYPE is fine; the computation is not.
func TestForkDoesNotImportCanonicalSet(t *testing.T) {
	root := "../.."
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "canonical.Set(") {
			t.Errorf("%s calls canonical.Set — the fork must keep its own computation path (§6.4)", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 4: Build and run against regtest**

```bash
go build -o blindbit-oracle ./cmd/blindbit-oracle
bitcoind -regtest -daemon -rest=1 -txindex=1
bitcoin-cli -regtest createwallet canary
ADDR=$(bitcoin-cli -regtest getnewaddress '' bech32m)
bitcoin-cli -regtest generatetoaddress 200 "$ADDR"

mkdir -p ~/.blindbit-oracle-regtest
cat > ~/.blindbit-oracle-regtest/blindbit.toml <<'TOML'
# Full index, no dust filter — the only configuration comparable to T_base.
# The week-1 gate tests nothing if this is left at a filtered default (§6.6).
tweaks_only = 0
tweaks_full_basic = 1
TOML

./blindbit-oracle --datadir ~/.blindbit-oracle-regtest sync
curl -s localhost:8000/info | tee /tmp/info.json
```

Expected: `/info` reports `"network": "regtest"` and `"tweaks_full_basic": true`. Confirm the exact flag name against this checkout — §6.6 flags it as needing verification on day 1, because the name is from documentation rather than from the source.

- [ ] **Step 5: Run the guard test and commit**

```bash
go test ./internal/canary/ -run TestForkDoesNotImportCanonicalSet -v
git add go.mod go.sum docs/canary-fork.md internal/canary/independence_test.go
git commit -m "chore: fork blindbit-oracle for canary, pin upstream base"
```

---

### Task 2: Build canonical leaves from the indexer's own computation

**Files:**
- Create: `internal/canary/leaves.go`
- Test: `internal/canary/leaves_test.go`

**Interfaces:**
- Consumes: whatever per-block structure blindbit-oracle's indexing loop already produces — locate it in Step 1 before writing anything.
- Produces: `func LeavesFromBlock(txs []IndexedTx) ([]canonical.Leaf, error)` and `type IndexedTx struct { TxIDDisplay [32]byte; Tweak [33]byte; Eligible bool }`.

**The byte-order trap.** blindbit-oracle works in display order throughout, because that is what Core's REST API returns and what `bip352.Vin.Txid` requires. §3.2 pins the leaf preimage txid as **internal** order. The conversion happens here, once (§6.4).

- [ ] **Step 1: Locate the existing computation**

```bash
grep -rn "ComputeInputHash\|TweakPubkey\|ExtractEligibleVins" --include=*.go . | head -20
```

Read the function that produces per-block tweaks and note its exact type. `IndexedTx` below is an adapter over it, not a replacement for it.

- [ ] **Step 2: Write the failing test**

```go
// internal/canary/leaves_test.go
package canary

import (
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
)

func TestLeavesPreserveOrderAndFilterIneligible(t *testing.T) {
	mk := func(b byte, eligible bool) IndexedTx {
		var tx IndexedTx
		tx.TxIDDisplay[0] = b
		tx.Tweak[0] = 0x02
		tx.Tweak[1] = b
		tx.Eligible = eligible
		return tx
	}

	in := []IndexedTx{mk(1, true), mk(2, false), mk(3, true)}
	leaves, err := LeavesFromBlock(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 2 {
		t.Fatalf("got %d leaves, want 2", len(leaves))
	}
	// Transaction-index order, ineligible entries removed rather than reordered.
	if leaves[0].TxID[31] != 1 || leaves[1].TxID[31] != 3 {
		t.Errorf("order or byte conversion wrong: %x %x", leaves[0].TxID, leaves[1].TxID)
	}
}

func TestLeavesReverseTxidToInternalOrder(t *testing.T) {
	var tx IndexedTx
	for i := range tx.TxIDDisplay {
		tx.TxIDDisplay[i] = byte(i)
	}
	tx.Eligible = true
	tx.Tweak[0] = 0x02

	leaves, err := LeavesFromBlock([]IndexedTx{tx})
	if err != nil {
		t.Fatal(err)
	}
	// Internal order is the reverse of display order (§3.2, §6.4).
	for i := 0; i < 32; i++ {
		if leaves[0].TxID[i] != tx.TxIDDisplay[31-i] {
			t.Fatalf("byte %d: got %02x, want %02x", i, leaves[0].TxID[i], tx.TxIDDisplay[31-i])
		}
	}
}

func TestLeavesRejectAnUncompressedTweak(t *testing.T) {
	var tx IndexedTx
	tx.Eligible = true
	tx.Tweak[0] = 0x04 // uncompressed prefix — never valid here
	if _, err := LeavesFromBlock([]IndexedTx{tx}); err == nil {
		t.Error("a tweak that is not a compressed SEC point must be an error, not a silent leaf")
	}
}

func TestLeavesEmptyBlockIsEmptyNotAnError(t *testing.T) {
	leaves, err := LeavesFromBlock(nil)
	if err != nil {
		t.Fatalf("an empty block is not an error: %v", err)
	}
	if len(leaves) != 0 {
		t.Errorf("got %d leaves, want 0", len(leaves))
	}
	var _ []canonical.Leaf = leaves
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/canary/ -run TestLeaves -v`
Expected: FAIL — `undefined: LeavesFromBlock`.

- [ ] **Step 4: Write the implementation**

```go
// internal/canary/leaves.go
// Package canary adds commitment, publication and receipts to blindbit-oracle.
//
// It deliberately does NOT import canonical.Set. The fork keeps its own
// computation path so the week-1 differential gate compares two independent
// implementations rather than one implementation against itself (§6.4).
package canary

import (
	"fmt"

	"github.com/Sky-walkerX/canary/canonical"
)

// IndexedTx is one transaction as the indexer's existing loop sees it.
// TxIDDisplay is in display order, which is what Core's REST API returns.
type IndexedTx struct {
	TxIDDisplay [32]byte
	Tweak       [33]byte
	Eligible    bool
}

// LeavesFromBlock converts the indexer's own per-block result into the
// canonical leaf list.
//
// Two rules that are easy to get wrong and expensive to get wrong:
//
//   - Order is transaction-index order and ineligible entries are REMOVED, not
//     reordered or zero-filled. Position i must remain a specific transaction,
//     because that is what attribution reads (§2.2).
//   - The txid is reversed into INTERNAL byte order here, once. The rest of
//     this fork works in display order (§3.2, §6.4).
func LeavesFromBlock(txs []IndexedTx) ([]canonical.Leaf, error) {
	leaves := make([]canonical.Leaf, 0, len(txs))
	for i, tx := range txs {
		if !tx.Eligible {
			continue
		}
		if tx.Tweak[0] != 0x02 && tx.Tweak[0] != 0x03 {
			return nil, fmt.Errorf("tx %d: tweak prefix %02x is not a compressed SEC point", i, tx.Tweak[0])
		}
		var l canonical.Leaf
		for j := 0; j < 32; j++ {
			l.TxID[j] = tx.TxIDDisplay[31-j]
		}
		l.Tweak = tx.Tweak
		leaves = append(leaves, l)
	}
	return leaves, nil
}
```

- [ ] **Step 5: Run the tests and commit**

```bash
go test ./internal/canary/ -v
git add internal/canary/leaves.go internal/canary/leaves_test.go
git commit -m "feat(canary): canonical leaves from the indexer's own computation"
```

---

### Task 3: The commitment store and the 144-block hash window

**Files:**
- Create: `internal/canary/store.go`
- Test: `internal/canary/store_test.go`

**Interfaces:**
- Consumes: `canonical.Leaf`, `commit.Root`, `commit.LeafHash`.
- Produces: `type Store`, `func NewStore(db *pebble.DB) *Store`, `func (s *Store) PutBlock(net canonical.Network, height uint32, blockHash [32]byte, leaves []canonical.Leaf) error`, `func (s *Store) Record(blockHash [32]byte) (Record, error)`, `func (s *Store) LeafHashes(blockHash [32]byte) ([][32]byte, bool, error)`, `func (s *Store) PruneBelow(tipHeight uint32) error`, `const RetentionWindow = 144`.

**The cost, from §3.7.** 36 bytes per block retained forever — a 32-byte root plus `n` — which is about 35 MB for all of mainnet history. The hash window is bounded by `W × n × 32` = 9.2 MB at `W = 144` and `n ≈ 2000`, and reaching it would mean dropping every leaf for a day.

- [ ] **Step 1: Write the failing test**

```go
// internal/canary/store_test.go
package canary

import (
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := pebble.Open("", &pebble.Options{FS: vfs.NewMem()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewStore(db)
}

func mkLeaves(n int) []canonical.Leaf {
	out := make([]canonical.Leaf, n)
	for i := range out {
		out[i].TxID[0] = byte(i + 1)
		out[i].Tweak[0] = 0x02
		out[i].Tweak[1] = byte(i)
	}
	return out
}

const netRegtest = canonical.Network(0xdab5bffa)

func TestPutBlockStoresRootAndN(t *testing.T) {
	s := testStore(t)
	var bh [32]byte
	bh[0] = 0xAA
	leaves := mkLeaves(5)

	if err := s.PutBlock(netRegtest, 100, bh, leaves); err != nil {
		t.Fatal(err)
	}
	rec, err := s.Record(bh)
	if err != nil {
		t.Fatal(err)
	}
	if rec.N != 5 {
		t.Errorf("n = %d, want 5", rec.N)
	}
	if rec.Root != commit.Root(netRegtest, bh, leaves) {
		t.Error("stored root does not match commit.Root")
	}
	if rec.Height != 100 {
		t.Errorf("height = %d, want 100", rec.Height)
	}
}

func TestEmptyBlockIsStored(t *testing.T) {
	s := testStore(t)
	var bh [32]byte
	bh[0] = 0xBB

	// An empty set is committed, not skipped. Skipping restores the excuse
	// §2.5 step 0 exists to remove (§3.2).
	if err := s.PutBlock(netRegtest, 101, bh, nil); err != nil {
		t.Fatal(err)
	}
	rec, err := s.Record(bh)
	if err != nil {
		t.Fatalf("an empty block must still have a record: %v", err)
	}
	if rec.N != 0 {
		t.Errorf("n = %d, want 0", rec.N)
	}
	var zero [32]byte
	if rec.Root == zero {
		t.Error("the outer root of an empty set is a real hash, not zeroes")
	}
}

func TestLeafHashesRetainedInsideTheWindow(t *testing.T) {
	s := testStore(t)
	var bh [32]byte
	bh[0] = 0xCC
	leaves := mkLeaves(3)

	if err := s.PutBlock(netRegtest, 1000, bh, leaves); err != nil {
		t.Fatal(err)
	}

	hashes, ok, err := s.LeafHashes(bh)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("leaf hashes must be retained when the block is stored")
	}
	if len(hashes) != 3 {
		t.Fatalf("got %d hashes, want 3", len(hashes))
	}
	for i, l := range leaves {
		if hashes[i] != commit.LeafHash(l) {
			t.Errorf("hash %d does not match commit.LeafHash", i)
		}
	}
}

func TestPruneDropsHashesButKeepsRecordsForever(t *testing.T) {
	s := testStore(t)
	var old, recent [32]byte
	old[0], recent[0] = 0x01, 0x02

	if err := s.PutBlock(netRegtest, 1000, old, mkLeaves(2)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutBlock(netRegtest, 1100, recent, mkLeaves(2)); err != nil {
		t.Fatal(err)
	}

	// Tip 1100: the window covers 1100-144 = 956 upward, so BOTH are inside.
	if err := s.PruneBelow(1100); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.LeafHashes(old); !ok {
		t.Error("height 1000 is inside the 144-block window of tip 1100 and must be retained")
	}

	// Tip 1200: 1200-144 = 1056, so height 1000 falls out.
	if err := s.PruneBelow(1200); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.LeafHashes(old); ok {
		t.Error("height 1000 is outside the window of tip 1200 and may be pruned")
	}
	if _, ok, _ := s.LeafHashes(recent); !ok {
		t.Error("height 1100 is inside the window of tip 1200 and must be retained")
	}

	// The 36-byte record is never pruned. Accountability outlives the data
	// (§3.7): commit at index time, remain accountable forever.
	if _, err := s.Record(old); err != nil {
		t.Errorf("the per-block record must survive pruning: %v", err)
	}
}

func TestRetentionWindowIsAConstant(t *testing.T) {
	if RetentionWindow != 144 {
		t.Errorf("RetentionWindow = %d, want 144 (§2.4)", RetentionWindow)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/canary/ -run 'TestPut|TestEmpty|TestLeafHashes|TestPrune|TestRetention' -v`
Expected: FAIL — `undefined: Store`.

- [ ] **Step 3: Write the implementation**

```go
// internal/canary/store.go
package canary

import (
	"encoding/binary"
	"fmt"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/cockroachdb/pebble"
)

// RetentionWindow is how many blocks back leaf hashes must be kept.
//
// It is a PROTOCOL CONSTANT, not a configuration field. A server allowed to
// declare its own window declares zero, which is the hole verbatim (§2.4).
const RetentionWindow = 144

// Record is the permanent per-block state: 4 + 32 + 4 = 40 bytes on disk, of
// which §3.7's 36-byte figure is the root plus n. It is never pruned — the
// server stays accountable for what it dropped, forever.
type Record struct {
	Height uint32
	Root   [32]byte
	N      uint32
}

type Store struct{ db *pebble.DB }

func NewStore(db *pebble.DB) *Store { return &Store{db: db} }

func recordKey(blockHash [32]byte) []byte {
	return append([]byte("canary/rec/"), blockHash[:]...)
}

func hashesKey(blockHash [32]byte) []byte {
	return append([]byte("canary/lh/"), blockHash[:]...)
}

// PutBlock computes and stores the commitment for one block, plus the leaf
// hashes that the retention window requires.
//
// Called at index time because that is the only moment the server holds both
// the block and its prevouts (§2.1). It is called for EVERY block, including
// ones with no eligible transaction (§3.2).
func (s *Store) PutBlock(net canonical.Network, height uint32, blockHash [32]byte, leaves []canonical.Leaf) error {
	rec := Record{
		Height: height,
		Root:   commit.Root(net, blockHash, leaves),
		N:      uint32(len(leaves)),
	}

	buf := make([]byte, 40)
	binary.LittleEndian.PutUint32(buf[0:4], rec.Height)
	copy(buf[4:36], rec.Root[:])
	binary.LittleEndian.PutUint32(buf[36:40], rec.N)

	batch := s.db.NewBatch()
	defer batch.Close()

	if err := batch.Set(recordKey(blockHash), buf, nil); err != nil {
		return err
	}

	if len(leaves) > 0 {
		hashes := make([]byte, 0, len(leaves)*32)
		for _, l := range leaves {
			h := commit.LeafHash(l)
			hashes = append(hashes, h[:]...)
		}
		if err := batch.Set(hashesKey(blockHash), hashes, nil); err != nil {
			return err
		}
	}

	return batch.Commit(pebble.Sync)
}

func (s *Store) Record(blockHash [32]byte) (Record, error) {
	var rec Record
	val, closer, err := s.db.Get(recordKey(blockHash))
	if err != nil {
		return rec, fmt.Errorf("no commitment record for %x: %w", blockHash, err)
	}
	defer closer.Close()
	if len(val) != 40 {
		return rec, fmt.Errorf("corrupt record: %d bytes", len(val))
	}
	rec.Height = binary.LittleEndian.Uint32(val[0:4])
	copy(rec.Root[:], val[4:36])
	rec.N = binary.LittleEndian.Uint32(val[36:40])
	return rec, nil
}

// LeafHashes returns the retained hashes for a block. ok is false when they
// have been pruned, which is permitted only outside the retention window.
func (s *Store) LeafHashes(blockHash [32]byte) ([][32]byte, bool, error) {
	val, closer, err := s.db.Get(hashesKey(blockHash))
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()
	if len(val)%32 != 0 {
		return nil, false, fmt.Errorf("corrupt leaf hashes: %d bytes", len(val))
	}
	out := make([][32]byte, len(val)/32)
	for i := range out {
		copy(out[i][:], val[i*32:(i+1)*32])
	}
	return out, true, nil
}

// PruneBelow drops leaf hashes for blocks more than RetentionWindow behind the
// tip. Records are never dropped.
//
// This is nearly free: a transaction can only be cut through once all of its
// taproot outputs are spent, which at the tip is close to empty. Servers retain
// hashes exactly where there is almost nothing to retain (§2.4).
func (s *Store) PruneBelow(tipHeight uint32) error {
	if tipHeight <= RetentionWindow {
		return nil
	}
	cutoff := tipHeight - RetentionWindow

	iter, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte("canary/rec/"),
		UpperBound: []byte("canary/rec0"), // '0' is the byte after '/'
	})
	if err != nil {
		return err
	}
	defer iter.Close()

	batch := s.db.NewBatch()
	defer batch.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		val := iter.Value()
		if len(val) != 40 {
			continue
		}
		if binary.LittleEndian.Uint32(val[0:4]) >= cutoff {
			continue
		}
		var bh [32]byte
		key := iter.Key()
		copy(bh[:], key[len(key)-32:])
		if err := batch.Delete(hashesKey(bh), nil); err != nil {
			return err
		}
	}
	return batch.Commit(pebble.Sync)
}
```

- [ ] **Step 4: Run the tests and commit**

```bash
go test ./internal/canary/ -v
git add internal/canary/store.go internal/canary/store_test.go
git commit -m "feat(canary): commitment store with the 144-block hash window"
```

---

### Task 4: Publish the commitment to Nostr, and serve it over HTTP

**Files:**
- Create: `internal/canary/publish.go`, `internal/server/commitment.go`
- Test: `internal/canary/publish_test.go`

**Interfaces:**
- Consumes: `Store.Record` from Task 3, `feed.Commitment.ToEvent` from Plan A Task 12.
- Produces: `func (p *Publisher) Publish(ctx context.Context, net canonical.Network, height uint32, blockHash [32]byte, rec Record) error`, `type EventLookup interface { Event(blockHash [32]byte) (nostr.Event, bool, error) }` with `*Store` implementing it, and the HTTP handler `func (h *CommitmentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request)`.

**Two channels, two jobs (§3.4).** The relay makes the statement *public*, which is what enables equivocation detection. The HTTP pull gives a client a signed statement from the party it is already talking to, so a client isolated to a single malicious server still extracts evidence. Neither substitutes for the other: without the pull, whoever controls the relay gets a veto over §2.5 step 0.

- [ ] **Step 1: Write the failing test**

```go
// internal/canary/publish_test.go
package canary

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/Sky-walkerX/canary/feed"
	"github.com/nbd-wtf/go-nostr"
)

type capturingRelay struct{ published []nostr.Event }

func (c *capturingRelay) Publish(ctx context.Context, ev nostr.Event) error {
	c.published = append(c.published, ev)
	return nil
}

type failingRelay struct{}

func (failingRelay) Publish(ctx context.Context, ev nostr.Event) error {
	return context.DeadlineExceeded
}

func testPublisher(t *testing.T, relays ...publisherRelay) (*Publisher, [32]byte) {
	t.Helper()
	skHex := nostr.GeneratePrivateKey()
	b, _ := hex.DecodeString(skHex)
	var sk [32]byte
	copy(sk[:], b)
	return &Publisher{sk: sk, relays: relays}, sk
}

func TestPublishSignsAndFansOut(t *testing.T) {
	a, b := &capturingRelay{}, &capturingRelay{}
	p, _ := testPublisher(t, a, b)

	var bh [32]byte
	bh[0] = 0xAA
	rec := Record{Height: 500, N: 3}
	rec.Root[0] = 0x77

	if err := p.Publish(context.Background(), netRegtest, 500, bh, rec); err != nil {
		t.Fatal(err)
	}

	for name, r := range map[string]*capturingRelay{"a": a, "b": b} {
		if len(r.published) != 1 {
			t.Fatalf("relay %s got %d events, want 1", name, len(r.published))
		}
		ev := r.published[0]
		if ev.Kind != feed.KindCommitment {
			t.Errorf("relay %s: kind = %d, want %d", name, ev.Kind, feed.KindCommitment)
		}
		c, err := feed.FromEvent(ev)
		if err != nil {
			t.Fatalf("relay %s: published event does not parse back: %v", name, err)
		}
		if c.Root != rec.Root || c.N != rec.N || c.BlockHash != bh {
			t.Errorf("relay %s: round trip lost data", name)
		}
	}
}

func TestPublishSucceedsIfAnyRelayAccepts(t *testing.T) {
	good := &capturingRelay{}
	p, _ := testPublisher(t, failingRelay{}, good)

	var bh [32]byte
	if err := p.Publish(context.Background(), netRegtest, 1, bh, Record{}); err != nil {
		t.Errorf("one failing relay must not fail the publish: %v", err)
	}
	if len(good.published) != 1 {
		t.Error("the healthy relay should still have received the event")
	}
}

func TestPublishFailsIfEveryRelayFails(t *testing.T) {
	p, _ := testPublisher(t, failingRelay{}, failingRelay{})
	var bh [32]byte
	// Silently swallowing this would make the server look like it committed
	// when it did not — exactly the state §2.5 step 0 refuses.
	if err := p.Publish(context.Background(), netRegtest, 1, bh, Record{}); err == nil {
		t.Error("a publish reaching no relay must be an error")
	}
}

func TestPublishesEvenWhenNIsZero(t *testing.T) {
	a := &capturingRelay{}
	p, _ := testPublisher(t, a)

	var bh [32]byte
	bh[0] = 0xEE
	if err := p.Publish(context.Background(), netRegtest, 7, bh, Record{Height: 7, N: 0}); err != nil {
		t.Fatal(err)
	}
	if len(a.published) != 1 {
		t.Error("an empty block still gets a commitment — skipping is the excuse §2.5 removes")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/canary/ -run TestPublish -v`
Expected: FAIL — `undefined: Publisher`.

- [ ] **Step 3: Write the publisher**

```go
// internal/canary/publish.go
package canary

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/nbd-wtf/go-nostr"
)

// publisherRelay is the slice of a relay we depend on, so tests need no socket.
type publisherRelay interface {
	Publish(ctx context.Context, ev nostr.Event) error
}

type Publisher struct {
	sk        [32]byte
	relays    []publisherRelay
	policyRef [32]byte
}

// LoadSecretKey reads the signing key from a file. Never a flag: a flag lands
// in shell history and in the process table.
func LoadSecretKey(path string) ([32]byte, error) {
	var sk [32]byte
	raw, err := os.ReadFile(path)
	if err != nil {
		return sk, err
	}
	s := strings.TrimSpace(string(raw))
	decoded, err := decodeNsecOrHex(s)
	if err != nil {
		return sk, err
	}
	copy(sk[:], decoded)
	return sk, nil
}

// Publish signs the commitment and sends it to every configured relay.
//
// It is called for EVERY indexed block, including empty ones. Selective
// non-publication is the attack §2.5 step 0 refuses: a server that commits to
// its neighbours but not to block B has its data refused outright.
func (p *Publisher) Publish(ctx context.Context, net canonical.Network, height uint32, blockHash [32]byte, rec Record) error {
	c := feed.Commitment{
		Network:     net,
		BlockHash:   blockHash,
		BlockHeight: height,
		N:           rec.N,
		Root:        rec.Root,
		PolicyRef:   p.policyRef,
	}

	ev, err := c.ToEvent(p.sk)
	if err != nil {
		return fmt.Errorf("canary: build commitment event: %w", err)
	}

	var lastErr error
	delivered := 0
	for _, r := range p.relays {
		if err := r.Publish(ctx, ev); err != nil {
			lastErr = err
			continue
		}
		delivered++
	}

	// Reaching no relay is a real failure. A server that believes it committed
	// while nobody can see the commitment is indistinguishable, from outside,
	// from a server that chose not to commit (§3.4).
	if delivered == 0 {
		return fmt.Errorf("canary: commitment for %x reached no relay: %w", blockHash, lastErr)
	}
	return nil
}
```

- [ ] **Step 4: Store the signed event so it can be served later**

Publishing is not enough. §3.4's pull channel hands a client the signed event
from the party it is already talking to, so the event has to survive locally
even when every relay is unreachable.

```go
// internal/canary/publish.go — additions

// EventLookup returns the signed commitment event for a block. The HTTP
// handler depends on this rather than on *Store directly, so a test can serve
// canned events without a database.
type EventLookup interface {
	Event(blockHash [32]byte) (nostr.Event, bool, error)
}

func eventKey(blockHash [32]byte) []byte {
	return append([]byte("canary/ev/"), blockHash[:]...)
}

// PutEvent records the signed event alongside the 36-byte record.
func (s *Store) PutEvent(blockHash [32]byte, ev nostr.Event) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return s.db.Set(eventKey(blockHash), raw, pebble.Sync)
}

// Event implements EventLookup.
func (s *Store) Event(blockHash [32]byte) (nostr.Event, bool, error) {
	var ev nostr.Event
	val, closer, err := s.db.Get(eventKey(blockHash))
	if err == pebble.ErrNotFound {
		return ev, false, nil
	}
	if err != nil {
		return ev, false, err
	}
	defer closer.Close()
	if err := json.Unmarshal(val, &ev); err != nil {
		return ev, false, err
	}
	return ev, true, nil
}
```

Call `PutEvent` from `Publish` **before** the relay fan-out, so a total relay
outage still leaves the client a signature it can present later. A server that
refuses to sign is refusing accountability, which is itself the alarm (§3.4);
a server that signed but could not reach a relay is a different and innocent
case, and the two must not look alike.

- [ ] **Step 5: Write the HTTP pull channel**

```go
// internal/server/commitment.go
package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/setavenger/blindbit-oracle/internal/canary"
)

// CommitmentHandler serves GET /commitment/:blockhash — §3.4's pull channel.
//
// It returns the raw signed Nostr event, not a JSON summary. The signature is
// the entire point: a client isolated to one malicious server still walks away
// with a non-repudiable statement it can present to anyone, later.
type CommitmentHandler struct {
	Store  *canary.Store
	Events canary.EventLookup
}

func (h *CommitmentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hashHex := r.PathValue("blockhash")
	raw, err := hex.DecodeString(hashHex)
	if err != nil || len(raw) != 32 {
		http.Error(w, "bad block hash", http.StatusBadRequest)
		return
	}
	var bh [32]byte
	for i := 0; i < 32; i++ {
		bh[i] = raw[31-i] // display hex in, internal order internally
	}

	ev, ok, err := h.Events.Event(bh)
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if !ok {
		// 404 here means "not indexed yet", which is different from refusing
		// to commit. A client distinguishes them via the declared start height
		// and the server's other blocks (§2.5 step 0).
		http.Error(w, "no commitment for that block", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ev)
}
```

- [ ] **Step 6: Wire the publisher into the indexing loop**

Find the point where the loop finishes a block, and call, in order: `LeavesFromBlock`, `Store.PutBlock`, `Publisher.Publish`, then `Store.PruneBelow(tipHeight)`. Publication failures must be retried rather than skipped — record the block in a pending queue and retry on the next tick.

- [ ] **Step 7: Run the tests and commit**

```bash
go test ./internal/canary/ ./internal/server/ -v
git add internal/canary/publish.go internal/server/commitment.go internal/canary/publish_test.go
git commit -m "feat(canary): publish commitments to relays and serve them over HTTP"
```

---

### Task 5: Build the self-describing response from the store

**Files:**
- Create: `internal/server/tweaks_v2.go`
- Test: `internal/server/tweaks_v2_test.go`

**Interfaces:**
- Consumes: `wire.Position`, `wire.EncodeResponse` from the protocol core (Plan A Task 15), and `Store.LeafHashes` from Task 3.
- Produces: `func BuildPositions(leaves []canonical.Leaf, served map[int]bool, retained [][32]byte) ([]wire.Position, error)` and the HTTP handler that serves it.

**The encoding lives in the core, not here.** `wire.Position` and `wire.EncodeResponse` are in `github.com/Sky-walkerX/canary/wire` because the sidecar decodes what this server encodes, and Go forbids importing a module's `internal/` tree from another module. Defining them under `internal/server` would compile fine here and break the moment Plan C imported them. This task consumes that package; it does not reimplement it.

**What is left for the server, and it is the part with the policy in it.** Deciding *which* kind each position gets:

| Condition | Kind |
|---|---|
| The server still holds the leaf and policy permits serving it | `KindFull` |
| The leaf was pruned but its hash is retained (inside the 144-block window) | `KindHash` |
| The leaf and its hash are both gone (only outside the window) | `KindAbsent` |

The list is exactly `n` long in every case. **A response that is merely shorter is indistinguishable from a smaller block**, and under a single server there is no cross-check to catch the difference (§2.4).

- [ ] **Step 1: Write the failing test**

```go
// internal/server/tweaks_v2_test.go
package server

import (
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/wire"
)

func mkLeaves(n int) []canonical.Leaf {
	out := make([]canonical.Leaf, n)
	for i := range out {
		out[i].TxID[0] = byte(i + 1)
		out[i].Tweak[0] = 0x02
		out[i].Tweak[1] = byte(i)
	}
	return out
}

func retainedFor(leaves []canonical.Leaf) [][32]byte {
	out := make([][32]byte, len(leaves))
	for i, l := range leaves {
		out[i] = commit.LeafHash(l)
	}
	return out
}

func TestBuildServesEverythingWhenNothingIsPruned(t *testing.T) {
	leaves := mkLeaves(4)
	served := map[int]bool{0: true, 1: true, 2: true, 3: true}

	pos, err := BuildPositions(leaves, served, retainedFor(leaves))
	if err != nil {
		t.Fatal(err)
	}
	if len(pos) != 4 {
		t.Fatalf("got %d positions, want 4", len(pos))
	}
	for i, p := range pos {
		if p.Kind != wire.KindFull {
			t.Errorf("position %d kind = %d, want KindFull", i, p.Kind)
		}
	}
}

func TestPrunedPositionFallsBackToItsRetainedHash(t *testing.T) {
	leaves := mkLeaves(4)
	served := map[int]bool{0: true, 1: true, 3: true} // 2 was pruned

	pos, err := BuildPositions(leaves, served, retainedFor(leaves))
	if err != nil {
		t.Fatal(err)
	}
	if len(pos) != 4 {
		t.Fatalf("the list stays exactly n long, got %d", len(pos))
	}
	if pos[2].Kind != wire.KindHash {
		t.Errorf("pruned position kind = %d, want KindHash", pos[2].Kind)
	}
	if pos[2].Hash != commit.LeafHash(leaves[2]) {
		t.Error("retained hash does not match the leaf it stands for")
	}
	// A retained hash keeps the response verifiable from this one server alone,
	// with no second source needed (§2.4).
}

func TestAbsentOnlyWhenTheHashIsGoneToo(t *testing.T) {
	leaves := mkLeaves(3)
	served := map[int]bool{0: true, 2: true}
	retained := retainedFor(leaves)
	retained[1] = [32]byte{} // outside the window: hash pruned as well

	pos, err := BuildPositions(leaves, served, retained)
	if err != nil {
		t.Fatal(err)
	}
	if pos[1].Kind != wire.KindAbsent {
		t.Errorf("kind = %d, want KindAbsent", pos[1].Kind)
	}
	if len(pos) != 3 {
		t.Error("an absent position still occupies its slot — the list is always n long")
	}
}

func TestBuildRejectsARetentionMismatch(t *testing.T) {
	leaves := mkLeaves(3)
	// A retained slice of the wrong length means the store and the leaf list
	// disagree, which would silently shift every later position.
	if _, err := BuildPositions(leaves, map[int]bool{}, make([][32]byte, 2)); err == nil {
		t.Error("a retained-hash slice of the wrong length must be an error")
	}
}

func TestEncodedResponseRoundTripsThroughTheCorePackage(t *testing.T) {
	leaves := mkLeaves(5)
	served := map[int]bool{0: true, 2: true, 4: true}

	pos, err := BuildPositions(leaves, served, retainedFor(leaves))
	if err != nil {
		t.Fatal(err)
	}
	buf, err := wire.EncodeResponse(pos)
	if err != nil {
		t.Fatal(err)
	}
	got, err := wire.DecodeResponse(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("decoded %d positions, want 5", len(got))
	}
	for i := range got {
		if got[i].Kind != pos[i].Kind {
			t.Errorf("position %d: kind %d != %d after round trip", i, got[i].Kind, pos[i].Kind)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/server/ -run 'TestBuild|TestPruned|TestAbsent|TestEncoded' -v`
Expected: FAIL — `undefined: BuildPositions`.

- [ ] **Step 3: Write the implementation**

```go
// internal/server/tweaks_v2.go
package server

import (
	"fmt"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/wire"
)

// BuildPositions turns the canonical leaf list plus this server's storage state
// into §2.4's position list.
//
// served says which positions the server still holds in full; retained carries
// the leaf hash for every position, zeroed where even the hash has been pruned.
//
// The output is ALWAYS exactly len(leaves) long. Dropping a position instead of
// marking it would make the response indistinguishable from a smaller block,
// which is a different and weaker attack that no single-server check catches
// (§2.4).
func BuildPositions(leaves []canonical.Leaf, served map[int]bool, retained [][32]byte) ([]wire.Position, error) {
	if len(retained) != len(leaves) {
		return nil, fmt.Errorf("server: %d retained hashes for %d leaves", len(retained), len(leaves))
	}

	var zero [32]byte
	out := make([]wire.Position, len(leaves))

	for i, l := range leaves {
		switch {
		case served[i]:
			out[i] = wire.Position{Kind: wire.KindFull, Leaf: l}
		case retained[i] != zero:
			// Pruned the leaf, kept the hash. Inside the 144-block window this
			// is mandatory, and it keeps the block verifiable from this server
			// alone (§2.4).
			out[i] = wire.Position{Kind: wire.KindHash, Hash: retained[i]}
		default:
			// Permitted only outside the retention window. The block is now
			// verifiable only once the leaf is recovered elsewhere.
			out[i] = wire.Position{Kind: wire.KindAbsent}
		}
	}
	return out, nil
}

// LeafHashesFor is the convenience the handler uses when the server still holds
// every leaf: it derives the retained slice directly.
func LeafHashesFor(leaves []canonical.Leaf) [][32]byte {
	out := make([][32]byte, len(leaves))
	for i, l := range leaves {
		out[i] = commit.LeafHash(l)
	}
	return out
}
```

- [ ] **Step 4: Wire it into the tweaks endpoint**

The handler resolves the block, loads the canonical leaves and the retained hashes from `Store`, applies the omitter from Task 7 if configured, then calls `wire.EncodeResponse`. Serve the encoded bytes and sign the receipt (Task 6) over exactly those bytes — the receipt must cover what was actually sent, not what was intended.

- [ ] **Step 5: Run the tests and commit**

```bash
go test ./internal/server/ -v
git add internal/server/tweaks_v2.go internal/server/tweaks_v2_test.go
git commit -m "feat(server): build the self-describing response from stored state"
```

---

### Task 6: Receipts

**Files:**
- Create: `internal/canary/receipt.go`
- Test: `internal/canary/receipt_test.go`

**Interfaces:**
- Consumes: the publisher's key.
- Produces: `type Receipt struct { BlockHash [32]byte; DustThresholdSat uint64; ResponseDigest [32]byte; Sig [64]byte }` and `func (p *Publisher) SignReceipt(blockHash [32]byte, dust uint64, response []byte) (Receipt, error)`, `func VerifyReceipt(pub [32]byte, r Receipt, response []byte) bool`.

**Why this exists (§3.8).** The commitment says what exists; the receipt says what you were given. Omission is `commitment ≠ receipt`, both signed by the same key. Without it, a single server's omission is provable only to its victim — materially weaker than §1.4's claim.

**The receipt MUST cover the request parameters**, block hash and any client-supplied dust threshold, or a server can satisfy a request by replaying an older response.

- [ ] **Step 1: Write the failing test**

```go
// internal/canary/receipt_test.go
package canary

import (
	"encoding/hex"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func testReceiptSigner(t *testing.T) (*Publisher, [32]byte) {
	t.Helper()
	skHex := nostr.GeneratePrivateKey()
	b, _ := hex.DecodeString(skHex)
	var sk [32]byte
	copy(sk[:], b)

	pubHex, err := nostr.GetPublicKey(skHex)
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := hex.DecodeString(pubHex)
	var pub [32]byte
	copy(pub[:], pb)

	return &Publisher{sk: sk}, pub
}

func TestReceiptVerifies(t *testing.T) {
	p, pub := testReceiptSigner(t)
	var bh [32]byte
	bh[0] = 0x33
	response := []byte("the exact bytes served")

	r, err := p.SignReceipt(bh, 1000, response)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyReceipt(pub, r, response) {
		t.Error("a freshly signed receipt must verify")
	}
}

func TestReceiptRejectsADifferentResponse(t *testing.T) {
	p, pub := testReceiptSigner(t)
	var bh [32]byte
	r, err := p.SignReceipt(bh, 0, []byte("served"))
	if err != nil {
		t.Fatal(err)
	}
	if VerifyReceipt(pub, r, []byte("something else")) {
		t.Error("a receipt must not verify against a different response body")
	}
}

func TestReceiptBindsRequestParameters(t *testing.T) {
	p, pub := testReceiptSigner(t)
	response := []byte("served")

	var bh [32]byte
	bh[0] = 0x01
	r, err := p.SignReceipt(bh, 1000, response)
	if err != nil {
		t.Fatal(err)
	}

	// Replaying this receipt for a different block must fail, or a server can
	// satisfy any request by handing back an older response (§3.8).
	replayed := r
	replayed.BlockHash[0] = 0x02
	if VerifyReceipt(pub, replayed, response) {
		t.Error("a receipt must bind the block hash")
	}

	// The client-supplied dust threshold is a request parameter too.
	replayed = r
	replayed.DustThresholdSat = 5000
	if VerifyReceipt(pub, replayed, response) {
		t.Error("a receipt must bind the client-supplied dust threshold")
	}
}

func TestReceiptRejectsAnotherKey(t *testing.T) {
	p, _ := testReceiptSigner(t)
	_, otherPub := testReceiptSigner(t)
	var bh [32]byte
	r, err := p.SignReceipt(bh, 0, []byte("served"))
	if err != nil {
		t.Fatal(err)
	}
	if VerifyReceipt(otherPub, r, []byte("served")) {
		t.Error("a receipt must not verify under a different server's key")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/canary/ -run TestReceipt -v`
Expected: FAIL — `undefined: Receipt`.

- [ ] **Step 3: Write the implementation**

```go
// internal/canary/receipt.go
package canary

import (
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	bip352 "github.com/setavenger/go-bip352"
)

const tagReceipt = "canary/receipt/v1"

// Receipt is the server's signed statement about what it actually served.
//
// The commitment says what exists. The receipt says what you were given.
// Omission is commitment ≠ receipt, both signed by the same key (§3.8).
type Receipt struct {
	BlockHash        [32]byte
	DustThresholdSat uint64 // the CLIENT-supplied threshold, if any
	ResponseDigest   [32]byte
	Sig              [64]byte
}

// receiptDigest binds the request parameters and the response together.
//
// Covering the request parameters is mandatory: without them a server can
// satisfy any request by replaying an older response and its old receipt.
func receiptDigest(blockHash [32]byte, dust uint64, response []byte) [32]byte {
	body := bip352.TaggedHash(tagReceipt+"/body", response)

	buf := make([]byte, 0, 32+8+32)
	buf = append(buf, blockHash[:]...)
	var d [8]byte
	binary.LittleEndian.PutUint64(d[:], dust)
	buf = append(buf, d[:]...)
	buf = append(buf, body[:]...)

	return bip352.TaggedHash(tagReceipt, buf)
}

// SignReceipt signs over (request_params, response_digest). A Schnorr signature
// costs microseconds, and server cooperation is already assumed for
// commitments — so this is close to free (§3.8).
func (p *Publisher) SignReceipt(blockHash [32]byte, dust uint64, response []byte) (Receipt, error) {
	r := Receipt{
		BlockHash:        blockHash,
		DustThresholdSat: dust,
		ResponseDigest:   bip352.TaggedHash(tagReceipt+"/body", response),
	}

	priv, _ := btcec.PrivKeyFromBytes(p.sk[:])
	digest := receiptDigest(blockHash, dust, response)
	sig, err := schnorr.Sign(priv, digest[:])
	if err != nil {
		return Receipt{}, fmt.Errorf("canary: sign receipt: %w", err)
	}
	copy(r.Sig[:], sig.Serialize())
	return r, nil
}

// VerifyReceipt checks r against the response bytes the client actually holds.
func VerifyReceipt(pub [32]byte, r Receipt, response []byte) bool {
	if r.ResponseDigest != bip352.TaggedHash(tagReceipt+"/body", response) {
		return false
	}
	pk, err := schnorr.ParsePubKey(pub[:])
	if err != nil {
		return false
	}
	sig, err := schnorr.ParseSignature(r.Sig[:])
	if err != nil {
		return false
	}
	digest := receiptDigest(r.BlockHash, r.DustThresholdSat, response)
	return sig.Verify(digest[:], pk)
}
```

- [ ] **Step 4: Run the tests and commit**

```bash
go test ./internal/canary/ -v
git add internal/canary/receipt.go internal/canary/receipt_test.go
git commit -m "feat(canary): signed receipts over request params and response digest"
```

---

### Task 7: The deliberately malicious mode

**Files:**
- Create: `internal/canary/omit.go`
- Modify: `cmd/blindbit-oracle/flags.go`
- Test: `internal/canary/omit_test.go`

**Interfaces:**
- Consumes: `Position` from Task 5.
- Produces: `type Omitter struct { TxIDs map[[32]byte]bool }`, `func NewOmitter(displayHexes []string) (*Omitter, error)`, `func (o *Omitter) Apply(positions []Position) []Position`.

**The rules, from §8.4.** This is the demo's attack and it has to be *visibly deliberate*, so it is one flag in our fork with visible help text. It targets a txid rather than an address, because an indexer cannot select by address without the scan key, and demonstrating an address filter would concede §1.2's premise. And the malicious server **keeps publishing honest commitments** — the whole point of act 3 is that it is caught against its own signature.

- [ ] **Step 1: Write the failing test**

```go
// internal/canary/omit_test.go
package canary

import (
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/wire"
)

func leafWithTxIDByte(b byte) canonical.Leaf {
	var l canonical.Leaf
	l.TxID[0] = b // internal order
	l.Tweak[0] = 0x02
	return l
}

func TestOmitterDropsOnlyTheTargetedPosition(t *testing.T) {
	target := leafWithTxIDByte(0xAA)

	// The flag takes DISPLAY hex, because that is what a human copies from an
	// explorer. Internally the leaf is in internal order, so the omitter must
	// convert — the same boundary as everywhere else.
	var display [32]byte
	for i := 0; i < 32; i++ {
		display[i] = target.TxID[31-i]
	}
	o, err := NewOmitter([]string{hexOf(display)})
	if err != nil {
		t.Fatal(err)
	}

	in := []wire.Position{
		{Kind: wire.KindFull, Leaf: leafWithTxIDByte(0x01)},
		{Kind: wire.KindFull, Leaf: target},
		{Kind: wire.KindFull, Leaf: leafWithTxIDByte(0x03)},
	}
	out := o.Apply(in)

	if len(out) != 3 {
		t.Fatalf("got %d positions, want 3 — the list stays exactly n long (§2.4)", len(out))
	}
	if out[0].Kind != wire.KindFull || out[2].Kind != wire.KindFull {
		t.Error("untargeted positions must be untouched")
	}
	if out[1].Kind != wire.KindAbsent {
		t.Errorf("targeted position kind = %v, want KindAbsent", out[1].Kind)
	}
}

func TestOmitterLeavesLengthAndOrderIntact(t *testing.T) {
	o, err := NewOmitter(nil)
	if err != nil {
		t.Fatal(err)
	}
	in := []wire.Position{
		{Kind: wire.KindFull, Leaf: leafWithTxIDByte(1)},
		{Kind: wire.KindHash},
	}
	out := o.Apply(in)
	if len(out) != len(in) {
		t.Error("an omitter with no targets must be a no-op")
	}
}

func TestNewOmitterRejectsBadHex(t *testing.T) {
	if _, err := NewOmitter([]string{"nonsense"}); err == nil {
		t.Error("a malformed txid must fail at startup, not silently disable the attack")
	}
	if _, err := NewOmitter([]string{strings.Repeat("ab", 31)}); err == nil {
		t.Error("a 31-byte txid must be rejected")
	}
}
```

Add the small helper next to the test:

```go
func hexOf(b [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0x0f]
	}
	return string(out)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/canary/ -run 'TestOmitter|TestNewOmitter' -v`
Expected: FAIL — `undefined: Omitter`.

- [ ] **Step 3: Write the implementation**

```go
// internal/canary/omit.go
//
// The deliberately malicious mode. Isolated in one file, on purpose, so a
// reviewer can see the whole attack surface at once and so §8.2's act 2 has
// something short to put on screen.
//
// Two properties this must preserve, or the demo argues against itself:
//
//  1. The list stays exactly n long. The omitted position becomes KindAbsent,
//     not a gap in the sequence — a merely shorter response is indistinguishable
//     from a smaller block, which is a different and weaker attack (§2.4).
//  2. The server keeps publishing HONEST commitments. Act 3 works because the
//     server is caught against its own signature; committing to the omitted set
//     instead is the other branch, caught by rung 1 (§8.4, §8.7).
package canary

import (
	"encoding/hex"
	"fmt"

	"github.com/Sky-walkerX/canary/wire"
)

// Omitter drops specific transactions from responses.
//
// It targets txids, never addresses. An indexer cannot select by address —
// that requires the scan key it does not have — so an address filter would
// quietly concede the premise the whole threat model rests on (§1.2, §8.4).
type Omitter struct {
	TxIDs map[[32]byte]bool // keyed in INTERNAL byte order
}

// NewOmitter takes txids in DISPLAY hex, the form a human copies from a block
// explorer, and converts them to internal order once.
func NewOmitter(displayHexes []string) (*Omitter, error) {
	o := &Omitter{TxIDs: map[[32]byte]bool{}}
	for _, s := range displayHexes {
		raw, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("--omit-txid %q: %w", s, err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("--omit-txid %q: want 32 bytes, got %d", s, len(raw))
		}
		var internal [32]byte
		for i := 0; i < 32; i++ {
			internal[i] = raw[31-i]
		}
		o.TxIDs[internal] = true
	}
	return o, nil
}

// Apply blanks the targeted positions, preserving length and order.
func (o *Omitter) Apply(positions []wire.Position) []wire.Position {
	if len(o.TxIDs) == 0 {
		return positions
	}
	out := make([]wire.Position, len(positions))
	copy(out, positions)
	for i, p := range out {
		if p.Kind != wire.KindFull {
			continue
		}
		if o.TxIDs[p.Leaf.TxID] {
			out[i] = wire.Position{Kind: wire.KindAbsent}
		}
	}
	return out
}
```

- [ ] **Step 4: Add the flags with visible help text**

The help text is part of the demo. A judge watching act 2 should be able to read what the flag does without narration.

```go
// cmd/blindbit-oracle/flags.go — additions
rootCmd.PersistentFlags().Bool("commit", false,
	"publish a signed per-block commitment to the canonical tweak set (Canary, §2.1)")
rootCmd.PersistentFlags().String("canary-nsec-file", "",
	"path to the file holding the Nostr secret key used to sign commitments and receipts")
rootCmd.PersistentFlags().StringSlice("canary-relays", nil,
	"Nostr relay URLs to publish commitments to")
rootCmd.PersistentFlags().StringSlice("omit-txid", nil,
	"DELIBERATELY MALICIOUS: withhold these txids from tweak responses while still "+
		"publishing honest commitments. Demonstration only — this is the attack Canary detects.")
```

- [ ] **Step 5: Run the tests and commit**

```bash
go test ./... -v
git add internal/canary/omit.go internal/canary/omit_test.go cmd/blindbit-oracle/flags.go
git commit -m "feat(canary): deliberately malicious --omit-txid mode"
```

---

### Task 8: End-to-end on regtest

**Files:**
- Create: `scripts/e2e-regtest.sh`

**Interfaces:**
- Consumes: everything above.
- Produces: a reproducible script that stands up Core, a relay, and two oracles — one honest, one omitting — which is the shape §8 records.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# scripts/e2e-regtest.sh — stand up the full loop on regtest.
#
# Two oracles against one node: one honest, one omitting a chosen txid while
# still publishing honest commitments. That second property is what makes the
# omission catchable from a single server (§8.4).
set -euo pipefail

DATA=${DATA:-/tmp/canary-e2e}
rm -rf "$DATA" && mkdir -p "$DATA"/{core,honest,evil,relay}

bitcoind -regtest -datadir="$DATA/core" -daemon -rest=1 -txindex=1 -fallbackfee=0.0001
sleep 2
bitcoin-cli -regtest -datadir="$DATA/core" createwallet canary
ADDR=$(bitcoin-cli -regtest -datadir="$DATA/core" getnewaddress '' bech32m)
bitcoin-cli -regtest -datadir="$DATA/core" generatetoaddress 200 "$ADDR"

# A local relay, because depending on a public one is the fragility this
# project is about (prior art §5).
nostr-rs-relay --db "$DATA/relay" &
RELAY_PID=$!
trap 'kill $RELAY_PID 2>/dev/null || true' EXIT
sleep 1

# Generate two signing keys. Never committed, never passed as a flag.
openssl rand -hex 32 > "$DATA/honest/nsec"
openssl rand -hex 32 > "$DATA/evil/nsec"
chmod 600 "$DATA"/*/nsec

for role in honest evil; do
  cat > "$DATA/$role/blindbit.toml" <<'TOML'
tweaks_only = 0
tweaks_full_basic = 1
TOML
done

./blindbit-oracle --datadir "$DATA/honest" \
  --commit --canary-nsec-file "$DATA/honest/nsec" \
  --canary-relays ws://localhost:8080 run &

echo "Honest oracle up. Send a payment, note its txid, then start the evil one:"
echo "  ./blindbit-oracle --datadir $DATA/evil --commit \\"
echo "    --canary-nsec-file $DATA/evil/nsec \\"
echo "    --canary-relays ws://localhost:8080 --omit-txid <TXID> run"
wait
```

- [ ] **Step 2: Run it and confirm both oracles publish**

```bash
chmod +x scripts/e2e-regtest.sh
./scripts/e2e-regtest.sh
```

Expected: both oracles index to the tip and publish one kind-1352 event per block to the local relay, including for empty blocks. Verify with any Nostr client, or by querying the relay for `{"kinds":[1352]}`.

- [ ] **Step 3: Commit**

```bash
git add scripts/e2e-regtest.sh
git commit -m "chore: regtest end-to-end script with an honest and an omitting oracle"
```

---

## Definition of done

- [ ] `go test ./...` passes in the fork, including the independence guard.
- [ ] The fork indexes regtest and publishes one kind-1352 event per block, empty blocks included.
- [ ] `GET /commitment/:blockhash` returns the raw signed event.
- [ ] Responses are self-describing at length `n`, and truncation fails to decode.
- [ ] Leaf hashes are retained within 144 blocks of the tip and pruned beyond it; the 36-byte records are never pruned.
- [ ] `--omit-txid` withholds a transaction while commitments stay honest.
- [ ] No `canonical.Set` call anywhere in the fork's non-test code.

**Handoff:** Plan C's ladder consumes the wire response, the commitment feed, and `GET /commitment/:blockhash`. The contract between the two plans is the core's `wire` package (Plan A Task 15), which both sides import rather than either owning.
