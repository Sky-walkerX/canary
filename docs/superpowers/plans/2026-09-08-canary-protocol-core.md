# Canary Protocol Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Go library both other Canary tracks consume — the canonical BIP-352 tweak set for a block, the Merkle commitment over it, the policy declaration, and the Nostr transport.

**Architecture:** Four packages with no dependencies on each other except `commit` needing `canonical.Leaf`. `canonical` is a pure function of a block and its prevouts. `commit` is tagged hashing and a Merkle tree. `policy` is a struct plus a parser for blindbit's `/info`. `feed` maps a commitment onto a signed Nostr event and back. Nothing in this plan opens a socket except `feed`'s relay client, and that is behind an interface so every other test runs offline.

**Tech Stack:** Go 1.24.1+, `github.com/setavenger/go-bip352` v0.1.8 (BIP-352 primitives), `github.com/btcsuite/btcd` **v0.25.0** (block and transaction parsing), `github.com/nbd-wtf/go-nostr` v0.52.3 (events and relays).

**Spec:** [`docs/design/2026-09-06-canary-design.md`](../../design/2026-09-06-canary-design.md) — read §2, §3, §6.3 and §7 before starting. This plan argues from that document and cites it by section throughout.

**Owner:** Naman (§6.5). **Weeks 1–2** of the four-week clock (§6.6).

## Global Constraints

Every task's requirements implicitly include this section. Values are copied verbatim from the spec; do not paraphrase them into code.

- **Module path:** `github.com/Sky-walkerX/canary`. **Go directive:** `go 1.24.1` — blindbit-oracle requires 1.24.1+, and the indexer fork shares these packages. The patch level is not decoration: `go-nostr` v0.52.3 declares `go 1.24.1`, so a bare `go 1.24` fails to build.
- **btcd is pinned to v0.25.0, and the pin is load-bearing.** v0.26.0 moved `wire`, `chaincfg` and `txscript` out of the root module into separate `/v2` modules, so on v0.26.x every `github.com/btcsuite/btcd/wire` import in this plan fails to resolve. `go-bip352` also imports the root-module `chaincfg` and cannot resolve against v0.26.x at all. Never `go get github.com/btcsuite/btcd` without a version.
- **btcec is pinned to v2.4.0** — the newest release that does not declare `go 1.25`, which would raise the floor above the line above. btcd v0.25.0 requires v2.3.5, so v2.4.0 satisfies the graph.
- **BIP-352 library:** `github.com/setavenger/go-bip352` v0.1.8, imported as `bip352`. **NOT `github.com/setavenger/gobip352`** — that path is v0.1.4 and does not export `ExtractEligibleVins` or `ExtractPubKey` (§6.4). Task 1 installs a guard test against this.
- **Tagged-hash tags, exact strings:** `canary/leaf/v1`, `canary/node/v1`, `canary/root/v1`. `bip352.TaggedHash` is a verified BIP-340 tagged hash and is the only hash constructor used.
- **Leaf preimage:** `txid ‖ tweak` = 32 + 33 bytes. `txid` is **internal byte order**. `tweak` is 33-byte compressed SEC (§3.2).
- **Root preimage:** `network ‖ block_hash ‖ n_le32 ‖ merkle_root` = 4 + 32 + 4 + 32 bytes. `block_hash` is **internal byte order**. `n_le32` is unsigned little-endian (§3.2).
- **`network` is the 4-byte P2P message-start magic**, the little-endian encoding of btcd's `wire.BitcoinNet`, read from `chaincfg.Params.Net` and never from a literal (§3.2).
- **Odd Merkle nodes are promoted, never duplicated** — CVE-2012-2459 (§3.2).
- **`merkle_root(∅)` is 32 zero bytes**; `merkle_root` of a single leaf is that leaf's hash (§3.2).
- **Nostr kind 1352**, in the regular range 1000–9999 so events are append-only. **Never** a replaceable (10000–19999) or parameterized replaceable (30000–39999) kind — that would void non-repudiation (§3.3).
- **Block hash travels in the single-letter `b` tag**, display hex. Relays index single-letter tag names only (§3.3).
- **`created_at` is never trusted** for ordering or freshness (§3.5).
- **Interfaces freeze on day 2.** §6.3 is the contract. Changing a signature in this plan requires amending the spec first, because two other tracks are compiling against it (§6.3, §6.6).
- **Never commit secrets.** `nsec*`, `*.key`, `*.pem`, `.env`, `blindbit.toml`, `bitcoin.conf` are gitignored. Test keys are generated in-test, never checked in.

---

## File Structure

| Path | Responsibility |
|---|---|
| `go.mod`, `go.sum` | Module and pinned dependencies |
| `Makefile` | `make test`, `make vet`, `make vectors` |
| `.github/workflows/ci.yml` | `go vet ./...` and `go test ./...`, hermetic — no node, no network |
| `canonical/canonical.go` | §2.2's `T_base`: `Set`, `Leaf`, `Network`, `PrevoutSource` |
| `canonical/vin.go` | The `bip352.Vin` adapter and the byte-order boundary — the only place a txid is reversed |
| `canonical/eligible.go` | Per-transaction eligibility and tweak derivation |
| `commit/hash.go` | Leaf and node tagged hashes |
| `commit/tree.go` | Merkle root, promotion, the `n = 0` and `n = 1` base cases |
| `commit/proof.go` | `Prove`, `VerifyProof`, the `Proof` type |
| `commit/root.go` | `Root` — the outer preimage that binds network, block hash and `n` |
| `policy/policy.go` | §2.3's `Policy` struct |
| `policy/blindbit.go` | `FromBlindBitInfo` — the tool-first bridge over `GET /info` |
| `feed/commitment.go` | `Commitment`, `ToEvent`, `FromEvent` |
| `feed/feed.go` | The `Feed` interface, relay client, batched `Get` |
| `wire/response.go` | §2.4's self-describing position list — shared by the indexer fork and the sidecar |
| `internal/testvector/vector.go` | §7.4's JSON format: loader and generator |
| `testdata/vectors/*.json` | Golden vectors, committed, consumed by `go test` with no node |

Files that change together live together: the byte-order boundary lives beside the adapter that crosses it, and the proof code lives beside the tree it proves against.

---

### Task 1: Module scaffold, pinned dependencies, and the frozen §6.3 interfaces

**Files:**
- Create: `go.mod`, `Makefile`, `.github/workflows/ci.yml`
- Create: `canonical/canonical.go`, `commit/proof.go`, `policy/policy.go`, `feed/commitment.go`
- Test: `deps_guard_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: every type in §6.3, compiling with stub bodies. Later tasks fill the bodies and must not change the signatures.

- [ ] **Step 1: Initialise the module and pin dependencies**

```bash
cd /Users/skywalker/Coding/Dev/Hackathons/BOSS/canary
go mod init github.com/Sky-walkerX/canary
go get github.com/setavenger/go-bip352@v0.1.8
go get github.com/btcsuite/btcd@v0.25.0
go get github.com/btcsuite/btcd/btcec/v2@v2.4.0
go get github.com/btcsuite/btcd/chaincfg/chainhash
go get github.com/nbd-wtf/go-nostr
```

Then set the directive by hand — `go mod init` writes whatever toolchain is
installed locally, which on a 1.26 machine is not the floor this module promises:

```bash
# go.mod must read exactly: go 1.24.1
# Delete any `toolchain` line go get adds. CI pins go-version 1.24; a toolchain
# line makes that runner download a different Go anyway, defeating the pin.
```

**Do not run `go mod tidy` yet.** Tidy prunes requirements nothing imports, and at
this point nothing imports anything — it would delete all four requires, including
the `go-bip352` line Step 3's guard test is about to assert. Tidy once Step 4's
stubs exist; Step 2's guard test is what keeps `go-bip352` in the graph until
Task 2 imports it for the leaf hash.

- [ ] **Step 2: Write the guard test that fails on the wrong BIP-352 library**

This test exists because the spec originally named the wrong import path, and the wrong path compiles right up until you reach for eligibility. `go.mod` is read as data so the test cannot be satisfied by an unused import.

It has a second half. The file also references `ExtractEligibleVins` and `ExtractPubKey` directly, the two symbols the old `gobip352` module does not export. That makes a swapped module a compile error rather than a quiet loss of the eligibility layer, and it gives the dependency a real edge in the module graph so `go mod tidy` cannot prune the requirement the text assertion checks for.

```go
// deps_guard_test.go
package canary_test

import (
	"os"
	"strings"
	"testing"

	bip352 "github.com/setavenger/go-bip352"
)

func TestUsesRenamedBIP352Library(t *testing.T) {
	b, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	mod := string(b)

	if !strings.Contains(mod, "github.com/setavenger/go-bip352") {
		t.Error("go.mod must require github.com/setavenger/go-bip352 (§6.4)")
	}
	// The old path is a prefix-free distinct module. It is v0.1.4 and does not
	// export ExtractEligibleVins or ExtractPubKey — depending on it silently
	// removes the input-eligibility layer.
	for _, line := range strings.Split(mod, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "github.com/setavenger/gobip352" {
			t.Error("go.mod requires the OLD gobip352 path; it lacks ExtractEligibleVins (§6.4)")
		}
	}
}

// The check above reads go.mod as data, so an unused import cannot satisfy it.
// These two references are the complementary half: the old gobip352 path exports
// neither symbol, so aiming the module at it fails to compile here instead of
// silently deleting the eligibility layer (§6.4). They also give the dependency a
// real edge in the module graph before Task 2 imports it for the leaf hash, so
// `go mod tidy` cannot prune the very requirement the test above asserts.
var (
	_ = bip352.ExtractEligibleVins
	_ = bip352.ExtractPubKey
)

func TestNumsHIsThirtyTwoBytes(t *testing.T) {
	// §2.2 excludes script-path spends whose internal key is H. The exclusion is
	// only meaningful if the pinned library's H is the x-only 32-byte form.
	if len(bip352.NumsH) != 32 {
		t.Errorf("NumsH must be the 32-byte x-only NUMS point, got %d bytes", len(bip352.NumsH))
	}
}
```

- [ ] **Step 3: Run the guard test to verify it passes**

Run: `go test -run TestUsesRenamedBIP352Library ./...`
Expected: PASS. If it fails, `go.mod` is wrong — fix `go.mod`, not the test.

- [ ] **Step 4: Write the frozen type definitions with stub bodies**

```go
// canonical/canonical.go
// Package canonical computes T_base(block) — the policy-free BIP-352 tweak set
// for a block. Spec §2.2.
package canonical

import (
	"errors"

	"github.com/btcsuite/btcd/wire"
)

// Network is the P2P message-start magic, per §3.2. Read it from
// chaincfg.Params.Net; never write a literal.
type Network uint32

// Leaf is one entry of the canonical set, in transaction-index order.
type Leaf struct {
	TxID  [32]byte // INTERNAL byte order (§3.2)
	Tweak [33]byte // compressed SEC
}

// PrevoutSource supplies the spent outputs a block does not carry itself.
type PrevoutSource interface {
	Prevout(op wire.OutPoint) (*wire.TxOut, error)
}

var errNotImplemented = errors.New("canonical: not implemented")

// Set returns the canonical leaves of blk in transaction-index order. §2.2.
func Set(net Network, blk *wire.MsgBlock, pv PrevoutSource) ([]Leaf, error) {
	return nil, errNotImplemented
}
```

```go
// commit/proof.go
// Package commit builds the Merkle commitment over a canonical set. Spec §3.2.
package commit

import (
	"errors"

	"github.com/Sky-walkerX/canary/canonical"
)

// Proof is an inclusion proof for one position in the canonical order.
type Proof struct {
	Index    uint32     // position in canonical order
	N        uint32     // set size — bound into the root, so a proof cannot be replayed
	Siblings [][32]byte // bottom-up
}

var errNotImplemented = errors.New("commit: not implemented")

// Root computes the commitment root over leaves for the given block. §3.2.
func Root(net canonical.Network, blockHash [32]byte, leaves []canonical.Leaf) [32]byte {
	return [32]byte{}
}

// Prove builds an inclusion proof for position i.
func Prove(leaves []canonical.Leaf, i uint32) (Proof, error) {
	return Proof{}, errNotImplemented
}

// VerifyProof checks p against root without needing the full leaf set.
func VerifyProof(net canonical.Network, blockHash, root [32]byte, leaf canonical.Leaf, p Proof) bool {
	return false
}
```

```go
// policy/policy.go
// Package policy holds a server's declared, subtractive index policy. Spec §2.3.
package policy

import (
	"errors"
	"io"

	"github.com/Sky-walkerX/canary/canonical"
)

// Policy is every field a server may declare. Every field is subtractive.
type Policy struct {
	Network          canonical.Network
	StartHeight      uint32
	PrunesSpent      bool
	DustThresholdSat uint64 // declared, never verified (§2.3)
	DustConfigurable bool
}

var errNotImplemented = errors.New("policy: not implemented")

// FromBlindBitInfo derives a Policy from blindbit-oracle's GET /info body.
// This is the tool-first bridge: unsigned, not per-block, strictly weaker
// than the signed per-block policy of the protocol layer (§2.3).
func FromBlindBitInfo(r io.Reader) (Policy, error) {
	return Policy{}, errNotImplemented
}
```

```go
// feed/commitment.go
// Package feed carries commitments over Nostr. Spec §3.3, §3.4.
package feed

import (
	"errors"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/nbd-wtf/go-nostr"
)

// KindCommitment is a regular kind (1000–9999), therefore append-only.
// A replaceable kind here would void non-repudiation entirely (§3.3).
const KindCommitment = 1352

// TagBlockHash is single-letter because relays index nothing else (§3.3).
const TagBlockHash = "b"

// Commitment is one server's signed statement about one block.
type Commitment struct {
	Network     canonical.Network
	BlockHash   [32]byte
	BlockHeight uint32
	N           uint32
	Root        [32]byte
	PolicyRef   [32]byte // event id of the policy declaration in force
	Author      [32]byte // Nostr pubkey — implicit signer
}

var errNotImplemented = errors.New("feed: not implemented")

// ToEvent builds and signs the Nostr event carrying c.
func (c Commitment) ToEvent(sk [32]byte) (nostr.Event, error) {
	return nostr.Event{}, errNotImplemented
}

// FromEvent parses and verifies an event into a Commitment.
func FromEvent(e nostr.Event) (Commitment, error) {
	return Commitment{}, errNotImplemented
}
```

- [ ] **Step 5: Write the Makefile and CI workflow**

```makefile
# Makefile
.PHONY: test vet vectors

test:
	go test ./...

vet:
	go vet ./...

# Regenerates testdata/vectors from a local regtest node. Dev-time only —
# CI consumes the committed JSON and never runs this (§7.4).
vectors:
	go run ./internal/testvector/cmd/genvectors
```

```yaml
# .github/workflows/ci.yml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      - run: go vet ./...
      # Hermetic: no Bitcoin Core, no network, no relay. §7.4.
      - run: go test ./...
```

- [ ] **Step 6: Verify everything compiles and the guard passes**

Run: `go vet ./... && go test ./...`
Expected: PASS. No test asserts behaviour yet beyond the dependency guard.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum Makefile .github canonical commit policy feed deps_guard_test.go
git commit -m "feat: module scaffold and the frozen §6.3 interfaces"
```

---

### Task 2: The leaf hash

**Files:**
- Create: `commit/hash.go`
- Test: `commit/hash_test.go`

**Interfaces:**
- Consumes: `canonical.Leaf` from Task 1.
- Produces: `func LeafHash(l canonical.Leaf) [32]byte` and `func nodeHash(l, r [32]byte) [32]byte`. `LeafHash` is exported because the sidecar hashes candidate leaves during gap resolution (§2.5 step 2); `nodeHash` stays package-private.

- [ ] **Step 1: Write the failing test**

The expected value is computed independently, from the tag and preimage rather than from our own implementation, so the test would catch a wrong tag string or a swapped concatenation.

```go
// commit/hash_test.go
package commit

import (
	"crypto/sha256"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
)

// bip340 recomputes the tagged hash from first principles so the test does not
// simply agree with whatever our implementation does.
func bip340(tag string, msg []byte) [32]byte {
	t := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(t[:])
	h.Write(t[:])
	h.Write(msg)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func TestLeafHashMatchesTaggedPreimage(t *testing.T) {
	var l canonical.Leaf
	for i := range l.TxID {
		l.TxID[i] = byte(i)
	}
	for i := range l.Tweak {
		l.Tweak[i] = byte(0x40 + i)
	}

	preimage := append(append([]byte{}, l.TxID[:]...), l.Tweak[:]...)
	if len(preimage) != 65 {
		t.Fatalf("preimage must be 32+33=65 bytes, got %d", len(preimage))
	}
	want := bip340("canary/leaf/v1", preimage)

	if got := LeafHash(l); got != want {
		t.Errorf("LeafHash = %x, want %x", got, want)
	}
}

func TestNodeHashIsOrderSensitive(t *testing.T) {
	a := [32]byte{1}
	b := [32]byte{2}
	if nodeHash(a, b) == nodeHash(b, a) {
		t.Error("nodeHash must not be commutative — order carries position")
	}
}

func TestLeafAndNodeTagsAreDistinct(t *testing.T) {
	// A 65-byte node preimage is impossible, but the point is that the two
	// domains never collide even if an attacker contrives equal inputs.
	var l canonical.Leaf
	lh := LeafHash(l)
	var zero [32]byte
	if lh == nodeHash(zero, zero) {
		t.Error("leaf and node domains collide")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./commit/ -run 'TestLeafHash|TestNodeHash|TestLeafAndNode' -v`
Expected: FAIL — `undefined: LeafHash`, `undefined: nodeHash`.

- [ ] **Step 3: Write the implementation**

```go
// commit/hash.go
package commit

import (
	"github.com/Sky-walkerX/canary/canonical"
	bip352 "github.com/setavenger/go-bip352"
)

// Tag strings are fixed by §3.2. Changing one is a protocol fork.
const (
	tagLeaf = "canary/leaf/v1"
	tagNode = "canary/node/v1"
	tagRoot = "canary/root/v1"
)

// LeafHash hashes one canonical leaf. The preimage is txid ‖ tweak, 32+33
// bytes, with the txid in INTERNAL byte order (§3.2). Exported because gap
// resolution hashes candidate leaves recovered from other servers (§2.5).
func LeafHash(l canonical.Leaf) [32]byte {
	buf := make([]byte, 0, 65)
	buf = append(buf, l.TxID[:]...)
	buf = append(buf, l.Tweak[:]...)
	return bip352.TaggedHash(tagLeaf, buf)
}

// nodeHash hashes an internal node. A distinct tag from the leaf domain is
// what makes second-preimage substitution impossible (§3.2).
func nodeHash(left, right [32]byte) [32]byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, left[:]...)
	buf = append(buf, right[:]...)
	return bip352.TaggedHash(tagNode, buf)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./commit/ -v`
Expected: PASS, three tests.

- [ ] **Step 5: Commit**

```bash
git add commit/hash.go commit/hash_test.go
git commit -m "feat(commit): leaf and node tagged hashes"
```

---

### Task 3: The Merkle tree — promotion, and the `n = 0` and `n = 1` base cases

**Files:**
- Create: `commit/tree.go`
- Test: `commit/tree_test.go`

**Interfaces:**
- Consumes: `LeafHash`, `nodeHash` from Task 2.
- Produces: `func merkleRoot(leaves []canonical.Leaf) [32]byte` (package-private) and `func levels(leaves []canonical.Leaf) [][][32]byte`, which Task 5's `Prove` walks.

- [ ] **Step 1: Write the failing test**

The `n = 0` case is first because §3.2 calls it the common case, not a corner, and §7.4's own example vector needs it.

```go
// commit/tree_test.go
package commit

import (
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
)

func mkLeaves(n int) []canonical.Leaf {
	out := make([]canonical.Leaf, n)
	for i := range out {
		out[i].TxID[0] = byte(i + 1)
		out[i].Tweak[0] = byte(0x80 + i)
	}
	return out
}

func TestMerkleRootEmptyIsZeroes(t *testing.T) {
	var zero [32]byte
	if got := merkleRoot(nil); got != zero {
		t.Errorf("merkleRoot(∅) = %x, want 32 zero bytes (§3.2)", got)
	}
	if got := merkleRoot([]canonical.Leaf{}); got != zero {
		t.Errorf("merkleRoot(empty slice) = %x, want 32 zero bytes", got)
	}
}

func TestMerkleRootSingleLeafIsThatLeafHash(t *testing.T) {
	l := mkLeaves(1)
	if got, want := merkleRoot(l), LeafHash(l[0]); got != want {
		t.Errorf("merkleRoot(1 leaf) = %x, want the leaf hash %x (§3.2)", got, want)
	}
}

// The CVE-2012-2459 guard. Duplicating an unpaired node would make these two
// sets produce the same root; promotion keeps them distinct.
func TestOddNodeIsPromotedNotDuplicated(t *testing.T) {
	three := mkLeaves(3)

	// What a *duplicating* implementation would compute for n=3.
	h := []([32]byte){LeafHash(three[0]), LeafHash(three[1]), LeafHash(three[2])}
	dupL1 := []([32]byte){nodeHash(h[0], h[1]), nodeHash(h[2], h[2])}
	duplicated := nodeHash(dupL1[0], dupL1[1])

	if got := merkleRoot(three); got == duplicated {
		t.Error("odd node was duplicated; §3.2 requires promotion (CVE-2012-2459)")
	}

	// What promotion should compute: h2 rides up untouched.
	promoted := nodeHash(nodeHash(h[0], h[1]), h[2])
	if got := merkleRoot(three); got != promoted {
		t.Errorf("merkleRoot(3) = %x, want promoted %x", got, promoted)
	}
}

func TestMerkleRootDistinctAcrossSizes(t *testing.T) {
	seen := map[[32]byte]int{}
	for _, n := range []int{0, 1, 2, 3, 4, 5, 8, 9, 16, 17} {
		r := merkleRoot(mkLeaves(n))
		if prev, dup := seen[r]; dup {
			t.Errorf("root collision between n=%d and n=%d", prev, n)
		}
		seen[r] = n
	}
}

func TestPermutationChangesRoot(t *testing.T) {
	a := mkLeaves(4)
	b := mkLeaves(4)
	b[0], b[1] = b[1], b[0]
	if merkleRoot(a) == merkleRoot(b) {
		t.Error("permuting leaves must change the root — §2.2 chose transaction order deliberately")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./commit/ -run 'TestMerkle|TestOddNode|TestPermutation' -v`
Expected: FAIL — `undefined: merkleRoot`.

- [ ] **Step 3: Write the implementation**

```go
// commit/tree.go
package commit

import "github.com/Sky-walkerX/canary/canonical"

// levels builds the tree bottom-up and returns every level, level 0 being the
// leaf hashes. Prove walks this. An empty set has no levels at all.
//
// Unpaired nodes are PROMOTED to the next level untouched, never duplicated.
// Duplication is CVE-2012-2459 (§3.2).
func levels(leaves []canonical.Leaf) [][][32]byte {
	if len(leaves) == 0 {
		return nil
	}

	cur := make([][32]byte, len(leaves))
	for i, l := range leaves {
		cur[i] = LeafHash(l)
	}

	out := [][][32]byte{cur}
	for len(cur) > 1 {
		next := make([][32]byte, 0, (len(cur)+1)/2)
		for i := 0; i+1 < len(cur); i += 2 {
			next = append(next, nodeHash(cur[i], cur[i+1]))
		}
		if len(cur)%2 == 1 {
			next = append(next, cur[len(cur)-1]) // promotion
		}
		out = append(out, next)
		cur = next
	}
	return out
}

// merkleRoot is the inner root, before §3.2's outer tagged hash.
//
// The empty set is 32 zero bytes. That is safe rather than sloppy because the
// outer preimage binds n, so an n=0 root cannot collide with any n≥1 root for
// the same block — and it avoids inventing a fourth tag (§3.2).
func merkleRoot(leaves []canonical.Leaf) [32]byte {
	ls := levels(leaves)
	if len(ls) == 0 {
		return [32]byte{}
	}
	top := ls[len(ls)-1]
	return top[0]
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./commit/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add commit/tree.go commit/tree_test.go
git commit -m "feat(commit): merkle tree with promotion and the n=0/n=1 base cases"
```

---

### Task 4: `Root` — the outer preimage that binds network, block hash and `n`

**Files:**
- Create: `commit/root.go`
- Modify: `commit/proof.go:23-26` — delete the `Root` stub, which now lives in `root.go`
- Test: `commit/root_test.go`

**Interfaces:**
- Consumes: `merkleRoot` from Task 3.
- Produces: `func Root(net canonical.Network, blockHash [32]byte, leaves []canonical.Leaf) [32]byte`, matching §6.3 exactly.

- [ ] **Step 1: Write the failing test**

```go
// commit/root_test.go
package commit

import (
	"encoding/binary"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/btcsuite/btcd/chaincfg"
)

const (
	netMain    = canonical.Network(0xd9b4bef9) // wire bytes f9 be b4 d9
	netRegtest = canonical.Network(0xdab5bffa) // wire bytes fa bf b5 da
)

func TestRootBindsNetworkBlockHashAndN(t *testing.T) {
	leaves := mkLeaves(3)
	var bh [32]byte
	bh[0] = 0xAA

	base := Root(netRegtest, bh, leaves)

	// Different network → different root. §2.7's same-network precondition
	// depends on this holding for custom signets too.
	if Root(netMain, bh, leaves) == base {
		t.Error("root must bind the network magic")
	}

	// Different block → different root, so a root cannot be replayed.
	var other [32]byte
	other[0] = 0xBB
	if Root(netRegtest, other, leaves) == base {
		t.Error("root must bind the block hash")
	}

	// Different n → different root, even though it is a prefix of the same set.
	if Root(netRegtest, bh, leaves[:2]) == base {
		t.Error("root must bind n")
	}
}

func TestRootOfEmptySetIsWellDefinedAndBlockSpecific(t *testing.T) {
	var a, b [32]byte
	a[0], b[0] = 1, 2

	ra := Root(netRegtest, a, nil)
	rb := Root(netRegtest, b, nil)

	var zero [32]byte
	if ra == zero {
		t.Error("an empty-set root is a real hash, not zeroes — only merkle_root(∅) is zeroes")
	}
	if ra == rb {
		t.Error("empty-set roots must still differ per block")
	}
}

func TestRootPreimageIsExactlySeventyTwoBytes(t *testing.T) {
	// 4 + 32 + 4 + 32. Fixed width is why no length prefixes are needed (§3.2).
	var netBuf [4]byte
	binary.LittleEndian.PutUint32(netBuf[:], uint32(netRegtest))
	if 4+32+4+32 != 72 {
		t.Fatal("arithmetic")
	}
	if netBuf != [4]byte{0xfa, 0xbf, 0xb5, 0xda} {
		t.Errorf("network LE encoding = %x, want fabfb5da (§3.2)", netBuf)
	}
}

// The magics must come from chaincfg, never from our own literals (§3.2).
func TestNetworkConstantsMatchChaincfg(t *testing.T) {
	if uint32(chaincfg.MainNetParams.Net) != uint32(netMain) {
		t.Errorf("mainnet magic drift: chaincfg %08x, test %08x", uint32(chaincfg.MainNetParams.Net), uint32(netMain))
	}
	if uint32(chaincfg.RegressionNetParams.Net) != uint32(netRegtest) {
		t.Errorf("regtest magic drift: chaincfg %08x, test %08x", uint32(chaincfg.RegressionNetParams.Net), uint32(netRegtest))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./commit/ -run TestRoot -v`
Expected: FAIL — `Root` returns the zero value from its Task 1 stub, so the binding assertions fail.

- [ ] **Step 3: Delete the stub and write the implementation**

Remove the `Root` stub from `commit/proof.go` (it was placed there in Task 1 only so the package compiled), then:

```go
// commit/root.go
package commit

import (
	"encoding/binary"

	"github.com/Sky-walkerX/canary/canonical"
	bip352 "github.com/setavenger/go-bip352"
)

// Root computes the commitment root. The preimage is
//
//	network ‖ block_hash ‖ n_le32 ‖ merkle_root      (4 + 32 + 4 + 32 = 72 bytes)
//
// every field fixed-width, so no length prefixes are needed. Binding network,
// block hash and n means a root cannot be replayed onto another block or
// reused with a different length (§3.2).
func Root(net canonical.Network, blockHash [32]byte, leaves []canonical.Leaf) [32]byte {
	inner := merkleRoot(leaves)

	buf := make([]byte, 0, 72)

	// The 4-byte P2P message-start magic, in the order it appears in a message
	// header — the little-endian encoding of wire.BitcoinNet (§3.2).
	var netBuf [4]byte
	binary.LittleEndian.PutUint32(netBuf[:], uint32(net))
	buf = append(buf, netBuf[:]...)

	buf = append(buf, blockHash[:]...) // INTERNAL byte order

	var nBuf [4]byte
	binary.LittleEndian.PutUint32(nBuf[:], uint32(len(leaves)))
	buf = append(buf, nBuf[:]...)

	buf = append(buf, inner[:]...)

	return bip352.TaggedHash(tagRoot, buf)
}
```

- [ ] **Step 4: Add the leaf-hash variant the sidecar needs**

The sidecar recomputes roots from leaf *hashes*, not leaves, because a position
filled from a server's retained hash (§2.4) never yields the leaf itself. Both
paths must agree forever, so they are written together and tested against each
other.

```go
// commit/tree.go — addition
//
// merkleRootFromHashes is merkleRoot starting from leaf hashes. Same promotion
// rule, same empty-set convention.
func merkleRootFromHashes(cur [][32]byte) [32]byte {
	if len(cur) == 0 {
		return [32]byte{}
	}
	level := make([][32]byte, len(cur))
	copy(level, cur)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i+1 < len(level); i += 2 {
			next = append(next, nodeHash(level[i], level[i+1]))
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1]) // promotion
		}
		level = next
	}
	return level[0]
}
```

Do not write the 72-byte preimage out a second time. Factor it, so the two
entry points differ only in how they reach `inner`:

```go
// commit/root.go — restructured
//
// rootFromInner builds §3.2's outer preimage. Root and RootFromLeafHashes both
// go through it: the agreement test below would catch the two drifting apart,
// but sharing the construction means they cannot drift in the first place.
func rootFromInner(net canonical.Network, blockHash [32]byte, n int, inner [32]byte) [32]byte {
	buf := make([]byte, 0, 72)
	var netBuf [4]byte
	binary.LittleEndian.PutUint32(netBuf[:], uint32(net))
	buf = append(buf, netBuf[:]...)
	buf = append(buf, blockHash[:]...) // INTERNAL byte order
	var nBuf [4]byte
	binary.LittleEndian.PutUint32(nBuf[:], uint32(n))
	buf = append(buf, nBuf[:]...)
	buf = append(buf, inner[:]...)
	return bip352.TaggedHash(tagRoot, buf)
}

// Root computes the commitment root over a block's canonical leaves. §3.2.
func Root(net canonical.Network, blockHash [32]byte, leaves []canonical.Leaf) [32]byte {
	return rootFromInner(net, blockHash, len(leaves), merkleRoot(leaves))
}

// RootFromLeafHashes is Root for a caller holding leaf hashes rather than
// leaves. §2.5's comparison needs it: a gap filled from a retained hash is
// verifiable without ever recovering the leaf.
func RootFromLeafHashes(net canonical.Network, blockHash [32]byte, leafHashes [][32]byte) [32]byte {
	return rootFromInner(net, blockHash, len(leafHashes), merkleRootFromHashes(leafHashes))
}
```

Both exported signatures are unchanged from §6.3; `rootFromInner` is private.

Add the agreement test, which is the only thing stopping the two paths drifting:

```go
// commit/root_test.go — addition
func TestRootFromLeafHashesAgreesWithRoot(t *testing.T) {
	var bh [32]byte
	bh[0] = 0x5A
	for _, n := range []int{0, 1, 2, 3, 5, 8, 9, 16, 17} {
		leaves := mkLeaves(n)
		hashes := make([][32]byte, n)
		for i, l := range leaves {
			hashes[i] = LeafHash(l)
		}
		if got, want := RootFromLeafHashes(netRegtest, bh, hashes), Root(netRegtest, bh, leaves); got != want {
			t.Errorf("n=%d: hash path %x != leaf path %x", n, got, want)
		}
	}
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./commit/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add commit/root.go commit/tree.go commit/proof.go commit/root_test.go
git commit -m "feat(commit): root binding network, block hash and n"
```

---

### Task 5: Inclusion proofs

**Files:**
- Modify: `commit/proof.go` — replace the `Prove` and `VerifyProof` stubs
- Test: `commit/proof_test.go`

**Interfaces:**
- Consumes: `levels` from Task 3, `Root` from Task 4.
- Produces: `Prove(leaves []canonical.Leaf, i uint32) (Proof, error)` and `VerifyProof(net canonical.Network, blockHash, root [32]byte, leaf canonical.Leaf, p Proof) bool`, both matching §6.3. The evidence artifact (§4.7) consumes both.

- [ ] **Step 1: Write the failing test**

```go
// commit/proof_test.go
package commit

import (
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
)

func TestProveVerifyRoundTripAllPositions(t *testing.T) {
	var bh [32]byte
	bh[0] = 0x11

	for _, n := range []int{1, 2, 3, 4, 5, 8, 9, 16, 17} {
		leaves := mkLeaves(n)
		root := Root(netRegtest, bh, leaves)
		for i := 0; i < n; i++ {
			p, err := Prove(leaves, uint32(i))
			if err != nil {
				t.Fatalf("n=%d i=%d: Prove: %v", n, i, err)
			}
			if !VerifyProof(netRegtest, bh, root, leaves[i], p) {
				t.Errorf("n=%d i=%d: proof did not verify", n, i)
			}
		}
	}
}

func TestProveRejectsOutOfRangeAndEmpty(t *testing.T) {
	if _, err := Prove(mkLeaves(3), 3); err == nil {
		t.Error("Prove must reject an index past the end")
	}
	if _, err := Prove(nil, 0); err == nil {
		t.Error("Prove must reject the empty set — there is nothing to prove")
	}
}

func TestProofDoesNotVerifyAgainstWrongContext(t *testing.T) {
	var bh, other [32]byte
	bh[0], other[0] = 1, 2

	leaves := mkLeaves(5)
	root := Root(netRegtest, bh, leaves)
	p, err := Prove(leaves, 2)
	if err != nil {
		t.Fatal(err)
	}

	if VerifyProof(netRegtest, other, root, leaves[2], p) {
		t.Error("proof verified against the wrong block hash")
	}
	if VerifyProof(netMain, bh, root, leaves[2], p) {
		t.Error("proof verified against the wrong network")
	}
	if VerifyProof(netRegtest, bh, root, leaves[3], p) {
		t.Error("proof verified for the wrong leaf")
	}

	// n is bound into the root, so a proof cannot be replayed at another size.
	bad := p
	bad.N = uint32(len(leaves)) + 1
	if VerifyProof(netRegtest, bh, root, leaves[2], bad) {
		t.Error("proof verified with a tampered N")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./commit/ -run 'TestProve|TestProof' -v`
Expected: FAIL — the stubs return `errNotImplemented` and `false`.

- [ ] **Step 3: Write the implementation**

```go
// commit/proof.go
package commit

import (
	"encoding/binary"
	"errors"

	"github.com/Sky-walkerX/canary/canonical"
	bip352 "github.com/setavenger/go-bip352"
)

// Proof is an inclusion proof for one position in the canonical order.
type Proof struct {
	Index    uint32     // position in canonical order
	N        uint32     // set size — bound into the root, so a proof cannot be replayed
	Siblings [][32]byte // bottom-up
}

var (
	ErrIndexOutOfRange = errors.New("commit: leaf index out of range")
	ErrEmptySet        = errors.New("commit: nothing to prove in an empty set")
)

// Prove builds an inclusion proof for position i. A promoted node contributes
// no sibling at its level, which is why Siblings is shorter than the tree is
// tall for some positions.
func Prove(leaves []canonical.Leaf, i uint32) (Proof, error) {
	if len(leaves) == 0 {
		return Proof{}, ErrEmptySet
	}
	if int(i) >= len(leaves) {
		return Proof{}, ErrIndexOutOfRange
	}

	ls := levels(leaves)
	p := Proof{Index: i, N: uint32(len(leaves))}

	idx := int(i)
	for lvl := 0; lvl < len(ls)-1; lvl++ {
		cur := ls[lvl]
		if idx == len(cur)-1 && len(cur)%2 == 1 {
			// Promoted: rides to the next level with no sibling.
			idx = idx / 2
			continue
		}
		sib := idx ^ 1
		p.Siblings = append(p.Siblings, cur[sib])
		idx = idx / 2
	}
	return p, nil
}

// VerifyProof recomputes the root from leaf and p and compares. It needs no
// leaf set, which is what makes the evidence artifact small enough to read
// (§3.2, §4.7).
func VerifyProof(net canonical.Network, blockHash, root [32]byte, leaf canonical.Leaf, p Proof) bool {
	if p.N == 0 || p.Index >= p.N {
		return false
	}

	h := LeafHash(leaf)

	// Walk the same promotion rule upward, tracking the level width so we know
	// when this position is unpaired.
	idx := int(p.Index)
	width := int(p.N)
	si := 0
	for width > 1 {
		if idx == width-1 && width%2 == 1 {
			idx = idx / 2
			width = (width + 1) / 2
			continue
		}
		if si >= len(p.Siblings) {
			return false
		}
		sib := p.Siblings[si]
		si++
		if idx%2 == 0 {
			h = nodeHash(h, sib)
		} else {
			h = nodeHash(sib, h)
		}
		idx = idx / 2
		width = (width + 1) / 2
	}
	if si != len(p.Siblings) {
		return false // trailing siblings mean a malformed proof
	}

	buf := make([]byte, 0, 72)
	var netBuf [4]byte
	binary.LittleEndian.PutUint32(netBuf[:], uint32(net))
	buf = append(buf, netBuf[:]...)
	buf = append(buf, blockHash[:]...)
	var nBuf [4]byte
	binary.LittleEndian.PutUint32(nBuf[:], p.N)
	buf = append(buf, nBuf[:]...)
	buf = append(buf, h[:]...)

	return bip352.TaggedHash(tagRoot, buf) == root
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./commit/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add commit/proof.go commit/proof_test.go
git commit -m "feat(commit): inclusion proofs with promotion-aware verification"
```

---

### Task 6: The §7.5 property tests

**Files:**
- Create: `commit/property_test.go`

**Interfaces:**
- Consumes: everything in `commit`.
- Produces: no new API. This task exists because §7.5's rows each defend a specific §3.2 decision, and fixed vectors cannot reach them.

- [ ] **Step 1: Write the property tests**

Each function name names the §7.5 row it defends.

```go
// commit/property_test.go
package commit

import (
	"math/rand"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
)

func randLeaves(r *rand.Rand, n int) []canonical.Leaf {
	out := make([]canonical.Leaf, n)
	for i := range out {
		r.Read(out[i].TxID[:])
		r.Read(out[i].Tweak[:])
	}
	return out
}

// §7.5 row 1: basic soundness, over random sets at the sizes where promotion bites.
func TestPropertyProofRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	var bh [32]byte
	for iter := 0; iter < 200; iter++ {
		n := 1 + r.Intn(40)
		leaves := randLeaves(r, n)
		r.Read(bh[:])
		root := Root(netRegtest, bh, leaves)
		i := uint32(r.Intn(n))
		p, err := Prove(leaves, i)
		if err != nil {
			t.Fatalf("n=%d i=%d: %v", n, i, err)
		}
		if !VerifyProof(netRegtest, bh, root, leaves[i], p) {
			t.Fatalf("n=%d i=%d: round trip failed", n, i)
		}
	}
}

// §7.5 row 2: permuting transaction order changes the root.
func TestPropertyPermutationChangesRoot(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	var bh [32]byte
	for iter := 0; iter < 100; iter++ {
		n := 2 + r.Intn(20)
		leaves := randLeaves(r, n)
		before := Root(netRegtest, bh, leaves)

		shuffled := append([]canonical.Leaf(nil), leaves...)
		i, j := r.Intn(n), r.Intn(n)
		for i == j {
			j = r.Intn(n)
		}
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

		if Root(netRegtest, bh, shuffled) == before {
			t.Fatalf("n=%d: swapping %d and %d left the root unchanged", n, i, j)
		}
	}
}

// §7.5 row 3: a root over n leaves never validates as a root over n' ≠ n.
func TestPropertyRootNeverValidatesAtAnotherLength(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	var bh [32]byte
	for iter := 0; iter < 100; iter++ {
		n := 2 + r.Intn(20)
		leaves := randLeaves(r, n)
		root := Root(netRegtest, bh, leaves)
		for k := 0; k < n; k++ {
			if Root(netRegtest, bh, leaves[:k]) == root {
				t.Fatalf("n=%d: prefix of length %d produced the same root", n, k)
			}
		}
	}
}

// §7.5 row 4: n ∈ {0, 1, 2, 3, 5, 2ᵏ, 2ᵏ+1} — odd-node promotion and the base cases.
func TestPropertyPromotionSizes(t *testing.T) {
	r := rand.New(rand.NewSource(4))
	var bh [32]byte
	sizes := []int{0, 1, 2, 3, 5, 8, 9, 16, 17, 32, 33, 64, 65}
	roots := map[[32]byte]int{}
	for _, n := range sizes {
		leaves := randLeaves(r, n)
		root := Root(netRegtest, bh, leaves)
		if prev, dup := roots[root]; dup {
			t.Fatalf("root collision between n=%d and n=%d", prev, n)
		}
		roots[root] = n

		for i := 0; i < n; i++ {
			p, err := Prove(leaves, uint32(i))
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if !VerifyProof(netRegtest, bh, root, leaves[i], p) {
				t.Fatalf("n=%d i=%d: promotion path broken", n, i)
			}
		}
	}
}

// §7.5 row 5: an internal node hash never validates as a leaf.
func TestPropertyInternalNodeIsNotALeaf(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	for iter := 0; iter < 200; iter++ {
		leaves := randLeaves(r, 2)
		node := nodeHash(LeafHash(leaves[0]), LeafHash(leaves[1]))
		for _, l := range leaves {
			if LeafHash(l) == node {
				t.Fatal("a leaf hash collided with an internal node hash")
			}
		}
	}
}
```

- [ ] **Step 2: Run them and verify they pass**

Run: `go test ./commit/ -run TestProperty -v`
Expected: PASS, five tests. A failure here is a real §3.2 bug, not a flaky test — the seeds are fixed.

- [ ] **Step 3: Commit**

```bash
git add commit/property_test.go
git commit -m "test(commit): §7.5 property tests"
```

---

### Task 7: The `bip352.Vin` adapter and the byte-order boundary

**Files:**
- Create: `canonical/vin.go`
- Test: `canonical/vin_test.go`

**Interfaces:**
- Consumes: `PrevoutSource` from Task 1.
- Produces: `func vinsForTx(tx *wire.MsgTx, pv PrevoutSource) ([]*bip352.Vin, error)`, plus `func txidInternal(h chainhash.Hash) [32]byte` and `func txidDisplay(h chainhash.Hash) [32]byte`. Task 8 consumes `vinsForTx`; Task 9 consumes `txidInternal`.

**Why this is its own task.** `bip352.Vin.Txid` is documented as *"the normal human-readable format"* — display order, byte-reversed — and both `ComputeInputHash` and `FindSmallestOutpoint` depend on it being that way. §3.2 pins the leaf preimage txid as **internal** order. Two representations of a txid inside one package is how implementations silently fork, so the conversion lives in exactly one file with tests that assert the direction (§6.4).

- [ ] **Step 1: Write the failing test**

```go
// canonical/vin_test.go
package canonical

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// chainhash.Hash stores INTERNAL byte order; its String() reverses for display.
func TestTxidByteOrderConversions(t *testing.T) {
	var h chainhash.Hash
	for i := range h {
		h[i] = byte(i)
	}

	internal := txidInternal(h)
	if !bytes.Equal(internal[:], h[:]) {
		t.Errorf("txidInternal must be the raw hash bytes: got %x want %x", internal, h)
	}

	display := txidDisplay(h)
	want, err := hex.DecodeString(h.String())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(display[:], want) {
		t.Errorf("txidDisplay = %x, want %x (chainhash.String order)", display, want)
	}

	if internal == display {
		t.Error("a palindromic test vector proves nothing — pick asymmetric bytes")
	}
}

func TestDisplayIsTheReverseOfInternal(t *testing.T) {
	var h chainhash.Hash
	for i := range h {
		h[i] = byte(i * 7)
	}
	in, disp := txidInternal(h), txidDisplay(h)
	for i := 0; i < 32; i++ {
		if in[i] != disp[31-i] {
			t.Fatalf("byte %d: internal %02x, display[%d] %02x", i, in[i], 31-i, disp[31-i])
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./canonical/ -run 'TestTxid|TestDisplay' -v`
Expected: FAIL — `undefined: txidInternal`.

- [ ] **Step 3: Write the implementation**

```go
// canonical/vin.go
package canonical

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	bip352 "github.com/setavenger/go-bip352"
)

// txidInternal returns the txid in INTERNAL byte order — the bytes as they
// appear in the transaction serialization. This is what §3.2 pins for the
// leaf preimage. chainhash.Hash already stores this order.
func txidInternal(h chainhash.Hash) [32]byte {
	var out [32]byte
	copy(out[:], h[:])
	return out
}

// txidDisplay returns the txid in display order — the reversed form printed by
// block explorers and returned by Core's REST API.
//
// bip352.Vin.Txid must be in THIS order: the library documents it as "the
// normal human-readable format", and ComputeInputHash and FindSmallestOutpoint
// both depend on it. Every crossing between the two orders happens here (§6.4).
func txidDisplay(h chainhash.Hash) [32]byte {
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = h[31-i]
	}
	return out
}

// vinsForTx builds the bip352 input structures for tx, pulling each spent
// output from pv. The prevout is required for every input because eligibility
// is decided by the scriptPubKey being spent, not by the spending script alone.
func vinsForTx(tx *wire.MsgTx, pv PrevoutSource) ([]*bip352.Vin, error) {
	vins := make([]*bip352.Vin, 0, len(tx.TxIn))
	for _, in := range tx.TxIn {
		prev, err := pv.Prevout(in.PreviousOutPoint)
		if err != nil {
			return nil, fmt.Errorf("prevout %s: %w", in.PreviousOutPoint, err)
		}
		if prev == nil {
			return nil, fmt.Errorf("prevout %s: not found", in.PreviousOutPoint)
		}

		vins = append(vins, &bip352.Vin{
			Txid:         txidDisplay(in.PreviousOutPoint.Hash), // display order — library contract
			Vout:         in.PreviousOutPoint.Index,
			Amount:       uint64(prev.Value),
			ScriptPubKey: prev.PkScript,
			ScriptSig:    in.SignatureScript,
			Witness:      in.Witness,
		})
	}
	return vins, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./canonical/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add canonical/vin.go canonical/vin_test.go
git commit -m "feat(canonical): vin adapter and the single txid byte-order boundary"
```

---

### Task 8: Per-transaction eligibility and the tweak

**Files:**
- Create: `canonical/eligible.go`
- Test: `canonical/eligible_test.go`

**Interfaces:**
- Consumes: `vinsForTx` from Task 7.
- Produces: `func tweakForTx(tx *wire.MsgTx, pv PrevoutSource) (tweak [33]byte, eligible bool, err error)`. Task 9 consumes it. `eligible == false` with `err == nil` means the transaction is legitimately not in the set; a non-nil error means we could not decide and the caller must not silently drop it.

**The four rules, from §2.2.** A transaction is included iff it has at least one BIP-341 taproot output *without* the optional unspent clause; at least one input from *Inputs For Shared Secret Derivation*; no input spending a SegWit v>1 output; and `A_sum` not the point at infinity with `input_hash` a valid scalar.

**Verified library behaviour, do not re-derive.** Read against v0.1.8's source, not its docs:

- `ExtractEligibleVins` **does not deep-copy.** It appends the caller's own `*Vin` pointers and sets `Taproot` on them in place. Build the vins fresh per transaction and this is harmless; reuse a slice across calls and it is not.
- `ExtractEligibleVins` **never returns an error** in v0.1.8 — it always returns `(vins, nil)`, so `ErrNoEligibleVins` and `ErrVinsEmpty` exist but are unreachable from it. `len(eligibleVins) == 0` is the real "no eligible inputs" signal. Handle the error branch anyway, as a verdict rather than a failure, so a future version does not turn a verdict into a crash.
- `ExtractPubKey` returns **33 bytes for P2WPKH/P2PKH/P2SH** and **32 bytes (x-only) for P2TR**, and signals failure by returning `TypeUTXO == Unknown` rather than an error. So x-only keys must be lifted to 33 bytes with an `0x02` prefix before summing.
- **`ExtractPubKey` panics on an empty witness.** The P2WPKH and P2SH-P2WPKH paths read `vin.Witness[len(vin.Witness)-1]` with no length check, giving `index out of range [-1]`. The P2TR path guards (`len(witnessStack) >= 1`) and the P2PKH path reads only the scriptSig, so only those two shapes are affected. Confirmed by running it. A block and its prevouts come from a source §1.2 treats as hostile, so this is reachable input: filter such vins out before calling in. Dropping them is not a behaviour change, because a witness-spending prevout with no witness has no extractable key and would return `Unknown` from a library that checked.

- [ ] **Step 1: Write the failing test**

```go
// canonical/eligible_test.go
package canonical

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// mapPrevouts is a PrevoutSource backed by a map, so tests need no node.
type mapPrevouts map[wire.OutPoint]*wire.TxOut

func (m mapPrevouts) Prevout(op wire.OutPoint) (*wire.TxOut, error) {
	return m[op], nil
}

func p2trScript(t *testing.T, xonly string) []byte {
	return append([]byte{0x51, 0x20}, mustHex(t, xonly)...)
}

func p2wpkhScript() []byte {
	return append([]byte{0x00, 0x14}, make([]byte, 20)...)
}

// segwitV2Script is an anyone-can-spend v2 witness program: OP_2 <32 bytes>.
func segwitV2Script() []byte {
	return append([]byte{0x52, 0x20}, make([]byte, 32)...)
}

const testXOnly = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

// buildTx wires one input spending prevScript with the given witness, and the
// given output scripts.
func buildTx(t *testing.T, prevScript []byte, witness [][]byte, outScripts ...[]byte) (*wire.MsgTx, mapPrevouts) {
	t.Helper()
	var prevHash chainhash.Hash
	prevHash[0] = 0x99
	op := wire.OutPoint{Hash: prevHash, Index: 0}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Witness: witness})
	for _, s := range outScripts {
		tx.AddTxOut(wire.NewTxOut(10_000, s))
	}
	return tx, mapPrevouts{op: wire.NewTxOut(50_000, prevScript)}
}

func TestEligibleWithTaprootOutputAndWitnessInput(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	tx, pv := buildTx(t, p2wpkhScript(), [][]byte{make([]byte, 71), pk33}, p2trScript(t, testXOnly))

	tweak, ok, err := tweakForTx(tx, pv)
	if err != nil {
		t.Fatalf("tweakForTx: %v", err)
	}
	if !ok {
		t.Fatal("transaction should be eligible: taproot output + P2WPKH input")
	}
	if tweak[0] != 0x02 && tweak[0] != 0x03 {
		t.Errorf("tweak must be a compressed SEC point, got prefix %02x", tweak[0])
	}
}

func TestNotEligibleWithoutTaprootOutput(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	tx, pv := buildTx(t, p2wpkhScript(), [][]byte{make([]byte, 71), pk33}, p2wpkhScript())

	_, ok, err := tweakForTx(tx, pv)
	if err != nil {
		t.Fatalf("tweakForTx: %v", err)
	}
	if ok {
		t.Error("no BIP-341 taproot output means not eligible (§2.2 rule 1)")
	}
}

func TestNotEligibleWhenSpendingSegWitV2(t *testing.T) {
	tx, pv := buildTx(t, segwitV2Script(), [][]byte{make([]byte, 64)}, p2trScript(t, testXOnly))

	_, ok, err := tweakForTx(tx, pv)
	if err != nil {
		t.Fatalf("tweakForTx: %v", err)
	}
	if ok {
		t.Error("spending a SegWit v>1 output excludes the whole transaction (§2.2 rule 3)")
	}
}

func TestNotEligibleWithNoEligibleInputs(t *testing.T) {
	// Bare OP_RETURN-ish prevout: no extractable public key of any accepted type.
	tx, pv := buildTx(t, []byte{0x6a, 0x01, 0x00}, nil, p2trScript(t, testXOnly))

	_, ok, err := tweakForTx(tx, pv)
	if err != nil {
		t.Fatalf("tweakForTx: %v", err)
	}
	if ok {
		t.Error("no input from Inputs For Shared Secret Derivation means not eligible (§2.2 rule 2)")
	}
}

func TestCoinbaseIsNotEligible(t *testing.T) {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}})
	tx.AddTxOut(wire.NewTxOut(50_000, p2trScript(t, testXOnly)))

	_, ok, err := tweakForTx(tx, mapPrevouts{})
	if err != nil {
		t.Fatalf("coinbase must be reported as ineligible, not as an error: %v", err)
	}
	if ok {
		t.Error("a coinbase has no prevouts and cannot be eligible")
	}
}

func TestTweakIsDeterministic(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	tx, pv := buildTx(t, p2wpkhScript(), [][]byte{make([]byte, 71), pk33}, p2trScript(t, testXOnly))

	a, ok, err := tweakForTx(tx, pv)
	if err != nil || !ok {
		t.Fatalf("setup: ok=%v err=%v", ok, err)
	}
	b, _, _ := tweakForTx(tx, pv)
	if a != b {
		t.Error("tweak derivation must be deterministic")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./canonical/ -run 'Eligible|Coinbase|Tweak' -v`
Expected: FAIL — `undefined: tweakForTx`.

- [ ] **Step 3: Write the implementation**

```go
// canonical/eligible.go
package canonical

import (
	"fmt"

	"github.com/btcsuite/btcd/wire"
	bip352 "github.com/setavenger/go-bip352"
)

// isTaprootOutput reports whether pkScript is a BIP-341 v1 witness program:
// OP_1 <32 bytes>. §2.2 rule 1 uses this WITHOUT the optional unspent clause —
// that clause is exactly the cut-through policy §2.1 refuses to bake in.
func isTaprootOutput(pkScript []byte) bool {
	return len(pkScript) == 34 && pkScript[0] == 0x51 && pkScript[1] == 0x20
}

// isSegWitVersionAbove1 reports whether pkScript is a witness program of
// version 2..16. Spending one excludes the whole transaction (§2.2 rule 3).
func isSegWitVersionAbove1(pkScript []byte) bool {
	if len(pkScript) < 4 || len(pkScript) > 42 {
		return false
	}
	op := pkScript[0]
	// OP_2..OP_16 are 0x52..0x60.
	if op < 0x52 || op > 0x60 {
		return false
	}
	pushLen := int(pkScript[1])
	return pushLen >= 2 && pushLen <= 40 && len(pkScript) == pushLen+2
}

// tweakForTx decides eligibility and, when eligible, derives the 33-byte tweak.
//
// eligible == false with err == nil means the transaction is legitimately
// outside T_base. A non-nil error means we could not decide — the caller must
// surface it rather than silently dropping the transaction, because a dropped
// transaction is indistinguishable from the attack this project detects.
func tweakForTx(tx *wire.MsgTx, pv PrevoutSource) (tweak [33]byte, eligible bool, err error) {
	if len(tx.TxIn) == 0 {
		return tweak, false, nil
	}
	// A coinbase spends a null outpoint and has no prevout to fetch.
	if len(tx.TxIn) == 1 && tx.TxIn[0].PreviousOutPoint.Index == 0xffffffff {
		return tweak, false, nil
	}

	// Rule 1: at least one BIP-341 taproot output.
	hasTaprootOut := false
	for _, out := range tx.TxOut {
		if isTaprootOutput(out.PkScript) {
			hasTaprootOut = true
			break
		}
	}
	if !hasTaprootOut {
		return tweak, false, nil
	}

	vins, err := vinsForTx(tx, pv)
	if err != nil {
		return tweak, false, err
	}

	// Rule 3: no input spending a SegWit v>1 output.
	for _, v := range vins {
		if isSegWitVersionAbove1(v.ScriptPubKey) {
			return tweak, false, nil
		}
	}

	// Rule 2: at least one input from Inputs For Shared Secret Derivation.
	eligibleVins, err := bip352.ExtractEligibleVins(vins)
	if err != nil {
		// ErrNoEligibleVins is a verdict, not a failure.
		if err == bip352.ErrNoEligibleVins || err == bip352.ErrVinsEmpty {
			return tweak, false, nil
		}
		return tweak, false, fmt.Errorf("extract eligible vins: %w", err)
	}
	if len(eligibleVins) == 0 {
		return tweak, false, nil
	}

	// Sum the input public keys. ExtractPubKey returns 33 bytes for
	// P2WPKH/P2PKH/P2SH and 32 x-only bytes for P2TR, and signals failure with
	// TypeUTXO == Unknown rather than an error (verified against v0.1.8).
	keys := make([][33]byte, 0, len(eligibleVins))
	for _, v := range eligibleVins {
		pk, typ := bip352.ExtractPubKey(v)
		if typ == bip352.Unknown || len(pk) == 0 {
			continue
		}
		if len(pk) == 32 {
			pk = append([]byte{0x02}, pk...) // lift x-only to even-Y compressed
		}
		if len(pk) != 33 {
			return tweak, false, fmt.Errorf("unexpected public key length %d", len(pk))
		}
		keys = append(keys, bip352.ConvertToFixedLength33(pk))
	}
	if len(keys) == 0 {
		return tweak, false, nil
	}

	// Rule 4a: A_sum must not be the point at infinity. SumPublicKeys errors
	// when the sum does not lie on the curve, which is that condition.
	sum, err := bip352.SumPublicKeys(keys)
	if err != nil {
		return tweak, false, nil
	}

	// Rule 4b: input_hash must be a valid scalar.
	inputHash, err := bip352.ComputeInputHash(eligibleVins, sum)
	if err != nil {
		return tweak, false, nil
	}

	// The served tweak is A_tweaked = input_hash · A_sum — the public component
	// a light client scans with (BIP-352 light-client scenario).
	t, err := bip352.TweakPubkey(sum, inputHash)
	if err != nil {
		return tweak, false, nil
	}
	return t, true, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./canonical/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add canonical/eligible.go canonical/eligible_test.go
git commit -m "feat(canonical): §2.2 eligibility rules and tweak derivation"
```

---

### Task 9: `Set` — the canonical set over a whole block

**Files:**
- Modify: `canonical/canonical.go` — replace the `Set` stub
- Test: `canonical/canonical_test.go`

**Interfaces:**
- Consumes: `tweakForTx` from Task 8, `txidInternal` from Task 7.
- Produces: `Set(net Network, blk *wire.MsgBlock, pv PrevoutSource) ([]Leaf, error)` exactly as §6.3 froze it. Every other track compiles against this.

- [ ] **Step 1: Write the failing test**

```go
// canonical/canonical_test.go
package canonical

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// blockWith assembles a block from a coinbase plus the given transactions,
// returning a PrevoutSource covering all of them.
func blockWith(t *testing.T, txs []*wire.MsgTx, prevouts mapPrevouts) *wire.MsgBlock {
	t.Helper()
	blk := &wire.MsgBlock{}
	cb := wire.NewMsgTx(2)
	cb.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}})
	cb.AddTxOut(wire.NewTxOut(50_000, p2wpkhScript()))
	blk.AddTransaction(cb)
	for _, tx := range txs {
		blk.AddTransaction(tx)
	}
	return blk
}

func TestSetEmptyBlockIsEmptyNotAnError(t *testing.T) {
	blk := blockWith(t, nil, mapPrevouts{})
	leaves, err := Set(Network(0xdab5bffa), blk, mapPrevouts{})
	if err != nil {
		t.Fatalf("a block with no eligible transactions is not an error: %v", err)
	}
	if len(leaves) != 0 {
		t.Errorf("got %d leaves, want 0", len(leaves))
	}
}

func TestSetReturnsTransactionIndexOrder(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	var txs []*wire.MsgTx
	pv := mapPrevouts{}
	for i := 0; i < 3; i++ {
		var prevHash chainhash.Hash
		prevHash[0] = byte(0xA0 + i)
		op := wire.OutPoint{Hash: prevHash, Index: 0}

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Witness: [][]byte{make([]byte, 71), pk33}})
		tx.AddTxOut(wire.NewTxOut(10_000, p2trScript(t, testXOnly)))
		txs = append(txs, tx)
		pv[op] = wire.NewTxOut(50_000, p2wpkhScript())
	}

	blk := blockWith(t, txs, pv)
	leaves, err := Set(Network(0xdab5bffa), blk, pv)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 3 {
		t.Fatalf("got %d leaves, want 3", len(leaves))
	}

	// Order must follow block position, and each TxID must be the INTERNAL
	// byte order of the transaction's own hash.
	for i, tx := range txs {
		want := txidInternal(tx.TxHash())
		if leaves[i].TxID != want {
			t.Errorf("leaf %d TxID = %x, want %x (transaction-index order, internal bytes)",
				i, leaves[i].TxID, want)
		}
	}
}

func TestSetSkipsIneligibleButKeepsOrder(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	pv := mapPrevouts{}

	mk := func(i int, outScript []byte) *wire.MsgTx {
		var prevHash chainhash.Hash
		prevHash[0] = byte(0xB0 + i)
		op := wire.OutPoint{Hash: prevHash, Index: 0}
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Witness: [][]byte{make([]byte, 71), pk33}})
		tx.AddTxOut(wire.NewTxOut(10_000, outScript))
		pv[op] = wire.NewTxOut(50_000, p2wpkhScript())
		return tx
	}

	eligibleA := mk(0, p2trScript(t, testXOnly))
	notEligible := mk(1, p2wpkhScript()) // no taproot output
	eligibleB := mk(2, p2trScript(t, testXOnly))

	blk := blockWith(t, []*wire.MsgTx{eligibleA, notEligible, eligibleB}, pv)
	leaves, err := Set(Network(0xdab5bffa), blk, pv)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 2 {
		t.Fatalf("got %d leaves, want 2", len(leaves))
	}
	if leaves[0].TxID != txidInternal(eligibleA.TxHash()) {
		t.Error("leaf 0 is not the first eligible transaction")
	}
	if leaves[1].TxID != txidInternal(eligibleB.TxHash()) {
		t.Error("leaf 1 is not the second eligible transaction")
	}
}

func TestSetPropagatesMissingPrevout(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	var prevHash chainhash.Hash
	prevHash[0] = 0xC0
	op := wire.OutPoint{Hash: prevHash, Index: 0}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Witness: [][]byte{make([]byte, 71), pk33}})
	tx.AddTxOut(wire.NewTxOut(10_000, p2trScript(t, testXOnly)))

	blk := blockWith(t, []*wire.MsgTx{tx}, mapPrevouts{})

	// The prevout map is deliberately empty. A missing prevout must be an
	// error, never a silently skipped transaction — silence here is the attack.
	if _, err := Set(Network(0xdab5bffa), blk, mapPrevouts{}); err == nil {
		t.Error("a missing prevout must surface as an error, not a dropped transaction")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./canonical/ -run TestSet -v`
Expected: FAIL — `Set` returns `errNotImplemented`.

- [ ] **Step 3: Write the implementation**

```go
// canonical/canonical.go — replace the Set stub, keep the types unchanged.

// Set returns the canonical leaves of blk in transaction-index order.
//
// Pure: no chain state after the block, no thresholds, no configuration. That
// is what makes it the thing servers commit to and clients recompute (§2.2).
//
// Ordering is block position, not lexicographic. Position i is a specific
// transaction, which is what attribution needs (§2.2).
func Set(net Network, blk *wire.MsgBlock, pv PrevoutSource) ([]Leaf, error) {
	leaves := make([]Leaf, 0, len(blk.Transactions))

	for i, tx := range blk.Transactions {
		tweak, eligible, err := tweakForTx(tx, pv)
		if err != nil {
			return nil, fmt.Errorf("tx %d (%s): %w", i, tx.TxHash(), err)
		}
		if !eligible {
			continue
		}
		leaves = append(leaves, Leaf{
			TxID:  txidInternal(tx.TxHash()), // INTERNAL byte order (§3.2)
			Tweak: tweak,
		})
	}
	return leaves, nil
}
```

Add `"fmt"` to the imports and delete the now-unused `errNotImplemented`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./canonical/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add canonical/canonical.go canonical/canonical_test.go
git commit -m "feat(canonical): Set over a block in transaction-index order"
```

---

### Task 10: BIP-352 vector conformance — testing layer A

**Files:**
- Create: `canonical/bip352_vectors_test.go`
- Create: `testdata/bip352/send_and_receive_test_vectors.json` (downloaded once, committed)

**Interfaces:**
- Consumes: nothing new.
- Produces: no API. This is §7.1's layer A — someone else's test, and the only independent check we have on our dependency.

- [ ] **Step 1: Fetch the upstream vectors and commit them**

```bash
mkdir -p testdata/bip352
curl -fsSL -o testdata/bip352/send_and_receive_test_vectors.json \
  https://raw.githubusercontent.com/bitcoin/bips/master/bip-0352/send_and_receive_test_vectors.json
# Record what we pinned, since the file is upstream and moves.
sha256sum testdata/bip352/send_and_receive_test_vectors.json > testdata/bip352/SHA256SUMS
```

- [ ] **Step 2: Write the conformance test**

The vectors are input-level, so they exercise the primitives rather than `Set`. That is the point: layer C compares us against blindbit-oracle, which shares our library, so this is the only check on the library itself (§6.4, §7.1).

```go
// canonical/bip352_vectors_test.go
package canonical

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	bip352 "github.com/setavenger/go-bip352"
)

type bipVectorFile []struct {
	Comment string `json:"comment"`
	Sending []struct {
		Given struct {
			Vin []struct {
				Txid      string `json:"txid"`
				Vout      uint32 `json:"vout"`
				ScriptSig string `json:"scriptSig"`
				Witness   string `json:"txinwitness"`
				Prevout   struct {
					ScriptPubKey struct {
						Hex string `json:"hex"`
					} `json:"scriptPubKey"`
				} `json:"prevout"`
			} `json:"vin"`
		} `json:"given"`
	} `json:"sending"`
}

func TestBIP352VectorsInputHashAgrees(t *testing.T) {
	raw, err := os.ReadFile("../testdata/bip352/send_and_receive_test_vectors.json")
	if err != nil {
		t.Skipf("upstream vectors not present: %v", err)
	}
	var file bipVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file) == 0 {
		t.Fatal("vector file is empty")
	}

	cases := 0
	for _, c := range file {
		for _, s := range c.Sending {
			vins := make([]*bip352.Vin, 0, len(s.Given.Vin))
			for _, v := range s.Given.Vin {
				txidBytes, err := hex.DecodeString(v.Txid)
				if err != nil {
					t.Fatalf("%s: bad txid: %v", c.Comment, err)
				}
				spk, _ := hex.DecodeString(v.Prevout.ScriptPubKey.Hex)
				ss, _ := hex.DecodeString(v.ScriptSig)
				wit, _ := bip352.ParseWitnessScript(v.Witness)

				vins = append(vins, &bip352.Vin{
					Txid:         bip352.ConvertToFixedLength32(txidBytes),
					Vout:         v.Vout,
					ScriptPubKey: spk,
					ScriptSig:    ss,
					Witness:      wit,
				})
			}

			eligible, err := bip352.ExtractEligibleVins(vins)
			if err != nil {
				continue // vectors include deliberately ineligible input sets
			}
			if len(eligible) == 0 {
				continue
			}

			keys := make([][33]byte, 0, len(eligible))
			for _, v := range eligible {
				pk, typ := bip352.ExtractPubKey(v)
				if typ == bip352.Unknown || len(pk) == 0 {
					continue
				}
				if len(pk) == 32 {
					pk = append([]byte{0x02}, pk...)
				}
				keys = append(keys, bip352.ConvertToFixedLength33(pk))
			}
			if len(keys) == 0 {
				continue
			}

			sum, err := bip352.SumPublicKeys(keys)
			if err != nil {
				continue
			}
			if _, err := bip352.ComputeInputHash(eligible, sum); err != nil {
				t.Errorf("%s: ComputeInputHash failed on a vector the library accepted: %v", c.Comment, err)
			}
			cases++
		}
	}

	if cases == 0 {
		t.Fatal("no vector produced an eligible input set — the harness is not exercising anything")
	}
	t.Logf("exercised %d sending vectors", cases)
}
```

- [ ] **Step 3: Run it**

Run: `go test ./canonical/ -run TestBIP352Vectors -v`
Expected: PASS, with a log line naming a non-zero case count. A zero count fails deliberately — a green test that asserts nothing is worse than no test.

- [ ] **Step 4: Commit**

```bash
git add testdata/bip352 canonical/bip352_vectors_test.go
git commit -m "test(canonical): BIP-352 upstream vector conformance (§7.1 layer A)"
```

---

### Task 11: `policy` — the struct and the blindbit `/info` bridge

**Files:**
- Create: `policy/blindbit.go`
- Modify: `policy/policy.go` — delete the `FromBlindBitInfo` stub
- Test: `policy/blindbit_test.go`

**Interfaces:**
- Consumes: `canonical.Network` from Task 1.
- Produces: `FromBlindBitInfo(r io.Reader) (Policy, error)` as §6.3 froze it. The sidecar's ladder consumes `Policy`.

**The `/info` body**, verbatim from blindbit-oracle's README:

```json
{
  "network": "signet",
  "height": 834761,
  "tweaks_only": false,
  "tweaks_full_basic": true,
  "tweaks_full_with_dust_filter": false,
  "tweaks_cut_through_with_dust_filter": false
}
```

**The mapping, and why.** `tweaks_cut_through_with_dust_filter` is the only flag that prunes spent transactions, so it alone sets `PrunesSpent`. Both `*_with_dust_filter` flags mean a dust threshold is in force, but `/info` does not report its *value* — and per §2.3 the value was never verifiable anyway, so an unknown-but-present threshold loses nothing. `StartHeight` is absent from `/info` entirely and stays zero, which is the honest answer: this bridge is unsigned, not per-block, and strictly weaker than the protocol layer (§2.3).

- [ ] **Step 1: Write the failing test**

```go
// policy/blindbit_test.go
package policy

import (
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
)

const infoFullBasic = `{
  "network": "signet",
  "height": 834761,
  "tweaks_only": false,
  "tweaks_full_basic": true,
  "tweaks_full_with_dust_filter": false,
  "tweaks_cut_through_with_dust_filter": false
}`

const infoCutThrough = `{
  "network": "regtest",
  "height": 200,
  "tweaks_only": false,
  "tweaks_full_basic": false,
  "tweaks_full_with_dust_filter": false,
  "tweaks_cut_through_with_dust_filter": true
}`

func TestFromBlindBitInfoFullIndexDeclaresNoSubtraction(t *testing.T) {
	p, err := FromBlindBitInfo(strings.NewReader(infoFullBasic))
	if err != nil {
		t.Fatal(err)
	}
	if p.Network != canonical.Network(0x40cf030a) {
		t.Errorf("network = %08x, want signet magic 40cf030a", uint32(p.Network))
	}
	if p.PrunesSpent {
		t.Error("tweaks_full_basic does not prune spent transactions")
	}
	if p.DustThresholdSat != 0 {
		t.Error("no dust filter flag means no declared threshold")
	}
	// A server declaring a full index that then shows a gap has contradicted
	// itself — that is §2.3's first job for this struct.
}

func TestFromBlindBitInfoCutThroughDeclaresPruning(t *testing.T) {
	p, err := FromBlindBitInfo(strings.NewReader(infoCutThrough))
	if err != nil {
		t.Fatal(err)
	}
	if p.Network != canonical.Network(0xdab5bffa) {
		t.Errorf("network = %08x, want regtest magic dab5bffa", uint32(p.Network))
	}
	if !p.PrunesSpent {
		t.Error("tweaks_cut_through_with_dust_filter prunes spent transactions (§2.3)")
	}
	if p.DustThresholdSat == 0 {
		t.Error("a dust-filter flag must record that a threshold is in force")
	}
}

func TestFromBlindBitInfoRejectsUnknownNetwork(t *testing.T) {
	_, err := FromBlindBitInfo(strings.NewReader(`{"network":"testnet4"}`))
	if err == nil {
		t.Error("an unrecognised network must be an error — §2.7 requires both servers on the same network")
	}
}

func TestFromBlindBitInfoRejectsMalformedJSON(t *testing.T) {
	if _, err := FromBlindBitInfo(strings.NewReader(`{`)); err == nil {
		t.Error("malformed /info must error rather than yield a zero-value policy")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./policy/ -v`
Expected: FAIL — the stub returns `errNotImplemented`.

- [ ] **Step 3: Write the implementation**

```go
// policy/blindbit.go
package policy

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/btcsuite/btcd/chaincfg"
)

type blindbitInfo struct {
	Network                        string `json:"network"`
	Height                         uint32 `json:"height"`
	TweaksOnly                     bool   `json:"tweaks_only"`
	TweaksFullBasic                bool   `json:"tweaks_full_basic"`
	TweaksFullWithDustFilter       bool   `json:"tweaks_full_with_dust_filter"`
	TweaksCutThroughWithDustFilter bool   `json:"tweaks_cut_through_with_dust_filter"`
}

// dustThresholdUnknown records that a dust filter is in force without claiming
// to know its value. /info does not report the number, and §2.3 establishes
// that the number was never verifiable anyway — the declaration's job is to
// route effort and to create a contradiction rung 4 can check, not to be an
// input to any verdict.
const dustThresholdUnknown = 1

// networkFromName maps blindbit's display name onto the 4-byte P2P magic, read
// from chaincfg rather than written as a literal (§3.2).
func networkFromName(name string) (canonical.Network, error) {
	switch name {
	case "main", "mainnet", "bitcoin":
		return canonical.Network(chaincfg.MainNetParams.Net), nil
	case "signet":
		return canonical.Network(chaincfg.SigNetParams.Net), nil
	case "regtest":
		return canonical.Network(chaincfg.RegressionNetParams.Net), nil
	default:
		return 0, fmt.Errorf("policy: unrecognised network %q", name)
	}
}

// FromBlindBitInfo derives a Policy from blindbit-oracle's GET /info body.
//
// This is the tool-first bridge (§2.3): unsigned, not per-block, and revisable
// retroactively by the server, therefore strictly weaker than the signed
// per-block policy of the protocol layer. It is also what lets the differ run
// against unmodified blindbit today, which is the whole point of §0's layering.
func FromBlindBitInfo(r io.Reader) (Policy, error) {
	var info blindbitInfo
	dec := json.NewDecoder(r)
	if err := dec.Decode(&info); err != nil {
		return Policy{}, fmt.Errorf("policy: decode /info: %w", err)
	}

	net, err := networkFromName(info.Network)
	if err != nil {
		return Policy{}, err
	}

	p := Policy{
		Network: net,
		// /info carries no start height. Leaving it zero is honest: below a
		// real start height absence is not evidence, and we do not know it.
		StartHeight: 0,
		// Only the cut-through mode prunes spent transactions. The two full
		// modes keep them, differing solely in dust handling (§2.3).
		PrunesSpent: info.TweaksCutThroughWithDustFilter,
	}

	if info.TweaksFullWithDustFilter || info.TweaksCutThroughWithDustFilter {
		p.DustThresholdSat = dustThresholdUnknown
	}

	return p, nil
}
```

Delete the `FromBlindBitInfo` stub and the now-unused `errNotImplemented` from `policy/policy.go`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./policy/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add policy/ && git commit -m "feat(policy): §2.3 struct and the blindbit /info bridge"
```

---

### Task 12: `feed` — commitment to signed Nostr event and back

**Files:**
- Modify: `feed/commitment.go` — replace the `ToEvent` and `FromEvent` stubs
- Test: `feed/commitment_test.go`

**Interfaces:**
- Consumes: `canonical.Network`.
- Produces: `ToEvent`, `FromEvent`, and the exported constants `KindCommitment` and `TagBlockHash`. The indexer fork (Plan B) publishes with `ToEvent`; the sidecar (Plan C) parses with `FromEvent`.

**Event shape.** Kind 1352, regular range, append-only. The block hash goes in the single-letter `b` tag in display hex, because relays index nothing else (§3.3). `height`, `n`, `network` and `policy_ref` are multi-letter and carried for readers, not filters. Content carries the root as hex. The event id hashes tags and content together, so one signature covers all of it.

- [ ] **Step 1: Write the failing test**

```go
// feed/commitment_test.go
package feed

import (
	"encoding/hex"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/nbd-wtf/go-nostr"
)

func testCommitment() Commitment {
	c := Commitment{
		Network:     canonical.Network(0xdab5bffa),
		BlockHeight: 812345,
		N:           7,
	}
	for i := range c.BlockHash {
		c.BlockHash[i] = byte(i)
	}
	for i := range c.Root {
		c.Root[i] = byte(0x80 + i)
	}
	for i := range c.PolicyRef {
		c.PolicyRef[i] = byte(0x40 + i)
	}
	return c
}

func testKey(t *testing.T) ([32]byte, string) {
	t.Helper()
	skHex := nostr.GeneratePrivateKey()
	b, err := hex.DecodeString(skHex)
	if err != nil {
		t.Fatal(err)
	}
	var sk [32]byte
	copy(sk[:], b)
	return sk, skHex
}

func TestToEventFromEventRoundTrip(t *testing.T) {
	sk, _ := testKey(t)
	want := testCommitment()

	ev, err := want.ToEvent(sk)
	if err != nil {
		t.Fatalf("ToEvent: %v", err)
	}

	got, err := FromEvent(ev)
	if err != nil {
		t.Fatalf("FromEvent: %v", err)
	}

	// Author is filled in from the event, so compare it separately.
	if got.Author == [32]byte{} {
		t.Error("FromEvent must populate Author from the event pubkey")
	}
	want.Author = got.Author

	if got != want {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestEventIsSignedAndUsesTheRegularKind(t *testing.T) {
	sk, _ := testKey(t)
	ev, err := testCommitment().ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}

	if ev.Kind != KindCommitment {
		t.Errorf("kind = %d, want %d", ev.Kind, KindCommitment)
	}
	// Regular kinds are append-only. A replaceable kind would let a server
	// overwrite a commitment it had already published (§3.3).
	if ev.Kind < 1000 || ev.Kind > 9999 {
		t.Errorf("kind %d is outside the regular range 1000–9999 — replaceable kinds void non-repudiation", ev.Kind)
	}

	ok, err := ev.CheckSignature()
	if err != nil || !ok {
		t.Errorf("event signature invalid: ok=%v err=%v", ok, err)
	}
	if !ev.CheckID() {
		t.Error("event id does not match its own content and tags")
	}
}

func TestBlockHashIsInASingleLetterIndexedTag(t *testing.T) {
	sk, _ := testKey(t)
	c := testCommitment()
	ev, err := c.ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}

	if len(TagBlockHash) != 1 {
		t.Fatalf("TagBlockHash %q must be a single letter — relays index nothing else (§3.3)", TagBlockHash)
	}

	tag := ev.Tags.Find(TagBlockHash)
	if tag == nil {
		t.Fatalf("no %q tag on the event", TagBlockHash)
	}
	// Display hex, so a human reading the relay sees the familiar form.
	if tag[1] != displayHex(c.BlockHash) {
		t.Errorf("b tag = %s, want %s", tag[1], displayHex(c.BlockHash))
	}
}

func TestFromEventRejectsWrongKind(t *testing.T) {
	sk, _ := testKey(t)
	ev, err := testCommitment().ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}
	ev.Kind = 30000 // a parameterized replaceable kind
	if _, err := FromEvent(ev); err == nil {
		t.Error("FromEvent must reject a non-1352 kind, especially a replaceable one")
	}
}

func TestFromEventRejectsBadSignature(t *testing.T) {
	sk, _ := testKey(t)
	ev, err := testCommitment().ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}
	ev.Content = "00" // tamper after signing
	if _, err := FromEvent(ev); err == nil {
		t.Error("FromEvent must verify the signature — an unverified commitment proves nothing")
	}
}

func TestFromEventRejectsTagRootDisagreement(t *testing.T) {
	sk, skHex := testKey(t)
	c := testCommitment()
	ev, err := c.ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite the root tag so it disagrees with the content, then re-sign, so
	// the signature is valid and only the internal inconsistency is wrong.
	// §3.3 calls this redundancy deliberate; Step 3 adds the guard that makes
	// it real. Requires "strings" in the test imports.
	for i, tg := range ev.Tags {
		if tg[0] == "root" {
			ev.Tags[i] = nostr.Tag{"root", strings.Repeat("00", 32)}
		}
	}
	ev.ID = ""
	ev.Sig = ""
	if err := ev.Sign(skHex); err != nil {
		t.Fatal(err)
	}

	if _, err := FromEvent(ev); err == nil {
		t.Error("FromEvent must reject an event whose tags contradict its content")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./feed/ -v`
Expected: FAIL — the stubs return `errNotImplemented`, and `displayHex` is undefined.

- [ ] **Step 3: Write the implementation**

```go
// feed/commitment.go — replace the stubs, keep the types and constants.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/nbd-wtf/go-nostr"
)

// displayHex renders a 32-byte hash in display order — reversed, the form a
// block explorer prints. Tags carry this so a human reading a relay sees the
// familiar string; the root preimage uses internal order (§3.2).
func displayHex(h [32]byte) string {
	var rev [32]byte
	for i := 0; i < 32; i++ {
		rev[i] = h[31-i]
	}
	return hex.EncodeToString(rev[:])
}

func parseDisplayHex(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	for i := 0; i < 32; i++ {
		out[i] = b[31-i]
	}
	return out, nil
}

// ToEvent builds and signs the Nostr event carrying c.
//
// The block hash goes in the single-letter b tag because relays index no other
// tag names. The rest are carried for readers, not filters (§3.3).
func (c Commitment) ToEvent(sk [32]byte) (nostr.Event, error) {
	skHex := hex.EncodeToString(sk[:])
	pub, err := nostr.GetPublicKey(skHex)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("feed: derive pubkey: %w", err)
	}

	ev := nostr.Event{
		PubKey: pub,
		// created_at is set because the protocol requires a value, never
		// because we trust it. Ordering comes from the block hash (§3.5).
		CreatedAt: nostr.Now(),
		Kind:      KindCommitment,
		Tags: nostr.Tags{
			nostr.Tag{TagBlockHash, displayHex(c.BlockHash)},
			nostr.Tag{"height", strconv.FormatUint(uint64(c.BlockHeight), 10)},
			nostr.Tag{"n", strconv.FormatUint(uint64(c.N), 10)},
			nostr.Tag{"network", strconv.FormatUint(uint64(c.Network), 10)},
			nostr.Tag{"policy_ref", hex.EncodeToString(c.PolicyRef[:])},
		},
		Content: hex.EncodeToString(c.Root[:]),
	}

	if err := ev.Sign(skHex); err != nil {
		return nostr.Event{}, fmt.Errorf("feed: sign: %w", err)
	}
	return ev, nil
}

var (
	ErrWrongKind      = errors.New("feed: event is not a commitment kind")
	ErrBadSignature   = errors.New("feed: event signature invalid")
	ErrInconsistent   = errors.New("feed: event tags contradict its content")
	ErrMissingTag     = errors.New("feed: required tag missing")
)

// FromEvent parses and verifies an event into a Commitment.
//
// Verification is not optional here. An unverified commitment proves nothing,
// and every downstream verdict in §2.5 treats a commitment as a signed
// statement the server cannot later revise.
func FromEvent(e nostr.Event) (Commitment, error) {
	var c Commitment

	if e.Kind != KindCommitment {
		return c, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, e.Kind, KindCommitment)
	}
	if !e.CheckID() {
		return c, fmt.Errorf("%w: id does not match", ErrBadSignature)
	}
	ok, err := e.CheckSignature()
	if err != nil {
		return c, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if !ok {
		return c, ErrBadSignature
	}

	author, err := hex.DecodeString(e.PubKey)
	if err != nil || len(author) != 32 {
		return c, fmt.Errorf("feed: bad author pubkey %q", e.PubKey)
	}
	copy(c.Author[:], author)

	get := func(name string) (string, error) {
		tag := e.Tags.Find(name)
		if tag == nil || len(tag) < 2 {
			return "", fmt.Errorf("%w: %s", ErrMissingTag, name)
		}
		return tag[1], nil
	}

	bhStr, err := get(TagBlockHash)
	if err != nil {
		return c, err
	}
	if c.BlockHash, err = parseDisplayHex(bhStr); err != nil {
		return c, fmt.Errorf("feed: bad block hash: %w", err)
	}

	heightStr, err := get("height")
	if err != nil {
		return c, err
	}
	h, err := strconv.ParseUint(heightStr, 10, 32)
	if err != nil {
		return c, fmt.Errorf("feed: bad height: %w", err)
	}
	c.BlockHeight = uint32(h)

	nStr, err := get("n")
	if err != nil {
		return c, err
	}
	n, err := strconv.ParseUint(nStr, 10, 32)
	if err != nil {
		return c, fmt.Errorf("feed: bad n: %w", err)
	}
	c.N = uint32(n)

	netStr, err := get("network")
	if err != nil {
		return c, err
	}
	netVal, err := strconv.ParseUint(netStr, 10, 32)
	if err != nil {
		return c, fmt.Errorf("feed: bad network: %w", err)
	}
	c.Network = canonical.Network(netVal)

	prStr, err := get("policy_ref")
	if err != nil {
		return c, err
	}
	pr, err := hex.DecodeString(prStr)
	if err != nil || len(pr) != 32 {
		return c, fmt.Errorf("feed: bad policy_ref")
	}
	copy(c.PolicyRef[:], pr)

	rootBytes, err := hex.DecodeString(e.Content)
	if err != nil || len(rootBytes) != 32 {
		return c, fmt.Errorf("feed: content is not a 32-byte root")
	}
	copy(c.Root[:], rootBytes)

	return c, nil
}
```

**The cross-field guard.** §3.3 calls the redundancy between tags and content
deliberate, and that is only true if something checks it. Add
`nostr.Tag{"root", hex.EncodeToString(c.Root[:])}` to `ToEvent`'s tag list, and
in `FromEvent`, immediately after parsing the content root:

```go
	rootTag, err := get("root")
	if err != nil {
		return c, err
	}
	if rootTag != e.Content {
		return c, fmt.Errorf("%w: root tag %s vs content %s", ErrInconsistent, rootTag, e.Content)
	}
```

Carrying the root twice without comparing the copies would be worse than
carrying it once, so this guard is what earns the redundancy.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./feed/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add feed/commitment.go feed/commitment_test.go
git commit -m "feat(feed): commitment to signed kind-1352 event and back"
```

---

### Task 13: `feed` — the relay client, subscribe and batched get

**Files:**
- Create: `feed/feed.go`
- Test: `feed/feed_test.go`

**Interfaces:**
- Consumes: `Commitment`, `FromEvent` from Task 12.
- Produces: the `Feed` interface exactly as §6.3 froze it, plus `func NewRelayFeed(urls []string) Feed` and `const MaxHashesPerFilter = 500`.

**Why `Get` takes a slice.** NIP-01 has no range query. Tag filters carry no range or ordering operators, and `since`/`until` act on `created_at`, which §3.5 refuses to trust. A client covering a block range therefore batches the hashes it already knows into one filter, chunked to the relay's limit (§3.3).

- [ ] **Step 1: Write the failing test**

The test drives a fake relay rather than a real one, so it runs in CI with no network.

```go
// feed/feed_test.go
package feed

import (
	"context"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// fakeRelay records the filters it was asked for and replays canned events.
type fakeRelay struct {
	events []nostr.Event
	seen   []nostr.Filter
}

func (f *fakeRelay) QuerySync(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	f.seen = append(f.seen, filter)
	var out []*nostr.Event
	for i := range f.events {
		if filter.Matches(&f.events[i]) {
			out = append(out, &f.events[i])
		}
	}
	return out, nil
}

func TestGetBatchesHashesIntoOneFilter(t *testing.T) {
	sk, _ := testKey(t)

	var want []Commitment
	var events []nostr.Event
	for i := 0; i < 3; i++ {
		c := testCommitment()
		c.BlockHash[31] = byte(i) // distinct blocks
		ev, err := c.ToEvent(sk)
		if err != nil {
			t.Fatal(err)
		}
		c.Author = mustAuthor(t, ev.PubKey)
		want = append(want, c)
		events = append(events, ev)
	}

	fr := &fakeRelay{events: events}
	f := &relayFeed{queriers: []querier{fr}}

	hashes := [][32]byte{want[0].BlockHash, want[1].BlockHash, want[2].BlockHash}
	got, err := f.Get(context.Background(), want[0].Author, hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d commitments, want 3", len(got))
	}

	// One filter, not three. Three round trips per block range is the thing
	// batching exists to avoid.
	if len(fr.seen) != 1 {
		t.Errorf("issued %d filters, want 1 batched filter (§3.3)", len(fr.seen))
	}
	if n := len(fr.seen[0].Tags[TagBlockHash]); n != 3 {
		t.Errorf("filter carried %d block hashes, want 3", n)
	}
	if len(fr.seen[0].Kinds) != 1 || fr.seen[0].Kinds[0] != KindCommitment {
		t.Errorf("filter must pin the kind to %d", KindCommitment)
	}
	if len(fr.seen[0].Authors) != 1 {
		t.Error("filter must pin the author")
	}
	// created_at is never a query bound (§3.5).
	if fr.seen[0].Since != nil || fr.seen[0].Until != nil {
		t.Error("filter must not constrain created_at — it is self-asserted and backdatable")
	}
}

func TestGetChunksBeyondTheRelayLimit(t *testing.T) {
	fr := &fakeRelay{}
	f := &relayFeed{queriers: []querier{fr}}

	hashes := make([][32]byte, MaxHashesPerFilter+1)
	for i := range hashes {
		hashes[i][0] = byte(i % 256)
		hashes[i][1] = byte(i / 256)
	}

	var author [32]byte
	if _, err := f.Get(context.Background(), author, hashes); err != nil {
		t.Fatal(err)
	}
	if len(fr.seen) != 2 {
		t.Errorf("issued %d filters for %d hashes, want 2 chunks at limit %d",
			len(fr.seen), len(hashes), MaxHashesPerFilter)
	}
}

func TestGetSkipsEventsThatFailVerification(t *testing.T) {
	sk, _ := testKey(t)
	c := testCommitment()
	ev, err := c.ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}
	ev.Content = "00" // tamper: signature no longer covers it

	fr := &fakeRelay{events: []nostr.Event{ev}}
	f := &relayFeed{queriers: []querier{fr}}

	got, err := f.Get(context.Background(), mustAuthor(t, ev.PubKey), [][32]byte{c.BlockHash})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Error("a commitment failing verification must be dropped, never returned")
	}
}
```

Add the helper the tests use, in `feed/commitment_test.go`:

```go
func mustAuthor(t *testing.T, pubHex string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(pubHex)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad pubkey %q", pubHex)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./feed/ -run TestGet -v`
Expected: FAIL — `undefined: relayFeed`, `undefined: querier`, `undefined: MaxHashesPerFilter`.

- [ ] **Step 3: Write the implementation**

```go
// feed/feed.go
package feed

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/nbd-wtf/go-nostr"
)

// MaxHashesPerFilter caps how many block hashes ride in one filter. Relays
// impose their own limits and reject or truncate oversized filters, so we
// chunk rather than discover the ceiling in production.
const MaxHashesPerFilter = 500

// Feed is the commitment transport. §6.3 froze this signature.
type Feed interface {
	Subscribe(ctx context.Context, authors [][32]byte) (<-chan Commitment, error)
	// Get is batched deliberately: NIP-01 offers no range query, so a range
	// fetch is one filter over block hashes the client already knows (§3.3).
	Get(ctx context.Context, author [32]byte, blockHashes [][32]byte) ([]Commitment, error)
}

// querier is the slice of a relay connection we depend on, so tests can drive
// a fake without a socket.
type querier interface {
	QuerySync(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error)
}

type relayFeed struct {
	queriers []querier
}

// NewRelayFeed connects to each URL. Several relays are used because a single
// relay can drop, delay, or serve split views (§3.5).
func NewRelayFeed(ctx context.Context, urls []string) (Feed, error) {
	f := &relayFeed{}
	for _, u := range urls {
		r, err := nostr.RelayConnect(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("feed: connect %s: %w", u, err)
		}
		f.queriers = append(f.queriers, r)
	}
	if len(f.queriers) == 0 {
		return nil, fmt.Errorf("feed: no relays configured")
	}
	return f, nil
}

func (f *relayFeed) Get(ctx context.Context, author [32]byte, blockHashes [][32]byte) ([]Commitment, error) {
	authorHex := hex.EncodeToString(author[:])

	var out []Commitment
	for start := 0; start < len(blockHashes); start += MaxHashesPerFilter {
		end := start + MaxHashesPerFilter
		if end > len(blockHashes) {
			end = len(blockHashes)
		}

		values := make([]string, 0, end-start)
		for _, bh := range blockHashes[start:end] {
			values = append(values, displayHex(bh))
		}

		filter := nostr.Filter{
			Kinds:   []int{KindCommitment},
			Authors: []string{authorHex},
			Tags:    nostr.TagMap{TagBlockHash: values},
			// No Since/Until. created_at is self-asserted (§3.5).
		}

		for _, q := range f.queriers {
			evs, err := q.QuerySync(ctx, filter)
			if err != nil {
				continue // one relay failing is not the query failing
			}
			for _, ev := range evs {
				c, err := FromEvent(*ev)
				if err != nil {
					continue // unverifiable events are dropped, never returned
				}
				out = append(out, c)
			}
		}
	}
	return out, nil
}

func (f *relayFeed) Subscribe(ctx context.Context, authors [][32]byte) (<-chan Commitment, error) {
	hexAuthors := make([]string, 0, len(authors))
	for _, a := range authors {
		hexAuthors = append(hexAuthors, hex.EncodeToString(a[:]))
	}

	filter := nostr.Filter{
		Kinds:   []int{KindCommitment},
		Authors: hexAuthors,
	}

	ch := make(chan Commitment, 64)

	// The client subscribes to all its configured indexers and never reveals
	// which block it cares about — that is the privacy argument for using a
	// relay rather than N direct connections (§3.4).
	for _, q := range f.queriers {
		r, ok := q.(*nostr.Relay)
		if !ok {
			continue
		}
		sub, err := r.Subscribe(ctx, nostr.Filters{filter})
		if err != nil {
			return nil, fmt.Errorf("feed: subscribe: %w", err)
		}
		go func() {
			for ev := range sub.Events {
				c, err := FromEvent(*ev)
				if err != nil {
					continue
				}
				select {
				case ch <- c:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		<-ctx.Done()
		close(ch)
	}()

	return ch, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./feed/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add feed/feed.go feed/feed_test.go feed/commitment_test.go
git commit -m "feat(feed): relay client with batched Get and author subscribe"
```

---

### Task 14: The §7.4 vector format, a generator, and hermetic CI

**Files:**
- Create: `internal/testvector/vector.go`
- Create: `testdata/vectors/empty-block.json`
- Test: `internal/testvector/vector_test.go`

**Interfaces:**
- Consumes: `canonical.Set`, `commit.Root`.
- Produces: `type Vector`, `func Load(path string) (Vector, error)`, `func (v Vector) Run() error`. Plan B's differential suite and §7.3's corner cases both extend this format.

**The format, from §7.4.** The prevout map is what makes a vector self-contained — it is exactly what a node would otherwise supply, so any implementation consumes these with no node and no network. Keys are `<txid>:<vout>` with the txid in **display** hex, matching what Core's REST API returns.

- [ ] **Step 1: Write the failing test**

```go
// internal/testvector/vector_test.go
package testvector

import (
	"os"
	"path/filepath"
	"testing"
)

// Every committed vector must load and pass. This is the whole CI contract for
// §7: hermetic, no node, no network.
func TestAllCommittedVectorsPass(t *testing.T) {
	paths, err := filepath.Glob("../../testdata/vectors/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no vectors committed — the suite asserts nothing")
	}

	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			v, err := Load(p)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if v.Name == "" {
				t.Error("vector has no name")
			}
			if v.Rationale == "" {
				t.Error("vector has no rationale — a vector nobody can explain is a vector nobody can fix")
			}
			if err := v.Run(); err != nil {
				t.Errorf("run: %v", err)
			}
		})
	}
}

func TestVectorDetectsAWrongExpectedRoot(t *testing.T) {
	v, err := Load("../../testdata/vectors/empty-block.json")
	if err != nil {
		t.Fatal(err)
	}
	v.Expected.Root = "00" + v.Expected.Root[2:]
	if err := v.Run(); err == nil {
		t.Error("a corrupted expected root must fail the vector")
	}
}

func TestLoadRejectsMalformed(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmp, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(tmp); err == nil {
		t.Error("malformed vector must fail to load")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/testvector/ -v`
Expected: FAIL — the package does not exist.

- [ ] **Step 3: Write the vector type and runner**

```go
// internal/testvector/vector.go
// Package testvector implements §7.4's self-contained vector format. A vector
// carries a whole block plus the prevouts a node would otherwise supply, so any
// implementation can consume it with no node and no network.
package testvector

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type Prevout struct {
	ScriptPubKey string `json:"scriptPubKey"`
	Value        int64  `json:"value"`
}

type Expected struct {
	N      uint32   `json:"n"`
	Leaves []string `json:"leaves"` // "<txid display hex>:<tweak hex>"
	Root   string   `json:"root"`
}

type Vector struct {
	Name string `json:"name"`
	// Network is a display name; the root binds the 4-byte magic (§3.2).
	Network string `json:"network"`
	// Block is the full serialized block, hex.
	Block string `json:"block"`
	// Prevouts is keyed "<txid display hex>:<vout>" — Core's REST form.
	Prevouts  map[string]Prevout `json:"prevouts"`
	Expected  Expected           `json:"expected"`
	Rationale string             `json:"rationale"`
}

func Load(path string) (Vector, error) {
	var v Vector
	raw, err := os.ReadFile(path)
	if err != nil {
		return v, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

type mapPrevouts map[wire.OutPoint]*wire.TxOut

func (m mapPrevouts) Prevout(op wire.OutPoint) (*wire.TxOut, error) {
	out, ok := m[op]
	if !ok {
		return nil, fmt.Errorf("prevout %s not in vector", op)
	}
	return out, nil
}

func networkFromName(name string) (canonical.Network, error) {
	switch name {
	case "main", "mainnet":
		return canonical.Network(chaincfg.MainNetParams.Net), nil
	case "signet":
		return canonical.Network(chaincfg.SigNetParams.Net), nil
	case "regtest":
		return canonical.Network(chaincfg.RegressionNetParams.Net), nil
	default:
		return 0, fmt.Errorf("unknown network %q", name)
	}
}

// Run recomputes the canonical set and the root from the vector's own data and
// compares against expected. Including expected.root means the vectors exercise
// §3.2's tagged hashing and odd-node promotion, not eligibility alone (§7.4).
func (v Vector) Run() error {
	net, err := networkFromName(v.Network)
	if err != nil {
		return err
	}

	blockBytes, err := hex.DecodeString(v.Block)
	if err != nil {
		return fmt.Errorf("block hex: %w", err)
	}
	var blk wire.MsgBlock
	if err := blk.Deserialize(bytes.NewReader(blockBytes)); err != nil {
		return fmt.Errorf("deserialize block: %w", err)
	}

	pv := mapPrevouts{}
	for key, p := range v.Prevouts {
		parts := strings.Split(key, ":")
		if len(parts) != 2 {
			return fmt.Errorf("prevout key %q is not <txid>:<vout>", key)
		}
		h, err := chainhash.NewHashFromStr(parts[0]) // display hex
		if err != nil {
			return fmt.Errorf("prevout key %q: %w", key, err)
		}
		vout, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("prevout key %q: %w", key, err)
		}
		spk, err := hex.DecodeString(p.ScriptPubKey)
		if err != nil {
			return fmt.Errorf("prevout %q scriptPubKey: %w", key, err)
		}
		pv[wire.OutPoint{Hash: *h, Index: uint32(vout)}] = wire.NewTxOut(p.Value, spk)
	}

	leaves, err := canonical.Set(net, &blk, pv)
	if err != nil {
		return fmt.Errorf("canonical.Set: %w", err)
	}

	if uint32(len(leaves)) != v.Expected.N {
		return fmt.Errorf("n = %d, want %d", len(leaves), v.Expected.N)
	}

	blockHash := blk.BlockHash()
	var bh [32]byte
	copy(bh[:], blockHash[:]) // chainhash is already internal order

	gotRoot := commit.Root(net, bh, leaves)
	if got := hex.EncodeToString(gotRoot[:]); got != v.Expected.Root {
		return fmt.Errorf("root = %s, want %s", got, v.Expected.Root)
	}
	return nil
}
```

- [ ] **Step 4: Write the generator**

The generator is Task 16's deliverable, because it needs the regtest harness
that task builds. This task's vector is written by hand in Step 5 below, which
is the right order: the format has to be exercised by something before a
generator is worth writing against it.

- [ ] **Step 5: Write the first committed vector by hand**

The empty block is the right first vector because §3.2 calls `n = 0` the common case, and it needs no prevouts at all. Generate its expected root once, from the implementation under test, then eyeball it against the definition — `merkle_root(∅)` is 32 zero bytes, so the root is `TaggedHash("canary/root/v1", magic ‖ blockhash ‖ 00000000 ‖ 00…00)`.

```bash
cat > /tmp/genempty.go <<'EOF'
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

func main() {
	// A regtest block containing only a coinbase.
	blk := wire.MsgBlock{Header: wire.BlockHeader{Version: 1, Bits: 0x207fffff, Nonce: 2}}
	cb := wire.NewMsgTx(2)
	cb.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, SignatureScript: []byte{0x51}})
	cb.AddTxOut(wire.NewTxOut(5000000000, []byte{0x51}))
	blk.AddTransaction(cb)

	var buf bytes.Buffer
	if err := blk.Serialize(&buf); err != nil {
		panic(err)
	}
	net := canonical.Network(chaincfg.RegressionNetParams.Net)
	h := blk.BlockHash()
	var bh [32]byte
	copy(bh[:], h[:])
	root := commit.Root(net, bh, nil)

	fmt.Printf("block: %s\n", hex.EncodeToString(buf.Bytes()))
	fmt.Printf("root:  %s\n", hex.EncodeToString(root[:]))
}
EOF
go run /tmp/genempty.go
```

Paste the two values into the vector:

```json
{
  "name": "empty-block",
  "network": "regtest",
  "block": "<block hex from the command above>",
  "prevouts": {},
  "expected": {
    "n": 0,
    "leaves": [],
    "root": "<root hex from the command above>"
  },
  "rationale": "A block with only a coinbase. n=0 is the common case on regtest, not a corner (§3.2), and merkle_root(∅) is 32 zero bytes, so this vector pins the empty-set rule and the outer root preimage at the same time."
}
```

- [ ] **Step 6: Run the full suite**

Run: `go vet ./... && go test ./...`
Expected: PASS across every package, with no node and no network running.

- [ ] **Step 7: Commit**

```bash
git add internal/testvector testdata/vectors Makefile
git commit -m "feat(testvector): §7.4 self-contained vector format and the empty-block vector"
```

---

### Task 15: `wire` — the self-describing position list

**Files:**
- Create: `wire/response.go`
- Test: `wire/response_test.go`

**Interfaces:**
- Consumes: `canonical.Leaf`.
- Produces: `type PositionKind`, `type Position struct { Kind PositionKind; Leaf canonical.Leaf; Hash [32]byte }`, `KindFull`, `KindHash`, `KindAbsent`, `func EncodeResponse(positions []Position) ([]byte, error)`, `func DecodeResponse(buf []byte) ([]Position, error)`.

**Why this lives in the core and not in the fork.** Both the indexer fork and the sidecar need this type — one encodes, the other decodes. Go forbids importing a module's `internal/` tree from another module, so putting it in `blindbit-oracle/internal/server` would compile inside the fork and fail the moment the sidecar imported it. It is protocol, not server plumbing, so it belongs here.

**The format, from §2.4.** Each position is a full leaf, that leaf's 32-byte hash, or nothing, and the client must be able to tell which without inference. The list is exactly `n` long. **A response that is merely shorter is indistinguishable from a smaller block**, and under a single server there is no cross-check to catch the difference.

Encoding: a 4-byte little-endian `n`, then `n` records, each a 1-byte tag followed by 65 bytes (`KindFull`), 32 bytes (`KindHash`), or nothing (`KindAbsent`).

- [ ] **Step 1: Write the failing test**

```go
// wire/response_test.go
package wire

import (
	"encoding/binary"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
)

func TestEncodeIsSelfDescribingAtLengthN(t *testing.T) {
	var leaf canonical.Leaf
	leaf.TxID[0] = 0x11
	leaf.Tweak[0] = 0x02

	var hash [32]byte
	hash[0] = 0x22

	positions := []Position{
		{Kind: KindFull, Leaf: leaf},
		{Kind: KindAbsent},
		{Kind: KindHash, Hash: hash},
	}

	out, err := EncodeResponse(positions)
	if err != nil {
		t.Fatal(err)
	}

	if n := binary.LittleEndian.Uint32(out[0:4]); n != 3 {
		t.Errorf("declared n = %d, want 3", n)
	}
	// 4 + (1+65) + (1) + (1+32) = 104
	if len(out) != 104 {
		t.Errorf("encoded length = %d, want 104", len(out))
	}
	if out[4] != byte(KindFull) || out[4+66] != byte(KindAbsent) || out[4+66+1] != byte(KindHash) {
		t.Error("position tags are wrong — the client must not have to infer the kind")
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	var leaf canonical.Leaf
	for i := range leaf.TxID {
		leaf.TxID[i] = byte(i)
	}
	leaf.Tweak[0] = 0x03

	in := []Position{{Kind: KindFull, Leaf: leaf}, {Kind: KindAbsent}}
	out, err := EncodeResponse(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeResponse(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Leaf != leaf || got[1].Kind != KindAbsent {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestDecodeRejectsTruncation(t *testing.T) {
	var leaf canonical.Leaf
	out, err := EncodeResponse([]Position{{Kind: KindFull, Leaf: leaf}, {Kind: KindFull, Leaf: leaf}})
	if err != nil {
		t.Fatal(err)
	}
	// Truncation is caught by the declared n, not by trailing-byte luck. A
	// shorter response that decoded cleanly would be indistinguishable from a
	// smaller block, which is the hole §2.4 closes.
	if _, err := DecodeResponse(out[:len(out)-10]); err == nil {
		t.Error("a truncated response must fail to decode")
	}
}

func TestDecodeRejectsUnknownKind(t *testing.T) {
	buf := make([]byte, 5)
	binary.LittleEndian.PutUint32(buf[0:4], 1)
	buf[4] = 0x7f
	if _, err := DecodeResponse(buf); err == nil {
		t.Error("an unknown position kind must fail rather than be skipped")
	}
}

func TestDecodeRejectsAnOverlongDeclaredN(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf[0:4], 1_000_000)
	// A huge n with no body must fail rather than allocate a million entries.
	if _, err := DecodeResponse(buf); err == nil {
		t.Error("a declared n with no body must fail to decode")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./wire/ -v`
Expected: FAIL — the package does not exist.

- [ ] **Step 3: Write the implementation**

```go
// wire/response.go
//
// Package wire is §2.4's response format: the canonical-order list in which
// every position is a full leaf, that leaf's hash, or nothing.
//
// It lives in the protocol core rather than in either binary because both need
// it — the indexer encodes, the sidecar decodes — and Go will not let one
// module import another module's internal tree.
package wire

import (
	"encoding/binary"
	"fmt"

	"github.com/Sky-walkerX/canary/canonical"
)

type PositionKind byte

const (
	// KindFull carries the whole 65-byte leaf: txid ‖ tweak.
	KindFull PositionKind = 1
	// KindHash carries the 32-byte leaf hash for a position the server pruned
	// but retained (§2.4). The response stays verifiable from that one server.
	KindHash PositionKind = 2
	// KindAbsent carries nothing. Permitted only outside the retention window;
	// the block is then verifiable only once the leaf is recovered elsewhere.
	KindAbsent PositionKind = 3
)

type Position struct {
	Kind PositionKind
	Leaf canonical.Leaf
	Hash [32]byte
}

// EncodeResponse writes the self-describing position list.
//
// The leading n and the per-position tag together are what make truncation
// detectable. Without them a shorter response is indistinguishable from a
// smaller block, and under a single server nothing else would catch it.
func EncodeResponse(positions []Position) ([]byte, error) {
	out := make([]byte, 4, 4+len(positions)*66)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(positions)))

	for i, p := range positions {
		switch p.Kind {
		case KindFull:
			out = append(out, byte(KindFull))
			out = append(out, p.Leaf.TxID[:]...)
			out = append(out, p.Leaf.Tweak[:]...)
		case KindHash:
			out = append(out, byte(KindHash))
			out = append(out, p.Hash[:]...)
		case KindAbsent:
			out = append(out, byte(KindAbsent))
		default:
			return nil, fmt.Errorf("wire: position %d has unknown kind %d", i, p.Kind)
		}
	}
	return out, nil
}

func DecodeResponse(buf []byte) ([]Position, error) {
	if len(buf) < 4 {
		return nil, fmt.Errorf("wire: response shorter than its length prefix")
	}
	n := binary.LittleEndian.Uint32(buf[0:4])

	// Guard the allocation before trusting the declared length: the smallest
	// possible record is one tag byte, so n cannot exceed the remaining bytes.
	if uint64(n) > uint64(len(buf)-4) {
		return nil, fmt.Errorf("wire: declared n=%d exceeds the %d bytes available", n, len(buf)-4)
	}

	off := 4
	positions := make([]Position, 0, n)
	for i := uint32(0); i < n; i++ {
		if off >= len(buf) {
			return nil, fmt.Errorf("wire: truncated at position %d of %d", i, n)
		}
		kind := PositionKind(buf[off])
		off++

		switch kind {
		case KindFull:
			if off+65 > len(buf) {
				return nil, fmt.Errorf("wire: truncated leaf at position %d", i)
			}
			var p Position
			p.Kind = KindFull
			copy(p.Leaf.TxID[:], buf[off:off+32])
			copy(p.Leaf.Tweak[:], buf[off+32:off+65])
			off += 65
			positions = append(positions, p)
		case KindHash:
			if off+32 > len(buf) {
				return nil, fmt.Errorf("wire: truncated hash at position %d", i)
			}
			var p Position
			p.Kind = KindHash
			copy(p.Hash[:], buf[off:off+32])
			off += 32
			positions = append(positions, p)
		case KindAbsent:
			positions = append(positions, Position{Kind: KindAbsent})
		default:
			return nil, fmt.Errorf("wire: position %d has unknown kind %d", i, kind)
		}
	}

	if uint32(len(positions)) != n {
		return nil, fmt.Errorf("wire: decoded %d positions, header declared %d", len(positions), n)
	}
	return positions, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./wire/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add wire/
git commit -m "feat(wire): §2.4 self-describing position list"
```

---

### Task 16: The §7.3 corner vectors and a real generator

**Files:**
- Create: `internal/testvector/cmd/genvectors/main.go` (replacing Task 14's placeholder)
- Create: `internal/testvector/regtest.go`
- Create: `testdata/vectors/nums-h-script-path.json`, `ordinary-script-path.json`, `segwit-v2-input.json`, `uncompressed-p2pkh.json`
- Test: covered by Task 14's `TestAllCommittedVectorsPass`

**Interfaces:**
- Consumes: `canonical.Set`, `commit.Root`, `testvector.Vector`.
- Produces: a `genvectors` binary and four committed corner vectors.

**Why these four.** §7.3 lists the places two correct implementations can disagree on `T_base`, and §7.6 ships them upstream — so an inverted expectation would teach exactly the bug the vector exists to catch. The NUMS-H pair is the richest corner and it is deliberately a *pair*: one case where the input must be excluded and one where it must be included, so the suite catches both over- and under-exclusion.

| Vector | Construction | Expected |
|---|---|---|
| `nums-h-script-path` | P2TR with internal key *H*, spent via script path | Input **excluded**. If it is the only eligible input, the transaction is not in the set |
| `ordinary-script-path` | Random internal key *P* ≠ *H*, script path | Input **included** — only *H* is excluded, not script-path spends in general |
| `segwit-v2-input` | Spend a v2 witness program alongside an eligible input | **Whole transaction excluded** (§2.2 rule 3) |
| `uncompressed-p2pkh` | 65-byte public key in a P2PKH scriptSig | Input **excluded** — compressed and x-only only |

- [ ] **Step 1: Write the regtest harness**

```go
// internal/testvector/regtest.go
//
// Dev-time helpers that talk to a local regtest node. Never imported by CI —
// the committed JSON is what `go test` consumes (§7.4).
package testvector

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Client is a thin Bitcoin Core REST client. REST rather than RPC because
// blindbit-oracle v2 requires Core v30+ REST anyway, so the dependency is
// already there.
type Client struct {
	BaseURL string // e.g. http://localhost:18443/rest
}

func (c Client) get(path string) ([]byte, error) {
	resp, err := http.Get(c.BaseURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("core REST %s: %s", path, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// BlockHex returns the serialized block.
func (c Client) BlockHex(blockHash string) (string, error) {
	b, err := c.get("/block/" + blockHash + ".hex")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// SpentTxOuts returns the outputs spent by a block — Core v30's
// /rest/spenttxouts endpoint (PR #32540), which is exactly the prevout data a
// vector needs to be self-contained.
func (c Client) SpentTxOuts(blockHash string) (map[string]Prevout, error) {
	raw, err := c.get("/spenttxouts/" + blockHash + ".json")
	if err != nil {
		return nil, err
	}
	var parsed []struct {
		TxID    string `json:"txid"`
		Vout    uint32 `json:"vout"`
		Value   float64 `json:"value"`
		ScriptPubKey struct {
			Hex string `json:"hex"`
		} `json:"scriptPubKey"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse spenttxouts: %w", err)
	}

	out := map[string]Prevout{}
	for _, p := range parsed {
		if _, err := hex.DecodeString(p.ScriptPubKey.Hex); err != nil {
			return nil, fmt.Errorf("prevout %s:%d: bad scriptPubKey", p.TxID, p.Vout)
		}
		out[fmt.Sprintf("%s:%d", p.TxID, p.Vout)] = Prevout{
			ScriptPubKey: p.ScriptPubKey.Hex,
			Value:        int64(p.Value * 1e8),
		}
	}
	return out, nil
}
```

Confirm the `/spenttxouts` response shape against the node on day 1 rather than trusting this sketch — §6.6 already lists Core's REST behaviour as a day-1 verification, and this is the endpoint it means.

- [ ] **Step 2: Write the generator**

```go
// internal/testvector/cmd/genvectors/main.go
//
// Command genvectors turns a regtest block into a §7.4 vector. Dev-time only:
// it needs a running node, and CI never invokes it. Run it via `make vectors`.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/internal/testvector"
	"github.com/btcsuite/btcd/chaincfg"
)

func main() {
	var (
		rest      = flag.String("rest", "http://localhost:18443/rest", "Bitcoin Core REST base URL")
		blockHash = flag.String("block", "", "block hash, display hex")
		name      = flag.String("name", "", "vector name")
		rationale = flag.String("rationale", "", "why this vector exists")
		out       = flag.String("out", "", "output path")
	)
	flag.Parse()

	if *blockHash == "" || *name == "" || *out == "" || *rationale == "" {
		flag.Usage()
		os.Exit(2)
	}

	c := testvector.Client{BaseURL: *rest}

	blockHex, err := c.BlockHex(*blockHash)
	if err != nil {
		fail("fetch block: %v", err)
	}
	prevouts, err := c.SpentTxOuts(*blockHash)
	if err != nil {
		fail("fetch prevouts: %v", err)
	}

	v := testvector.Vector{
		Name:      *name,
		Network:   "regtest",
		Block:     blockHex,
		Prevouts:  prevouts,
		Rationale: *rationale,
	}

	// Fill expected by running our own implementation, then REVIEW IT BY HAND
	// against the §7.3 table before committing. A generated expectation that
	// nobody checked just freezes today's bug into the suite — and §7.6 ships
	// these upstream, where a wrong expectation teaches the bug it exists to
	// catch.
	blk, pv, err := testvector.Materialize(v)
	if err != nil {
		fail("materialize: %v", err)
	}
	net := canonical.Network(chaincfg.RegressionNetParams.Net)
	leaves, err := canonical.Set(net, blk, pv)
	if err != nil {
		fail("canonical.Set: %v", err)
	}

	h := blk.BlockHash()
	var bh [32]byte
	copy(bh[:], h[:])
	root := commit.Root(net, bh, leaves)

	v.Expected.N = uint32(len(leaves))
	v.Expected.Root = hex.EncodeToString(root[:])
	for _, l := range leaves {
		var disp [32]byte
		for i := 0; i < 32; i++ {
			disp[i] = l.TxID[31-i]
		}
		v.Expected.Leaves = append(v.Expected.Leaves,
			hex.EncodeToString(disp[:])+":"+hex.EncodeToString(l.Tweak[:]))
	}

	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fail("marshal: %v", err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fail("write: %v", err)
	}

	fmt.Fprintf(os.Stderr, "wrote %s: n=%d root=%s\n", *out, v.Expected.N, v.Expected.Root)
	fmt.Fprintf(os.Stderr, "REVIEW the expectation against §7.3 before committing.\n")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "genvectors: "+format+"\n", args...)
	os.Exit(1)
}
```

Extract the block-and-prevout materialisation out of `Vector.Run` into an exported `testvector.Materialize(v Vector) (*wire.MsgBlock, PrevoutSource, error)` so the generator and the runner share one parser. `Run` then calls `Materialize` too.

- [ ] **Step 3: Construct the corner transactions on regtest**

Regtest, not signet: several of these need arbitrary scripts and controlled block composition, and on public signet we cannot mine (§7.2).

```bash
# NUMS-H script path. H is the BIP-341 NUMS point, exported by the library as
# bip352.NumsH, so the construction and the assertion share one constant.
#
# Build a taproot output whose internal key is H with a single anyone-can-spend
# leaf, spend it via the script path, and put an eligible P2WPKH input beside it
# in a second vector so the two cases differ only in the internal key.
bitcoin-cli -regtest generatetoaddress 1 "$ADDR"
# ... construct with a raw transaction, then:
./genvectors -block "$(bitcoin-cli -regtest getbestblockhash)" \
  -name nums-h-script-path \
  -rationale "BIP-352 excludes script-path spends whose taproot internal key is the NUMS point H. If it is the only eligible input the transaction is not in T_base (§7.3)." \
  -out testdata/vectors/nums-h-script-path.json
```

Repeat for the other three, each with its own `-rationale`.

- [ ] **Step 4: Hand-review every expectation**

For each generated vector, check `expected.n` and `expected.leaves` against the §7.3 table above **before** committing. The NUMS-H pair is the one to check twice: an earlier draft of §7.3 had this exact expectation inverted, and §7.6 ships these upstream where a wrong expectation teaches the bug.

- [ ] **Step 5: Run the suite and commit**

```bash
go test ./internal/testvector/ -v
git add internal/testvector testdata/vectors
git commit -m "feat(testvector): §7.3 corner vectors and a real generator"
```

---

## Definition of done

- [ ] `go vet ./...` and `go test ./...` pass with no Bitcoin Core, no relay, and no network.
- [ ] Every signature in §6.3 exists with exactly the frozen shape — no renames, no added parameters.
- [ ] The dependency guard test passes and `go.mod` names `go-bip352`, not `gobip352`.
- [ ] `canonical`, `commit`, `policy` and `feed` are importable by Plans B and C.
- [ ] `testdata/vectors/` holds the empty-block vector plus §7.3's four corners, and the suite fails if a vector's expected root is corrupted.
- [ ] `wire.EncodeResponse` / `DecodeResponse` exist in the core, not in either binary's internal tree.
- [ ] `commit.RootFromLeafHashes` agrees with `commit.Root` for every set size tested.

**Handoff:** Plan B (indexer fork) needs `canonical.Leaf`, `commit.Root` and `feed.Commitment.ToEvent`. Plan C (sidecar) needs all four packages plus `commit.LeafHash`, `commit.VerifyProof` and `feed.Feed`. Neither can start against stubs before Task 1 lands, which is why §6.6 puts the interface freeze on day 2.
