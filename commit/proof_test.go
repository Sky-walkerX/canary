package commit

import (
	"errors"
	"math/rand"
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
		t.Error("Prove must reject the empty set, which has nothing to prove")
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

func leafHashes(leaves []canonical.Leaf) [][32]byte {
	out := make([][32]byte, len(leaves))
	for i, l := range leaves {
		out[i] = LeafHash(l)
	}
	return out
}

func sameProof(a, b Proof) bool {
	if a.Index != b.Index || a.N != b.N || len(a.Siblings) != len(b.Siblings) {
		return false
	}
	for k := range a.Siblings {
		if a.Siblings[k] != b.Siblings[k] {
			return false
		}
	}
	return true
}

// Prove walks the stored tree levels. ProveFromLeafHashes rebuilds each
// sibling from a slice of leaf hashes. The two paths share no walking code,
// so agreement at every position is a real cross-check. n = 3 and n = 5
// exercise the rule that an unpaired node moves up a level without a sibling.
func TestProveFromLeafHashesAgreesWithProve(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	var bh [32]byte

	sizes := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 33}
	for iter := 0; iter < 20; iter++ {
		sizes = append(sizes, 1+r.Intn(64))
	}

	for _, n := range sizes {
		leaves := randLeaves(r, n)
		hashes := leafHashes(leaves)
		r.Read(bh[:])
		root := Root(netRegtest, bh, leaves)

		for i := 0; i < n; i++ {
			want, err := Prove(leaves, uint32(i))
			if err != nil {
				t.Fatalf("n=%d i=%d: Prove: %v", n, i, err)
			}
			got, err := ProveFromLeafHashes(hashes, uint32(i))
			if err != nil {
				t.Fatalf("n=%d i=%d: ProveFromLeafHashes: %v", n, i, err)
			}
			if !sameProof(got, want) {
				t.Fatalf("n=%d i=%d: hash path %+v != leaf path %+v", n, i, got, want)
			}
			if !VerifyProof(netRegtest, bh, root, leaves[i], got) {
				t.Fatalf("n=%d i=%d: proof from hashes did not verify", n, i)
			}
		}
	}
}

// The case the function exists for. A server sent full entries at positions
// 0, 2 and 4 and only hashes at 1 and 3. The test holds no leaf for 1 or 3.
// Their hashes are fixed bytes, not derived from any leaf, so a proof that
// verifies here cannot have used a leaf at a hash-only position.
func TestProveFromLeafHashesWithSomePositionsHashOnly(t *testing.T) {
	var bh [32]byte
	bh[0] = 0x42

	held := mkLeaves(3)
	full := map[int]canonical.Leaf{0: held[0], 2: held[1], 4: held[2]}
	hashOnly := map[int][32]byte{1: fixedHash(0xa1), 3: fixedHash(0xa3)}

	// The client hashes what it holds in full and uses the rest as sent.
	received := make([][32]byte, 5)
	for i := range received {
		if l, ok := full[i]; ok {
			received[i] = LeafHash(l)
		} else {
			received[i] = hashOnly[i]
		}
	}
	// No leaf set exists for this block, so the root can only come from the
	// hashes. This is the root a client checks against the signed record.
	root := RootFromLeafHashes(netRegtest, bh, received)

	for i, l := range full {
		p, err := ProveFromLeafHashes(received, uint32(i))
		if err != nil {
			t.Fatalf("i=%d: %v", i, err)
		}
		if !VerifyProof(netRegtest, bh, root, l, p) {
			t.Errorf("i=%d: proof built next to hash-only positions did not verify", i)
		}
	}

	// A proof must still bind its position. The entry held for position 2
	// must not verify at position 0.
	p0, err := ProveFromLeafHashes(received, 0)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyProof(netRegtest, bh, root, full[2], p0) {
		t.Error("the entry at position 2 verified with the proof for position 0")
	}

	// Position 4 of 5 moves up twice without a sibling, then pairs once.
	p4, err := ProveFromLeafHashes(received, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(p4.Siblings) != 1 {
		t.Errorf("position 4 of 5 has %d siblings, want 1", len(p4.Siblings))
	}

	// That one sibling covers positions 0 to 3, hash-only ones included. So
	// the proof must fail against a root over a different hash at position 3.
	altered := append([][32]byte(nil), received...)
	altered[3] = fixedHash(0xb3)
	if VerifyProof(netRegtest, bh, RootFromLeafHashes(netRegtest, bh, altered), full[4], p4) {
		t.Error("the proof for position 4 verified against a root over a different hash at position 3")
	}
}

// fixedHash returns 32 copies of b. Tests use it for a hash that no leaf
// produced.
func fixedHash(b byte) [32]byte {
	var h [32]byte
	for k := range h {
		h[k] = b
	}
	return h
}

func TestProveFromLeafHashesRejectsOutOfRangeAndEmpty(t *testing.T) {
	hashes := leafHashes(mkLeaves(3))
	if _, err := ProveFromLeafHashes(hashes, 3); !errors.Is(err, ErrIndexOutOfRange) {
		t.Errorf("index past the end: err = %v, want ErrIndexOutOfRange", err)
	}
	if _, err := Prove(mkLeaves(3), 3); !errors.Is(err, ErrIndexOutOfRange) {
		t.Errorf("Prove disagrees on the index past the end: err = %v", err)
	}
	if _, err := ProveFromLeafHashes(nil, 0); !errors.Is(err, ErrEmptySet) {
		t.Errorf("empty set: err = %v, want ErrEmptySet", err)
	}
	if _, err := Prove(nil, 0); !errors.Is(err, ErrEmptySet) {
		t.Errorf("Prove disagrees on the empty set: err = %v", err)
	}
}
