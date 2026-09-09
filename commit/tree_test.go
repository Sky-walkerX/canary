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
	h := [][32]byte{LeafHash(three[0]), LeafHash(three[1]), LeafHash(three[2])}
	dupL1 := [][32]byte{nodeHash(h[0], h[1]), nodeHash(h[2], h[2])}
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
