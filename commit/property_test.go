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
