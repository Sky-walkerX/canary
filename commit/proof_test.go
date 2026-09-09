package commit

import "testing"

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
