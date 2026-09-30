// Package commit builds the Merkle commitment over a canonical set.
package commit

import (
	"errors"

	"github.com/Sky-walkerX/canary/canonical"
)

// Proof is an inclusion proof for one position in the canonical order.
type Proof struct {
	Index    uint32     // position in canonical order
	N        uint32     // set size, bound into the root so a proof cannot be replayed at another length
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

// ProveFromLeafHashes builds the same proof as Prove from leaf hashes in
// canonical order. A client needs it when a server sent some positions as
// hashes only. The client then holds hashes, not leaves, and must still prove
// that a full entry it received is in the root.
func ProveFromLeafHashes(hashes [][32]byte, i uint32) (Proof, error) {
	if len(hashes) == 0 {
		return Proof{}, ErrEmptySet
	}
	if int(i) >= len(hashes) {
		return Proof{}, ErrIndexOutOfRange
	}

	n := len(hashes)
	p := Proof{Index: i, N: uint32(n)}

	// Each sibling is rebuilt from a slice of hashes, so no tree level is
	// stored. At level L, where span = 2^L, node j covers the half-open leaf
	// range [j*span, min((j+1)*span, n)). Pairing starts from the left at
	// every level. A slice that starts at a multiple of span therefore pairs
	// its nodes exactly as the full tree does, so merkleRootFromHashes of that
	// slice is the node. The siblings cover disjoint ranges that exclude leaf
	// i, so one proof costs fewer than n node hashes.
	idx, width := int(i), n
	for span := 1; width > 1; span *= 2 {
		sib := idx ^ 1
		if sib < width {
			lo := sib * span
			hi := min(lo+span, n)
			p.Siblings = append(p.Siblings, merkleRootFromHashes(hashes[lo:hi]))
		}
		// sib >= width means this node is the unpaired last one. It moves up
		// a level with no sibling, the same promotion rule Prove follows.
		idx /= 2
		width = (width + 1) / 2
	}
	return p, nil
}

// VerifyProof recomputes the root from leaf and p and compares. It needs no
// leaf set, which keeps an evidence file small enough to read.
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

	// Same outer preimage as Root, by construction rather than by convention.
	return rootFromInner(net, blockHash, int(p.N), h) == root
}
