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

// Prove builds an inclusion proof for position i.
func Prove(leaves []canonical.Leaf, i uint32) (Proof, error) {
	return Proof{}, errNotImplemented
}

// VerifyProof checks p against root without needing the full leaf set.
func VerifyProof(net canonical.Network, blockHash, root [32]byte, leaf canonical.Leaf, p Proof) bool {
	return false
}
