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
