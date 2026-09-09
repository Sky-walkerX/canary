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
