// Package policy holds a server's declared, subtractive index policy. Spec §2.3.
package policy

import (
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
