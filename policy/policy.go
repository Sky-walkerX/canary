package policy

import (
	"github.com/Sky-walkerX/canary/canonical"
)

// Policy is every field a server may declare. Each field only removes entries.
type Policy struct {
	Network          canonical.Network
	StartHeight      uint32
	PrunesSpent      bool
	DustThresholdSat uint64 // declared, never verified: entries carry no amount
	DustConfigurable bool
}
