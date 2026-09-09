// Package feed carries commitments over Nostr. Spec §3.3, §3.4.
package feed

import (
	"errors"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/nbd-wtf/go-nostr"
)

// KindCommitment is a regular kind (1000–9999), therefore append-only.
// A replaceable kind here would void non-repudiation entirely (§3.3).
const KindCommitment = 1352

// TagBlockHash is single-letter because relays index nothing else (§3.3).
const TagBlockHash = "b"

// Commitment is one server's signed statement about one block.
type Commitment struct {
	Network     canonical.Network
	BlockHash   [32]byte
	BlockHeight uint32
	N           uint32
	Root        [32]byte
	PolicyRef   [32]byte // event id of the policy declaration in force
	Author      [32]byte // Nostr pubkey — implicit signer
}

var errNotImplemented = errors.New("feed: not implemented")

// ToEvent builds and signs the Nostr event carrying c.
func (c Commitment) ToEvent(sk [32]byte) (nostr.Event, error) {
	return nostr.Event{}, errNotImplemented
}

// FromEvent parses and verifies an event into a Commitment.
func FromEvent(e nostr.Event) (Commitment, error) {
	return Commitment{}, errNotImplemented
}
