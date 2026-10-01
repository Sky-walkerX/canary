package ladder

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/nbd-wtf/go-nostr"
)

// ErrBadRecord means a served record failed the checks, so it counts as no
// record. Errors from the feed package's own checks are wrapped as well.
var ErrBadRecord = errors.New("ladder: record rejected")

// CheckRecord reads the body of /commitment/{hash} and checks it the way step
// 1 does. The event id and signature must be valid, and the pinned key must
// have signed it. Its b tag must name blockHash, and its network tag must
// name Core's network.
//
// blockHash is in internal byte order. The feed package converts the tag's
// display order, so the conversion happens in one place.
//
// canary check can call this for every block before the ladder runs, to
// learn which neighbouring blocks a server signed records for.
func CheckRecord(body []byte, pubkey, blockHash [32]byte, net canonical.Network) (*Record, error) {
	var ev nostr.Event
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, fmt.Errorf("%w: not a Nostr event: %v", ErrBadRecord, err)
	}
	c, err := feed.FromEvent(ev)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadRecord, err)
	}
	if c.Author != pubkey {
		return nil, fmt.Errorf("%w: signed by %x, not the pinned key %x", ErrBadRecord, c.Author, pubkey)
	}
	if c.BlockHash != blockHash {
		return nil, fmt.Errorf("%w: the b tag names another block", ErrBadRecord)
	}
	if c.Network != net {
		return nil, fmt.Errorf("%w: network magic %d, Core is on %d", ErrBadRecord, uint32(c.Network), uint32(net))
	}
	return &Record{Event: ev, Commitment: c}, nil
}
