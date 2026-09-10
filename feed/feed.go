// Package feed carries commitments over Nostr. Spec §3.3, §3.4.
package feed

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/nbd-wtf/go-nostr"
)

// MaxHashesPerFilter caps how many block hashes ride in one filter. Relays
// impose their own limits and reject or truncate oversized filters, so we
// chunk rather than discover the ceiling in production.
const MaxHashesPerFilter = 500

// Feed is the commitment transport. §6.3 froze this signature.
type Feed interface {
	Subscribe(ctx context.Context, authors [][32]byte) (<-chan Commitment, error)
	// Get is batched deliberately: NIP-01 offers no range query, so a range
	// fetch is one filter over block hashes the client already knows (§3.3).
	Get(ctx context.Context, author [32]byte, blockHashes [][32]byte) ([]Commitment, error)
}

// querier is the slice of a relay connection we depend on, so tests can drive
// a fake without a socket.
type querier interface {
	QuerySync(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error)
}

type relayFeed struct {
	queriers []querier
}

// NewRelayFeed connects to each URL. Several relays are used because a single
// relay can drop, delay, or serve split views (§3.5).
func NewRelayFeed(ctx context.Context, urls []string) (Feed, error) {
	f := &relayFeed{}
	for _, u := range urls {
		r, err := nostr.RelayConnect(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("feed: connect %s: %w", u, err)
		}
		f.queriers = append(f.queriers, r)
	}
	if len(f.queriers) == 0 {
		return nil, fmt.Errorf("feed: no relays configured")
	}
	return f, nil
}

func (f *relayFeed) Get(ctx context.Context, author [32]byte, blockHashes [][32]byte) ([]Commitment, error) {
	authorHex := hex.EncodeToString(author[:])

	var out []Commitment
	for start := 0; start < len(blockHashes); start += MaxHashesPerFilter {
		end := start + MaxHashesPerFilter
		if end > len(blockHashes) {
			end = len(blockHashes)
		}

		values := make([]string, 0, end-start)
		for _, bh := range blockHashes[start:end] {
			values = append(values, displayHex(bh))
		}

		filter := nostr.Filter{
			Kinds:   []int{KindCommitment},
			Authors: []string{authorHex},
			Tags:    nostr.TagMap{TagBlockHash: values},
			// No Since/Until. created_at is self-asserted (§3.5).
		}

		for _, q := range f.queriers {
			evs, err := q.QuerySync(ctx, filter)
			if err != nil {
				continue // one relay failing is not the query failing
			}
			for _, ev := range evs {
				c, err := FromEvent(*ev)
				if err != nil {
					continue // unverifiable events are dropped, never returned
				}
				out = append(out, c)
			}
		}
	}
	return out, nil
}

func (f *relayFeed) Subscribe(ctx context.Context, authors [][32]byte) (<-chan Commitment, error) {
	hexAuthors := make([]string, 0, len(authors))
	for _, a := range authors {
		hexAuthors = append(hexAuthors, hex.EncodeToString(a[:]))
	}

	filter := nostr.Filter{
		Kinds:   []int{KindCommitment},
		Authors: hexAuthors,
	}

	ch := make(chan Commitment, 64)
	var wg sync.WaitGroup

	// The client subscribes to all its configured indexers and never reveals
	// which block it cares about — that is the privacy argument for using a
	// relay rather than N direct connections (§3.4).
	for _, q := range f.queriers {
		r, ok := q.(*nostr.Relay)
		if !ok {
			continue
		}
		sub, err := r.Subscribe(ctx, nostr.Filters{filter})
		if err != nil {
			return nil, fmt.Errorf("feed: subscribe: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ev := range sub.Events {
				c, err := FromEvent(*ev)
				if err != nil {
					continue
				}
				select {
				case ch <- c:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Close only after every forwarding goroutine above has returned, never
	// on ctx.Done() directly: a goroutine still in flight when ctx is
	// cancelled can otherwise win the race and send on an already-closed
	// channel. sub.Events itself closes once ctx is cancelled (its context
	// is a child of ctx), so this still completes and does not leak.
	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch, nil
}
