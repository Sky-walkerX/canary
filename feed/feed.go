package feed

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/nbd-wtf/go-nostr"
)

// MaxHashesPerFilter caps how many block hashes go in one filter. Relays set
// their own limits and reject or truncate oversized filters, so Get splits the
// list instead of finding the limit in production.
const MaxHashesPerFilter = 500

// Feed fetches signed records from relays. Its signature is frozen, because
// the checker and the indexer build against it in parallel.
type Feed interface {
	Subscribe(ctx context.Context, authors [][32]byte) (<-chan Commitment, error)
	// Get takes a batch of block hashes on purpose. NIP-01 has no range query,
	// so fetching a range means one filter over block hashes the client
	// already knows.
	Get(ctx context.Context, author [32]byte, blockHashes [][32]byte) ([]Commitment, error)
}

// querier is the part of a relay connection Get uses, so tests can drive a fake
// without a socket.
type querier interface {
	QuerySync(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error)
}

// subscriber is the part of a relay connection Subscribe uses. It is an
// interface, not the concrete *nostr.Relay, so tests can drive Subscribe's real
// fan-out and fan-in with a fake and no socket. Its signature, opts included,
// must match *nostr.Relay's Subscribe method exactly, or *nostr.Relay stops
// satisfying it.
type subscriber interface {
	Subscribe(ctx context.Context, filters nostr.Filters, opts ...nostr.SubscriptionOption) (*nostr.Subscription, error)
}

type relayFeed struct {
	queriers []querier
}

// NewRelayFeed connects to each URL. It uses several relays because one relay
// can drop events, delay them or show different clients different views.
func NewRelayFeed(ctx context.Context, urls []string) (Feed, error) {
	f := &relayFeed{}
	for _, u := range urls {
		r, err := nostr.RelayConnect(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("feed: connect to relay %s: %w", u, err)
		}
		f.queriers = append(f.queriers, r)
	}
	if len(f.queriers) == 0 {
		return nil, fmt.Errorf("feed: connect to relays: none configured")
	}
	return f, nil
}

func (f *relayFeed) Get(ctx context.Context, author [32]byte, blockHashes [][32]byte) ([]Commitment, error) {
	authorHex := hex.EncodeToString(author[:])

	var out []Commitment
	var attempts, succeeded int
	for start := 0; start < len(blockHashes); start += MaxHashesPerFilter {
		end := start + MaxHashesPerFilter
		if end > len(blockHashes) {
			end = len(blockHashes)
		}

		chunk := blockHashes[start:end]
		values := make([]string, 0, len(chunk))
		wantHash := make(map[[32]byte]bool, len(chunk))
		for _, bh := range chunk {
			values = append(values, displayHex(bh))
			wantHash[bh] = true
		}

		filter := nostr.Filter{
			Kinds:   []int{KindCommitment},
			Authors: []string{authorHex},
			Tags:    nostr.TagMap{TagBlockHash: values},
			// No Since or Until: the author sets created_at and can backdate it.
		}

		for _, q := range f.queriers {
			attempts++
			evs, err := q.QuerySync(ctx, filter)
			if err != nil {
				continue // one relay failing does not fail the query
			}
			succeeded++
			for _, ev := range evs {
				c, err := FromEvent(*ev)
				if err != nil {
					continue // unverifiable events are dropped, never returned
				}
				// NIP-01 filters are advisory. A relay need not honor
				// Authors or Tags, so a malicious or buggy one can return a
				// genuine, validly signed event from another author or for
				// another block. Canary names one specific server, so an
				// off-target event is dropped silently here. It is noise,
				// not an error.
				if c.Author != author {
					continue
				}
				if !wantHash[c.BlockHash] {
					continue
				}
				out = append(out, c)
			}
		}
	}

	if attempts > 0 && succeeded == 0 {
		return nil, fmt.Errorf("feed: query relays: all %d attempts failed across %d relays",
			attempts, len(f.queriers))
	}
	return out, nil
}

func (f *relayFeed) Subscribe(ctx context.Context, authors [][32]byte) (<-chan Commitment, error) {
	hexAuthors := make([]string, 0, len(authors))
	wantAuthor := make(map[[32]byte]bool, len(authors))
	for _, a := range authors {
		hexAuthors = append(hexAuthors, hex.EncodeToString(a[:]))
		wantAuthor[a] = true
	}

	filter := nostr.Filter{
		Kinds:   []int{KindCommitment},
		Authors: hexAuthors,
	}

	ch := make(chan Commitment, 64)
	var wg sync.WaitGroup

	// The client subscribes to every configured server and never reveals which
	// block it cares about. That is the privacy reason for one relay
	// subscription instead of a connection to each server.
	for _, q := range f.queriers {
		r, ok := q.(subscriber)
		if !ok {
			continue
		}
		sub, err := r.Subscribe(ctx, nostr.Filters{filter})
		if err != nil {
			return nil, fmt.Errorf("feed: subscribe to relay: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ev := range sub.Events {
				c, err := FromEvent(*ev)
				if err != nil {
					continue
				}
				// The same guard as in Get. NIP-01 filters are advisory,
				// so a relay may forward a genuine event from an author
				// nobody asked for. Drop it silently.
				if !wantAuthor[c.Author] {
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

	// Close only after every forwarding goroutine above has returned, never on
	// ctx.Done() directly. Otherwise a goroutine still running when ctx is
	// canceled can win the race and send on a closed channel. sub.Events
	// closes once ctx is canceled, because its context is a child of ctx, so
	// this still finishes and does not leak.
	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch, nil
}
