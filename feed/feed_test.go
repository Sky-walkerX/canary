package feed

import (
	"context"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// fakeRelay records the filters it was asked for and replays canned events.
type fakeRelay struct {
	events []nostr.Event
	seen   []nostr.Filter
}

func (f *fakeRelay) QuerySync(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	f.seen = append(f.seen, filter)
	var out []*nostr.Event
	for i := range f.events {
		if filter.Matches(&f.events[i]) {
			out = append(out, &f.events[i])
		}
	}
	return out, nil
}

func TestGetBatchesHashesIntoOneFilter(t *testing.T) {
	sk, _ := testKey(t)

	var want []Commitment
	var events []nostr.Event
	for i := 0; i < 3; i++ {
		c := testCommitment()
		c.BlockHash[31] = byte(i) // distinct blocks
		ev, err := c.ToEvent(sk)
		if err != nil {
			t.Fatal(err)
		}
		c.Author = mustAuthor(t, ev.PubKey)
		want = append(want, c)
		events = append(events, ev)
	}

	fr := &fakeRelay{events: events}
	f := &relayFeed{queriers: []querier{fr}}

	hashes := [][32]byte{want[0].BlockHash, want[1].BlockHash, want[2].BlockHash}
	got, err := f.Get(context.Background(), want[0].Author, hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d commitments, want 3", len(got))
	}

	// One filter, not three. Three round trips per block range is the thing
	// batching exists to avoid.
	if len(fr.seen) != 1 {
		t.Errorf("issued %d filters, want 1 batched filter (§3.3)", len(fr.seen))
	}
	if n := len(fr.seen[0].Tags[TagBlockHash]); n != 3 {
		t.Errorf("filter carried %d block hashes, want 3", n)
	}
	if len(fr.seen[0].Kinds) != 1 || fr.seen[0].Kinds[0] != KindCommitment {
		t.Errorf("filter must pin the kind to %d", KindCommitment)
	}
	if len(fr.seen[0].Authors) != 1 {
		t.Error("filter must pin the author")
	}
	// created_at is never a query bound (§3.5).
	if fr.seen[0].Since != nil || fr.seen[0].Until != nil {
		t.Error("filter must not constrain created_at — it is self-asserted and backdatable")
	}
}

func TestGetChunksBeyondTheRelayLimit(t *testing.T) {
	fr := &fakeRelay{}
	f := &relayFeed{queriers: []querier{fr}}

	hashes := make([][32]byte, MaxHashesPerFilter+1)
	for i := range hashes {
		hashes[i][0] = byte(i % 256)
		hashes[i][1] = byte(i / 256)
	}

	var author [32]byte
	if _, err := f.Get(context.Background(), author, hashes); err != nil {
		t.Fatal(err)
	}
	if len(fr.seen) != 2 {
		t.Errorf("issued %d filters for %d hashes, want 2 chunks at limit %d",
			len(fr.seen), len(hashes), MaxHashesPerFilter)
	}
}

func TestGetSkipsEventsThatFailVerification(t *testing.T) {
	sk, _ := testKey(t)
	c := testCommitment()
	ev, err := c.ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}
	ev.Content = "00" // tamper: signature no longer covers it

	fr := &fakeRelay{events: []nostr.Event{ev}}
	f := &relayFeed{queriers: []querier{fr}}

	got, err := f.Get(context.Background(), mustAuthor(t, ev.PubKey), [][32]byte{c.BlockHash})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Error("a commitment failing verification must be dropped, never returned")
	}
}
