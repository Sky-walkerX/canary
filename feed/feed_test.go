package feed

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// fakeRelay records the filters it was asked for and replays canned events,
// honoring NIP-01 filter matching the way a well-behaved relay would.
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

// maliciousRelay returns every canned event to every query, regardless of
// what the filter actually asked for. NIP-01 filters are advisory only — a
// relay is not obligated to honor Authors/Kinds/Tags — so a malicious (or
// just buggy) relay can legally hand back a genuine, validly-signed event
// the caller never asked about. This models that.
type maliciousRelay struct {
	events []nostr.Event
}

func (m *maliciousRelay) QuerySync(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	out := make([]*nostr.Event, len(m.events))
	for i := range m.events {
		out[i] = &m.events[i]
	}
	return out, nil
}

// alwaysFailQuerier models a relay that cannot be queried at all — e.g. a
// total network outage — so every QuerySync call fails.
type alwaysFailQuerier struct{}

func (alwaysFailQuerier) QuerySync(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	return nil, fmt.Errorf("connection refused")
}

// fakeSubscriber satisfies both querier and subscriber, exactly as
// *nostr.Relay does, so it can sit in relayFeed.queriers and be exercised
// through Subscribe's type assertion. It hands back a *nostr.Subscription
// built directly around a caller-controlled channel — nostr.Subscription's
// Events field is exported specifically so this works without a socket.
type fakeSubscriber struct {
	events chan *nostr.Event
}

func (s *fakeSubscriber) QuerySync(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	return nil, nil
}

func (s *fakeSubscriber) Subscribe(ctx context.Context, filters nostr.Filters, opts ...nostr.SubscriptionOption) (*nostr.Subscription, error) {
	return &nostr.Subscription{Events: s.events}, nil
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

// TestGetDropsEventsFromUnrequestedAuthor covers auth-scope-not-enforced: a
// relay is free to return a genuine, validly-signed event from a pubkey the
// caller never asked about, and Get must never surface it. Attribution to a
// specific named indexer is the whole point of the project (§1.2) — a
// caller asking Get(ctx, indexerX, blocks) must get back only commitments
// actually signed by indexerX.
func TestGetDropsEventsFromUnrequestedAuthor(t *testing.T) {
	signerSK, _ := testKey(t)
	c := testCommitment()
	ev, err := c.ToEvent(signerSK)
	if err != nil {
		t.Fatal(err)
	}

	// The caller asks about a completely different author than the one that
	// actually signed ev.
	var wantAuthor [32]byte
	wantAuthor[0] = 0xAA

	mr := &maliciousRelay{events: []nostr.Event{ev}}
	f := &relayFeed{queriers: []querier{mr}}

	got, err := f.Get(context.Background(), wantAuthor, [][32]byte{c.BlockHash})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d commitments from an unrequested author, want 0", len(got))
	}
}

// TestGetDropsEventsForUnrequestedBlockHash covers input-scope-not-enforced:
// a relay can return a genuine, validly-signed, correctly-authored event for
// a block the caller never asked about in the current chunk, and Get must
// drop it.
func TestGetDropsEventsForUnrequestedBlockHash(t *testing.T) {
	sk, _ := testKey(t)
	c := testCommitment()
	ev, err := c.ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}
	author := mustAuthor(t, ev.PubKey)

	var otherBlock [32]byte
	otherBlock[0] = 0xBB

	mr := &maliciousRelay{events: []nostr.Event{ev}}
	f := &relayFeed{queriers: []querier{mr}}

	got, err := f.Get(context.Background(), author, [][32]byte{otherBlock})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d commitments for an unrequested block hash, want 0", len(got))
	}
}

// TestGetReturnsErrorWhenEveryRelayFails covers silent-failure: a total
// outage across every relay and every chunk must be surfaced as an error,
// distinguishable from "queried fine, nothing to report".
func TestGetReturnsErrorWhenEveryRelayFails(t *testing.T) {
	f := &relayFeed{queriers: []querier{alwaysFailQuerier{}, alwaysFailQuerier{}}}

	var author [32]byte
	got, err := f.Get(context.Background(), author, [][32]byte{{1}})
	if err == nil {
		t.Fatal("want an error when every relay query fails, got nil")
	}
	if got != nil {
		t.Errorf("want nil result on total relay failure, got %v", got)
	}
}

// TestGetToleratesPartialRelayFailure guards against overcorrecting finding
// 3: one relay failing while another succeeds must still return a nil
// error, per the original "one relay failing is not the query failing"
// design intent.
func TestGetToleratesPartialRelayFailure(t *testing.T) {
	sk, _ := testKey(t)
	c := testCommitment()
	ev, err := c.ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}

	fr := &fakeRelay{events: []nostr.Event{ev}}
	f := &relayFeed{queriers: []querier{alwaysFailQuerier{}, fr}}

	got, err := f.Get(context.Background(), mustAuthor(t, ev.PubKey), [][32]byte{c.BlockHash})
	if err != nil {
		t.Fatalf("one relay failing must not fail the whole query: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d commitments, want 1", len(got))
	}
}

// TestSubscribeForwardsEvents is the basic regression test for Subscribe's
// fan-out/fan-in path, now reachable via the subscriber interface instead of
// a concrete *nostr.Relay. It also covers auth-scope-not-enforced for the
// Subscribe path: a second event from an unrequested author must be
// dropped, never forwarded.
func TestSubscribeForwardsEvents(t *testing.T) {
	sk, _ := testKey(t)
	c := testCommitment()
	ev, err := c.ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}
	author := mustAuthor(t, ev.PubKey)

	otherSK, _ := testKey(t)
	otherC := testCommitment()
	otherC.BlockHash[0] = 0xCC
	otherEv, err := otherC.ToEvent(otherSK)
	if err != nil {
		t.Fatal(err)
	}

	events := make(chan *nostr.Event, 2)
	fs := &fakeSubscriber{events: events}
	f := &relayFeed{queriers: []querier{fs}}

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := f.Subscribe(ctx, [][32]byte{author})
	if err != nil {
		t.Fatal(err)
	}

	// otherEv is from an author never asked for; ev is. Only ev should come
	// through.
	events <- &otherEv
	events <- &ev

	select {
	case got, ok := <-ch:
		if !ok {
			t.Fatal("channel closed before delivering the requested commitment")
		}
		if got.BlockHash != c.BlockHash {
			t.Errorf("got block hash %x, want %x", got.BlockHash, c.BlockHash)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for forwarded commitment")
	}

	select {
	case got, ok := <-ch:
		if ok {
			t.Errorf("got a second commitment %+v, want only the requested-author one forwarded", got)
		}
	case <-time.After(100 * time.Millisecond):
		// Expected: nothing more to deliver right now.
	}

	// Clean shutdown so the forwarding goroutine doesn't leak past the
	// test: cancel, then close events the way the real library would once
	// its (child) context is done.
	cancel()
	close(events)
}

// TestSubscribeClosesWithoutPanicUnderConcurrentCancel is the regression
// test for the sync.WaitGroup-based fix to the send-on-closed-channel race:
// a forwarding goroutine racing to deliver an event at the exact moment ctx
// is cancelled must never see the returned channel already closed, and the
// channel must still close promptly once every forwarder has exited. Run
// under -race and repeated to build confidence the race window is actually
// exercised, not just possible in theory.
func TestSubscribeClosesWithoutPanicUnderConcurrentCancel(t *testing.T) {
	sk, _ := testKey(t)
	c := testCommitment()
	ev, err := c.ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}
	author := mustAuthor(t, ev.PubKey)

	for i := 0; i < 200; i++ {
		events := make(chan *nostr.Event) // unbuffered: forces the send/cancel race
		fs := &fakeSubscriber{events: events}
		f := &relayFeed{queriers: []querier{fs}}

		ctx, cancel := context.WithCancel(context.Background())

		ch, err := f.Subscribe(ctx, [][32]byte{author})
		if err != nil {
			t.Fatal(err)
		}

		// Drain the output channel so a forwarder's send never blocks on an
		// idle consumer, which would mask the race under test.
		drained := make(chan struct{})
		go func() {
			for range ch {
			}
			close(drained)
		}()

		var wg sync.WaitGroup
		wg.Add(2)
		// Sender: keeps trying to push events right up until ctx is done,
		// racing the cancellation below on purpose.
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				select {
				case events <- &ev:
				case <-ctx.Done():
				}
			}
		}()
		// Canceller.
		go func() {
			defer wg.Done()
			cancel()
		}()
		wg.Wait()

		// The real go-nostr library closes sub.Events once its (child)
		// context is done; simulate that here now that both goroutines
		// above have finished racing.
		close(events)

		select {
		case <-drained:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: timed out waiting for channel to close", i)
		}

		cancel() // no-op if already cancelled; silences vet's lostcancel
	}
}
