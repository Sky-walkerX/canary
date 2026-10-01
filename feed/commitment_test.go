package feed

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/nbd-wtf/go-nostr"
)

func testCommitment() Commitment {
	c := Commitment{
		Network:     canonical.Network(0xdab5bffa),
		BlockHeight: 812345,
		N:           7,
	}
	for i := range c.BlockHash {
		c.BlockHash[i] = byte(i)
	}
	for i := range c.Root {
		c.Root[i] = byte(0x80 + i)
	}
	for i := range c.PolicyRef {
		c.PolicyRef[i] = byte(0x40 + i)
	}
	return c
}

func mustAuthor(t *testing.T, pubHex string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(pubHex)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad pubkey %q", pubHex)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func testKey(t *testing.T) ([32]byte, string) {
	t.Helper()
	skHex := nostr.GeneratePrivateKey()
	b, err := hex.DecodeString(skHex)
	if err != nil {
		t.Fatal(err)
	}
	var sk [32]byte
	copy(sk[:], b)
	return sk, skHex
}

func TestToEventFromEventRoundTrip(t *testing.T) {
	sk, _ := testKey(t)
	want := testCommitment()

	ev, err := want.ToEvent(sk)
	if err != nil {
		t.Fatalf("ToEvent: %v", err)
	}

	got, err := FromEvent(ev)
	if err != nil {
		t.Fatalf("FromEvent: %v", err)
	}

	// Author is filled in from the event, so compare it separately.
	if got.Author == [32]byte{} {
		t.Error("FromEvent must populate Author from the event pubkey")
	}
	want.Author = got.Author

	if got != want {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestEventIsSignedAndUsesTheRegularKind(t *testing.T) {
	sk, _ := testKey(t)
	ev, err := testCommitment().ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}

	if ev.Kind != KindCommitment {
		t.Errorf("kind = %d, want %d", ev.Kind, KindCommitment)
	}
	// Regular kinds are append-only. A replaceable kind would let a server
	// overwrite a record it had already published.
	if ev.Kind < 1000 || ev.Kind > 9999 {
		t.Errorf("kind %d is outside the regular range 1000 to 9999, and a replaceable kind lets a server overwrite its record", ev.Kind)
	}

	ok, err := ev.CheckSignature()
	if err != nil || !ok {
		t.Errorf("event signature invalid: ok=%v err=%v", ok, err)
	}
	if !ev.CheckID() {
		t.Error("event id does not match its own content and tags")
	}
}

func TestBlockHashIsInASingleLetterIndexedTag(t *testing.T) {
	sk, _ := testKey(t)
	c := testCommitment()
	ev, err := c.ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}

	if len(TagBlockHash) != 1 {
		t.Fatalf("TagBlockHash %q must be a single letter, because relays index no other tag names", TagBlockHash)
	}

	tag := ev.Tags.Find(TagBlockHash)
	if tag == nil {
		t.Fatalf("no %q tag on the event", TagBlockHash)
	}
	// Display hex, so a human reading the relay sees the familiar form.
	if tag[1] != displayHex(c.BlockHash) {
		t.Errorf("b tag = %s, want %s", tag[1], displayHex(c.BlockHash))
	}
}

func TestFromEventRejectsWrongKind(t *testing.T) {
	sk, _ := testKey(t)
	ev, err := testCommitment().ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}
	ev.Kind = 30000 // a parameterized replaceable kind
	if _, err := FromEvent(ev); err == nil {
		t.Error("FromEvent must reject a non-1352 kind, especially a replaceable one")
	}
}

func TestFromEventRejectsBadSignature(t *testing.T) {
	sk, _ := testKey(t)
	ev, err := testCommitment().ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}
	ev.Content = "00" // tamper after signing
	if _, err := FromEvent(ev); err == nil {
		t.Error("FromEvent must verify the signature, because an unverified record proves nothing")
	}
}

func TestFromEventRejectsTagRootDisagreement(t *testing.T) {
	sk, skHex := testKey(t)
	c := testCommitment()
	ev, err := c.ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite the root tag so it disagrees with the content, then re-sign, so
	// the signature is valid and only the internal inconsistency is wrong.
	// The design repeats the root on purpose, and FromEvent's check is what
	// makes the repetition catch anything.
	for i, tg := range ev.Tags {
		if tg[0] == "root" {
			ev.Tags[i] = nostr.Tag{"root", strings.Repeat("00", 32)}
		}
	}
	ev.ID = ""
	ev.Sig = ""
	if err := ev.Sign(skHex); err != nil {
		t.Fatal(err)
	}

	if _, err := FromEvent(ev); err == nil {
		t.Error("FromEvent must reject an event whose tags contradict its content")
	}
}
