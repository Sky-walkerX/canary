// Package feed carries commitments over Nostr. Spec §3.3, §3.4.
package feed

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

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

// displayHex renders a 32-byte hash in display order — reversed, the form a
// block explorer prints. Tags carry this so a human reading a relay sees the
// familiar string; the root preimage uses internal order (§3.2).
func displayHex(h [32]byte) string {
	var rev [32]byte
	for i := 0; i < 32; i++ {
		rev[i] = h[31-i]
	}
	return hex.EncodeToString(rev[:])
}

func parseDisplayHex(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	for i := 0; i < 32; i++ {
		out[i] = b[31-i]
	}
	return out, nil
}

// ToEvent builds and signs the Nostr event carrying c.
//
// The block hash goes in the single-letter b tag because relays index no other
// tag names. The rest are carried for readers, not filters (§3.3). The root is
// carried both in the content and in a multi-letter "root" tag; FromEvent
// checks the two agree, which is what makes the redundancy meaningful rather
// than just extra bytes.
func (c Commitment) ToEvent(sk [32]byte) (nostr.Event, error) {
	skHex := hex.EncodeToString(sk[:])
	pub, err := nostr.GetPublicKey(skHex)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("feed: derive pubkey: %w", err)
	}

	ev := nostr.Event{
		PubKey: pub,
		// created_at is set because the protocol requires a value, never
		// because we trust it. Ordering comes from the block hash (§3.5).
		CreatedAt: nostr.Now(),
		Kind:      KindCommitment,
		Tags: nostr.Tags{
			nostr.Tag{TagBlockHash, displayHex(c.BlockHash)},
			nostr.Tag{"height", strconv.FormatUint(uint64(c.BlockHeight), 10)},
			nostr.Tag{"n", strconv.FormatUint(uint64(c.N), 10)},
			nostr.Tag{"network", strconv.FormatUint(uint64(c.Network), 10)},
			nostr.Tag{"policy_ref", hex.EncodeToString(c.PolicyRef[:])},
			nostr.Tag{"root", hex.EncodeToString(c.Root[:])},
		},
		Content: hex.EncodeToString(c.Root[:]),
	}

	if err := ev.Sign(skHex); err != nil {
		return nostr.Event{}, fmt.Errorf("feed: sign: %w", err)
	}
	return ev, nil
}

var (
	ErrWrongKind    = errors.New("feed: event is not a commitment kind")
	ErrBadSignature = errors.New("feed: event signature invalid")
	ErrInconsistent = errors.New("feed: event tags contradict its content")
	ErrMissingTag   = errors.New("feed: required tag missing")
)

// FromEvent parses and verifies an event into a Commitment.
//
// Verification is not optional here. An unverified commitment proves nothing,
// and every downstream verdict in §2.5 treats a commitment as a signed
// statement the server cannot later revise.
func FromEvent(e nostr.Event) (Commitment, error) {
	var c Commitment

	if e.Kind != KindCommitment {
		return c, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, e.Kind, KindCommitment)
	}
	if !e.CheckID() {
		return c, fmt.Errorf("%w: id does not match", ErrBadSignature)
	}
	ok, err := e.CheckSignature()
	if err != nil {
		return c, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if !ok {
		return c, ErrBadSignature
	}

	author, err := hex.DecodeString(e.PubKey)
	if err != nil || len(author) != 32 {
		return c, fmt.Errorf("feed: bad author pubkey %q", e.PubKey)
	}
	copy(c.Author[:], author)

	get := func(name string) (string, error) {
		tag := e.Tags.Find(name)
		if tag == nil || len(tag) < 2 {
			return "", fmt.Errorf("%w: %s", ErrMissingTag, name)
		}
		return tag[1], nil
	}

	bhStr, err := get(TagBlockHash)
	if err != nil {
		return c, err
	}
	if c.BlockHash, err = parseDisplayHex(bhStr); err != nil {
		return c, fmt.Errorf("feed: bad block hash: %w", err)
	}

	heightStr, err := get("height")
	if err != nil {
		return c, err
	}
	h, err := strconv.ParseUint(heightStr, 10, 32)
	if err != nil {
		return c, fmt.Errorf("feed: bad height: %w", err)
	}
	c.BlockHeight = uint32(h)

	nStr, err := get("n")
	if err != nil {
		return c, err
	}
	n, err := strconv.ParseUint(nStr, 10, 32)
	if err != nil {
		return c, fmt.Errorf("feed: bad n: %w", err)
	}
	c.N = uint32(n)

	netStr, err := get("network")
	if err != nil {
		return c, err
	}
	netVal, err := strconv.ParseUint(netStr, 10, 32)
	if err != nil {
		return c, fmt.Errorf("feed: bad network: %w", err)
	}
	c.Network = canonical.Network(netVal)

	prStr, err := get("policy_ref")
	if err != nil {
		return c, err
	}
	pr, err := hex.DecodeString(prStr)
	if err != nil || len(pr) != 32 {
		return c, fmt.Errorf("feed: bad policy_ref")
	}
	copy(c.PolicyRef[:], pr)

	rootBytes, err := hex.DecodeString(e.Content)
	if err != nil || len(rootBytes) != 32 {
		return c, fmt.Errorf("feed: content is not a 32-byte root")
	}
	copy(c.Root[:], rootBytes)

	rootTag, err := get("root")
	if err != nil {
		return c, err
	}
	if rootTag != e.Content {
		return c, fmt.Errorf("%w: root tag %s vs content %s", ErrInconsistent, rootTag, e.Content)
	}

	return c, nil
}
