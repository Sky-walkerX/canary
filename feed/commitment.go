package feed

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/nbd-wtf/go-nostr"
)

// KindCommitment is the Nostr kind of a signed record. It is a regular kind, in
// 1000 to 9999, so relays keep every event. A replaceable kind would let a
// server overwrite a record it already published, and the original would
// vanish.
const KindCommitment = 1352

// TagBlockHash is a single letter because relays index no other tag names.
const TagBlockHash = "b"

// Commitment is one server's signed record for one block. The design doc calls
// a signed record a commitment.
type Commitment struct {
	Network     canonical.Network
	BlockHash   [32]byte
	BlockHeight uint32
	N           uint32
	Root        [32]byte
	PolicyRef   [32]byte // event id of the policy declaration in force
	Author      [32]byte // Nostr pubkey of the signer
}

// displayHex renders a 32-byte hash in display order: reversed, the form a
// block explorer prints. Tags carry this form, so a person reading a relay sees
// the familiar string. The root preimage uses internal order.
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
		return out, fmt.Errorf("got %d bytes, want 32", len(b))
	}
	for i := 0; i < 32; i++ {
		out[i] = b[31-i]
	}
	return out, nil
}

// ToEvent builds and signs the Nostr event carrying c.
//
// The block hash goes in the single-letter b tag because relays index no other
// tag names. The other tags are for readers, not filters. The root appears both
// in the content and in a multi-letter "root" tag. FromEvent checks that the
// two agree, which is what makes the repetition worth its bytes.
func (c Commitment) ToEvent(sk [32]byte) (nostr.Event, error) {
	skHex := hex.EncodeToString(sk[:])
	pub, err := nostr.GetPublicKey(skHex)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("feed: derive public key: %w", err)
	}

	ev := nostr.Event{
		PubKey: pub,
		// created_at is set because Nostr requires a value, never because
		// Canary trusts it. Order comes from the chain, through the block
		// hash.
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
		return nostr.Event{}, fmt.Errorf("feed: sign event: %w", err)
	}
	return ev, nil
}

// Errors FromEvent wraps, so a caller can tell the cases apart with errors.Is.
var (
	ErrWrongKind    = errors.New("feed: check kind: not a signed-record kind")
	ErrBadSignature = errors.New("feed: check signature: invalid")
	ErrInconsistent = errors.New("feed: check root: tags contradict content")
	ErrMissingTag   = errors.New("feed: read tags: required tag missing")
)

// FromEvent verifies an event and parses it into a Commitment.
//
// Verification is not optional. An unverified record proves nothing, and every
// later step of the comparison treats a record as a signed statement the
// server cannot take back.
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
		return c, fmt.Errorf("feed: parse author: bad pubkey %q", e.PubKey)
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
		return c, fmt.Errorf("feed: parse b tag: %w", err)
	}

	heightStr, err := get("height")
	if err != nil {
		return c, err
	}
	h, err := strconv.ParseUint(heightStr, 10, 32)
	if err != nil {
		return c, fmt.Errorf("feed: parse height tag: %w", err)
	}
	c.BlockHeight = uint32(h)

	nStr, err := get("n")
	if err != nil {
		return c, err
	}
	n, err := strconv.ParseUint(nStr, 10, 32)
	if err != nil {
		return c, fmt.Errorf("feed: parse n tag: %w", err)
	}
	c.N = uint32(n)

	netStr, err := get("network")
	if err != nil {
		return c, err
	}
	netVal, err := strconv.ParseUint(netStr, 10, 32)
	if err != nil {
		return c, fmt.Errorf("feed: parse network tag: %w", err)
	}
	c.Network = canonical.Network(netVal)

	prStr, err := get("policy_ref")
	if err != nil {
		return c, err
	}
	pr, err := hex.DecodeString(prStr)
	if err != nil || len(pr) != 32 {
		return c, fmt.Errorf("feed: parse policy_ref tag: want 32 bytes of hex")
	}
	copy(c.PolicyRef[:], pr)

	rootBytes, err := hex.DecodeString(e.Content)
	if err != nil || len(rootBytes) != 32 {
		return c, fmt.Errorf("feed: parse content: want a 32-byte root in hex")
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
