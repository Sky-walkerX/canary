// Package evidence reads, writes and checks evidence files, format
// canary-evidence/1.
//
// An evidence file lets anyone check a Data withheld finding offline. It
// carries the accused server's signed record for a block, a Merkle proof that
// the record includes one entry, and the tweak list the server sent with the
// receipt that signs it. Verify recomputes every step from those bytes and
// opens no network connection. The file stores no result, and Verify never
// trusts what the file says about itself.
//
// With a receipt, the file holds two of the server's signatures that
// contradict each other. The record includes the entry. The signed list left
// it out: it marked the position absent inside the retention window, or put
// other data there. Anyone can check that. Without a receipt, the file shows only that the server signed for the
// entry. Whoever ran the check that saw the gap knows it, but cannot yet
// prove it to others.
//
// The format claims omission only. It says nothing about entries a server
// adds, and nothing about the payment outputs a wallet matches against.
package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/nbd-wtf/go-nostr"
)

// Format is the only evidence format this package reads and writes.
const Format = "canary-evidence/1"

// ClaimOmission is the one claim canary-evidence/1 makes: the server signed a
// record containing an entry, then served a list that did not carry it.
const ClaimOmission = "omission"

// File is one canary-evidence/1 document. Hashes and txids are display-order
// hex, as the formats doc fixes them. Receipt and ServedBase64 are both set or
// both nil.
type File struct {
	Format          string   `json:"format"`
	Claim           string   `json:"claim"`
	Accused         string   `json:"accused"`
	Network         Network  `json:"network"`
	Block           Block    `json:"block"`
	CommitmentEvent Event    `json:"commitment_event"`
	Receipt         *string  `json:"receipt"`
	ServedBase64    *string  `json:"served_base64"`
	Missing         Missing  `json:"missing"`
	Proof           Proof    `json:"proof"`
	Context         *Context `json:"context,omitempty"`
}

// Network names a chain by its P2P magic. Verify derives the name from the
// magic and ignores the name a file carries.
type Network struct {
	Name  string `json:"name"`
	Magic uint32 `json:"magic"`
}

// Block names a block by its display-order hash and its height.
type Block struct {
	Hash   string `json:"hash"`
	Height uint32 `json:"height"`
}

// Event is the server's signed kind-1352 record, every field as served. It is
// its own type, rather than nostr.Event, so that reading it rejects unknown
// fields like every other level of the file.
type Event struct {
	Kind      int        `json:"kind"`
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// Missing is the left-out entry: its txid in display order and its 33-byte
// compressed tweak.
type Missing struct {
	TxID  string `json:"txid"`
	Tweak string `json:"tweak"`
}

// Proof is the Merkle proof of the entry in the signed root. Siblings are
// hex hashes, bottom-up.
type Proof struct {
	Index    uint32   `json:"index"`
	N        uint32   `json:"n"`
	Siblings []string `json:"siblings"`
}

// Context holds notes for people. Verify never reads it and nothing checks
// it, so a screen that shows these strings labels them as unchecked.
type Context struct {
	ServerLabel string `json:"server_label,omitempty"`
	ServerURL   string `json:"server_url,omitempty"`
	FoundBy     string `json:"found_by,omitempty"`
	WrittenBy   string `json:"written_by,omitempty"`
	WrittenAt   string `json:"written_at,omitempty"`
}

// Marshal writes f as indented JSON with a trailing newline.
func (f File) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, fmt.Errorf("evidence: write file: %w", err)
	}
	return buf.Bytes(), nil
}

// Name returns the file name canary check gives f:
// omission-<network>-<height>-<txid first 8 hex>-<pubkey first 8 hex>.json.
// The network name comes from the magic, and the txid prefix is display order.
func (f File) Name() string {
	return fmt.Sprintf("omission-%s-%d-%s-%s.json",
		core.NetworkName(canonical.Network(f.Network.Magic)), f.Block.Height, prefix8(f.Missing.TxID), prefix8(f.Accused))
}

func prefix8(s string) string {
	if len(s) < 8 {
		return s
	}
	return s[:8]
}

// Parse reads a canary-evidence/1 file strictly. It fails with
// ErrUnsupportedFormat for another format or claim, and with ErrMalformed for
// anything else it cannot read: bad JSON, an unknown or missing field, a
// duplicate key, a value of the wrong type or length, or data after the file.
//
// Parse checks the file's shape only. Verify checks what the file claims.
func Parse(b []byte) (File, error) {
	p, _, err := read(b)
	if err != nil {
		return File{}, err
	}
	return p.file, nil
}

// parsed is a file that passed the read step, with its values decoded.
type parsed struct {
	file      File
	accused   [32]byte
	blockHash [32]byte // internal order
	event     nostr.Event
	entry     canonical.Leaf // TxID in internal order
	proof     commit.Proof
	served    []byte // nil without a receipt
}

// head is what read learns before the full decode, for the report.
type head struct {
	format, claim *string
}

// read runs the read step. It checks the version first, so a newer file reads
// as unsupported rather than as malformed.
func read(b []byte) (*parsed, head, error) {
	var h head
	if err := checkJSON(b); err != nil {
		return nil, h, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var top struct {
		Format json.RawMessage `json:"format"`
		Claim  json.RawMessage `json:"claim"`
	}
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, h, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	format, err := rawString("format", top.Format)
	if err != nil {
		return nil, h, err
	}
	h.format = &format
	if format != Format {
		return nil, h, fmt.Errorf("%w: format %q, this reader knows only %s", ErrUnsupportedFormat, format, Format)
	}
	claim, err := rawString("claim", top.Claim)
	if err != nil {
		return nil, h, err
	}
	h.claim = &claim
	if claim != ClaimOmission {
		return nil, h, fmt.Errorf("%w: claim %q, %s makes only the %s claim", ErrUnsupportedFormat, claim, Format, ClaimOmission)
	}

	var raw rawFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, h, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	p, err := raw.decode()
	if err != nil {
		return nil, h, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return p, h, nil
}

func rawString(key string, raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("%w: no %s field", ErrMalformed, key)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%w: %s is not a string", ErrMalformed, key)
	}
	return s, nil
}

// checkJSON checks that b holds exactly one JSON object and nothing after it.
// Every key must be lowercase ASCII letters, digits or underscores, and unique
// in its object. The field names of this format follow that rule, and
// encoding/json matches keys without regard to case. So the rule leaves each
// field exactly one spelling, and a second copy of a field cannot hide behind
// the one a careless tool would read.
//
// A null is allowed only as the value of receipt or served_base64 at the top
// level. Anywhere else the decoder would treat it as absent or as zero.
func checkJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("not JSON: %v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("the file is not a JSON object")
	}
	if err := walkObject(dec, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data follows the JSON object")
	}
	return nil
}

// maxDepth bounds nesting. The format needs four levels: the file, the event,
// its tags and one tag.
const maxDepth = 8

func walkObject(dec *json.Decoder, depth int) error {
	seen := make(map[string]bool)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("not JSON: %v", err)
		}
		key, _ := tok.(string)
		if !plainKey(key) {
			return fmt.Errorf("key %q is not lowercase letters, digits and underscores", key)
		}
		if seen[key] {
			return fmt.Errorf("key %q appears twice in one object", key)
		}
		seen[key] = true
		nullable := depth == 1 && (key == "receipt" || key == "served_base64")
		if err := walkValue(dec, depth, nullable); err != nil {
			return err
		}
	}
	_, err := dec.Token() // the closing brace
	return err
}

func walkValue(dec *json.Decoder, depth int, nullable bool) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("not JSON: %v", err)
	}
	switch t := tok.(type) {
	case nil:
		if !nullable {
			return errors.New("null where a value is required")
		}
	case json.Delim:
		if depth >= maxDepth {
			return errors.New("nested too deeply")
		}
		if t == '{' {
			return walkObject(dec, depth+1)
		}
		for dec.More() {
			if err := walkValue(dec, depth+1, false); err != nil {
				return err
			}
		}
		_, err := dec.Token() // the closing bracket
		return err
	}
	return nil
}

func plainKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// rawFile mirrors File with pointers, so a missing field reads as nil rather
// than as a zero value that looks real.
type rawFile struct {
	Format          *string         `json:"format"`
	Claim           *string         `json:"claim"`
	Accused         *string         `json:"accused"`
	Network         *rawNetwork     `json:"network"`
	Block           *rawBlock       `json:"block"`
	CommitmentEvent *rawEvent       `json:"commitment_event"`
	Receipt         json.RawMessage `json:"receipt"`
	ServedBase64    json.RawMessage `json:"served_base64"`
	Missing         *rawMissing     `json:"missing"`
	Proof           *rawProof       `json:"proof"`
	Context         *Context        `json:"context"`
}

type rawNetwork struct {
	Name  *string `json:"name"`
	Magic *uint32 `json:"magic"`
}

type rawBlock struct {
	Hash   *string `json:"hash"`
	Height *uint32 `json:"height"`
}

type rawEvent struct {
	Kind      *int        `json:"kind"`
	ID        *string     `json:"id"`
	PubKey    *string     `json:"pubkey"`
	CreatedAt *int64      `json:"created_at"`
	Tags      *[][]string `json:"tags"`
	Content   *string     `json:"content"`
	Sig       *string     `json:"sig"`
}

type rawMissing struct {
	TxID  *string `json:"txid"`
	Tweak *string `json:"tweak"`
}

type rawProof struct {
	Index    *uint32   `json:"index"`
	N        *uint32   `json:"n"`
	Siblings *[]string `json:"siblings"`
}

// missing names the first required field that is absent, or returns "".
func (r *rawFile) missing() string {
	switch {
	case r.Accused == nil:
		return "accused"
	case r.Network == nil || r.Network.Name == nil || r.Network.Magic == nil:
		return "network"
	case r.Block == nil || r.Block.Hash == nil || r.Block.Height == nil:
		return "block"
	case r.CommitmentEvent == nil:
		return "commitment_event"
	case len(r.Receipt) == 0:
		return "receipt"
	case len(r.ServedBase64) == 0:
		return "served_base64"
	case r.Missing == nil || r.Missing.TxID == nil || r.Missing.Tweak == nil:
		return "missing"
	case r.Proof == nil || r.Proof.Index == nil || r.Proof.N == nil || r.Proof.Siblings == nil:
		return "proof"
	}
	e := r.CommitmentEvent
	if e.Kind == nil || e.ID == nil || e.PubKey == nil || e.CreatedAt == nil || e.Tags == nil || e.Content == nil || e.Sig == nil {
		return "commitment_event"
	}
	return ""
}

// decode checks every value's type and length and converts the hex. Hashes
// in display order go through core.ParseDisplayHash, the one place this
// program turns display order into internal order.
func (r *rawFile) decode() (*parsed, error) {
	if m := r.missing(); m != "" {
		return nil, fmt.Errorf("%s is missing a field", m)
	}
	p := &parsed{}
	var err error

	if p.accused, err = hex32(*r.Accused); err != nil {
		return nil, fmt.Errorf("accused: %v", err)
	}
	if p.blockHash, err = core.ParseDisplayHash(*r.Block.Hash); err != nil {
		return nil, fmt.Errorf("block hash: %v", err)
	}

	e := r.CommitmentEvent
	if _, err := hex32(*e.ID); err != nil {
		return nil, fmt.Errorf("event id: %v", err)
	}
	if _, err := hex32(*e.PubKey); err != nil {
		return nil, fmt.Errorf("event pubkey: %v", err)
	}
	if _, err := lowerHex(*e.Sig, 64); err != nil {
		return nil, fmt.Errorf("event sig: %v", err)
	}
	tags := make(nostr.Tags, len(*e.Tags))
	for i, tag := range *e.Tags {
		tags[i] = nostr.Tag(tag)
	}
	p.event = nostr.Event{
		ID:        *e.ID,
		PubKey:    *e.PubKey,
		CreatedAt: nostr.Timestamp(*e.CreatedAt),
		Kind:      *e.Kind,
		Tags:      tags,
		Content:   *e.Content,
		Sig:       *e.Sig,
	}

	if p.entry.TxID, err = core.ParseDisplayHash(*r.Missing.TxID); err != nil {
		return nil, fmt.Errorf("missing txid: %v", err)
	}
	tweak, err := lowerHex(*r.Missing.Tweak, 33)
	if err != nil {
		return nil, fmt.Errorf("missing tweak: %v", err)
	}
	copy(p.entry.Tweak[:], tweak)

	p.proof = commit.Proof{Index: *r.Proof.Index, N: *r.Proof.N, Siblings: make([][32]byte, len(*r.Proof.Siblings))}
	for i, s := range *r.Proof.Siblings {
		if p.proof.Siblings[i], err = hex32(s); err != nil {
			return nil, fmt.Errorf("proof sibling %d: %v", i, err)
		}
	}

	receipt, err := nullableString("receipt", r.Receipt)
	if err != nil {
		return nil, err
	}
	served, err := nullableString("served_base64", r.ServedBase64)
	if err != nil {
		return nil, err
	}
	if (receipt == nil) != (served == nil) {
		return nil, errors.New("receipt and served_base64 must both be present or both be null")
	}
	if served != nil {
		if p.served, err = strictBase64(*served); err != nil {
			return nil, fmt.Errorf("served_base64: %v", err)
		}
	}

	p.file = File{
		Format:  *r.Format,
		Claim:   *r.Claim,
		Accused: *r.Accused,
		Network: Network{Name: *r.Network.Name, Magic: *r.Network.Magic},
		Block:   Block{Hash: *r.Block.Hash, Height: *r.Block.Height},
		CommitmentEvent: Event{
			Kind:      *e.Kind,
			ID:        *e.ID,
			PubKey:    *e.PubKey,
			CreatedAt: *e.CreatedAt,
			Tags:      *e.Tags,
			Content:   *e.Content,
			Sig:       *e.Sig,
		},
		Receipt:      receipt,
		ServedBase64: served,
		Missing:      Missing{TxID: *r.Missing.TxID, Tweak: *r.Missing.Tweak},
		Proof:        Proof{Index: *r.Proof.Index, N: *r.Proof.N, Siblings: *r.Proof.Siblings},
		Context:      r.Context,
	}
	return p, nil
}

func nullableString(key string, raw json.RawMessage) (*string, error) {
	if string(raw) == "null" {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s is neither a string nor null", key)
	}
	return &s, nil
}

// strictBase64 decodes standard, padded base64 and accepts only the one
// spelling that encodes back to the same string. The standard decoder skips
// line breaks, so without this check two spellings would decode alike.
func strictBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("not in the one canonical spelling")
	}
	return b, nil
}

// lowerHex decodes exactly size bytes of lowercase hex.
func lowerHex(s string, size int) ([]byte, error) {
	if len(s) != 2*size {
		return nil, fmt.Errorf("%d hex characters, want %d", len(s), 2*size)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, fmt.Errorf("character %d is not lowercase hex", i)
		}
	}
	return hex.DecodeString(s)
}

func hex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := lowerHex(s, 32)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// fileEvent copies a nostr event into the file's event type.
func fileEvent(ev nostr.Event) Event {
	tags := make([][]string, len(ev.Tags))
	for i, tag := range ev.Tags {
		tags[i] = append([]string{}, tag...)
	}
	return Event{
		Kind:      ev.Kind,
		ID:        ev.ID,
		PubKey:    ev.PubKey,
		CreatedAt: int64(ev.CreatedAt),
		Tags:      tags,
		Content:   ev.Content,
		Sig:       ev.Sig,
	}
}
