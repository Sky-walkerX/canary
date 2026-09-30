package wire

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Sky-walkerX/canary/canonical"
	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	bip352 "github.com/setavenger/go-bip352"
)

// ReceiptHeader is the HTTP response header that carries a receipt next to
// the tweak list it signs. Its value is the 178 bytes as lowercase hex.
const ReceiptHeader = "X-Canary-Receipt"

// ReceiptSize is the length of an encoded receipt: 114 signed bytes, then a
// 64-byte signature.
const ReceiptSize = 178

// ReceiptVersion is the only receipt version this reader knows. It rejects
// any other version instead of guessing at its layout.
const ReceiptVersion byte = 0x01

// tagReceipt separates the receipt digest from every other Canary hash.
// Changing it changes every receipt's digest.
const tagReceipt = "canary/receipt/v1"

// Byte offsets of the receipt fields, in layout order.
const (
	offVersion    = 0
	offNetwork    = 1
	offResource   = 5
	offBlockHash  = 6
	offDustSat    = 38
	offTipHeight  = 46
	offTipHash    = 50
	offBodySHA256 = 82
	offSig        = 114 // also the length of the signed part
)

// receiptHexLen is the length of the header value: two hex characters a byte.
const receiptHexLen = 2 * ReceiptSize

// Resource names the kind of response a receipt covers.
type Resource byte

// ResourceTweakList marks a receipt for a tweak list, the only resource v1
// defines. The byte keeps a later receipt for another kind of response from
// passing as a receipt for a tweak list.
const ResourceTweakList Resource = 0x01

// Receipt is a server's signed statement of what it served for one request.
//
// BlockHash and TipHash are in internal byte order, the order a serialized
// block header holds them. Explorers print them reversed. The receipt carries
// the bytes unchanged, so callers convert at their display boundary.
//
// The receipt carries no public key. A client checks it against the key it
// pinned for the server, so it never trusts a key that arrived with the data.
type Receipt struct {
	// Network is the chain's P2P message-start magic, from chaincfg.Params.Net.
	// It stops a receipt from one chain being presented as one from another.
	Network canonical.Network

	// Resource says what kind of response the receipt covers.
	Resource Resource

	// BlockHash names the block the served list is about.
	BlockHash [32]byte

	// DustSat is the dust threshold in satoshis that the client asked for and
	// the server applied. Zero means none. Signing it stops a server from
	// answering with an older, differently filtered list.
	DustSat uint64

	// TipHeight is the height of the server's best block when it served the
	// list. The retention rule measures a block's depth from it.
	TipHeight uint32

	// TipHash is the hash of that best block. It ties the claimed tip to one
	// chain, so a client with a Bitcoin Core node can check it.
	TipHash [32]byte

	// BodySHA256 is the plain SHA-256 of the exact response body. Anyone can
	// recompute it with sha256sum.
	BodySHA256 [32]byte

	// Sig is the BIP-340 Schnorr signature over Digest.
	Sig [64]byte
}

// ReceiptRequest is what the client asked the server for. VerifyReceipt
// compares a receipt against it.
type ReceiptRequest struct {
	Network   canonical.Network
	BlockHash [32]byte // internal byte order
	DustSat   uint64
}

var (
	// ErrReceiptMalformed means the bytes are not a v1 receipt. The length is
	// wrong, the hex is invalid or not lowercase, or the version is unknown.
	ErrReceiptMalformed = errors.New("wire: receipt malformed")

	// ErrReceiptSignature means the signature does not verify under the
	// server's pinned pubkey. The receipt proves nothing about that server.
	ErrReceiptSignature = errors.New("wire: receipt signature invalid")

	// ErrReceiptMismatch means a validly signed receipt covers something other
	// than what the client asked for or received.
	ErrReceiptMismatch = errors.New("wire: receipt does not match the request")
)

// signedPart lays out the 114 bytes the signature covers. Integers are
// little-endian. The network is its message-start bytes in wire order, the
// little-endian encoding of the magic, as the commitment root also uses.
func (r Receipt) signedPart() []byte {
	b := make([]byte, offSig, ReceiptSize)
	b[offVersion] = ReceiptVersion
	binary.LittleEndian.PutUint32(b[offNetwork:], uint32(r.Network))
	b[offResource] = byte(r.Resource)
	copy(b[offBlockHash:], r.BlockHash[:])
	binary.LittleEndian.PutUint64(b[offDustSat:], r.DustSat)
	binary.LittleEndian.PutUint32(b[offTipHeight:], r.TipHeight)
	copy(b[offTipHash:], r.TipHash[:])
	copy(b[offBodySHA256:], r.BodySHA256[:])
	return b
}

// Digest is the 32-byte message the server signs. It is the BIP-340 tagged
// hash, under the tag canary/receipt/v1, of the receipt's first 114 bytes.
func (r Receipt) Digest() [32]byte {
	return bip352.TaggedHash(tagReceipt, r.signedPart())
}

// SignReceipt signs r with the server's secret key and returns it with Sig
// set. Use the key that signs the server's Nostr records, so a client pins
// one pubkey for both.
//
// The nonce comes from RFC 6979, so the same key and receipt always give the
// same signature. SignReceipt refuses a zero key, a key not below the curve
// order, and a resource v1 does not define.
func SignReceipt(r Receipt, sk [32]byte) (Receipt, error) {
	if r.Resource != ResourceTweakList {
		return r, fmt.Errorf("wire: sign receipt: resource %#x is not defined in v1", byte(r.Resource))
	}

	var d btcec.ModNScalar
	if overflow := d.SetBytes(&sk); overflow != 0 || d.IsZero() {
		return r, errors.New("wire: sign receipt: secret key is zero or not below the curve order")
	}
	priv := btcec.PrivKeyFromScalar(&d)
	defer priv.Zero()
	d.Zero()

	digest := r.Digest()
	sig, err := schnorr.Sign(priv, digest[:])
	if err != nil {
		return r, fmt.Errorf("wire: sign receipt: %w", err)
	}
	copy(r.Sig[:], sig.Serialize())
	return r, nil
}

// EncodeReceipt writes r as the 178-byte layout: the signed part, then Sig.
func EncodeReceipt(r Receipt) []byte {
	return append(r.signedPart(), r.Sig[:]...)
}

// DecodeReceipt reads the 178-byte layout. It fails with ErrReceiptMalformed
// on a wrong length or an unknown version.
//
// It does not judge the resource byte or check the signature. VerifyReceipt
// does both, so a caller can tell an unreadable receipt from an invalid one.
func DecodeReceipt(b []byte) (Receipt, error) {
	var r Receipt
	if len(b) != ReceiptSize {
		return r, fmt.Errorf("%w: %d bytes, want %d", ErrReceiptMalformed, len(b), ReceiptSize)
	}
	if b[offVersion] != ReceiptVersion {
		return r, fmt.Errorf("%w: version %d, this reader knows only version %d", ErrReceiptMalformed, b[offVersion], ReceiptVersion)
	}

	r.Network = canonical.Network(binary.LittleEndian.Uint32(b[offNetwork:]))
	r.Resource = Resource(b[offResource])
	copy(r.BlockHash[:], b[offBlockHash:offDustSat])
	r.DustSat = binary.LittleEndian.Uint64(b[offDustSat:])
	r.TipHeight = binary.LittleEndian.Uint32(b[offTipHeight:])
	copy(r.TipHash[:], b[offTipHash:offBodySHA256])
	copy(r.BodySHA256[:], b[offBodySHA256:offSig])
	copy(r.Sig[:], b[offSig:])
	return r, nil
}

// EncodeReceiptHeader returns the ReceiptHeader value for r: its 178 bytes as
// 356 lowercase hex characters. Evidence files store the same string.
func EncodeReceiptHeader(r Receipt) string {
	return hex.EncodeToString(EncodeReceipt(r))
}

// DecodeReceiptHeader reads a ReceiptHeader value. It accepts exactly 356
// lowercase hex characters, with no prefix and no surrounding whitespace, so
// every receipt has one spelling. Anything else fails with
// ErrReceiptMalformed.
func DecodeReceiptHeader(s string) (Receipt, error) {
	if len(s) != receiptHexLen {
		return Receipt{}, fmt.Errorf("%w: header value is %d characters, want %d", ErrReceiptMalformed, len(s), receiptHexLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return Receipt{}, fmt.Errorf("%w: character %d is %q, want lowercase hex", ErrReceiptMalformed, i, c)
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %v", ErrReceiptMalformed, err)
	}
	return DecodeReceipt(b)
}

// VerifyReceiptSignature checks Sig against Digest under the server's pinned
// x-only pubkey. Any failure, including a pubkey that is not a curve point,
// wraps ErrReceiptSignature.
func VerifyReceiptSignature(r Receipt, pubkey [32]byte) error {
	pub, err := schnorr.ParsePubKey(pubkey[:])
	if err != nil {
		return fmt.Errorf("%w: pinned pubkey %x is not a valid x-only key: %v", ErrReceiptSignature, pubkey, err)
	}
	sig, err := schnorr.ParseSignature(r.Sig[:])
	if err != nil {
		return fmt.Errorf("%w: signature does not parse: %v", ErrReceiptSignature, err)
	}
	digest := r.Digest()
	if !sig.Verify(digest[:], pub) {
		return fmt.Errorf("%w: not signed by pubkey %x", ErrReceiptSignature, pubkey)
	}
	return nil
}

// VerifyReceipt runs the client's receipt checks, in this order:
//
//  1. The signature is valid under the server's pinned pubkey.
//  2. The network is the one the client's Bitcoin Core node is on.
//  3. The resource is the tweak list.
//  4. The block hash is the block the client asked for.
//  5. The dust threshold is the one the client asked for.
//  6. BodySHA256 is the SHA-256 of body, the bytes the client received.
//
// The signature comes first, so a forged receipt never reads as a mismatch
// the server signed. A failed signature wraps ErrReceiptSignature. Every other
// failure wraps ErrReceiptMismatch. A caller whose checks fail treats the list
// as unsigned: it can act on what it saw but cannot prove it to others.
//
// VerifyReceipt does not judge the signed tip. The retention rule reads it
// through InsideRetentionWindow, and only where a position is absent.
func VerifyReceipt(r Receipt, pubkey [32]byte, req ReceiptRequest, body []byte) error {
	if err := VerifyReceiptSignature(r, pubkey); err != nil {
		return err
	}
	if r.Network != req.Network {
		return fmt.Errorf("%w: network magic %d, the client is on %d", ErrReceiptMismatch, uint32(r.Network), uint32(req.Network))
	}
	if r.Resource != ResourceTweakList {
		return fmt.Errorf("%w: resource %#x, want the tweak list %#x", ErrReceiptMismatch, byte(r.Resource), byte(ResourceTweakList))
	}
	if r.BlockHash != req.BlockHash {
		return fmt.Errorf("%w: the receipt names a different block hash than the one requested", ErrReceiptMismatch)
	}
	if r.DustSat != req.DustSat {
		return fmt.Errorf("%w: dust threshold %d sat, the client asked for %d sat", ErrReceiptMismatch, r.DustSat, req.DustSat)
	}
	if sum := sha256.Sum256(body); sum != r.BodySHA256 {
		return fmt.Errorf("%w: body_sha256 %x, the %d-byte body received hashes to %x", ErrReceiptMismatch, r.BodySHA256, len(body), sum)
	}
	return nil
}

// RetentionWindow is how many of its most recent blocks a server must keep at
// least each entry's hash for. It is a protocol constant, not a policy field.
// A server allowed to declare its own window would declare zero.
//
// Every package reads the window from here. A literal 144 elsewhere is a
// second definition, and a test rejects it.
const RetentionWindow = 144

// BlockDepth returns how far a block sits below the server's signed tip,
// tipHeight minus blockHeight. The tip itself has depth 0. The result is
// negative when the server served a block above its own signed tip.
func BlockDepth(tipHeight, blockHeight uint32) int64 {
	return int64(tipHeight) - int64(blockHeight)
}

// InsideRetentionWindow reports whether a block was inside the retention
// window when the server served it. Inside means a depth below
// RetentionWindow, so depth 143 is the oldest block inside.
//
// Both heights must be ones the server signed with the same key. tipHeight
// comes from the receipt that covers the list. blockHeight comes from the
// height tag of the server's signed record for the block. An absent position
// in a block inside the window is an omission.
//
// A negative depth counts as inside. A server cannot escape the rule by
// understating its tip.
func InsideRetentionWindow(tipHeight, blockHeight uint32) bool {
	return BlockDepth(tipHeight, blockHeight) < RetentionWindow
}
