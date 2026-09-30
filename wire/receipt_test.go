package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/nbd-wtf/go-nostr"
)

// docListHex is the 137-byte tweak list from the tweak-list example in the v1
// formats doc: entry 0 in full, position 1 absent, entry 2 in full.
const docListHex = "03000000" +
	"01" + "75d59e36a1e1ccbbd5a47f129b923047268c580d6a09a9d63c3084bd397166ae" +
	"03f9a5befd0ea1dbba15e6ccba383fbdbc750a0f637698a06fa47c6823044e09eb" +
	"03" +
	"01" + "3f692f812332917a1bc7cafd01d5d02a7bf2b4c25bb4f5d7211b670610c0e0b8" +
	"0362573ab3eb6eccc73071623c211f41b392bf29edcb9fabe7aa9addeb4bbd6ab9"

// The receipt example from the v1 formats doc, with the digest and pubkey the
// doc publishes for it. Nobody holds this key outside that example.
const (
	docReceiptHex = "01fabfb5da01b809dc22838a13852fcf3deead2c3427ba0781d87fab1789c3d9a7cfb364fbca" +
		"0000000000000000d4000000d2311c5f151c5222bd9bcc59dbcc55fb7375ce61792dc71d6dd8691687c45b8f" +
		"a1b3b064b0286290f4b87ac6915a523301f0b4977ea3b04d3663df60bcc707c9b3f5f6f98dddbd7080322b8e42" +
		"a6384d00841fba8e69dc37687cd492830379bfedd2111778f28cb1ea58c0b1ec183ce7e4c8aeb1e1d34eb03f09" +
		"0df07139ed0b"
	docDigestHex      = "b4d40cabc899c628f452b60d05b80f3c68e85aac6dceb9ceeec21b875ec5e9e6"
	docPubHex         = "b1070620799e7da6bbc296ec7ea6aacf7f027317af796abf35f0c9c83710270d"
	docBlockDisplay   = "cafb64b3cfa7d9c38917ab7fd88107ba27342cadee3dcf2f85138a8322dc09b8"
	docTipHashDisplay = "8f5bc4871669d86d1dc72d7961ce7573fb55ccdb59cc9bbd22521c155f1c31d2"
)

// vectorKey is the secret key of BIP-340 test vector 0, which is 3. That
// vector publishes the matching public key, so the key derivation is checked
// against an outside source. It is a test key and must never sign anything
// real.
var vectorKey = [32]byte{31: 0x03}

const vectorPubHex = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

// vectorDigestHex and the first 114 bytes of vectorEncodingHex were computed
// outside Go, from the byte layout in the formats doc. The last 64 bytes are
// the signature. btcec signs with a deterministic RFC 6979 nonce, so the same
// key and digest always give these bytes. The test also checks them against
// btcec's verifier directly, not through the code under test.
const (
	vectorDigestHex   = "b8f1caaa9a9ef59e734ef9777bd6ed0d44479cdeade2c2b3e0e89b754f4b331b"
	vectorEncodingHex = "01" + // version
		"0a03cf40" + // network: signet message-start bytes
		"01" + // resource: tweak list
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + // block_hash, internal order
		"2202000000000000" + // dust_sat: 546
		"70110100" + // tip_height: 70000
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + // tip_hash, internal order
		"a1b3b064b0286290f4b87ac6915a523301f0b4977ea3b04d3663df60bcc707c9" + // body_sha256 of the doc's list
		vectorSigHex
	vectorSigHex = "ed4bc362c1e4cd10bc4c4b5617b4b850afd1d8e75e08e11792a99217ba88456d" +
		"c37ec358d97d1127a3d0ff6e2543e6d458825cbc74ce98664671e8c934f1c691"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test hex %q: %v", s, err)
	}
	return b
}

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	b := mustHex(t, s)
	if len(b) != 32 {
		t.Fatalf("test hex %q is %d bytes, want 32", s, len(b))
	}
	copy(out[:], b)
	return out
}

// fromDisplay turns a display-order hash, as an explorer prints it, into the
// internal order a receipt carries.
func fromDisplay(t *testing.T, s string) [32]byte {
	t.Helper()
	d := mustHex32(t, s)
	var out [32]byte
	for i := range d {
		out[i] = d[31-i]
	}
	return out
}

// nostrPub derives the x-only pubkey the way feed.ToEvent does for the signed
// record. A receipt must verify under that same key.
func nostrPub(t *testing.T, sk [32]byte) [32]byte {
	t.Helper()
	pub, err := nostr.GetPublicKey(hex.EncodeToString(sk[:]))
	if err != nil {
		t.Fatalf("derive nostr pubkey: %v", err)
	}
	return mustHex32(t, pub)
}

func docList(t *testing.T) []byte {
	t.Helper()
	return mustHex(t, docListHex)
}

// vectorReceipt is an unsigned receipt with values chosen so that a swapped
// field, a reversed hash or a big-endian integer each shows up in the bytes.
func vectorReceipt(t *testing.T) Receipt {
	t.Helper()
	var blockHash, tipHash [32]byte
	for i := range blockHash {
		blockHash[i] = byte(i)
		tipHash[i] = byte(0xa0 + i)
	}
	return Receipt{
		Network:    canonical.Network(chaincfg.SigNetParams.Net),
		Resource:   ResourceTweakList,
		BlockHash:  blockHash,
		DustSat:    546,
		TipHeight:  70000,
		TipHash:    tipHash,
		BodySHA256: sha256.Sum256(docList(t)),
	}
}

func signedVector(t *testing.T) Receipt {
	t.Helper()
	r, err := SignReceipt(vectorReceipt(t), vectorKey)
	if err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}
	return r
}

// The expected digest is built here byte by byte from the documented layout,
// never by calling the code under test.
func TestReceiptFixedVector(t *testing.T) {
	var pre []byte
	pre = append(pre, 0x01)                   // version
	pre = append(pre, 0x0a, 0x03, 0xcf, 0x40) // network: signet message-start bytes
	pre = append(pre, 0x01)                   // resource: tweak list
	for i := 0; i < 32; i++ {                 // block_hash, internal order
		pre = append(pre, byte(i))
	}
	pre = append(pre, 0x22, 0x02, 0, 0, 0, 0, 0, 0) // dust_sat 546, uint64 little-endian
	pre = append(pre, 0x70, 0x11, 0x01, 0x00)       // tip_height 70000, uint32 little-endian
	for i := 0; i < 32; i++ {                       // tip_hash, internal order
		pre = append(pre, byte(0xa0+i))
	}
	bodySum := sha256.Sum256(docList(t)) // plain SHA-256 of the body
	pre = append(pre, bodySum[:]...)
	if len(pre) != 114 {
		t.Fatalf("hand-built signed part is %d bytes, want 114", len(pre))
	}

	// TaggedHash(tag, m) = SHA-256(SHA-256(tag) || SHA-256(tag) || m)
	tagSum := sha256.Sum256([]byte("canary/receipt/v1"))
	h := sha256.New()
	h.Write(tagSum[:])
	h.Write(tagSum[:])
	h.Write(pre)
	var wantDigest [32]byte
	copy(wantDigest[:], h.Sum(nil))

	if got := hex.EncodeToString(wantDigest[:]); got != vectorDigestHex {
		t.Fatalf("hand-built digest = %s, pinned %s", got, vectorDigestHex)
	}

	if got := nostrPub(t, vectorKey); hex.EncodeToString(got[:]) != vectorPubHex {
		t.Fatalf("vector pubkey = %x, BIP-340 vector 0 says %s", got, vectorPubHex)
	}

	r := signedVector(t)
	if got := r.Digest(); got != wantDigest {
		t.Errorf("Digest() = %x, want %x", got, wantDigest)
	}

	enc := EncodeReceipt(r)
	if len(enc) != ReceiptSize || ReceiptSize != 178 {
		t.Fatalf("encoded receipt is %d bytes, ReceiptSize %d, want 178", len(enc), ReceiptSize)
	}
	if !bytes.Equal(enc[:114], pre) {
		t.Errorf("signed part = %x\nwant          %x", enc[:114], pre)
	}
	if got := hex.EncodeToString(enc); got != vectorEncodingHex {
		t.Errorf("encoding = %s\nwant       %s", got, vectorEncodingHex)
	}

	// Check the signature with btcec directly, outside the code under test.
	pub, err := schnorr.ParsePubKey(mustHex(t, vectorPubHex))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.ParseSignature(enc[114:])
	if err != nil {
		t.Fatalf("signature bytes do not parse: %v", err)
	}
	if !sig.Verify(wantDigest[:], pub) {
		t.Error("the encoded signature does not verify under the vector pubkey")
	}
}

// The formats doc publishes a complete receipt. The code must read it, get the
// same digest, and accept its signature under the doc's pubkey.
func TestReceiptDocExample(t *testing.T) {
	r, err := DecodeReceiptHeader(docReceiptHex)
	if err != nil {
		t.Fatalf("DecodeReceiptHeader(doc example): %v", err)
	}

	regtest := canonical.Network(chaincfg.RegressionNetParams.Net)
	if r.Network != regtest {
		t.Errorf("network = %d, want regtest %d", r.Network, regtest)
	}
	if r.Resource != ResourceTweakList {
		t.Errorf("resource = %d, want tweak list", r.Resource)
	}
	if r.BlockHash != fromDisplay(t, docBlockDisplay) {
		t.Errorf("block_hash = %x, want the internal order of %s", r.BlockHash, docBlockDisplay)
	}
	if r.DustSat != 0 {
		t.Errorf("dust_sat = %d, want 0", r.DustSat)
	}
	if r.TipHeight != 212 {
		t.Errorf("tip_height = %d, want 212", r.TipHeight)
	}
	if r.TipHash != fromDisplay(t, docTipHashDisplay) {
		t.Errorf("tip_hash = %x, want the internal order of %s", r.TipHash, docTipHashDisplay)
	}
	if r.BodySHA256 != sha256.Sum256(docList(t)) {
		t.Error("body_sha256 is not the SHA-256 of the doc's 137-byte list")
	}

	if got := r.Digest(); hex.EncodeToString(got[:]) != docDigestHex {
		t.Errorf("digest = %x, doc says %s", got, docDigestHex)
	}

	pub := mustHex32(t, docPubHex)
	if err := VerifyReceiptSignature(r, pub); err != nil {
		t.Errorf("doc example signature rejected: %v", err)
	}
	req := ReceiptRequest{Network: regtest, BlockHash: fromDisplay(t, docBlockDisplay), DustSat: 0}
	if err := VerifyReceipt(r, pub, req, docList(t)); err != nil {
		t.Errorf("doc example fails the client checks: %v", err)
	}

	if got := EncodeReceiptHeader(r); got != docReceiptHex {
		t.Errorf("re-encoded header differs from the doc example:\n got %s\nwant %s", got, docReceiptHex)
	}
}

// The server signs receipts with the key that signs its Nostr records, so a
// client pins one pubkey per server.
func TestSignVerifyRoundTrip(t *testing.T) {
	unsigned := vectorReceipt(t)
	r := signedVector(t)

	withoutSig := r
	withoutSig.Sig = [64]byte{}
	if withoutSig != unsigned {
		t.Error("SignReceipt changed a field other than Sig")
	}
	if err := VerifyReceiptSignature(r, nostrPub(t, vectorKey)); err != nil {
		t.Errorf("a fresh receipt fails under the signer's Nostr pubkey: %v", err)
	}

	decoded, err := DecodeReceipt(EncodeReceipt(r))
	if err != nil {
		t.Fatalf("DecodeReceipt(EncodeReceipt(r)): %v", err)
	}
	if decoded != r {
		t.Errorf("binary round trip changed the receipt:\n got %+v\nwant %+v", decoded, r)
	}
	if err := VerifyReceiptSignature(decoded, nostrPub(t, vectorKey)); err != nil {
		t.Errorf("a decoded receipt fails verification: %v", err)
	}
}

// receiptFields is the byte layout from the formats doc, in order.
var receiptFields = []struct {
	name      string
	off, size int
}{
	{"version", 0, 1},
	{"network", 1, 4},
	{"resource", 5, 1},
	{"block_hash", 6, 32},
	{"dust_sat", 38, 8},
	{"tip_height", 46, 4},
	{"tip_hash", 50, 32},
	{"body_sha256", 82, 32},
	{"sig", 114, 64},
}

func TestReceiptLayoutIsContiguous(t *testing.T) {
	next := 0
	for _, f := range receiptFields {
		if f.off != next {
			t.Errorf("%s starts at %d, want %d", f.name, f.off, next)
		}
		next = f.off + f.size
	}
	if next != ReceiptSize {
		t.Errorf("fields end at %d, ReceiptSize is %d", next, ReceiptSize)
	}
}

// Flipping any single byte of an encoded receipt must stop it verifying. A
// changed version fails to decode. Every other change fails the signature.
func TestEveryReceiptByteIsCovered(t *testing.T) {
	enc := EncodeReceipt(signedVector(t))
	pub := nostrPub(t, vectorKey)

	for _, f := range receiptFields {
		for i := f.off; i < f.off+f.size; i++ {
			tampered := bytes.Clone(enc)
			tampered[i] ^= 0x01

			r, err := DecodeReceipt(tampered)
			if f.name == "version" {
				if !errors.Is(err, ErrReceiptMalformed) {
					t.Errorf("byte %d (%s) flipped: decode error = %v, want ErrReceiptMalformed", i, f.name, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("byte %d (%s) flipped: decode failed early: %v", i, f.name, err)
				continue
			}
			if err := VerifyReceiptSignature(r, pub); !errors.Is(err, ErrReceiptSignature) {
				t.Errorf("byte %d (%s) flipped: verify = %v, want ErrReceiptSignature", i, f.name, err)
			}
		}
	}
}

// Changing any signed field on the struct must break the signature, and each
// field must land in its documented byte range.
func TestChangingAnySignedFieldBreaksTheSignature(t *testing.T) {
	signed := signedVector(t)
	base := EncodeReceipt(signed)
	pub := nostrPub(t, vectorKey)

	cases := []struct {
		name      string
		off, size int
		mutate    func(*Receipt)
	}{
		{"network", 1, 4, func(r *Receipt) { r.Network = canonical.Network(chaincfg.RegressionNetParams.Net) }},
		{"resource", 5, 1, func(r *Receipt) { r.Resource = 0x02 }},
		{"block_hash", 6, 32, func(r *Receipt) { r.BlockHash[31] ^= 0x80 }},
		{"dust_sat", 38, 8, func(r *Receipt) { r.DustSat = 1 << 56 }},
		{"tip_height", 46, 4, func(r *Receipt) { r.TipHeight = 70000 + 1<<24 }},
		{"tip_hash", 50, 32, func(r *Receipt) { r.TipHash[0] ^= 0x01 }},
		{"body_sha256", 82, 32, func(r *Receipt) { r.BodySHA256[16] ^= 0x01 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := signed
			c.mutate(&m)

			got := EncodeReceipt(m)
			changed := false
			for i := range got {
				if got[i] == base[i] {
					continue
				}
				changed = true
				if i < c.off || i >= c.off+c.size {
					t.Errorf("changing %s altered byte %d, outside [%d, %d)", c.name, i, c.off, c.off+c.size)
				}
			}
			if !changed {
				t.Fatalf("changing %s altered no encoded byte", c.name)
			}
			if err := VerifyReceiptSignature(m, pub); !errors.Is(err, ErrReceiptSignature) {
				t.Errorf("verify after changing %s = %v, want ErrReceiptSignature", c.name, err)
			}
		})
	}
}

func TestWrongKeyFails(t *testing.T) {
	r := signedVector(t)

	other := nostrPub(t, [32]byte{31: 0x04})
	if err := VerifyReceiptSignature(r, other); !errors.Is(err, ErrReceiptSignature) {
		t.Errorf("verify under another server's key = %v, want ErrReceiptSignature", err)
	}

	// An x coordinate at or above the field prime is no point at all.
	var notAKey [32]byte
	for i := range notAKey {
		notAKey[i] = 0xff
	}
	if err := VerifyReceiptSignature(r, notAKey); !errors.Is(err, ErrReceiptSignature) {
		t.Errorf("verify under an invalid pubkey = %v, want ErrReceiptSignature", err)
	}

	unsigned := vectorReceipt(t)
	if err := VerifyReceiptSignature(unsigned, nostrPub(t, vectorKey)); !errors.Is(err, ErrReceiptSignature) {
		t.Errorf("verify of an unsigned receipt = %v, want ErrReceiptSignature", err)
	}
}

func TestSignReceiptRejectsBadInput(t *testing.T) {
	order := mustHex32(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	var allFF [32]byte
	for i := range allFF {
		allFF[i] = 0xff
	}

	keys := map[string][32]byte{
		"zero key":             {},
		"key equal to order n": order,
		"key above order n":    allFF,
	}
	for name, sk := range keys {
		if _, err := SignReceipt(vectorReceipt(t), sk); err == nil {
			t.Errorf("%s: SignReceipt accepted it", name)
		} else if !strings.HasPrefix(err.Error(), "wire: ") {
			t.Errorf("%s: error %q lacks the wire: prefix", name, err)
		}
	}

	for _, res := range []Resource{0x00, 0x02} {
		r := vectorReceipt(t)
		r.Resource = res
		if _, err := SignReceipt(r, vectorKey); err == nil {
			t.Errorf("SignReceipt signed resource %#x, which v1 does not define", byte(res))
		}
	}
}

func TestDecodeReceiptRejectsMalformed(t *testing.T) {
	good := EncodeReceipt(signedVector(t))

	withVersion := func(v byte) []byte {
		b := bytes.Clone(good)
		b[0] = v
		return b
	}
	cases := map[string][]byte{
		"empty":        nil,
		"177 bytes":    good[:177],
		"179 bytes":    append(bytes.Clone(good), 0x00),
		"version 0x00": withVersion(0x00),
		"version 0x02": withVersion(0x02),
	}
	for name, b := range cases {
		_, err := DecodeReceipt(b)
		if !errors.Is(err, ErrReceiptMalformed) {
			t.Errorf("%s: error = %v, want ErrReceiptMalformed", name, err)
			continue
		}
		if !strings.HasPrefix(err.Error(), "wire: receipt malformed: ") {
			t.Errorf("%s: error %q does not follow wire: <what failed>: <detail>", name, err)
		}
	}
}

// The decoder reads the resource byte but leaves judging it to the client
// checks. The evidence verifier reports a wrong resource as an invalid
// receipt, not as an unreadable one.
func TestDecodeReceiptKeepsUnknownResource(t *testing.T) {
	b := EncodeReceipt(signedVector(t))
	b[5] = 0x02
	r, err := DecodeReceipt(b)
	if err != nil {
		t.Fatalf("decode with resource 0x02: %v", err)
	}
	if r.Resource != 0x02 {
		t.Errorf("resource = %#x, want 0x02", byte(r.Resource))
	}
}

func TestReceiptHeaderRoundTrip(t *testing.T) {
	r := signedVector(t)
	h := EncodeReceiptHeader(r)

	if len(h) != 356 {
		t.Errorf("header value is %d characters, want 356", len(h))
	}
	if h != strings.ToLower(h) {
		t.Error("header value must be lowercase hex")
	}
	if h != hex.EncodeToString(EncodeReceipt(r)) {
		t.Error("header value is not the hex of the 178-byte receipt")
	}
	got, err := DecodeReceiptHeader(h)
	if err != nil {
		t.Fatalf("DecodeReceiptHeader: %v", err)
	}
	if got != r {
		t.Errorf("header round trip changed the receipt:\n got %+v\nwant %+v", got, r)
	}
	if ReceiptHeader != "X-Canary-Receipt" {
		t.Errorf("ReceiptHeader = %q, want X-Canary-Receipt", ReceiptHeader)
	}
}

func TestDecodeReceiptHeaderRejectsMalformed(t *testing.T) {
	r := signedVector(t)
	good := EncodeReceiptHeader(r)

	// The first letter in the value, so the uppercase case changes one
	// character and nothing else.
	letter := strings.IndexAny(good, "abcdef")
	if letter < 0 {
		t.Fatal("vector header has no hex letter to uppercase")
	}

	cases := map[string]string{
		"empty":                "",
		"177 bytes":            good[:354],
		"odd length":           good[:355],
		"one extra character":  good + "0",
		"179 bytes":            good + "00",
		"all uppercase":        strings.ToUpper(good),
		"one uppercase letter": good[:letter] + strings.ToUpper(good[letter:letter+1]) + good[letter+1:],
		"non-hex character":    good[:10] + "g" + good[11:],
		"0x prefix":            "0x" + good[2:],
		"leading space":        " " + good[1:],
		"trailing newline":     good + "\n",
		"base64 instead":       base64.StdEncoding.EncodeToString(EncodeReceipt(r)),
		"version 0x02":         "02" + good[2:],
	}
	for name, s := range cases {
		_, err := DecodeReceiptHeader(s)
		if !errors.Is(err, ErrReceiptMalformed) {
			t.Errorf("%s: error = %v, want ErrReceiptMalformed", name, err)
		}
	}
}

func TestVerifyReceiptChecks(t *testing.T) {
	r := signedVector(t)
	pub := nostrPub(t, vectorKey)
	body := docList(t)
	req := ReceiptRequest{Network: r.Network, BlockHash: r.BlockHash, DustSat: r.DustSat}

	if err := VerifyReceipt(r, pub, req, body); err != nil {
		t.Fatalf("a matching receipt fails: %v", err)
	}

	// A receipt for another resource, signed with btcec directly because
	// SignReceipt refuses to sign one.
	otherResource := vectorReceipt(t)
	otherResource.Resource = 0x02
	priv, _ := btcec.PrivKeyFromBytes(vectorKey[:])
	d := otherResource.Digest()
	sig, err := schnorr.Sign(priv, d[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(otherResource.Sig[:], sig.Serialize())

	changedBody := bytes.Clone(body)
	changedBody[len(changedBody)-1] ^= 0x01

	type check struct {
		name    string
		r       Receipt
		pub     [32]byte
		req     ReceiptRequest
		body    []byte
		wantErr error
		mention string
	}
	with := func(f func(*ReceiptRequest)) ReceiptRequest {
		q := req
		f(&q)
		return q
	}
	cases := []check{
		{"signature", r, nostrPub(t, [32]byte{31: 0x04}), req, body, ErrReceiptSignature, ""},
		{"network", r, pub, with(func(q *ReceiptRequest) {
			q.Network = canonical.Network(chaincfg.RegressionNetParams.Net)
		}), body, ErrReceiptMismatch, "network"},
		{"resource", otherResource, pub, req, body, ErrReceiptMismatch, "resource"},
		{"block_hash", r, pub, with(func(q *ReceiptRequest) { q.BlockHash[0] ^= 0x01 }), body, ErrReceiptMismatch, "block"},
		{"dust_sat", r, pub, with(func(q *ReceiptRequest) { q.DustSat = 0 }), body, ErrReceiptMismatch, "dust"},
		{"body changed", r, pub, req, changedBody, ErrReceiptMismatch, "body"},
		{"body missing", r, pub, req, nil, ErrReceiptMismatch, "body"},
		// The signature is checked first. A forged receipt must not be
		// reported as a mismatch the server signed.
		{"signature before fields", r, nostrPub(t, [32]byte{31: 0x04}), with(func(q *ReceiptRequest) {
			q.Network = canonical.Network(chaincfg.RegressionNetParams.Net)
		}), body, ErrReceiptSignature, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := VerifyReceipt(c.r, c.pub, c.req, c.body)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("error = %v, want %v", err, c.wantErr)
			}
			if c.mention != "" && !strings.Contains(err.Error(), c.mention) {
				t.Errorf("error %q does not name the %s check", err, c.mention)
			}
		})
	}
}

func TestRetentionWindowIs144(t *testing.T) {
	if RetentionWindow != 144 {
		t.Errorf("RetentionWindow = %d, the protocol fixes it at 144", RetentionWindow)
	}
}

func TestRetentionBoundary(t *testing.T) {
	cases := []struct {
		name       string
		tip, block uint32
		depth      int64
		inside     bool
	}{
		{"the tip itself", 1000, 1000, 0, true},
		{"depth 143, the oldest block inside", 1143, 1000, 143, true},
		{"depth 144, the first block outside", 1144, 1000, 144, false},
		{"depth 145", 1145, 1000, 145, false},
		{"tip one below the block", 999, 1000, -1, true},
		{"tip far below the block", 0, math.MaxUint32, -math.MaxUint32, true},
		{"deepest possible block", math.MaxUint32, 0, math.MaxUint32, false},
		{"doc example: record 205, tip 212", 212, 205, 7, true},
		{"doc example leaves the window at tip 349", 349, 205, 144, false},
		{"doc example still inside at tip 348", 348, 205, 143, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := BlockDepth(c.tip, c.block); got != c.depth {
				t.Errorf("BlockDepth(%d, %d) = %d, want %d", c.tip, c.block, got, c.depth)
			}
			if got := InsideRetentionWindow(c.tip, c.block); got != c.inside {
				t.Errorf("InsideRetentionWindow(%d, %d) = %v, want %v", c.tip, c.block, got, c.inside)
			}
		})
	}
}

// Every other package reads the window from RetentionWindow. A literal 144 in
// production code is a second definition that can drift from the first. Test
// files are exempt, because pinning the value there is the point.
func TestNoLiteralRetentionWindowOutsideItsDefinition(t *testing.T) {
	root := ".."
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found above wire: %v", err)
	}

	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor" || name == "node_modules") {
				return filepath.SkipDir
			}
			// A nested module is somebody else's code.
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if spec, ok := n.(*ast.ValueSpec); ok && file.Name.Name == "wire" {
				for _, id := range spec.Names {
					if id.Name == "RetentionWindow" {
						return false // the one definition
					}
				}
			}
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.INT {
				return true
			}
			if v, err := strconv.ParseInt(lit.Value, 0, 64); err == nil && v == 144 {
				t.Errorf("%s: literal 144; use wire.RetentionWindow", fset.Position(lit.Pos()))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
