package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/wire"
	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/nbd-wtf/go-nostr"
)

var regtest = canonical.Network(chaincfg.RegressionNetParams.Net)

// testKey derives a valid secret key from one byte. Test keys only.
func testKey(seed byte) [32]byte {
	return sha256.Sum256([]byte{'e', 'v', 'i', 'd', 'e', 'n', 'c', 'e', seed})
}

func pubOf(t *testing.T, sk [32]byte) [32]byte {
	t.Helper()
	pub, err := nostr.GetPublicKey(hex.EncodeToString(sk[:]))
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	b, _ := hex.DecodeString(pub)
	copy(out[:], b)
	return out
}

// leafFor builds a deterministic entry. The tweak need not be a curve point,
// because nothing in verify reads it as one.
func leafFor(seed byte) canonical.Leaf {
	var l canonical.Leaf
	l.TxID = sha256.Sum256([]byte{'t', seed})
	k := sha256.Sum256([]byte{'k', seed})
	l.Tweak[0] = 0x02
	copy(l.Tweak[1:], k[:])
	return l
}

// scenario is everything one evidence file is built from, before signing.
// The defaults give a file that checks out: three entries, position 1 absent
// in the served list, and a signed tip 7 blocks above the block.
type scenario struct {
	recordKey  [32]byte
	receiptKey [32]byte
	net        canonical.Network
	blockHash  [32]byte
	height     uint32
	leaves     []canonical.Leaf
	index      uint32

	served     []wire.Position
	body       []byte       // replaces the encoded served list when set
	receipt    wire.Receipt // signed by receiptKey; BodySHA256 comes from the body
	keepDigest bool         // sign receipt.BodySHA256 as set, not the body's hash
	noReceipt  bool
}

func newScenario() *scenario {
	leaves := []canonical.Leaf{leafFor(0), leafFor(1), leafFor(2)}
	s := &scenario{
		recordKey:  testKey(1),
		receiptKey: testKey(1),
		net:        regtest,
		blockHash:  sha256.Sum256([]byte("block 205")),
		height:     205,
		leaves:     leaves,
		index:      1,
		served: []wire.Position{
			{Kind: wire.KindFull, Leaf: leaves[0]},
			{Kind: wire.KindAbsent},
			{Kind: wire.KindFull, Leaf: leaves[2]},
		},
	}
	s.receipt = wire.Receipt{
		Network:   regtest,
		Resource:  wire.ResourceTweakList,
		BlockHash: s.blockHash,
		TipHeight: 212,
		TipHash:   sha256.Sum256([]byte("block 212")),
	}
	return s
}

// scenarioCreatedAt is the created_at every scenario record carries:
// 2026-10-03 08:00:00 UTC. ToEvent stamps the clock's time, so the scenario
// re-signs with this value, and two builds of one scenario give one id.
const scenarioCreatedAt nostr.Timestamp = 1791014400

func (s *scenario) event(t *testing.T) nostr.Event {
	t.Helper()
	c := feed.Commitment{
		Network:     s.net,
		BlockHash:   s.blockHash,
		BlockHeight: s.height,
		N:           uint32(len(s.leaves)),
		Root:        commit.Root(s.net, s.blockHash, s.leaves),
	}
	ev, err := c.ToEvent(s.recordKey)
	if err != nil {
		t.Fatal(err)
	}
	ev.CreatedAt = scenarioCreatedAt
	if err := ev.Sign(hex.EncodeToString(s.recordKey[:])); err != nil {
		t.Fatal(err)
	}
	return ev
}

func (s *scenario) servedBody(t *testing.T) []byte {
	t.Helper()
	if s.body != nil {
		return s.body
	}
	b, err := wire.EncodeResponse(s.served)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signReceipt signs r with sk without SignReceipt's resource check, so a test
// can sign a receipt for a resource v1 does not define.
func signReceipt(t *testing.T, r wire.Receipt, sk [32]byte) wire.Receipt {
	t.Helper()
	priv, _ := btcec.PrivKeyFromBytes(sk[:])
	d := r.Digest()
	sig, err := schnorr.Sign(priv, d[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(r.Sig[:], sig.Serialize())
	return r
}

// input returns the Build input for the scenario.
func (s *scenario) input(t *testing.T) Input {
	t.Helper()
	in := Input{Record: s.event(t), Leaves: s.leaves, Index: s.index}
	if !s.noReceipt {
		body := s.servedBody(t)
		r := s.receipt
		if !s.keepDigest {
			r.BodySHA256 = sha256.Sum256(body)
		}
		r = signReceipt(t, r, s.receiptKey)
		in.Served = body
		in.Receipt = wire.EncodeReceiptHeader(r)
	}
	return in
}

// file assembles the scenario's file without verifying it, so a test can
// build a file that must not check out.
func (s *scenario) file(t *testing.T) File {
	t.Helper()
	f, err := assemble(s.input(t))
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	return f
}

func (s *scenario) json(t *testing.T) []byte {
	t.Helper()
	return marshal(t, s.file(t))
}

func marshal(t *testing.T, f File) []byte {
	t.Helper()
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// edit decodes a file into generic JSON, lets fn change it, and encodes it
// again. Numbers stay exact.
func edit(t *testing.T, b []byte, fn func(m map[string]any)) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func obj(m map[string]any, key string) map[string]any { return m[key].(map[string]any) }

// flipHex flips the lowest bit of the hex digit at position i.
func flipHex(s string, i int) string {
	b := []byte(s)
	switch {
	case b[i] == '0':
		b[i] = '1'
	case b[i] == 'f':
		b[i] = 'e'
	default:
		b[i] = "0123456789abcdef"[(bytes.IndexByte([]byte("0123456789abcdef"), b[i]))^1]
	}
	return string(b)
}

// eventWith signs a record whose tags or content the test chose, so the
// record verifies but breaks a rule verify checks after the signature.
func eventWith(t *testing.T, sk [32]byte, fn func(*nostr.Event)) Event {
	t.Helper()
	s := newScenario()
	ev := s.event(t)
	fn(&ev)
	if err := ev.Sign(hex.EncodeToString(sk[:])); err != nil {
		t.Fatal(err)
	}
	return fileEvent(ev)
}
