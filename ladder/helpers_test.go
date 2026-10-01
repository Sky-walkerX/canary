package ladder

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/policy"
	"github.com/Sky-walkerX/canary/wire"
	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// regtest is the regtest magic as the v1 formats doc prints it in decimal.
const regtest = canonical.Network(3669344250)

// coreTip is the height of the test node's best block.
const coreTip uint32 = 300

// Two block heights the tests use most. A recent block sits 10 blocks below
// the tip, inside the window. A deep block sits 200 below, outside it.
const (
	recent uint32 = 290
	deep   uint32 = 100
)

// blockHash is the fake hash of the test chain's block at height h, in
// internal byte order.
func blockHash(h uint32) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("block %d", h)))
}

// chainMap is a Core view backed by a map from height to hash.
type chainMap map[uint32][32]byte

func (c chainMap) ActiveHash(h uint32) ([32]byte, bool, error) {
	v, ok := c[h]
	return v, ok, nil
}

func newChain() chainMap {
	m := chainMap{}
	for h := uint32(0); h <= coreTip; h++ {
		m[h] = blockHash(h)
	}
	return m
}

type key struct {
	sk  [32]byte
	pub [32]byte
}

func newKey(t testing.TB, seed byte) key {
	t.Helper()
	sk := sha256.Sum256([]byte{'l', 'a', 'd', 'd', 'e', 'r', seed})
	priv, _ := btcec.PrivKeyFromBytes(sk[:])
	var k key
	k.sk = sk
	copy(k.pub[:], schnorr.SerializePubKey(priv.PubKey()))
	return k
}

// leaves returns n distinct entries. The salt keeps two sets apart.
func leaves(n int, salt string) []canonical.Leaf {
	out := make([]canonical.Leaf, n)
	for i := range out {
		out[i].TxID = sha256.Sum256([]byte(fmt.Sprintf("tx %s %d", salt, i)))
		tw := sha256.Sum256([]byte(fmt.Sprintf("tweak %s %d", salt, i)))
		out[i].Tweak[0] = 0x02
		copy(out[i].Tweak[1:], tw[:])
	}
	return out
}

func full(ls []canonical.Leaf) []wire.Position {
	out := make([]wire.Position, len(ls))
	for i, l := range ls {
		out[i] = wire.Position{Kind: wire.KindFull, Leaf: l}
	}
	return out
}

// absentAt returns a copy of pos with the given positions marked absent.
func absentAt(pos []wire.Position, idx ...int) []wire.Position {
	out := append([]wire.Position(nil), pos...)
	for _, i := range idx {
		out[i] = wire.Position{Kind: wire.KindAbsent}
	}
	return out
}

// hashAt returns a copy of pos with the given positions sent as hashes.
func hashAt(pos []wire.Position, idx ...int) []wire.Position {
	out := append([]wire.Position(nil), pos...)
	for _, i := range idx {
		out[i] = wire.Position{Kind: wire.KindHash, Hash: commit.LeafHash(pos[i].Leaf)}
	}
	return out
}

func encode(t testing.TB, pos []wire.Position) []byte {
	t.Helper()
	b, err := wire.EncodeResponse(pos)
	if err != nil {
		t.Fatalf("encode list: %v", err)
	}
	return b
}

func signRecord(t testing.TB, k key, hash [32]byte, height uint32, ls []canonical.Leaf) []byte {
	t.Helper()
	c := feed.Commitment{
		Network:     regtest,
		BlockHash:   hash,
		BlockHeight: height,
		N:           uint32(len(ls)),
		Root:        commit.Root(regtest, hash, ls),
	}
	ev, err := c.ToEvent(k.sk)
	if err != nil {
		t.Fatalf("sign record: %v", err)
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	return b
}

func signReceipt(t testing.TB, k key, hash [32]byte, tipHeight uint32, tipHash [32]byte, body []byte) string {
	t.Helper()
	r, err := wire.SignReceipt(wire.Receipt{
		Network:    regtest,
		Resource:   wire.ResourceTweakList,
		BlockHash:  hash,
		DustSat:    0,
		TipHeight:  tipHeight,
		TipHash:    tipHash,
		BodySHA256: sha256.Sum256(body),
	}, k.sk)
	if err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	return wire.EncodeReceiptHeader(r)
}

// fixture builds one block on the test chain and the servers that answer
// for it.
type fixture struct {
	t        testing.TB
	height   uint32
	hash     [32]byte
	chain    chainMap
	payments []Payment
}

func newFixture(t testing.TB, height uint32) *fixture {
	return &fixture{t: t, height: height, hash: blockHash(height), chain: newChain()}
}

func (f *fixture) block(servers ...Server) Block {
	return Block{
		Hash:     f.hash,
		Height:   f.height,
		Core:     Core{Network: regtest, TipHeight: coreTip, Chain: f.chain},
		Servers:  servers,
		Payments: f.payments,
	}
}

// srvConf is what one test server signs and serves.
type srvConf struct {
	signed       []canonical.Leaf // nil signs no record
	noRecord     bool
	recordHeight uint32
	served       []wire.Position // nil serves no list
	noList       bool
	body         []byte // replaces the encoded list when set
	receipt      bool
	tipHeight    uint32
	tipHash      [32]byte
	policy       *policy.Policy
}

type opt func(*srvConf)

func noReceipt() opt                  { return func(c *srvConf) { c.receipt = false } }
func noList() opt                     { return func(c *srvConf) { c.noList = true } }
func noRecord() opt                   { return func(c *srvConf) { c.noRecord = true } }
func rawBody(b []byte) opt            { return func(c *srvConf) { c.body = b } }
func recordHeight(h uint32) opt       { return func(c *srvConf) { c.recordHeight = h } }
func withPolicy(p *policy.Policy) opt { return func(c *srvConf) { c.policy = p } }
func prunes() opt                     { return withPolicy(&policy.Policy{Network: regtest, PrunesSpent: true}) }
func signedTip(h uint32, hash [32]byte) opt {
	return func(c *srvConf) { c.tipHeight, c.tipHash = h, hash }
}

// srv builds a server that signs signed and serves served, with a valid
// receipt whose tip is Core's tip, unless an option says otherwise.
func (f *fixture) srv(label string, k key, signed []canonical.Leaf, served []wire.Position, opts ...opt) Server {
	f.t.Helper()
	c := srvConf{
		signed:       signed,
		recordHeight: f.height,
		served:       served,
		receipt:      true,
		tipHeight:    coreTip,
		tipHash:      f.chain[coreTip],
		policy:       &policy.Policy{Network: regtest},
	}
	for _, o := range opts {
		o(&c)
	}
	pub := k.pub
	s := Server{Label: label, Pubkey: &pub, Policy: c.policy}
	if !c.noRecord {
		s.Record = signRecord(f.t, k, f.hash, c.recordHeight, c.signed)
	}
	if c.noList {
		return s
	}
	body := c.body
	if body == nil {
		body = encode(f.t, c.served)
	}
	s.List = &List{Body: body}
	if c.receipt {
		s.List.Receipt = signReceipt(f.t, k, f.hash, c.tipHeight, c.tipHash, body)
	}
	return s
}

func evaluate(t testing.TB, b Block) BlockResult {
	t.Helper()
	res, err := Evaluate(b)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return res
}

func byLabel(t testing.TB, res BlockResult, label string) ServerResult {
	t.Helper()
	for _, s := range res.Servers {
		if s.Label == label {
			return s
		}
	}
	t.Fatalf("no result for server %q", label)
	return ServerResult{}
}

func u32(v uint32) *uint32 { return &v }

// unspent is a payment output Core shows unspent.
func unspent(sat uint64) Output { return Output{ValueSat: sat, Unspent: true} }

// spent is a payment output Core shows spent.
func spent(sat uint64) Output { return Output{ValueSat: sat} }

// le32 is a helper for hand-built bodies.
func le32(n uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], n)
	return b[:]
}
