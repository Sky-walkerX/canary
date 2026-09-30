package indexer_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/core/coretest"
	"github.com/Sky-walkerX/canary/internal/indexer"
	"github.com/Sky-walkerX/canary/wire"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	btcwire "github.com/btcsuite/btcd/wire"
	"github.com/nbd-wtf/go-nostr"
)

// regtest is the regtest magic as the v1 formats doc prints it in decimal.
// A literal, so a wrong mapping from Core's chain name fails here.
const regtest = canonical.Network(3669344250)

// testKey derives a valid secret key from one byte.
func testKey(seed byte) [32]byte {
	return sha256.Sum256([]byte{'c', 'a', 'n', 'a', 'r', 'y', seed})
}

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(string(bytes.TrimRight(p, "\n")))
	return len(p), nil
}

// server is one reference indexer, reading the synthetic chain and serving
// its HTTP API on an httptest server.
type server struct {
	idx *indexer.Indexer
	srv *httptest.Server
}

type option func(*indexer.Config)

func withholding(txid chainhash.Hash) option {
	return func(c *indexer.Config) {
		id := [32]byte(txid) // chainhash.Hash holds internal order
		c.WithholdTxID = &id
	}
}

func startServer(t *testing.T, restURL string, seed byte, opts ...option) *server {
	t.Helper()
	client, err := core.New(restURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := indexer.Config{
		Core:     client,
		Key:      testKey(seed),
		Software: indexer.Software{Name: "canary-indexer", Version: "0.1.0", Build: "test"},
		Logger:   log.New(testLogWriter{t}, "", 0),
	}
	for _, o := range opts {
		o(&cfg)
	}
	idx, err := indexer.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(idx.Handler())
	t.Cleanup(srv.Close)
	return &server{idx: idx, srv: srv}
}

func (s *server) sync(t *testing.T) {
	t.Helper()
	if err := s.idx.Sync(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}
}

func (s *server) do(t *testing.T, method, path string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, s.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func (s *server) get(t *testing.T, path string) (*http.Response, []byte) {
	t.Helper()
	return s.do(t, http.MethodGet, path)
}

// commitment fetches and verifies the signed record for the block whose
// display-order hash is hash.
func (s *server) commitment(t *testing.T, hash string) (feed.Commitment, []byte) {
	t.Helper()
	resp, body := s.get(t, "/commitment/"+hash)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /commitment/%s: status %d: %s", hash, resp.StatusCode, body)
	}
	var ev nostr.Event
	if err := json.Unmarshal(body, &ev); err != nil {
		t.Fatalf("commitment body is not a Nostr event: %v", err)
	}
	c, err := feed.FromEvent(ev)
	if err != nil {
		t.Fatalf("commitment does not verify: %v", err)
	}
	return c, body
}

// tweaks fetches the tweak list and decodes both it and its receipt.
func (s *server) tweaks(t *testing.T, hash string) ([]wire.Position, []byte, wire.Receipt) {
	t.Helper()
	resp, body := s.get(t, "/tweaks/"+hash)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /tweaks/%s: status %d: %s", hash, resp.StatusCode, body)
	}
	positions, err := wire.DecodeResponse(body)
	if err != nil {
		t.Fatalf("tweak list does not decode: %v", err)
	}
	r, err := wire.DecodeReceiptHeader(resp.Header.Get(wire.ReceiptHeader))
	if err != nil {
		t.Fatalf("receipt header does not decode: %v", err)
	}
	return positions, body, r
}

// fixture is a chain whose block at height 2 holds three taproot-paying
// transactions and, between the first two, one that pays no taproot output.
// Two empty blocks follow, so the tip sits two blocks above it.
type fixture struct {
	chain   *coretest.Chain
	rest    string
	blk     *btcwire.MsgBlock
	payers  []*btcwire.MsgTx // the three entries, in block order
	skipped *btcwire.MsgTx
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	chain := coretest.NewChain(t)
	chain.MineEmpty(1)

	a := chain.PayToTaproot(coretest.P2WPKH)
	skipped := chain.PayToWitnessKeyHash(coretest.P2TR)
	b := chain.PayToTaproot(coretest.P2TR, coretest.P2WPKH)
	c := chain.PayToTaproot(coretest.P2TR)
	blk := chain.Mine(a, skipped, b, c)
	chain.MineEmpty(2)

	return &fixture{
		chain:   chain,
		rest:    coretest.Serve(t, chain),
		blk:     blk,
		payers:  []*btcwire.MsgTx{a, b, c},
		skipped: skipped,
	}
}

// hash is the block's hash in display order, as a URL carries it.
func (f *fixture) hash() string { return f.blk.BlockHash().String() }

func leavesOf(t *testing.T, positions []wire.Position) []canonical.Leaf {
	t.Helper()
	leaves := make([]canonical.Leaf, len(positions))
	for i, p := range positions {
		if p.Kind != wire.KindFull {
			t.Fatalf("position %d has kind %d, want full", i, p.Kind)
		}
		leaves[i] = p.Leaf
	}
	return leaves
}
