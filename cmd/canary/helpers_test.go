package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/core/coretest"
	"github.com/Sky-walkerX/canary/internal/indexer"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/btcsuite/btcd/wire"
)

// syncBuffer is a bytes.Buffer that a command goroutine and the test share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// result is one run of the command.
type result struct {
	code           int
	stdout, stderr string
}

func (r result) String() string {
	return "exit " + strconv.Itoa(r.code) + "\nstdout:\n" + r.stdout + "\nstderr:\n" + r.stderr
}

func runCLI(t *testing.T, args ...string) result {
	t.Helper()
	return runCLIContext(t, context.Background(), args...)
}

// runCLIContext runs the command under ctx, as main does under the signal
// context.
func runCLIContext(t *testing.T, ctx context.Context, args ...string) result {
	t.Helper()
	var out, errb syncBuffer
	code := run(ctx, args, &out, &errb)
	return result{code: code, stdout: out.String(), stderr: errb.String()}
}

// wantExit fails the test unless the run exited with code.
func wantExit(t *testing.T, r result, code int) {
	t.Helper()
	if r.code != code {
		t.Fatalf("want exit %d, got %s", code, r)
	}
}

// testKey is a fixed secret key for one test server.
func testKey(seed byte) [32]byte {
	return sha256.Sum256([]byte{'c', 'l', 'i', seed})
}

func pubHex(t testing.TB, sk [32]byte) string {
	t.Helper()
	pub, err := indexer.PublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub[:])
}

// startIndexer runs one reference indexer over the synthetic chain, synced
// to its tip, behind an httptest server. wrap, when set, sits in front of it.
func startIndexer(t testing.TB, rest string, key [32]byte, withhold *[32]byte, wrap func(http.Handler) http.Handler) *httptest.Server {
	t.Helper()
	client, err := core.New(rest, nil)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := indexer.New(indexer.Config{
		Core:         client,
		Key:          key,
		WithholdTxID: withhold,
		Software:     indexer.Software{Name: "canary-indexer", Version: "0.1.0", Build: "test"},
		Logger:       log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := idx.Sync(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	var h http.Handler = idx.Handler()
	if wrap != nil {
		h = wrap(h)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// stripReceipts drops the receipt header, the way a server that signs no
// receipts would answer.
func stripReceipts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			if http.CanonicalHeaderKey(k) == "X-Canary-Receipt" {
				continue
			}
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
}

// world is a synthetic chain with one block that holds three taproot
// payments and one transaction BIP-352 skips. The target payment sits at
// position 1 of that block's entries.
type world struct {
	chain  *coretest.Chain
	rest   string
	block  *wire.MsgBlock
	height uint32
	target *wire.MsgTx
	tip    uint32
	dir    string
}

func newWorld(t testing.TB) *world {
	t.Helper()
	return newWorldMined(t, func(a, skipped, b, c *wire.MsgTx) []*wire.MsgTx {
		return []*wire.MsgTx{a, skipped, b, c}
	})
}

// newWorldMined builds newWorld's chain, with the payment block's
// transactions in the order order gives. The transactions and heights are
// the same in every order, so only the block hash and the positions change,
// as when a wiped regtest chain is mined again.
func newWorldMined(t testing.TB, order func(a, skipped, b, c *wire.MsgTx) []*wire.MsgTx) *world {
	t.Helper()
	chain := coretest.NewChain(t)
	chain.MineEmpty(2)
	a := chain.PayToTaproot(coretest.P2WPKH)
	skipped := chain.PayToWitnessKeyHash(coretest.P2TR)
	b := chain.PayToTaproot(coretest.P2TR, coretest.P2WPKH)
	c := chain.PayToTaproot(coretest.P2TR)
	blk := chain.Mine(order(a, skipped, b, c)...)
	chain.MineEmpty(4)
	tip, _ := chain.Tip()
	return &world{
		chain: chain, rest: coretest.Serve(t, chain), block: blk, height: 3,
		target: b, tip: tip, dir: t.TempDir(),
	}
}

func (w *world) statePath() string   { return filepath.Join(w.dir, "state.json") }
func (w *world) evidenceDir() string { return filepath.Join(w.dir, "evidence") }
func (w *world) txid() string        { return w.target.TxHash().String() }
func (w *world) blockHash() string   { return w.block.BlockHash().String() }
func (w *world) targetID() [32]byte  { return [32]byte(w.target.TxHash()) }

// server is one --indexer with its pin.
type server struct {
	label  string
	url    string
	pubkey string // hex or "none"
}

func (w *world) args(servers []server, extra ...string) []string {
	args := []string{"check"}
	for _, s := range servers {
		args = append(args, "--indexer", s.url+"="+s.label, "--pubkey", s.label+"="+s.pubkey)
	}
	args = append(args, "--core-rest", w.rest, "--state", w.statePath(), "--evidence-dir", w.evidenceDir())
	return append(args, extra...)
}

func (w *world) honest(t testing.TB, label string, seed byte) server {
	t.Helper()
	k := testKey(seed)
	return server{label: label, url: startIndexer(t, w.rest, k, nil, nil).URL, pubkey: pubHex(t, k)}
}

func (w *world) withholder(t testing.TB, label string, seed byte, wrap func(http.Handler) http.Handler) server {
	t.Helper()
	k := testKey(seed)
	id := w.targetID()
	return server{label: label, url: startIndexer(t, w.rest, k, &id, wrap).URL, pubkey: pubHex(t, k)}
}

func loadState(t testing.TB, path string) *state.File {
	t.Helper()
	f, err := state.Load(path)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	return f
}

func blockAt(t testing.TB, f *state.File, height uint32) state.Block {
	t.Helper()
	for _, b := range f.Blocks {
		if b.Height == height {
			return b
		}
	}
	t.Fatalf("no block at height %d in the state file", height)
	return state.Block{}
}

func serverIn(t testing.TB, b state.Block, label string) state.BlockServer {
	t.Helper()
	for _, s := range b.Servers {
		if s.Label == label {
			return s
		}
	}
	t.Fatalf("block %d has no result for %s", b.Height, label)
	return state.BlockServer{}
}

// fixClock makes the command's clock read at, for the rest of the test.
func fixClock(t testing.TB, at time.Time) {
	t.Helper()
	old := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = old })
}

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
