package evidence

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/core/coretest"
	"github.com/Sky-walkerX/canary/internal/indexer"
	"github.com/Sky-walkerX/canary/wire"
	"github.com/nbd-wtf/go-nostr"
)

// startIndexer runs one reference indexer over the synthetic chain, synced
// to its tip, behind an httptest server.
func startIndexer(t *testing.T, rest string, key [32]byte, withhold *[32]byte) *httptest.Server {
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
	srv := httptest.NewServer(idx.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func fetch(t *testing.T, srv *httptest.Server, path string) ([]byte, http.Header) {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, resp.StatusCode, body)
	}
	return body, resp.Header
}

// golden is an evidence file built the way canary check builds one: from a
// withholding reference indexer's signed record, list and receipt, with the
// left-out entry recovered from an honest indexer.
type golden struct {
	bytes    []byte
	file     File
	txid     string // display order
	accused  [32]byte
	height   uint32
	tip      uint32
	fileName string
}

func buildGolden(t *testing.T) golden {
	t.Helper()
	chain := coretest.NewChain(t)
	chain.MineEmpty(1)
	a := chain.PayToTaproot(coretest.P2WPKH)
	skipped := chain.PayToWitnessKeyHash(coretest.P2TR)
	b := chain.PayToTaproot(coretest.P2TR, coretest.P2WPKH)
	c := chain.PayToTaproot(coretest.P2TR)
	blk := chain.Mine(a, skipped, b, c)
	chain.MineEmpty(7)
	rest := coretest.Serve(t, chain)

	target := [32]byte(b.TxHash()) // chainhash.Hash holds internal order
	honest := startIndexer(t, rest, testKey(3), nil)
	withholder := startIndexer(t, rest, testKey(4), &target)

	hash := blk.BlockHash().String() // display order, as a URL carries it
	evBody, _ := fetch(t, withholder, "/commitment/"+hash)
	var ev nostr.Event
	if err := json.Unmarshal(evBody, &ev); err != nil {
		t.Fatal(err)
	}
	served, hdr := fetch(t, withholder, "/tweaks/"+hash)
	honestBody, _ := fetch(t, honest, "/tweaks/"+hash)

	positions, err := wire.DecodeResponse(served)
	if err != nil {
		t.Fatal(err)
	}
	honestPositions, err := wire.DecodeResponse(honestBody)
	if err != nil {
		t.Fatal(err)
	}
	leaves := make([]canonical.Leaf, len(honestPositions))
	for i, p := range honestPositions {
		if p.Kind != wire.KindFull {
			t.Fatalf("honest position %d has kind %d", i, p.Kind)
		}
		leaves[i] = p.Leaf
	}
	index := -1
	for i, p := range positions {
		if p.Kind == wire.KindAbsent {
			index = i
		}
	}
	if index != 1 {
		t.Fatalf("the withheld entry sits at position %d, want 1", index)
	}

	f, err := Build(Input{
		Record:  ev,
		Leaves:  leaves,
		Index:   uint32(index),
		Served:  served,
		Receipt: hdr.Get(wire.ReceiptHeader),
		Context: &Context{
			ServerLabel: "withholder",
			ServerURL:   withholder.URL,
			FoundBy:     "other_server",
			WrittenBy:   "canary test",
			WrittenAt:   "2026-10-01T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	out, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	accused := pubOf(t, testKey(4))
	return golden{
		bytes:    out,
		file:     f,
		txid:     b.TxHash().String(),
		accused:  accused,
		height:   2,
		tip:      9,
		fileName: "omission-regtest-2-" + b.TxHash().String()[:8] + "-" + hex.EncodeToString(accused[:4]) + ".json",
	}
}

func TestGoldenRoundTripThroughTheIndexer(t *testing.T) {
	g := buildGolden(t)
	rep := wantChecksOut(t, g.bytes)

	if rep.Accused.Pubkey != hex.EncodeToString(g.accused[:]) {
		t.Errorf("accused %s, want the withholder", rep.Accused.Pubkey)
	}
	if rep.Block.Height != g.height || rep.Missing.TxID != g.txid || rep.Missing.Index != 1 {
		t.Errorf("block %+v missing %+v, want height %d txid %s", rep.Block, rep.Missing, g.height, g.txid)
	}
	if rep.ReceiptTip == nil || rep.ReceiptTip.Height != g.tip {
		t.Errorf("receipt tip %+v, want %d", rep.ReceiptTip, g.tip)
	}
	if got := rep.Checks[stepIndex(t, "window")].Text; !strings.Contains(got, "7 blocks deep") {
		t.Errorf("window text %q", got)
	}
	if g.file.Name() != g.fileName {
		t.Errorf("Name() = %s, want %s", g.file.Name(), g.fileName)
	}

	parsed, err := Parse(g.bytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !reflect.DeepEqual(parsed, g.file) {
		t.Errorf("Parse(Marshal(f)) differs from f:\n%+v\n%+v", parsed, g.file)
	}
}

// formatsDoc is the frozen v1 formats doc, the source of truth for the file
// and report examples.
const formatsDoc = "../docs/design/2026-09-30-v1-formats.md"

// docExample returns the first JSON block under "### Example" in the section
// whose heading starts with heading.
func docExample(t *testing.T, heading string) []byte {
	t.Helper()
	doc, err := os.ReadFile(formatsDoc)
	if err != nil {
		t.Fatalf("read the formats doc: %v", err)
	}
	s := string(doc)
	start := strings.Index(s, "\n"+heading)
	if start < 0 {
		t.Fatalf("no section %q in the formats doc", heading)
	}
	s = s[start+1:]
	if end := strings.Index(s[len(heading):], "\n## "); end >= 0 {
		s = s[:len(heading)+end]
	}
	ex := strings.Index(s, "\n### Example")
	if ex < 0 {
		t.Fatalf("section %q has no example", heading)
	}
	s = s[ex:]
	open := strings.Index(s, "```json\n")
	if open < 0 {
		t.Fatalf("section %q's example has no JSON block", heading)
	}
	s = s[open+len("```json\n"):]
	end := strings.Index(s, "\n```")
	if end < 0 {
		t.Fatalf("section %q's JSON block does not end", heading)
	}
	return []byte(s[:end+1])
}

// The formats doc's evidence example checks out, and verify's report for it
// is the doc's report example, field for field.
func TestFormatsDocExampleChecksOut(t *testing.T) {
	file := docExample(t, "## 6. The evidence file")
	want := docExample(t, "## 7. VerifyReport and error codes")

	rep := wantChecksOut(t, file)
	got, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("the doc's report example is not JSON: %v", err)
	}
	if !reflect.DeepEqual(g, w) {
		pretty, _ := json.MarshalIndent(rep, "", "  ")
		t.Errorf("report differs from the formats doc's example.\ngot:\n%s\nwant:\n%s", pretty, want)
	}

	f, err := Parse(file)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name() != "omission-regtest-205-01982d71-b1070620.json" {
		t.Errorf("Name() = %s, want the doc's example name", f.Name())
	}
}

// verify reads one file and opens no network connection. This test replaces
// every dialer the standard library would use with one that fails and counts,
// then shows verify still checks out and never tried to dial.
func TestVerifyOpensNoConnection(t *testing.T) {
	files := map[string][]byte{
		"golden":      buildGolden(t).bytes, // built before the network goes away
		"doc example": docExample(t, "## 6. The evidence file"),
	}

	var attempts atomic.Int32
	fail := func(ctx context.Context, network, addr string) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("evidence test: this test allows no connections")
	}
	oldTransport, oldResolver := http.DefaultTransport, net.DefaultResolver
	http.DefaultTransport = &http.Transport{DialContext: fail, DialTLSContext: fail}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: fail}
	t.Cleanup(func() {
		http.DefaultTransport, net.DefaultResolver = oldTransport, oldResolver
	})

	// The replacement must bite, or the test below proves nothing.
	if resp, err := http.Get("http://127.0.0.1:9/"); err == nil {
		resp.Body.Close()
		t.Fatal("a request succeeded with the failing transport installed")
	}
	if attempts.Load() == 0 {
		t.Fatal("the failing dialer was never called; the test cannot see a connection")
	}
	attempts.Store(0)

	for name, b := range files {
		t.Run(name, func(t *testing.T) {
			wantChecksOut(t, b)
			if _, err := Parse(b); err != nil {
				t.Fatal(err)
			}
		})
	}
	if n := attempts.Load(); n != 0 {
		t.Errorf("verify tried to open %d connections", n)
	}
}

// A file built from the doc's example parses and writes back to the same
// values, so Build's output and the documented layout agree.
func TestDocExampleRoundTrips(t *testing.T) {
	b := docExample(t, "## 6. The evidence file")
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	out := marshal(t, f)
	var x, y any
	_ = json.Unmarshal(b, &x)
	_ = json.Unmarshal(out, &y)
	if !reflect.DeepEqual(x, y) {
		t.Errorf("round trip changed the doc example:\n%s", out)
	}
	if !bytes.HasSuffix(out, []byte("}\n")) {
		t.Error("Marshal should end the file with a newline")
	}
}
