package main

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/core/coretest"
	"github.com/Sky-walkerX/canary/internal/indexer"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/wire"
	btcwire "github.com/btcsuite/btcd/wire"
)

// act5World is the chain scripts/demo-regtest.sh --act5 builds, without
// bitcoind. An early payment confirms, the chain grows 150 blocks from that
// block, then the main payment confirms in the tip. One server withholds
// both entries. The early block sits 150 blocks below the tip, outside the
// retention window. The main payment's block is the tip, inside it.
type act5World struct {
	rest                      string
	early, recent             *btcwire.MsgTx
	earlyBlk, recentBlk       *btcwire.MsgBlock
	earlyHeight, recentHeight uint32
	honest, withholder        server
}

func newAct5World(t *testing.T) *act5World {
	t.Helper()
	chain := coretest.NewChain(t)
	chain.MineEmpty(2)

	// The script mines 1 block to confirm the early payment, then 149 more.
	early := chain.PayToTaproot(coretest.P2WPKH)
	earlyBlk := chain.Mine(early)
	earlyHeight, _ := chain.Tip()
	chain.MineEmpty(149)

	// The main payment, then 1 block. Nothing is mined after it.
	recent := chain.PayToTaproot(coretest.P2TR)
	recentBlk := chain.Mine(chain.PayToTaproot(coretest.P2TR, coretest.P2WPKH), recent)
	recentHeight, _ := chain.Tip()
	if d := recentHeight - earlyHeight; d < wire.RetentionWindow {
		t.Fatalf("the early block is %d blocks deep; act 5 needs %d or more", d, wire.RetentionWindow)
	}

	rest := coretest.Serve(t, chain)
	hk, wk := testKey(1), testKey(2)
	return &act5World{
		rest:  rest,
		early: early, recent: recent,
		earlyBlk: earlyBlk, recentBlk: recentBlk,
		earlyHeight: earlyHeight, recentHeight: recentHeight,
		honest: server{label: "honest", url: startIndexer(t, rest, hk, nil, nil).URL, pubkey: pubHex(t, hk)},
		withholder: server{
			label:  "withholder",
			url:    startWithholdingIndexer(t, rest, wk, [32]byte(recent.TxHash()), [32]byte(early.TxHash())).URL,
			pubkey: pubHex(t, wk),
		},
	}
}

// startWithholdingIndexer is startIndexer for a server that withholds every
// txid in ids, as canary-indexer does with --withhold-txid repeated.
func startWithholdingIndexer(t testing.TB, rest string, key [32]byte, ids ...[32]byte) *httptest.Server {
	t.Helper()
	client, err := core.New(rest, nil)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := indexer.New(indexer.Config{
		Core:          client,
		Key:           key,
		WithholdTxIDs: ids,
		Software:      indexer.Software{Name: "canary-indexer", Version: "0.1.0", Build: "test"},
		Logger:        log.New(io.Discard, "", 0),
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

// checkArgs builds a canary check command line that writes into dir.
func (w *act5World) checkArgs(dir string, servers []server, from, to uint32, extra ...string) []string {
	args := []string{"check"}
	for _, s := range servers {
		args = append(args, "--indexer", s.url+"="+s.label, "--pubkey", s.label+"="+s.pubkey)
	}
	args = append(args, "--core-rest", w.rest,
		"--from", itoa(from), "--to", itoa(to),
		"--state", filepath.Join(dir, "state.json"), "--evidence-dir", filepath.Join(dir, "evidence"))
	return append(args, extra...)
}

func itoa(h uint32) string { return strconv.FormatUint(uint64(h), 10) }

// Act 5 of the demo, in process. The same server withholds two entries with
// the same switch. Depth alone decides what Canary may say about each.
//
// The main check runs as scripts/demo-regtest.sh runs it: both servers, the
// main payment declared, every block. It names the withholder for the recent
// entry, absent inside the window. The honest server fills the early gap.
//
// The act-5 check pins only the withholder, declares nothing, and covers the
// early block alone. Nobody can supply the entry, and the server's signed
// tip puts the block outside the window. So the block reads Can't be
// checked, reason gap_unfilled, and the run accuses nobody.
func TestAct5OldGapCantBeCheckedRecentGapIsWithheld(t *testing.T) {
	w := newAct5World(t)

	t.Run("main check names the withholder", func(t *testing.T) {
		dir := t.TempDir()
		r := runCLI(t, w.checkArgs(dir, []server{w.honest, w.withholder}, 0, w.recentHeight,
			"--expect", w.recent.TxHash().String()+"@"+w.recentBlk.BlockHash().String())...)
		wantExit(t, r, 1)
		f := loadState(t, filepath.Join(dir, "state.json"))

		b := blockAt(t, f, w.recentHeight)
		if b.State != state.Compromised || b.Reason != state.AbsentInWindow {
			t.Errorf("main payment's block = %s/%s, want compromised/absent_in_window", b.State, b.Reason)
		}
		if len(f.Findings) != 1 {
			t.Fatalf("findings = %+v, want one", f.Findings)
		}
		x := f.Findings[0]
		if x.Kind != state.KindWithheld || x.Reason != state.AbsentInWindow || len(x.Servers) != 1 ||
			x.Servers[0].Label != "withholder" || x.Block.Height != w.recentHeight ||
			x.Txid == nil || *x.Txid != w.recent.TxHash().String() || x.Evidence == nil || !x.Provable {
			t.Fatalf("finding = %+v, want a provable absent_in_window finding against the withholder", x)
		}

		// The script looks for the evidence file by this name.
		txid, pub := w.recent.TxHash().String(), w.withholder.pubkey
		name := "omission-regtest-" + itoa(w.recentHeight) + "-" + txid[:8] + "-" + pub[:8] + ".json"
		if *x.Evidence != name {
			t.Errorf("evidence file %s, the script expects %s", *x.Evidence, name)
		}
		rep, err := evidence.Verify(readFile(t, filepath.Join(dir, "evidence", name)))
		if err != nil || rep.Code != evidence.CodeOK {
			t.Errorf("the evidence file does not check out: %v %+v", err, rep)
		}

		// The early gap is outside the window, and the honest list fills it.
		e := blockAt(t, f, w.earlyHeight)
		if e.State != state.Verified || e.Reason != state.RecordsAgree {
			t.Errorf("early block = %s/%s, want verified/records_agree", e.State, e.Reason)
		}
		if s := serverIn(t, e, "withholder"); s.State != state.Resolved || s.Reason != state.FilledFromServer {
			t.Errorf("early block, withholder = %s/%s, want resolved/filled_from_server", s.State, s.Reason)
		}
	})

	t.Run("act-5 check reads Can't be checked", func(t *testing.T) {
		dir := t.TempDir()
		r := runCLI(t, w.checkArgs(dir, []server{w.withholder}, w.earlyHeight, w.earlyHeight)...)
		wantExit(t, r, 0)
		f := loadState(t, filepath.Join(dir, "state.json"))

		b := blockAt(t, f, w.earlyHeight)
		if b.Hash != w.earlyBlk.BlockHash().String() {
			t.Fatalf("block %d is %s, want the early payment's block %s", b.Height, b.Hash, w.earlyBlk.BlockHash())
		}
		if b.State != state.Unresolvable || b.Reason != state.GapUnfilled {
			t.Errorf("early block = %s/%s, want unresolvable/gap_unfilled", b.State, b.Reason)
		}
		s := serverIn(t, b, "withholder")
		if s.State != state.Unresolvable || s.Reason != state.GapUnfilled || s.Filled != 0 ||
			s.Positions == nil || s.Positions.Absent != 1 || !s.Signed || s.Tip == nil || s.Tip.Height != w.recentHeight {
			t.Errorf("withholder = %+v, want unresolvable/gap_unfilled from a signed list with one absent position", s)
		}
		if len(f.Coverage) != 1 || f.Coverage[0].State != state.Unresolvable || f.Coverage[0].Reason != state.GapUnfilled {
			t.Errorf("coverage = %+v, want one Can't be checked range", f.Coverage)
		}

		// Not an accusation, and not a warning either.
		if len(f.Findings) != 0 {
			t.Errorf("findings = %+v, want none", f.Findings)
		}
		if entries, err := os.ReadDir(filepath.Join(dir, "evidence")); err == nil && len(entries) > 0 {
			t.Errorf("the run wrote %d evidence files, want none", len(entries))
		}
		if !strings.Contains(r.stdout, "1 Can't be checked") || strings.Contains(r.stdout, "Data withheld") {
			t.Errorf("stdout does not read one Can't be checked block and nothing withheld:\n%s", r)
		}
	})

	// The contrast. The same single pin, with nothing declared, over the main
	// payment's block: inside the window the same gap is an accusation.
	t.Run("one server, recent gap is withheld", func(t *testing.T) {
		dir := t.TempDir()
		r := runCLI(t, w.checkArgs(dir, []server{w.withholder}, w.recentHeight, w.recentHeight)...)
		wantExit(t, r, 1)
		f := loadState(t, filepath.Join(dir, "state.json"))

		b := blockAt(t, f, w.recentHeight)
		if b.State != state.Compromised || b.Reason != state.AbsentInWindow {
			t.Errorf("main payment's block = %s/%s, want compromised/absent_in_window", b.State, b.Reason)
		}
		if len(f.Findings) != 1 || f.Findings[0].Kind != state.KindWithheld || f.Findings[0].Reason != state.AbsentInWindow {
			t.Errorf("findings = %+v, want one absent_in_window finding", f.Findings)
		}
	})
}
