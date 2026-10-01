package main

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/core/coretest"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
	"github.com/Sky-walkerX/canary/wire"
	btcwire "github.com/btcsuite/btcd/wire"
)

var hexKey = strings.Repeat("ab", 32)

func TestCheckUsageErrors(t *testing.T) {
	good := pubHex(t, testKey(1))
	core := "--core-rest=http://127.0.0.1:1/rest"
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no server", []string{core}, wording.CheckNoIndexer},
		{"no pin", []string{"--indexer", "http://h:1=honest", core}, wording.CheckMissingPin("honest")},
		{"bad indexer", []string{"--indexer", "honest", core}, wording.CheckBadIndexer("honest")},
		{"not http", []string{"--indexer", "ftp://h=honest", core}, wording.CheckBadIndexer("ftp://h=honest")},
		{"bad label", []string{"--indexer", "http://h:1=Honest", "--pubkey", "Honest=" + good, core}, wording.CheckBadLabel("Honest")},
		{"long label", []string{"--indexer", "http://h:1=" + strings.Repeat("a", 33), core}, wording.CheckBadLabel(strings.Repeat("a", 33))},
		{"label twice", []string{"--indexer", "http://h:1=a", "--indexer", "http://h:2=a", core}, wording.CheckDuplicateLabel("a")},
		{"pin form", []string{"--indexer", "http://h:1=a", "--pubkey", "a", core}, wording.CheckBadPubkeyFlag("a")},
		{"pin hex", []string{"--indexer", "http://h:1=a", "--pubkey", "a=xyz", core}, wording.CheckBadPubkey("a")},
		{"pin uppercase", []string{"--indexer", "http://h:1=a", "--pubkey", "a=" + strings.ToUpper(good), core}, wording.CheckBadPubkey("a")},
		{"pin off the curve", []string{"--indexer", "http://h:1=a", "--pubkey", "a=" + strings.Repeat("ff", 32), core}, wording.CheckBadPubkey("a")},
		{"pin unknown label", []string{"--indexer", "http://h:1=a", "--pubkey", "a=" + good, "--pubkey", "b=" + good, core}, wording.CheckPubkeyUnknownLabel("b")},
		{"pinned twice", []string{"--indexer", "http://h:1=a", "--pubkey", "a=" + good, "--pubkey", "a=none", core}, wording.CheckDuplicatePubkey("a")},
		{"no core", []string{"--indexer", "http://h:1=a", "--pubkey", "a=" + good}, wording.CheckNoCore},
		{"bad core", []string{"--indexer", "http://h:1=a", "--pubkey", "a=" + good, "--core-rest", "nope"}, wording.CheckBadCore("nope")},
		{"bad from", []string{"--indexer", "http://h:1=a", "--pubkey", "a=none", core, "--from", "-1"}, wording.CheckBadHeight("--from", "-1")},
		{"bad to", []string{"--indexer", "http://h:1=a", "--pubkey", "a=none", core, "--to", "x"}, wording.CheckBadHeight("--to", "x")},
		{"bad expect", []string{"--indexer", "http://h:1=a", "--pubkey", "a=none", core, "--expect", "abc"}, wording.CheckBadExpect("abc")},
		{"expect twice", []string{"--indexer", "http://h:1=a", "--pubkey", "a=none", core, "--expect", hexKey, "--expect", hexKey + "@" + hexKey}, wording.CheckDuplicateExpect(hexKey)},
		{"stray argument", []string{"--indexer", "http://h:1=a", "--pubkey", "a=none", core, "extra"}, wording.CLIUnexpectedArgument("extra")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runCLI(t, append([]string{"check"}, tt.args...)...)
			wantExit(t, r, 2)
			if !strings.Contains(r.stderr, tt.want) {
				t.Errorf("stderr lacks %q:\n%s", tt.want, r)
			}
			if !strings.Contains(r.stderr, wording.CLICommandHelpHint("check")) {
				t.Errorf("a usage error should point at --help:\n%s", r)
			}
		})
	}
}

// Canary splits --indexer on the last =, so a URL may carry = itself.
func TestCheckSplitsIndexerOnTheLastEquals(t *testing.T) {
	cfg, msg := parseCheck([]string{"--indexer", "http://h:1/x?a=b=honest", "--pubkey", "honest=none", "--core-rest", "http://c/rest"})
	if msg != "" {
		t.Fatal(msg)
	}
	if len(cfg.servers) != 1 || cfg.servers[0].url != "http://h:1/x?a=b" || cfg.servers[0].label != "honest" {
		t.Errorf("servers = %+v", cfg.servers)
	}
}

func TestCheckNeedsAUsableCore(t *testing.T) {
	w := newWorld(t)
	s := server{label: "a", url: "http://127.0.0.1:1", pubkey: "none"}

	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	r := runCLI(t, "check", "--indexer", s.url+"=a", "--pubkey", "a=none", "--core-rest", closed.URL+"/rest",
		"--state", w.statePath(), "--evidence-dir", w.evidenceDir())
	wantExit(t, r, 5)
	if !strings.Contains(r.stderr, wording.CheckCoreUnreachable(closed.URL+"/rest")) {
		t.Errorf("stderr lacks the Core failure:\n%s", r)
	}

	w.chain.SetInitialBlockDownload(true)
	r = runCLI(t, w.args([]server{s})...)
	wantExit(t, r, 5)
	if !strings.Contains(r.stderr, wording.CheckCoreSyncing) {
		t.Errorf("stderr lacks the sync notice:\n%s", r)
	}
	if _, err := os.Stat(w.statePath()); !os.IsNotExist(err) {
		t.Error("a failed run wrote a state file")
	}
}

func TestCheckRangeErrors(t *testing.T) {
	w := newWorld(t)
	s := server{label: "a", url: "http://127.0.0.1:1", pubkey: "none"}
	r := runCLI(t, w.args([]server{s}, "--to", "99")...)
	wantExit(t, r, 2)
	if !strings.Contains(r.stderr, wording.CheckRangeAboveTip(99, w.tip)) {
		t.Errorf("stderr:\n%s", r)
	}
	r = runCLI(t, w.args([]server{s}, "--from", "5", "--to", "2")...)
	wantExit(t, r, 2)
	if !strings.Contains(r.stderr, wording.CheckRangeBackwards(5, 2)) {
		t.Errorf("stderr:\n%s", r)
	}
}

func TestCheckRefusesAStateFileItWouldLose(t *testing.T) {
	w := newWorld(t)
	s := w.honest(t, "honest", 1)

	otherNet := loadState(t, exampleState)
	otherNet.Network = state.Network{Name: "main", Magic: state.MagicMain}
	b, err := state.Marshal(otherNet)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, body, want string
	}{
		{"unreadable", "{broken", wording.CheckStateUnreadable(w.statePath())},
		{"newer", `{"format":"canary-state/2"}`, wording.CheckStateNewer(w.statePath(), "canary-state/2")},
		{"other network", string(b), wording.CheckStateOtherNetwork(w.statePath(), "main", "regtest")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(w.statePath(), []byte(tt.body), 0o644); err != nil {
				t.Fatal(err)
			}
			r := runCLI(t, w.args([]server{s})...)
			wantExit(t, r, 3)
			if !strings.Contains(r.stderr, tt.want) {
				t.Errorf("stderr lacks %q:\n%s", tt.want, r)
			}
			if got := string(readFile(t, w.statePath())); got != tt.body {
				t.Error("canary check overwrote a state file it refused")
			}
		})
	}
}

// One honest server alone: every block reads Checked on its own record, and
// nothing is found.
func TestCheckOneHonestServer(t *testing.T) {
	w := newWorld(t)
	s := w.honest(t, "honest", 1)
	r := runCLI(t, w.args([]server{s})...)
	wantExit(t, r, 0)

	f := loadState(t, w.statePath())
	if f.Checked.From != 0 || f.Checked.To != w.tip || len(f.Blocks) != int(w.tip)+1 {
		t.Fatalf("checked %+v with %d blocks, want 0–%d", f.Checked, len(f.Blocks), w.tip)
	}
	if f.Counts.Verified != w.tip+1 || len(f.Findings) != 0 {
		t.Errorf("counts %+v findings %d, want all Checked and none found", f.Counts, len(f.Findings))
	}
	for _, b := range f.Blocks {
		if b.State != state.Verified || b.Reason != state.OwnRecord {
			t.Errorf("block %d = %s/%s, want verified/own_record", b.Height, b.State, b.Reason)
		}
	}
	srv := f.Servers[0]
	if !srv.PublishesRecords || !srv.SignsReceipts || !srv.Reachable || srv.Tip == nil || !srv.Tip.Signed ||
		srv.Tip.Height != w.tip || srv.Policy == nil || srv.Policy.Signed || srv.Error != nil {
		t.Errorf("server = %+v", srv)
	}
	if f.ChainTip.Height != w.tip || f.ChainTip.Source != "core" || f.Network.Name != "regtest" {
		t.Errorf("chain tip %+v network %+v", f.ChainTip, f.Network)
	}
	if !filepath.IsAbs(f.EvidenceDir) {
		t.Errorf("evidence_dir %q is not absolute", f.EvidenceDir)
	}
	if !strings.Contains(r.stdout, "Last check ") || !strings.Contains(r.stdout, wording.CheckSaved(w.statePath())) {
		t.Errorf("stdout lacks the summary:\n%s", r)
	}
}

// A server pinned as none signs nothing, so its results read Not checked,
// and the other server still decides each block.
func TestCheckServerPinnedAsNone(t *testing.T) {
	w := newWorld(t)
	honest := w.honest(t, "honest", 1)
	other := w.honest(t, "plain", 2)
	other.pubkey = "none"
	r := runCLI(t, w.args([]server{honest, other})...)
	wantExit(t, r, 0)
	f := loadState(t, w.statePath())
	for _, b := range f.Blocks {
		p := serverIn(t, b, "plain")
		if p.State != state.Unverified || p.Reason != state.NoRecords || b.State != state.Verified {
			t.Errorf("block %d: plain %s/%s, block %s", b.Height, p.State, p.Reason, b.State)
		}
	}
	if f.Servers[1].Pubkey != nil || f.Servers[1].PublishesRecords {
		t.Errorf("plain = %+v, want no pubkey and no records", f.Servers[1])
	}
}

// Two honest servers sign the same roots, so every block reads Checked with
// records_agree.
func TestCheckTwoHonestServersAgree(t *testing.T) {
	w := newWorld(t)
	r := runCLI(t, w.args([]server{w.honest(t, "one", 1), w.honest(t, "two", 2)})...)
	wantExit(t, r, 0)
	for _, b := range loadState(t, w.statePath()).Blocks {
		if b.State != state.Verified || b.Reason != state.RecordsAgree {
			t.Errorf("block %d = %s/%s, want verified/records_agree", b.Height, b.State, b.Reason)
		}
	}
}

func TestCheckUnreachableServer(t *testing.T) {
	w := newWorld(t)
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	dead := server{label: "gone", url: gone.URL, pubkey: pubHex(t, testKey(9))}
	r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), dead})...)
	wantExit(t, r, 0)
	f := loadState(t, w.statePath())
	if f.Servers[1].Reachable || f.Servers[1].Error == nil {
		t.Fatalf("gone = %+v, want unreachable with an error", f.Servers[1])
	}
	// The state file keeps the plain sentence. The Go error's text goes to
	// the terminal, under the sentence.
	if e := *f.Servers[1].Error; e != wording.ServerNotAsked(maxDownStreak) {
		t.Errorf("error = %q, want the plain sentence %q", e, wording.ServerNotAsked(maxDownStreak))
	}
	if !strings.Contains(r.stderr, wording.CheckServerLastError("gone", wording.ServerNotAsked(maxDownStreak))) ||
		!strings.Contains(r.stderr, wording.CLIDetails("canary: GET /commitment/")) {
		t.Errorf("stderr lacks the server's last error and its cause:\n%s", r)
	}
	b := blockAt(t, f, w.height)
	if g := serverIn(t, b, "gone"); g.State != state.Unverified || g.Reason != state.ServerUnreachable {
		t.Errorf("gone = %s/%s, want unverified/server_unreachable", g.State, g.Reason)
	}
}

// An --indexer URL that is not a v1 server stops the run with exit code 5
// and saves nothing, even the honest server's results. Nothing it sends
// verifies under the pin, and its /info is not canary-info/1.
func TestCheckServerThatIsNotAnIndexer(t *testing.T) {
	w := newWorld(t)
	web := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(web.Close)
	for _, url := range []string{strings.TrimSuffix(w.rest, "/rest"), web.URL} {
		wrong := server{label: "wrong", url: url, pubkey: pubHex(t, testKey(9))}
		r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), wrong})...)
		wantExit(t, r, 5)
		if !strings.Contains(r.stderr, wording.CheckServerUnusable("wrong", wrong.url)) ||
			!strings.Contains(r.stderr, wording.CLIDetails("canary: GET /info")) {
			t.Errorf("%s: stderr lacks the unusable server and its cause:\n%s", url, r)
		}
		if _, err := os.Stat(w.statePath()); !os.IsNotExist(err) {
			t.Errorf("%s: a stopped run wrote a state file: %v", url, err)
		}
	}
}

// The withholder is named from its own signatures. The honest server's list
// supplies the entry, and the evidence file checks out.
func TestCheckNamesTheWithholder(t *testing.T) {
	w := newWorld(t)
	r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), w.withholder(t, "withholder", 2, nil)})...)
	wantExit(t, r, 1)

	f := loadState(t, w.statePath())
	b := blockAt(t, f, w.height)
	if b.State != state.Compromised || b.Reason != state.AbsentInWindow {
		t.Errorf("block = %s/%s", b.State, b.Reason)
	}
	if len(f.Findings) != 1 {
		t.Fatalf("findings = %+v, want one", f.Findings)
	}
	x := f.Findings[0]
	if x.Kind != state.KindWithheld || x.Servers[0].Label != "withholder" || x.Txid == nil || *x.Txid != w.txid() ||
		x.Position == nil || *x.Position != 1 || x.Evidence == nil || !x.Provable {
		t.Errorf("finding = %+v", x)
	}
	ev := readFile(t, filepath.Join(w.evidenceDir(), *x.Evidence))
	rep, err := evidence.Verify(ev)
	if err != nil || rep.Code != evidence.CodeOK {
		t.Fatalf("the evidence file does not check out: %v %+v", err, rep)
	}
	var file evidence.File
	_ = json.Unmarshal(ev, &file)
	if file.Context == nil || file.Context.FoundBy != "other_server" || file.Context.ServerLabel != "withholder" {
		t.Errorf("context = %+v", file.Context)
	}
	if !strings.Contains(r.stdout, "withholder left out an entry it had signed for: block 3") {
		t.Errorf("stdout lacks the finding:\n%s", r)
	}
}

// With no second server, a declared payment supplies the left-out entry.
func TestCheckDeclaredPaymentFillsTheGap(t *testing.T) {
	w := newWorld(t)
	r := runCLI(t, w.args([]server{w.withholder(t, "withholder", 2, nil)}, "--expect", w.txid()+"@"+w.blockHash())...)
	wantExit(t, r, 1)
	f := loadState(t, w.statePath())
	x := f.Findings[0]
	if x.Reason != state.AbsentInWindow || x.Evidence == nil || !x.Provable || x.Txid == nil || *x.Txid != w.txid() {
		t.Fatalf("finding = %+v", x)
	}
	var file evidence.File
	_ = json.Unmarshal(readFile(t, filepath.Join(w.evidenceDir(), *x.Evidence)), &file)
	if file.Context.FoundBy != "expected_payment" {
		t.Errorf("found_by = %q, want expected_payment", file.Context.FoundBy)
	}
	p := f.ExpectedPayments[0]
	if p.Txid != w.txid() || p.Block == nil || p.Block.Height != w.height || p.Outcome != "withheld" ||
		len(p.Servers) != 1 || p.Servers[0].Outcome != "withheld" {
		t.Errorf("payment = %+v", p)
	}
}

func TestCheckExpectErrors(t *testing.T) {
	w := newWorld(t)
	s := w.honest(t, "honest", 1)
	other := w.chain.Block(1).BlockHash().String()

	r := runCLI(t, w.args([]server{s}, "--expect", w.txid()+"@"+other)...)
	wantExit(t, r, 2)
	if !strings.Contains(r.stderr, wording.CheckExpectNotInBlock(w.txid(), other)) {
		t.Errorf("stderr:\n%s", r)
	}

	r = runCLI(t, w.args([]server{s}, "--expect", w.txid()+"@"+hexKey)...)
	wantExit(t, r, 2)
	if !strings.Contains(r.stderr, wording.CheckExpectBlockUnknown(hexKey)) {
		t.Errorf("stderr:\n%s", r)
	}

	r = runCLI(t, w.args([]server{s}, "--from", "4", "--expect", w.txid()+"@"+w.blockHash())...)
	wantExit(t, r, 2)
	if !strings.Contains(r.stderr, wording.CheckExpectNotChecked(w.txid(), w.blockHash(), 4, w.tip)) {
		t.Errorf("stderr:\n%s", r)
	}

	// A bare txid needs Core's transaction index.
	r = runCLI(t, w.args([]server{s}, "--expect", w.txid())...)
	wantExit(t, r, 5)
	if !strings.Contains(r.stderr, wording.CheckExpectNotFound(w.txid())) {
		t.Errorf("stderr:\n%s", r)
	}
	w.chain.SetTxIndex(true)
	r = runCLI(t, w.args([]server{s}, "--expect", w.txid())...)
	wantExit(t, r, 0)
	p := loadState(t, w.statePath()).ExpectedPayments[0]
	if p.Outcome != "found" || p.Block == nil || p.Block.Hash != w.blockHash() {
		t.Errorf("payment = %+v, want found in its block", p)
	}
}

// A transaction with no taproot output has no entry, so there is nothing to
// check.
func TestCheckPaymentWithNoEntry(t *testing.T) {
	chain := coretest.NewChain(t)
	chain.MineEmpty(1)
	plain := chain.PayToWitnessKeyHash(coretest.P2WPKH)
	blk := chain.Mine(plain)
	w := &world{chain: chain, rest: coretest.Serve(t, chain), block: blk, height: 2, target: plain, dir: t.TempDir()}
	r := runCLI(t, w.args([]server{w.honest(t, "honest", 1)}, "--expect", w.txid()+"@"+w.blockHash())...)
	wantExit(t, r, 0)
	p := loadState(t, w.statePath()).ExpectedPayments[0]
	if p.Outcome != "not_eligible" || len(p.Servers) != 0 {
		t.Errorf("payment = %+v, want not_eligible", p)
	}
}

// Findings carry into later runs. A later run keeps first_seen, moves
// last_seen, and leaves an evidence file with a receipt alone. A chain that
// Core no longer knows drops its findings.
func TestCheckCarriesFindingsForward(t *testing.T) {
	w := newWorld(t)
	servers := []server{w.honest(t, "honest", 1), w.withholder(t, "withholder", 2, nil)}
	t1 := time.Date(2026, 10, 3, 8, 0, 0, 0, time.UTC)
	fixClock(t, t1)
	wantExit(t, runCLI(t, w.args(servers)...), 1)
	first := loadState(t, w.statePath()).Findings[0]
	evPath := filepath.Join(w.evidenceDir(), *first.Evidence)
	before := readFile(t, evPath)

	t2 := t1.Add(time.Hour)
	fixClock(t, t2)
	wantExit(t, runCLI(t, w.args(servers)...), 1)
	f := loadState(t, w.statePath())
	if len(f.Findings) != 1 {
		t.Fatalf("findings = %+v, want the same one", f.Findings)
	}
	got := f.Findings[0]
	if got.ID != first.ID || !got.FirstSeen.Equal(t1) || !got.LastSeen.Equal(t2) {
		t.Errorf("finding = %+v, want first_seen %s and last_seen %s", got, t1, t2)
	}
	if string(readFile(t, evPath)) != string(before) {
		t.Error("a later run rewrote an evidence file that carries a receipt")
	}

	// A new chain: Core no longer knows the finding's block.
	w2 := newWorldWithPrefix(t, 3)
	w2.dir = w.dir
	r := runCLI(t, w2.args([]server{w2.honest(t, "honest", 1)})...)
	wantExit(t, r, 0)
	if !strings.Contains(r.stdout, wording.CheckDroppedFinding(first.ID, first.Block.Hash)) {
		t.Errorf("stdout lacks the dropped finding:\n%s", r)
	}
	if n := len(loadState(t, w.statePath()).Findings); n != 0 {
		t.Errorf("%d findings left after the chain was replaced", n)
	}
	if _, err := os.Stat(evPath); err != nil {
		t.Errorf("the evidence file must stay on disk: %v", err)
	}
}

// newWorldWithPrefix builds a world whose blocks differ from newWorld's,
// because it mines extra blocks first.
func newWorldWithPrefix(t testing.TB, extra int) *world {
	t.Helper()
	chain := coretest.NewChain(t)
	chain.MineEmpty(2 + extra)
	pay := chain.PayToTaproot(coretest.P2WPKH)
	blk := chain.Mine(pay)
	tip, _ := chain.Tip()
	return &world{chain: chain, rest: coretest.Serve(t, chain), block: blk, height: tip, target: pay, tip: tip, dir: t.TempDir()}
}

// A list with no receipt proves inclusion only. A later run that gets a
// receipt replaces the file and makes the finding provable.
func TestCheckUpgradesEvidenceWhenAReceiptArrives(t *testing.T) {
	w := newWorld(t)
	honest := w.honest(t, "honest", 1)
	unsigned := w.withholder(t, "withholder", 2, stripReceipts)
	fixClock(t, time.Date(2026, 10, 3, 8, 0, 0, 0, time.UTC))
	wantExit(t, runCLI(t, w.args([]server{honest, unsigned})...), 1)
	f := loadState(t, w.statePath())
	x := f.Findings[0]
	if x.Evidence == nil || x.Provable || f.Servers[1].SignsReceipts {
		t.Fatalf("finding = %+v, server = %+v; want an inclusion-only file", x, f.Servers[1])
	}
	rep, _ := evidence.Verify(readFile(t, filepath.Join(w.evidenceDir(), *x.Evidence)))
	if rep.Code != evidence.CodeInclusionOnly {
		t.Fatalf("report code %s, want inclusion_only", rep.Code)
	}

	signed := w.withholder(t, "withholder", 2, nil)
	fixClock(t, time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC))
	wantExit(t, runCLI(t, w.args([]server{honest, signed})...), 1)
	y := loadState(t, w.statePath()).Findings[0]
	if y.ID != x.ID || !y.Provable || y.Evidence == nil || *y.Evidence != *x.Evidence {
		t.Errorf("finding = %+v, want the same finding made provable", y)
	}
	rep, _ = evidence.Verify(readFile(t, filepath.Join(w.evidenceDir(), *y.Evidence)))
	if rep.Code != evidence.CodeOK {
		t.Errorf("report code %s after the receipt arrived, want ok", rep.Code)
	}
}

// answerOn serves one error in the v1 error shape for paths with prefix,
// and passes every other request to next.
func answerOn(prefix string, status int, code string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, prefix) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":{"code":"` + code + `","message":"test","error_id":null}}`))
		})
	}
}

// A v1 server never answers Canary's requests with not_found,
// bad_block_hash or unsupported_parameter. From a server whose /info
// answered as canary-info/1, such an answer is the server refusing one
// block, so Canary records it like an outage and the run goes on. That
// holds even when no record of its verifies. A refused record reads Not
// checked, and a list refused after a valid record reads Can't be checked.
// The errors a v1 server does give, unknown_block and not_ready, are always
// data.
func TestCheckServerAnsweringOutsideTheAPI(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		status int
		code   string
		exit   int
		reason state.Reason // odd's reason at the payment block
	}{
		{"every record not_found", "/commitment/", http.StatusNotFound, "not_found", 0, state.ServerUnreachable},
		// A list refused inside the window raises a warning, and warnings
		// count as findings for the exit code.
		{"list bad_block_hash", "/tweaks/", http.StatusBadRequest, "bad_block_hash", 1, state.ListNotServed},
		{"list unsupported_parameter", "/tweaks/", http.StatusBadRequest, "unsupported_parameter", 1, state.ListNotServed},
		{"list not_found", "/tweaks/", http.StatusNotFound, "not_found", 1, state.ListNotServed},
		{"record not_ready", "/commitment/", http.StatusServiceUnavailable, "not_ready", 0, state.ServerUnreachable},
		{"list unknown_block", "/tweaks/", http.StatusNotFound, "unknown_block", 1, state.ListNotServed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			k := testKey(4)
			odd := server{label: "odd", url: startIndexer(t, w.rest, k, nil, answerOn(tt.prefix, tt.status, tt.code)).URL, pubkey: pubHex(t, k)}
			r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), odd})...)
			wantExit(t, r, tt.exit)
			f := loadState(t, w.statePath())
			o := serverIn(t, blockAt(t, f, w.height), "odd")
			if o.Reason != tt.reason || f.Servers[1].Error == nil || !f.Servers[1].Reachable {
				t.Errorf("odd = %s/%s error %v reachable %v, want %s with an error, reachable",
					o.State, o.Reason, f.Servers[1].Error, f.Servers[1].Reachable, tt.reason)
			}
			// The other server's blocks are unaffected.
			for _, b := range f.Blocks {
				if h := serverIn(t, b, "honest"); h.State != state.Verified || b.State != state.Verified {
					t.Errorf("block %d: honest %s, block %s, want both verified", b.Height, h.State, b.State)
				}
			}
		})
	}
}

// both puts outer in front of inner.
func both(outer, inner func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return outer(inner(next)) }
}

// A withholder cannot stop the run that would name it by answering a
// request with an error a v1 server never gives Canary. Once one of its
// records verifies under its pin, the --indexer URL is proven right, and
// Canary records every such answer like an outage. Here it refuses one
// block's list with not_found: that block reads Can't be checked for it,
// with a warning naming it, and the run still saves the evidence it found in
// another block. That holds whatever its /info does, because a server that
// leaves /info unanswered or answers it outside the API gains nothing: its
// policy reads as not declared, and the run goes on.
func TestCheckWithholderCannotStopTheRun(t *testing.T) {
	tests := []struct {
		name     string
		info     func(http.Handler) http.Handler // nil: /info answers
		answered bool
		infoErr  string // the /info error the terminal must print
	}{
		{"/info answers", nil, true, ""},
		{"/info off the API", answerOn("/info", http.StatusNotFound, "not_found"), false, wording.ServerInfoUnusable},
		{"/info gave no answer", dropOn("/info"), false, wording.ServerInfoFailed},
		{"/info internal", answerOn("/info", http.StatusInternalServerError, "internal"), false, wording.ServerInfoFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := coretest.NewChain(t)
			chain.MineEmpty(2)
			victim := chain.PayToTaproot(coretest.P2WPKH)
			refused := chain.Mine(victim) // height 3
			caught := chain.PayToTaproot(coretest.P2TR, coretest.P2WPKH)
			withheld := chain.Mine(caught) // height 4
			chain.MineEmpty(3)
			tip, _ := chain.Tip()
			w := &world{chain: chain, rest: coretest.Serve(t, chain), block: withheld, height: 4, target: caught, tip: tip, dir: t.TempDir()}

			refuse := answerOn("/tweaks/"+refused.BlockHash().String(), http.StatusNotFound, "not_found")
			if tt.info != nil {
				refuse = both(tt.info, refuse)
			}
			servers := []server{w.honest(t, "honest", 1), w.withholder(t, "withholder", 2, refuse)}
			victimID := victim.TxHash().String()
			r := runCLI(t, w.args(servers, "--expect", victimID+"@"+refused.BlockHash().String())...)
			wantExit(t, r, 1)

			f := loadState(t, w.statePath())
			if len(f.Blocks) != int(tip)+1 {
				t.Fatalf("%d blocks saved, want %d", len(f.Blocks), tip+1)
			}

			// The refused list: Can't be checked for the withholder, with the
			// list_not_served warning naming it. The honest server still
			// decides the block.
			b := blockAt(t, f, 3)
			if s := serverIn(t, b, "withholder"); s.State != state.Unresolvable || s.Reason != state.ListNotServed {
				t.Errorf("block 3: withholder = %s/%s, want unresolvable/list_not_served", s.State, s.Reason)
			}
			if b.State != state.Verified || b.Reason != state.RecordsAgree {
				t.Errorf("block 3 = %s/%s, want verified/records_agree from the honest server", b.State, b.Reason)
			}

			// Every block still reads Checked for the honest server.
			for _, b := range f.Blocks {
				if h := serverIn(t, b, "honest"); h.State != state.Verified {
					t.Errorf("block %d: honest = %s/%s, want verified", b.Height, h.State, h.Reason)
				}
			}

			var warned, accused *state.Finding
			for i := range f.Findings {
				x := &f.Findings[i]
				switch {
				case x.Kind == state.KindWarning && x.Reason == state.ListNotServed && x.Block.Height == 3:
					warned = x
				case x.Kind == state.KindWithheld && x.Block.Height == 4:
					accused = x
				default:
					t.Errorf("unexpected finding %+v", *x)
				}
			}
			if warned == nil || warned.Servers[0].Label != "withholder" {
				t.Errorf("findings = %+v, want a list_not_served warning naming the withholder at block 3", f.Findings)
			}
			if accused == nil || accused.Servers[0].Label != "withholder" || accused.Reason != state.AbsentInWindow ||
				accused.Evidence == nil || !accused.Provable {
				t.Fatalf("findings = %+v, want a provable absent_in_window finding against the withholder at block 4", f.Findings)
			}
			rep, err := evidence.Verify(readFile(t, filepath.Join(w.evidenceDir(), *accused.Evidence)))
			if err != nil || rep.Code != evidence.CodeOK {
				t.Errorf("the evidence file does not check out: %v %+v", err, rep)
			}

			// The state file keeps the last error. A failed /info shows as
			// not reachable, with no policy, and stderr names it on the way.
			wh := f.Servers[1]
			if e := wh.Error; e == nil || *e != wording.ServerListUnanswered(3) {
				t.Errorf("withholder error = %v, want %q", e, wording.ServerListUnanswered(3))
			}
			if !wh.PublishesRecords || !wh.SignsReceipts || wh.Reachable != tt.answered || (wh.Policy != nil) != tt.answered {
				t.Errorf("withholder = %+v, want records and receipts, reachable and a policy %v", wh, tt.answered)
			}
			if strings.Contains(r.stderr, wording.CheckServerUnusable("withholder", servers[1].url)) {
				t.Errorf("the run called the withholder unusable:\n%s", r)
			}
			// The list error replaced the /info error as the last error, so
			// the terminal prints the /info error on a line of its own.
			if n := strings.Count(r.stderr, "Its /info"); tt.infoErr == "" && n != 0 ||
				tt.infoErr != "" && (n != 1 || !strings.Contains(r.stderr, "canary check: "+wording.CheckServerInfoError("withholder", tt.infoErr)+"\n")) {
				t.Errorf("stderr should say %q once:\n%s", tt.infoErr, r)
			}

			// The tripwire cannot read the refused list, so the payment is
			// unresolvable for the withholder, not found and not withheld.
			p := f.ExpectedPayments[0]
			if p.Txid != victimID || p.Outcome != "unresolvable" || len(p.Servers) != 2 ||
				p.Servers[0].Outcome != "found" || p.Servers[1].Outcome != "unresolvable" {
				t.Errorf("payment = %+v, want found by honest and unresolvable for the withholder", p)
			}
		})
	}
}

// resignTip puts tip in the receipt for one block's list and signs the
// receipt again with sk, as a server that claims that tip would.
func resignTip(t *testing.T, sk [32]byte, blockHash string, tip uint32) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/tweaks/"+blockHash {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			rc, err := wire.DecodeReceiptHeader(rec.Header().Get(wire.ReceiptHeader))
			if err == nil {
				rc.TipHeight = tip
				rc, err = wire.SignReceipt(rc, sk)
			}
			if err != nil {
				t.Errorf("re-sign the receipt: %v", err)
			} else {
				w.Header().Set(wire.ReceiptHeader, wire.EncodeReceiptHeader(rc))
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
		})
	}
}

// A withholder can sign a tip that puts the hidden block past the window.
// Core's chain contradicts any such tip far from Core's own, so the run names
// the withholder with false_chain_claim. That holds for a tip too high for
// Core's REST interface to read: Core refuses that request with 400, and the
// refusal must not stop the run that names the withholder.
func TestCheckFalseSignedTipNamesTheWithholder(t *testing.T) {
	tests := []struct {
		name string
		tip  uint32
	}{
		{"far above Core's tip", 1000},
		{"above any height Core reads", 1 << 31},
		{"the largest height", math.MaxUint32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			k := testKey(2)
			id := w.targetID()
			liar := server{label: "withholder", url: startIndexer(t, w.rest, k, &id, resignTip(t, k, w.blockHash(), tt.tip)).URL, pubkey: pubHex(t, k)}
			r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), liar})...)
			wantExit(t, r, 1)

			f := loadState(t, w.statePath())
			b := blockAt(t, f, w.height)
			if s := serverIn(t, b, "withholder"); s.State != state.Compromised || s.Reason != state.FalseChainClaim {
				t.Errorf("withholder = %s/%s, want compromised/false_chain_claim", s.State, s.Reason)
			}
			if b.State != state.Compromised || b.Reason != state.FalseChainClaim {
				t.Errorf("block = %s/%s, want compromised/false_chain_claim", b.State, b.Reason)
			}
			if len(f.Findings) != 1 {
				t.Fatalf("findings = %+v, want one", f.Findings)
			}
			x := f.Findings[0]
			if x.Kind != state.KindWithheld || x.Reason != state.FalseChainClaim || x.Servers[0].Label != "withholder" ||
				x.Evidence != nil || x.Provable {
				t.Errorf("finding = %+v, want a false_chain_claim against the withholder, not provable, with no file", x)
			}
		})
	}
}

// A record request refused with not_found, from a server that signed a
// valid record in this run, reads Not checked like an outage. Canary decides
// after the record pass, so the refused block may come before every valid
// record. Here it is the first block of the range. The server's /info may
// answer outside the API too: its valid records prove the URL, so the run
// still goes on, and only its policy is unknown.
func TestCheckRefusedRecordReadsLikeAnOutage(t *testing.T) {
	for _, infoOffAPI := range []bool{false, true} {
		name := "/info answers"
		if infoOffAPI {
			name = "/info off the API"
		}
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			first := w.chain.Block(0).BlockHash().String()
			wrap := answerOn("/commitment/"+first, http.StatusNotFound, "not_found")
			if infoOffAPI {
				wrap = both(answerOn("/info", http.StatusNotFound, "not_found"), wrap)
			}
			k := testKey(4)
			odd := server{label: "odd", url: startIndexer(t, w.rest, k, nil, wrap).URL, pubkey: pubHex(t, k)}
			r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), odd})...)
			wantExit(t, r, 0)

			f := loadState(t, w.statePath())
			b := blockAt(t, f, 0)
			if o := serverIn(t, b, "odd"); o.State != state.Unverified || o.Reason != state.ServerUnreachable {
				t.Errorf("block 0: odd = %s/%s, want unverified/server_unreachable", o.State, o.Reason)
			}
			if b.State != state.Verified || b.Reason != state.OwnRecord {
				t.Errorf("block 0 = %s/%s, want verified/own_record from the honest server", b.State, b.Reason)
			}
			for _, b := range f.Blocks[1:] {
				if b.State != state.Verified || b.Reason != state.RecordsAgree {
					t.Errorf("block %d = %s/%s, want verified/records_agree", b.Height, b.State, b.Reason)
				}
			}
			o := f.Servers[1]
			if o.Error == nil || *o.Error != wording.ServerRecordRefused(0) {
				t.Errorf("odd error = %v, want %q", o.Error, wording.ServerRecordRefused(0))
			}
			if o.Reachable == infoOffAPI || (o.Policy == nil) != infoOffAPI || !o.PublishesRecords {
				t.Errorf("odd = %+v, want records, and reachable with a policy only when /info answered", o)
			}
			if said := strings.Contains(r.stderr, wording.CheckServerInfoError("odd", wording.ServerInfoUnusable)); said != infoOffAPI {
				t.Errorf("stderr names the /info error: %v, want %v\n%s", said, infoOffAPI, r)
			}
			if len(f.Findings) != 0 {
				t.Errorf("findings = %+v, want none", f.Findings)
			}
		})
	}
}

// A server that proves nothing stops the run with exit code 5 and saves
// nothing. None of its records verifies under its pin, its /info gives no
// usable answer, and at least one answer is outside the v1 API. Canary then
// can't tell a hostile server from a wrong --indexer URL, and the URL is
// the likelier.
func TestCheckStopsForAServerThatProvesNothing(t *testing.T) {
	tests := []struct {
		name  string
		wrap  func(w *world) func(http.Handler) http.Handler
		pin   string // "wrong" pins another key, "none" pins none
		cause string // the request whose answer stopped the run
	}{
		{"/info and every record not_found", func(*world) func(http.Handler) http.Handler {
			return answerOn("/", http.StatusNotFound, "not_found")
		}, "", "GET /info"},
		{"/info gave no answer, every record not_found", func(*world) func(http.Handler) http.Handler {
			return both(dropOn("/info"), answerOn("/commitment/", http.StatusNotFound, "not_found"))
		}, "", "GET /commitment/"},
		{"/info not_found, no record verifies under the pin", func(*world) func(http.Handler) http.Handler {
			return answerOn("/info", http.StatusNotFound, "not_found")
		}, "wrong", "GET /info"},
		{"/info not_found, pinned as none", func(*world) func(http.Handler) http.Handler {
			return answerOn("/info", http.StatusNotFound, "not_found")
		}, "none", "GET /info"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			k := testKey(4)
			odd := server{label: "odd", url: startIndexer(t, w.rest, k, nil, tt.wrap(w)).URL, pubkey: pubHex(t, k)}
			switch tt.pin {
			case "wrong":
				odd.pubkey = pubHex(t, testKey(5))
			case "none":
				odd.pubkey = "none"
			}
			r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), odd})...)
			wantExit(t, r, 5)
			// A server pinned as none was asked for no record, so the
			// sentence names no pin to check.
			want, other := wording.CheckServerUnusable("odd", odd.url), wording.CheckServerUnusablePinnedNone("odd", odd.url)
			if tt.pin == "none" {
				want, other = other, want
			}
			if !strings.Contains(r.stderr, want) || strings.Contains(r.stderr, other) {
				t.Errorf("stderr lacks %q:\n%s", want, r)
			}
			if !strings.Contains(r.stderr, wording.CLIDetails("canary: "+tt.cause)) || !strings.Contains(r.stderr, "not_found") {
				t.Errorf("stderr lacks the cause %q:\n%s", tt.cause, r)
			}
			if _, err := os.Stat(w.statePath()); !os.IsNotExist(err) {
				t.Errorf("a stopped run wrote a state file: %v", err)
			}
		})
	}
}

// A server whose /info answered as canary-info/1 reaches a v1 server, so
// its answers outside the API count like outages even when none of its
// records verifies. A server with a verified record has proven its URL, so
// an /info outside the API costs it only its declared policy. Either way
// the run goes on and saves.
func TestCheckKeepsGoingForAServerThatShowsItsURL(t *testing.T) {
	tests := []struct {
		name      string
		wrap      func(w *world) func(http.Handler) http.Handler
		wrongPin  bool
		reachable bool
		err       func(w *world) string // the server's last error
		reason    state.Reason          // its reason at the payment block
	}{
		{"/info not_found, records verify", func(*world) func(http.Handler) http.Handler {
			return answerOn("/info", http.StatusNotFound, "not_found")
		}, false, false, func(*world) string { return wording.ServerInfoUnusable }, state.RecordsAgree},
		{"/info gave no answer, records verify", func(*world) func(http.Handler) http.Handler {
			return dropOn("/info")
		}, false, false, func(*world) string { return wording.ServerInfoFailed }, state.RecordsAgree},
		{"/info answers, no record verifies under the pin, one not_found", func(w *world) func(http.Handler) http.Handler {
			return answerOn("/commitment/"+w.chain.Block(w.tip).BlockHash().String(), http.StatusNotFound, "not_found")
		}, true, true, func(w *world) string { return wording.ServerRecordRefused(w.tip) }, state.NoRecords},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			k := testKey(4)
			odd := server{label: "odd", url: startIndexer(t, w.rest, k, nil, tt.wrap(w)).URL, pubkey: pubHex(t, k)}
			if tt.wrongPin {
				odd.pubkey = pubHex(t, testKey(5))
			}
			r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), odd})...)
			wantExit(t, r, 0)
			f := loadState(t, w.statePath())
			o := f.Servers[1]
			if o.Reachable != tt.reachable || (o.Policy != nil) != tt.reachable {
				t.Errorf("odd = %+v, want reachable and a declared policy: %v", o, tt.reachable)
			}
			if want := tt.err(w); o.Error == nil || *o.Error != want {
				t.Errorf("odd error = %v, want %q", o.Error, want)
			}
			// An /info error that is still the last error prints once.
			if n := strings.Count(r.stderr, "Its /info"); n > 1 {
				t.Errorf("stderr gives the /info error %d times:\n%s", n, r)
			}
			if s := serverIn(t, blockAt(t, f, w.height), "odd"); s.Reason != tt.reason {
				t.Errorf("odd at the payment block = %s/%s, want reason %s", s.State, s.Reason, tt.reason)
			}
			for _, b := range f.Blocks {
				if b.State != state.Verified {
					t.Errorf("block %d = %s/%s, want verified", b.Height, b.State, b.Reason)
				}
			}
		})
	}
}

// rewriteList changes every tweak list the server serves and drops its
// receipt, since the receipt signed the original bytes.
func rewriteList(change func([]wire.Position) []wire.Position) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/tweaks/") {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			ps, err := wire.DecodeResponse(rec.Body.Bytes())
			if rec.Code != http.StatusOK || err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			body, _ := wire.EncodeResponse(change(ps))
			w.Header().Set("Content-Type", rec.Header().Get("Content-Type"))
			_, _ = w.Write(body)
		})
	}
}

// A list whose data differs from the record at a position names the
// server at that position. The honest server's list supplies the entry, so
// Canary writes an evidence file. The list had no receipt, so the file
// proves inclusion only.
func TestCheckWrongEntryAtACommittedPosition(t *testing.T) {
	w := newWorld(t)
	k := testKey(5)
	forged := rewriteList(func(ps []wire.Position) []wire.Position {
		for i := range ps {
			if ps[i].Kind == wire.KindFull && ps[i].Leaf.TxID == w.targetID() {
				ps[i].Leaf.Tweak[10] ^= 1
			}
		}
		return ps
	})
	liar := server{label: "liar", url: startIndexer(t, w.rest, k, nil, forged).URL, pubkey: pubHex(t, k)}
	wantExit(t, runCLI(t, w.args([]server{w.honest(t, "honest", 1), liar})...), 1)

	f := loadState(t, w.statePath())
	if len(f.Findings) != 1 {
		t.Fatalf("findings = %+v, want one", f.Findings)
	}
	x := f.Findings[0]
	if x.Reason != state.ServedContradictsRecord || x.Position == nil || *x.Position != 1 ||
		x.Txid == nil || *x.Txid != w.txid() || x.Evidence == nil || x.Provable {
		t.Fatalf("finding = %+v, want served_contradicts_record at position 1 with an inclusion-only file", x)
	}
	rep, _ := evidence.Verify(readFile(t, filepath.Join(w.evidenceDir(), *x.Evidence)))
	if rep.Code != evidence.CodeInclusionOnly {
		t.Errorf("evidence code %s, want inclusion_only", rep.Code)
	}
}

// A list of the wrong length cannot be matched to the record position by
// position, so the finding names the server and the block only. The longer
// list here still fits in the bytes a list of n positions may take, so
// Canary reads it. TestCheckReadsNoListLongerThanItsRecordAllows covers a
// list that does not.
func TestCheckListOfTheWrongLength(t *testing.T) {
	tests := []struct {
		name   string
		change func([]wire.Position) []wire.Position
	}{
		{"one position short", func(ps []wire.Position) []wire.Position { return ps[:len(ps)-1] }},
		{"one position long", func(ps []wire.Position) []wire.Position {
			ps[len(ps)-1] = wire.Position{Kind: wire.KindAbsent}
			return append(ps, wire.Position{Kind: wire.KindAbsent})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			k := testKey(5)
			odd := server{label: "odd", url: startIndexer(t, w.rest, k, nil, rewriteList(tt.change)).URL, pubkey: pubHex(t, k)}
			wantExit(t, runCLI(t, w.args([]server{w.honest(t, "honest", 1), odd}, "--from", "3", "--to", "3")...), 1)

			f := loadState(t, w.statePath())
			if len(f.Findings) != 1 {
				t.Fatalf("findings = %+v, want one", f.Findings)
			}
			x := f.Findings[0]
			if x.Reason != state.ServedContradictsRecord || x.Position != nil || x.Txid != nil || x.Evidence != nil || x.Provable {
				t.Errorf("finding = %+v, want served_contradicts_record with no position and no file", x)
			}
		})
	}
}

// A server that signs records on both sides of a block but not for it gets
// a warning. Nothing it signed shows the gap, so it is not accused.
func TestCheckMissingRecordBetweenTwoRecords(t *testing.T) {
	w := newWorld(t)
	k := testKey(6)
	skip := answerOn("/commitment/"+w.blockHash(), http.StatusNotFound, "unknown_block")
	gappy := server{label: "gappy", url: startIndexer(t, w.rest, k, nil, skip).URL, pubkey: pubHex(t, k)}
	wantExit(t, runCLI(t, w.args([]server{gappy})...), 1)

	f := loadState(t, w.statePath())
	b := blockAt(t, f, w.height)
	if b.State != state.Unverified || b.Reason != state.NoRecordForBlock {
		t.Errorf("block = %s/%s, want unverified/no_record_for_block", b.State, b.Reason)
	}
	if len(f.Findings) != 1 || f.Findings[0].Kind != state.KindWarning || f.Findings[0].Reason != state.NoRecordForBlock {
		t.Errorf("findings = %+v, want one no_record_for_block warning", f.Findings)
	}
}

// After a few requests in a row get no answer, Canary stops asking that
// server, so a dead server cannot hold the run for a timeout per block.
func TestCheckStopsAskingADeadServer(t *testing.T) {
	w := newWorld(t)
	var hits atomic.Int32
	dead := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		conn, _, err := rw.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer dead.Close()
	s := server{label: "dead", url: dead.URL, pubkey: pubHex(t, testKey(7))}
	wantExit(t, runCLI(t, w.args([]server{w.honest(t, "honest", 1), s})...), 0)
	// Without the limit, /info and one record per block make 9 requests,
	// and the client may retry each once.
	if n := hits.Load(); n > 2*maxDownStreak {
		t.Errorf("the dead server got %d requests, want at most %d", n, 2*maxDownStreak)
	}
	for _, b := range loadState(t, w.statePath()).Blocks {
		if d := serverIn(t, b, "dead"); d.Reason != state.ServerUnreachable {
			t.Errorf("block %d: dead = %s/%s, want server_unreachable", b.Height, d.State, d.Reason)
		}
	}
}

// An evidence file stays named and provable even when the state file that
// listed it is gone. A file that carries a receipt is never overwritten,
// even one that no longer checks out.
func TestCheckKeepsEvidenceThatCarriesAReceipt(t *testing.T) {
	w := newWorld(t)
	servers := []server{w.honest(t, "honest", 1), w.withholder(t, "withholder", 2, nil)}
	fixClock(t, time.Date(2026, 10, 3, 8, 0, 0, 0, time.UTC))
	wantExit(t, runCLI(t, w.args(servers)...), 1)
	name := *loadState(t, w.statePath()).Findings[0].Evidence
	path := filepath.Join(w.evidenceDir(), name)

	if err := os.Remove(w.statePath()); err != nil {
		t.Fatal(err)
	}
	fixClock(t, time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC))
	wantExit(t, runCLI(t, w.args(servers)...), 1)
	x := loadState(t, w.statePath()).Findings[0]
	if x.Evidence == nil || *x.Evidence != name || !x.Provable {
		t.Errorf("finding = %+v, want the kept file named and provable", x)
	}

	good := readFile(t, path)
	broken := tamper(t, good, fieldStart(t, good, "sig"), bump(fieldStart(t, good, "sig")))
	if _, err := evidence.Verify(broken); err == nil {
		t.Fatal("test setup: the changed file still checks out")
	}
	if err := os.WriteFile(path, broken, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(w.statePath()); err != nil {
		t.Fatal(err)
	}
	wantExit(t, runCLI(t, w.args(servers)...), 1)
	if string(readFile(t, path)) != string(broken) {
		t.Error("canary check overwrote an evidence file that carries a receipt")
	}
	if x := loadState(t, w.statePath()).Findings[0]; x.Evidence != nil || x.Provable {
		t.Errorf("finding = %+v, want no file named: the one on disk does not check out", x)
	}
}

// tripwire cancels the run's context the first time a request for a path
// with prefix arrives, then holds that request until the client gives up on
// it. cancel may be nil, and then it passes every request through.
type tripwire struct {
	prefix string
	cancel atomic.Pointer[context.CancelFunc]
}

func (tw *tripwire) arm(cancel context.CancelFunc) { tw.cancel.Store(&cancel) }

func (tw *tripwire) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, tw.prefix) {
			next.ServeHTTP(w, r)
			return
		}
		if c := tw.cancel.Swap(nil); c != nil {
			(*c)()
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}
		next.ServeHTTP(w, r)
	})
}

// An interrupted run saves nothing. The cut-off request says nothing about
// the server, so no warning, no Can't be checked block and no state file
// come from it, and an earlier state file stays as it was.
func TestCheckInterruptedSavesNothing(t *testing.T) {
	w := newWorld(t)
	k := testKey(1)
	tw := &tripwire{prefix: "/tweaks/"}
	s := server{label: "honest", url: startIndexer(t, w.rest, k, nil, tw.wrap).URL, pubkey: pubHex(t, k)}

	interrupt := func() result {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		tw.arm(cancel)
		return runCLIContext(t, ctx, w.args([]server{s})...)
	}

	r := interrupt()
	wantExit(t, r, 5)
	if !strings.Contains(r.stderr, wording.CheckInterrupted) {
		t.Errorf("stderr lacks the interrupt notice:\n%s", r)
	}
	if _, err := os.Stat(w.statePath()); !os.IsNotExist(err) {
		t.Fatalf("an interrupted run wrote a state file: %v", err)
	}

	wantExit(t, runCLI(t, w.args([]server{s})...), 0)
	before := readFile(t, w.statePath())
	r = interrupt()
	wantExit(t, r, 5)
	if got := readFile(t, w.statePath()); string(got) != string(before) {
		t.Errorf("an interrupted run changed the state file:\n%s", got)
	}
}

// dropOn closes the connection without an answer for every request whose
// path is one of paths.
func dropOn(paths ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, p := range paths {
				if r.URL.Path == p {
					if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
						conn.Close()
					}
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// A server that goes quiet for a moment during the record pass is asked
// again for its lists. A block Canary never asked about reads Not checked
// with no warning, because the server refused nothing.
func TestCheckNeverWarnsAboutAListItDidNotAskFor(t *testing.T) {
	w := newWorld(t)
	var quiet []string
	for h := uint32(2); h <= 4; h++ {
		quiet = append(quiet, "/commitment/"+w.chain.Block(h).BlockHash().String())
	}
	k := testKey(3)
	flaky := server{label: "flaky", url: startIndexer(t, w.rest, k, nil, dropOn(quiet...)).URL, pubkey: pubHex(t, k)}
	r := runCLI(t, w.args([]server{flaky})...)
	wantExit(t, r, 0)

	f := loadState(t, w.statePath())
	if len(f.Findings) != 0 {
		t.Errorf("findings = %+v, want none", f.Findings)
	}
	for _, b := range f.Blocks {
		want := state.ServerUnreachable
		if b.Height < 2 {
			want = state.OwnRecord
		}
		if b.Reason != want {
			t.Errorf("block %d = %s/%s, want %s", b.Height, b.State, b.Reason, want)
		}
	}
	if e := f.Servers[0].Error; e == nil || *e != wording.ServerNotAsked(maxDownStreak) {
		t.Errorf("error = %v, want %q", e, wording.ServerNotAsked(maxDownStreak))
	}
}

// A server that stops serving lists gets the formats' warning for each list
// it was asked for and did not serve. The lists Canary then stopped asking
// for read Not checked, with no warning.
func TestCheckStopsAskingForListsWithoutBlame(t *testing.T) {
	w := newWorld(t)
	var lists []string
	for h := uint32(0); h <= w.tip; h++ {
		lists = append(lists, "/tweaks/"+w.chain.Block(h).BlockHash().String())
	}
	k := testKey(3)
	gone := server{label: "gone", url: startIndexer(t, w.rest, k, nil, dropOn(lists...)).URL, pubkey: pubHex(t, k)}
	wantExit(t, runCLI(t, w.args([]server{gone})...), 1)

	f := loadState(t, w.statePath())
	warned := map[uint32]bool{}
	for _, x := range f.Findings {
		if x.Kind != state.KindWarning || x.Reason != state.ListNotServed {
			t.Errorf("finding %+v, want only list_not_served warnings", x)
		}
		warned[x.Block.Height] = true
	}
	for _, b := range f.Blocks {
		asked := b.Height < maxDownStreak
		want := state.ServerUnreachable
		if asked {
			want = state.ListNotServed
		}
		if b.Reason != want || warned[b.Height] != asked {
			t.Errorf("block %d = %s/%s warned %v, want %s warned %v", b.Height, b.State, b.Reason, warned[b.Height], want, asked)
		}
	}
}

// A finding stops claiming an evidence file once the file no longer checks
// out, with the state file kept between runs, whether or not the later run
// sees the finding again. The file itself is left as it is.
func TestCheckStopsNamingEvidenceThatNoLongerChecksOut(t *testing.T) {
	w := newWorld(t)
	servers := []server{w.honest(t, "honest", 1), w.withholder(t, "withholder", 2, nil)}
	fixClock(t, time.Date(2026, 10, 3, 8, 0, 0, 0, time.UTC))
	wantExit(t, runCLI(t, w.args(servers)...), 1)
	first := loadState(t, w.statePath()).Findings[0]
	if first.Evidence == nil || !first.Provable {
		t.Fatalf("finding = %+v, want a provable file", first)
	}
	path := filepath.Join(w.evidenceDir(), *first.Evidence)
	good := readFile(t, path)
	broken := tamper(t, good, fieldStart(t, good, "sig"), bump(fieldStart(t, good, "sig")))
	if err := os.WriteFile(path, broken, 0o644); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name  string
		extra []string
		exit  int // only a finding this run saw sets exit code 1
	}{
		{"carried without being seen", []string{"--from", "0", "--to", "1"}, 0},
		{"seen again", nil, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			wantExit(t, runCLI(t, w.args(servers, tt.extra...)...), tt.exit)
			f := loadState(t, w.statePath())
			if len(f.Findings) != 1 || f.Findings[0].ID != first.ID {
				t.Fatalf("findings = %+v, want the first finding carried", f.Findings)
			}
			if x := f.Findings[0]; x.Evidence != nil || x.Provable {
				t.Errorf("finding = %+v, want no file named and not provable", x)
			}
			if string(readFile(t, path)) != string(broken) {
				t.Error("canary check overwrote an evidence file that carries a receipt")
			}
		})
	}
}

// After a regtest chain is wiped and mined again, the same height can hold
// another block with the same transaction at another position. The file
// name is the same, but the file accuses the old block, so the new finding
// does not name it and the old file stays as it was.
func TestCheckNeverNamesAnotherFindingsEvidence(t *testing.T) {
	w := newWorld(t)
	wantExit(t, runCLI(t, w.args([]server{w.honest(t, "honest", 1), w.withholder(t, "withholder", 2, nil)})...), 1)
	old := loadState(t, w.statePath()).Findings[0]
	if old.Evidence == nil || !old.Provable {
		t.Fatalf("finding = %+v, want a provable file", old)
	}
	path := filepath.Join(w.evidenceDir(), *old.Evidence)
	before := readFile(t, path)

	again := newWorldMined(t, func(a, skipped, b, c *btcwire.MsgTx) []*btcwire.MsgTx {
		return []*btcwire.MsgTx{b, a, skipped, c}
	})
	again.dir = w.dir
	if again.blockHash() == w.blockHash() || again.txid() != w.txid() || again.height != w.height {
		t.Fatal("test setup: the new chain must hold the same payment at the same height in another block")
	}
	r := runCLI(t, again.args([]server{again.honest(t, "honest", 1), again.withholder(t, "withholder", 2, nil)})...)
	wantExit(t, r, 1)
	f := loadState(t, again.statePath())
	if len(f.Findings) != 1 {
		t.Fatalf("findings = %+v, want the new chain's one", f.Findings)
	}
	x := f.Findings[0]
	if x.Block.Hash != again.blockHash() || x.Position == nil || *x.Position != 0 {
		t.Fatalf("finding = %+v, want position 0 of the new block", x)
	}
	if x.Evidence != nil || x.Provable {
		t.Errorf("finding = %+v, want no file named: the file under its name is about block %s", x, w.blockHash())
	}
	if string(readFile(t, path)) != string(before) {
		t.Error("canary check overwrote another finding's evidence file")
	}
}

// canary check v1 accepts regtest and main only, and refuses signet. Every
// signet reports the chain name "signet", and a custom signet's magic comes
// from its challenge, so the name cannot say which magic to check against.
// Signet needs a flag that names the network, planned after v1. The run
// stops with exit code 5, says why on one line, and saves nothing.
func TestCheckRefusesSignet(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/chaininfo.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"chain":"signet","blocks":10,"bestblockhash":"` + strings.Repeat("00", 32) + `","initialblockdownload":false}`))
	}))
	defer core.Close()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	r := runCLI(t, "check", "--indexer", "http://127.0.0.1:1=a", "--pubkey", "a=none", "--core-rest", core.URL+"/rest",
		"--state", statePath, "--evidence-dir", filepath.Join(dir, "evidence"))
	wantExit(t, r, 5)
	want := `canary check: Bitcoin Core reports chain "signet". canary check v1 runs on regtest and main only. ` +
		"Every signet reports that same name, so Canary can't tell which signet Core is on. " +
		"Signet needs a flag that names the network, which is planned after v1.\n"
	if r.stderr != want {
		t.Errorf("stderr = %q\nwant     %q", r.stderr, want)
	}
	if r.stdout != "" {
		t.Errorf("stdout = %q, want nothing before the refusal", r.stdout)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Error("a refused run wrote a state file")
	}
}
