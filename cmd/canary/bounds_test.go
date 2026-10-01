package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/core/coretest"
	"github.com/Sky-walkerX/canary/internal/indexer"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
	"github.com/Sky-walkerX/canary/wire"
	"github.com/nbd-wtf/go-nostr"
)

// inflateRecord signs the server's record for one block again with n
// entries, and answers that block's list with n absent positions and no
// receipt. A server does this to make Canary build one finding per position.
// An empty blockHash does it for every block. lists counts the requests for
// those lists.
func inflateRecord(t *testing.T, sk [32]byte, blockHash string, n uint32, lists *atomic.Int32) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route, hash, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
			if blockHash != "" && hash != blockHash {
				route = ""
			}
			switch route {
			case "commitment":
				rec := httptest.NewRecorder()
				next.ServeHTTP(rec, r)
				var ev nostr.Event
				if err := json.Unmarshal(rec.Body.Bytes(), &ev); err != nil {
					t.Errorf("read the record: %v", err)
					return
				}
				c, err := feed.FromEvent(ev)
				if err == nil {
					c.N = n
					ev, err = c.ToEvent(sk)
				}
				if err != nil {
					t.Errorf("sign the record again: %v", err)
					return
				}
				body, _ := json.Marshal(ev)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			case "tweaks":
				lists.Add(1)
				body := make([]byte, 4+int(n))
				binary.LittleEndian.PutUint32(body, n)
				for i := 4; i < len(body); i++ {
					body[i] = byte(wire.KindAbsent)
				}
				w.Header().Set("Content-Type", "application/vnd.canary.tweaks.v1")
				_, _ = w.Write(body)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}

// A record can sign any n. BIP-352 gives at most one entry per transaction
// and none for the coinbase, so a record that claims more entries than its
// block has other transactions contradicts the user's own node. It fails the
// record checks and counts as no record, as a wrong network tag does. Canary
// never asks for its list, so a server cannot make one block cost a finding
// per position it invented. The payment block in newWorld holds a coinbase
// and four other transactions.
func TestCheckRecordClaimingMoreEntriesThanItsBlock(t *testing.T) {
	tests := []struct {
		name string
		n    uint32
	}{
		{"far more entries than transactions", 200000},
		{"one entry for every transaction, the coinbase too", 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			k := testKey(4)
			var lists atomic.Int32
			big := server{label: "big", url: startIndexer(t, w.rest, k, nil, inflateRecord(t, k, w.blockHash(), tt.n, &lists)).URL, pubkey: pubHex(t, k)}
			r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), big})...)
			wantExit(t, r, 1)

			if n := lists.Load(); n != 0 {
				t.Errorf("Canary asked %d times for the list of a record its block cannot hold", n)
			}
			f := loadState(t, w.statePath())
			b := blockAt(t, f, w.height)
			if s := serverIn(t, b, "big"); s.State != state.Unverified || s.Reason != state.NoRecordForBlock || s.N != nil {
				t.Errorf("big = %s/%s n=%v, want unverified/no_record_for_block with no record", s.State, s.Reason, s.N)
			}
			if b.State != state.Verified || b.Reason != state.OwnRecord {
				t.Errorf("block = %s/%s, want verified/own_record from the honest server", b.State, b.Reason)
			}
			// The server signed records on both sides, so the warning names
			// it. Nothing it signed shows withholding, so nothing accuses it.
			if len(f.Findings) != 1 {
				t.Fatalf("%d findings, want one warning", len(f.Findings))
			}
			if x := f.Findings[0]; x.Kind != state.KindWarning || x.Reason != state.NoRecordForBlock ||
				x.Servers[0].Label != "big" || x.Block.Height != w.height {
				t.Errorf("finding = %+v, want a no_record_for_block warning naming big", x)
			}
			want := wording.ServerRecordTooLarge(w.height, tt.n, 5)
			if e := f.Servers[1].Error; e == nil || *e != want {
				t.Errorf("big error = %v, want %q", e, want)
			}
			if !f.Servers[1].PublishesRecords {
				t.Error("big publishes_records = false, want true: its other records verified")
			}
			if !strings.Contains(r.stderr, want) {
				t.Errorf("stderr lacks %q:\n%s", want, r)
			}
		})
	}
}

// A record that claims no more entries than its block has other
// transactions is taken as signed, and the retention rule judges its list.
// Here the record claims four entries where the block holds three, and the
// list leaves all four out inside the window. Canary names the server at
// each position. The record kept the honest root, so the servers do not
// disagree: only the root is compared across servers.
func TestCheckRecordWithinItsBlockIsTakenAsSigned(t *testing.T) {
	w := newWorld(t)
	k := testKey(4)
	var lists atomic.Int32
	odd := server{label: "odd", url: startIndexer(t, w.rest, k, nil, inflateRecord(t, k, w.blockHash(), 4, &lists)).URL, pubkey: pubHex(t, k)}
	wantExit(t, runCLI(t, w.args([]server{w.honest(t, "honest", 1), odd}, "--from", "3", "--to", "3")...), 1)

	if n := lists.Load(); n != 1 {
		t.Errorf("Canary asked %d times for the list, want once", n)
	}
	f := loadState(t, w.statePath())
	if s := serverIn(t, blockAt(t, f, w.height), "odd"); s.State != state.Compromised || s.Reason != state.AbsentInWindow {
		t.Errorf("odd = %s/%s, want compromised/absent_in_window", s.State, s.Reason)
	}
	for _, x := range f.Findings {
		if x.Kind != state.KindWithheld || x.Reason != state.AbsentInWindow || x.Servers[0].Label != "odd" {
			t.Errorf("unexpected finding %+v", x)
		}
	}
	if len(f.Findings) != 4 {
		t.Errorf("%d findings, want one for each of the 4 positions", len(f.Findings))
	}
}

// padList appends extra absent positions to every tweak list the server
// serves, and drops its receipt, since the receipt signed the original
// bytes. It writes the bytes directly, so a long list costs the test little.
func padList(extra int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/tweaks/") {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			body := rec.Body.Bytes()
			if rec.Code != http.StatusOK || len(body) < 4 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			n := binary.LittleEndian.Uint32(body) + uint32(extra)
			out := binary.LittleEndian.AppendUint32(make([]byte, 0, len(body)+extra), n)
			out = append(out, body[4:]...)
			for range extra {
				out = append(out, byte(wire.KindAbsent))
			}
			w.Header().Set("Content-Type", rec.Header().Get("Content-Type"))
			_, _ = w.Write(out)
		})
	}
}

// No list of n positions is longer than 4 + 66n bytes. Canary reads no more
// than that, so a server cannot make it decode millions of positions for a
// block whose record names a few. A longer answer counts as no list, like
// any answer over a size limit: Can't be checked, with the warning inside
// the window. The record here names three entries, so the limit is 202
// bytes. The served list carries all three in full, then more.
func TestCheckReadsNoListLongerThanItsRecordAllows(t *testing.T) {
	tests := []struct {
		name  string
		extra int // absent positions after the three full ones
	}{
		{"one byte too long", 1},
		{"two million absent positions", 2_000_000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			k := testKey(5)
			odd := server{label: "odd", url: startIndexer(t, w.rest, k, nil, padList(tt.extra)).URL, pubkey: pubHex(t, k)}
			r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), odd}, "--from", "3", "--to", "3")...)
			wantExit(t, r, 1)

			f := loadState(t, w.statePath())
			if s := serverIn(t, blockAt(t, f, w.height), "odd"); s.State != state.Unresolvable || s.Reason != state.ListNotServed {
				t.Errorf("odd = %s/%s, want unresolvable/list_not_served", s.State, s.Reason)
			}
			if len(f.Findings) != 1 || f.Findings[0].Kind != state.KindWarning || f.Findings[0].Reason != state.ListNotServed {
				t.Errorf("findings = %+v, want one list_not_served warning", f.Findings)
			}
			if !strings.Contains(r.stderr, "longer than 202 bytes") {
				t.Errorf("stderr does not give the limit, 4 + 66 × 3 bytes:\n%s", r)
			}
		})
	}
}

// A record proves that the --indexer URL reaches the server the pin names
// once its signature verifies, whatever n it claims. So a server whose every
// record claims more entries than its block cannot stop the run by answering
// /info outside the API. Its records count as none, and the run goes on.
func TestCheckRecordsThatFailOnlyOnTheirCountStillProveTheURL(t *testing.T) {
	w := newWorld(t)
	k := testKey(4)
	var lists atomic.Int32
	wrap := both(answerOn("/info", http.StatusNotFound, "not_found"), inflateRecord(t, k, "", 1000, &lists))
	odd := server{label: "odd", url: startIndexer(t, w.rest, k, nil, wrap).URL, pubkey: pubHex(t, k)}
	r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), odd})...)
	wantExit(t, r, 0)
	if strings.Contains(r.stderr, wording.CheckServerUnusable("odd", odd.url)) {
		t.Errorf("the run called odd unusable:\n%s", r)
	}
	if n := lists.Load(); n != 0 {
		t.Errorf("Canary asked odd for %d lists, want none", n)
	}
	f := loadState(t, w.statePath())
	o := f.Servers[1]
	if want := wording.ServerRecordTooLarge(w.tip, 1000, 1); o.Error == nil || *o.Error != want {
		t.Errorf("odd error = %v, want %q", o.Error, want)
	}
	if o.PublishesRecords || o.Reachable {
		t.Errorf("odd = %+v, want no valid record and not reachable", o)
	}
	for _, b := range f.Blocks {
		if s := serverIn(t, b, "odd"); s.Reason != state.NoRecords || b.State != state.Verified {
			t.Errorf("block %d: odd = %s/%s, block %s, want no_records and a verified block", b.Height, s.State, s.Reason, b.State)
		}
	}
	if len(f.Findings) != 0 {
		t.Errorf("findings = %+v, want none", f.Findings)
	}
}

// add keeps one finding per id, in the order found, however many it holds.
func TestAddKeepsOneFindingPerID(t *testing.T) {
	ch := &checker{}
	for i := 0; i < 3; i++ {
		ch.add(state.Finding{ID: "aaaaaaaaaaaa"})
		ch.add(state.Finding{ID: "bbbbbbbbbbbb"})
	}
	if len(ch.fresh) != 2 || ch.fresh[0].ID != "aaaaaaaaaaaa" || ch.fresh[1].ID != "bbbbbbbbbbbb" {
		t.Errorf("fresh = %+v, want aaaa then bbbb, once each", ch.fresh)
	}
}

// recordLimit is the most bytes canary check reads of a record. The formats
// doc pins it.
const recordLimit = 4096

// padRecord answers every /commitment request with the server's own record,
// signed again with one more tag, sized so the body is exactly size bytes.
// The record still verifies under the server's pin, since a server can sign
// whatever it likes into its own event.
func padRecord(t *testing.T, sk [32]byte, size int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/commitment/") {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			if rec.Code != http.StatusOK {
				w.WriteHeader(rec.Code)
				_, _ = w.Write(rec.Body.Bytes())
				return
			}
			var ev nostr.Event
			if err := json.Unmarshal(rec.Body.Bytes(), &ev); err != nil {
				t.Errorf("read the record: %v", err)
				return
			}
			sign := func(pad int) []byte {
				e := ev
				e.Tags = append(slices.Clone(ev.Tags), nostr.Tag{"pad", strings.Repeat("a", pad)})
				if err := e.Sign(hex.EncodeToString(sk[:])); err != nil {
					t.Errorf("sign the record again: %v", err)
				}
				body, _ := json.Marshal(e)
				return body
			}
			body := sign(size - len(sign(0)))
			if len(body) != size {
				t.Errorf("padded record is %d bytes, want %d", len(body), size)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		})
	}
}

// A record is read to 4096 bytes at most. Canary keeps each valid record
// until the run ends, so without the limit a server could sign its records
// with a large extra tag and make the run's memory grow by that much per
// block. A longer answer counts as no answer, like any answer over
// a size limit: Not checked, server_unreachable. A record of exactly the
// limit is read and checked like any other.
func TestCheckReadsNoRecordLongerThanTheLimit(t *testing.T) {
	tests := []struct {
		name string
		size int
		read bool
	}{
		{"exactly the limit", recordLimit, true},
		{"one byte too long", recordLimit + 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			k := testKey(6)
			padded := server{label: "padded", url: startIndexer(t, w.rest, k, nil, padRecord(t, k, tt.size)).URL, pubkey: pubHex(t, k)}
			r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), padded})...)
			wantExit(t, r, 0)

			f := loadState(t, w.statePath())
			if len(f.Findings) != 0 {
				t.Errorf("findings = %+v, want none", f.Findings)
			}
			for _, b := range f.Blocks {
				s := serverIn(t, b, "padded")
				switch {
				case tt.read && s.State != state.Verified:
					t.Errorf("block %d: padded = %s/%s, want verified", b.Height, s.State, s.Reason)
				case !tt.read && (s.State != state.Unverified || s.Reason != state.ServerUnreachable):
					t.Errorf("block %d: padded = %s/%s, want unverified/server_unreachable", b.Height, s.State, s.Reason)
				}
				if b.State != state.Verified {
					t.Errorf("block %d = %s, want verified from the honest server", b.Height, b.State)
				}
			}
			p := f.Servers[1]
			if p.PublishesRecords != tt.read {
				t.Errorf("padded publishes_records = %v, want %v", p.PublishesRecords, tt.read)
			}
			if tt.read {
				if p.Error != nil {
					t.Errorf("padded error = %q, want none", *p.Error)
				}
				return
			}
			if want := wording.ServerRecordUnanswered(w.tip); p.Error == nil || *p.Error != want {
				t.Errorf("padded error = %v, want %q", p.Error, want)
			}
			if !strings.Contains(r.stderr, "longer than 4096 bytes") {
				t.Errorf("stderr does not give the record limit:\n%s", r)
			}
		})
	}
}

// An honest record is far below the limit, so the limit costs an honest
// server nothing.
func TestHonestRecordIsFarBelowTheRecordLimit(t *testing.T) {
	w := newWorld(t)
	s := w.honest(t, "honest", 1)
	resp, err := http.Get(s.url + "/commitment/" + w.blockHash())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /commitment: status %d, %v", resp.StatusCode, err)
	}
	if maxRecordBody != recordLimit {
		t.Errorf("maxRecordBody = %d, want %d", maxRecordBody, recordLimit)
	}
	if len(body)*4 > recordLimit {
		t.Errorf("an honest record is %d bytes, more than a quarter of the %d-byte limit", len(body), recordLimit)
	}
}

// The record pass keeps a record's bytes only when they pass the record
// checks. The ladder takes nothing from a record that fails them, so a
// server that answers with a 200 and bytes no pin accepts costs the run
// nothing past the request.
func TestRecordPassKeepsOnlyRecordsThatPassTheChecks(t *testing.T) {
	w := newWorld(t)
	k := testKey(1)
	junk := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write(bytes.Repeat([]byte("x"), recordLimit-100))
	}))
	t.Cleanup(junk.Close)
	var lists atomic.Int32
	tests := []struct {
		name  string
		url   string
		valid bool // whether the pass should find valid records
	}{
		{"records that pass", w.honest(t, "honest", 1).url, true},
		{"bytes that are no record", junk.URL, false},
		{"records signed by another key", w.honest(t, "other", 2).url, false},
		{"records that claim more entries than their block", startIndexer(t, w.rest, k, nil, inflateRecord(t, k, "", 1000, &lists)).URL, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			c, err := core.New(w.rest, nil)
			if err != nil {
				t.Fatal(err)
			}
			info, err := c.ChainInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}
			net, err := core.NetworkFromChain(info.Chain)
			if err != nil {
				t.Fatal(err)
			}
			pin, err := indexer.PublicKey(k)
			if err != nil {
				t.Fatal(err)
			}
			ch := &checker{ctx: ctx, core: c, net: net, txs: map[[32]byte]int{}}
			for h := uint32(0); h <= info.Height; h++ {
				hash, err := c.BlockHash(ctx, h)
				if err != nil {
					t.Fatal(err)
				}
				ch.blocks = append(ch.blocks, chainBlock{height: h, hash: hash})
			}
			ch.runs = []*serverRun{{
				cfg:    serverConfig{label: "s", url: tt.url, pubkey: &pin},
				client: &indexerClient{base: tt.url, hc: http.DefaultClient},
			}}
			if code := ch.fetchRecords(); code != 0 {
				t.Fatalf("fetchRecords = %d", code)
			}
			s := ch.runs[0]
			found := false
			for i, b := range ch.blocks {
				found = found || s.valid[i]
				if (s.records[i] != nil) != s.valid[i] {
					t.Errorf("block %d: kept a record = %v, valid = %v", b.height, s.records[i] != nil, s.valid[i])
				}
			}
			if found != tt.valid {
				t.Errorf("found valid records = %v, want %v", found, tt.valid)
			}
		})
	}
}

// canary check keeps a block's ladder result only while it reads that
// block, and takes each declared payment's row from it then. Each row still
// comes out in --expect order, from its own block, whatever the order of
// the blocks. Here the later block's payment is declared first, and only
// the withholder leaves it out.
func TestCheckReportsEachDeclaredPaymentFromItsOwnBlock(t *testing.T) {
	chain := coretest.NewChain(t)
	chain.MineEmpty(2)
	early := chain.PayToTaproot(coretest.P2WPKH)
	earlyBlock := chain.Mine(early)
	late := chain.PayToTaproot(coretest.P2TR)
	lateBlock := chain.Mine(late)
	chain.MineEmpty(4)
	tip, _ := chain.Tip()
	w := &world{chain: chain, rest: coretest.Serve(t, chain), block: lateBlock, height: 4, target: late, tip: tip, dir: t.TempDir()}

	r := runCLI(t, w.args([]server{w.honest(t, "honest", 1), w.withholder(t, "withholder", 2, nil)},
		"--expect", late.TxHash().String()+"@"+lateBlock.BlockHash().String(),
		"--expect", early.TxHash().String()+"@"+earlyBlock.BlockHash().String())...)
	wantExit(t, r, 1)

	f := loadState(t, w.statePath())
	if len(f.ExpectedPayments) != 2 {
		t.Fatalf("%d payment rows, want 2", len(f.ExpectedPayments))
	}
	want := []struct {
		txid    string
		height  uint32
		outcome string
		servers []string // honest's outcome, then the withholder's
	}{
		{late.TxHash().String(), 4, "withheld", []string{"found", "withheld"}},
		{early.TxHash().String(), 3, "found", []string{"found", "found"}},
	}
	for i, x := range want {
		p := f.ExpectedPayments[i]
		if p.Txid != x.txid || p.Block == nil || p.Block.Height != x.height || p.Outcome != x.outcome || len(p.Servers) != 2 {
			t.Errorf("payment %d = %+v, want %s at %d, %s", i, p, x.txid, x.height, x.outcome)
			continue
		}
		for j, o := range x.servers {
			if p.Servers[j].Outcome != o {
				t.Errorf("payment %d, %s = %s, want %s", i, p.Servers[j].Label, p.Servers[j].Outcome, o)
			}
		}
	}
}
