package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sky-walkerX/canary/internal/core/coretest"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// TestGate runs the v1 demo in one process. A synthetic regtest chain feeds
// two reference indexers. The honest one serves every entry. The other
// leaves one taproot payment out of what it serves while its signed record
// still includes it. canary check must name that server, the block and the
// transaction from the server's own signatures. The evidence file it writes
// must check out offline, fail at the right step after a one-byte change,
// and show on the dashboard under the server's name.
func TestGate(t *testing.T) {
	var timings []string
	lap := func(what string, start time.Time) {
		timings = append(timings, fmt.Sprintf("%s %s", what, time.Since(start).Round(time.Millisecond)))
	}

	// A chain of about the demo's length. The payment sits a few blocks
	// below the tip, well inside the 144-block window.
	start := time.Now()
	chain := coretest.NewChain(t)
	chain.MineEmpty(200)
	before := chain.PayToTaproot(coretest.P2WPKH)
	target := chain.PayToTaproot(coretest.P2TR, coretest.P2WPKH)
	after := chain.PayToTaproot(coretest.P2TR)
	blk := chain.Mine(before, target, after)
	chain.MineEmpty(7)
	tip, _ := chain.Tip()
	payHeight := tip - 7
	rest := coretest.Serve(t, chain)
	lap("chain", start)

	start = time.Now()
	honestKey, withholderKey := testKey(1), testKey(2)
	withhold := [32]byte(target.TxHash())
	honest := startIndexer(t, rest, honestKey, nil, nil)
	withholder := startIndexer(t, rest, withholderKey, &withhold, nil)
	lap("indexers", start)

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	evidenceDir := filepath.Join(dir, "evidence")
	txid, blockHash := target.TxHash().String(), blk.BlockHash().String()

	// canary check names the withholder.
	start = time.Now()
	r := runCLI(t, "check",
		"--indexer", honest.URL+"=honest", "--pubkey", "honest="+pubHex(t, honestKey),
		"--indexer", withholder.URL+"=withholder", "--pubkey", "withholder="+pubHex(t, withholderKey),
		"--core-rest", rest,
		"--expect", txid+"@"+blockHash,
		"--state", statePath, "--evidence-dir", evidenceDir)
	lap("check", start)
	wantExit(t, r, 1)

	f := loadState(t, statePath)
	if len(f.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", f.Findings)
	}
	x := f.Findings[0]
	if x.Kind != state.KindWithheld || x.Reason != state.AbsentInWindow ||
		len(x.Servers) != 1 || x.Servers[0].Label != "withholder" || x.Servers[0].Pubkey == nil ||
		*x.Servers[0].Pubkey != pubHex(t, withholderKey) ||
		x.Block.Hash != blockHash || x.Block.Height != payHeight ||
		x.Txid == nil || *x.Txid != txid || x.Position == nil || *x.Position != 1 ||
		x.Evidence == nil || !x.Provable {
		t.Fatalf("finding = %+v, want withheld/absent_in_window naming withholder, block %d and txid %s", x, payHeight, txid)
	}
	b := blockAt(t, f, payHeight)
	if b.State != state.Compromised || b.Reason != state.AbsentInWindow || b.Hash != blockHash {
		t.Errorf("payment block = %s/%s, want compromised/absent_in_window", b.State, b.Reason)
	}
	if w := serverIn(t, b, "withholder"); w.State != state.Compromised || w.Reason != state.AbsentInWindow ||
		!w.Signed || w.Filled != 1 || w.Positions == nil || w.Positions.Absent != 1 {
		t.Errorf("withholder in the payment block = %+v", w)
	}
	for _, blk := range f.Blocks {
		if h := serverIn(t, blk, "honest"); h.State != state.Verified {
			t.Errorf("honest server in block %d = %s/%s, want verified", blk.Height, h.State, h.Reason)
		}
		if blk.Height != payHeight && (blk.State != state.Verified || blk.Reason != state.RecordsAgree) {
			t.Errorf("block %d = %s/%s, want verified/records_agree", blk.Height, blk.State, blk.Reason)
		}
	}
	if f.Counts.Verified != tip || f.Counts.Compromised != 1 {
		t.Errorf("counts = %+v, want %d Checked and 1 Data withheld", f.Counts, tip)
	}
	p := f.ExpectedPayments[0]
	if p.Outcome != "withheld" || p.Servers[0].Outcome != "found" || p.Servers[1].Outcome != "withheld" {
		t.Errorf("declared payment = %+v", p)
	}
	wantLine := fmt.Sprintf("withholder left out an entry it had signed for: block %d, txid %s.",
		payHeight, wording.ShortHash(txid, 8, 4))
	if !strings.Contains(r.stdout, wantLine) {
		t.Errorf("check output lacks %q:\n%s", wantLine, r.stdout)
	}

	// canary status prints the same finding from the state file.
	r = runCLI(t, "status", "--state", statePath)
	wantExit(t, r, 0)
	if !strings.Contains(r.stdout, wantLine) || !strings.Contains(r.stdout, wording.EvidenceStatusLine(*x.Evidence, true)) {
		t.Errorf("status output lacks the finding:\n%s", r.stdout)
	}

	evPath := filepath.Join(evidenceDir, *x.Evidence)
	good := readFile(t, evPath)

	// canary verify checks the file with the network blocked.
	attempts, restore := blockNetwork(t)
	start = time.Now()
	r = runCLI(t, "verify", evPath)
	lap("verify", start)
	wantExit(t, r, 0)
	if first := strings.SplitN(r.stdout, "\n", 2)[0]; first != wording.VerifyChecksOut {
		t.Errorf("verify's first line = %q, want %q", first, wording.VerifyChecksOut)
	}

	// One changed byte fails the step that checks it.
	start = time.Now()
	tampers := []struct {
		name, old, new, step string
	}{
		{"record signature", fieldStart(t, good, "sig"), bump(fieldStart(t, good, "sig")), "record_signature"},
		{"accused key", fieldStart(t, good, "accused"), bump(fieldStart(t, good, "accused")), "signer"},
		{"block height", fmt.Sprintf(`"height": %d`, payHeight), fmt.Sprintf(`"height": %d`, payHeight+1), "block"},
		{"proof sibling", fieldStart(t, good, "siblings"), bump(fieldStart(t, good, "siblings")), "inclusion"},
		// The receipt's network bytes, which its signature covers. Its
		// version byte would read as malformed instead.
		{"receipt", fieldStart(t, good, "receipt"), bump(fieldStart(t, good, "receipt")), "receipt"},
		{"served list", fieldStart(t, good, "served_base64"), bumpBase64(fieldStart(t, good, "served_base64")), "receipt"},
	}
	for _, tt := range tampers {
		t.Run("tamper "+tt.name, func(t *testing.T) {
			bad := tamper(t, good, tt.old, tt.new)
			if diff := countDiff(good, bad); diff != 1 {
				t.Fatalf("the tamper changed %d bytes, want 1", diff)
			}
			r := runCLI(t, "verify", writeTemp(t, "tampered.json", bad))
			wantExit(t, r, 1)
			if first := strings.SplitN(r.stdout, "\n", 2)[0]; first != wording.VerifyDoesNotCheckOut(tt.step) {
				t.Errorf("first line = %q, want %q", first, wording.VerifyDoesNotCheckOut(tt.step))
			}
		})
	}
	lap("tampers", start)
	if n := attempts.Load(); n != 0 {
		t.Errorf("canary verify tried to open %d connections", n)
	}
	restore()

	// The dashboard shows the finding under the server's name.
	start = time.Now()
	base, stop := uiServer(t, statePath)
	code, page := get(t, base+"findings/"+x.ID)
	if code != http.StatusOK || !strings.Contains(page, "withholder") || !strings.Contains(page, *x.Evidence) {
		t.Errorf("GET /findings/%s = %d, want the finding naming withholder:\n%.400s", x.ID, code, page)
	}
	code, served := get(t, base+"evidence/"+*x.Evidence)
	if code != http.StatusOK || served != string(good) {
		t.Errorf("GET /evidence/%s = %d, want the file's bytes", *x.Evidence, code)
	}
	// The update check hashes the state file's bytes and the build id of the
	// running canary ui, which is the one canary check wrote.
	code, etag := get(t, base+"state.etag")
	wantTag := state.ETag(readFile(t, statePath), version+"+"+buildID())
	if code != http.StatusOK || !strings.Contains(etag, `"etag":"`+wantTag+`"`) ||
		!strings.Contains(etag, `"findings":1`) || !strings.Contains(etag, `"state":"ok"`) {
		t.Errorf("GET /state.etag = %d %s, want etag %s", code, etag, wantTag)
	}
	if f.Canary.Version != version || f.Canary.Build != buildID() {
		t.Errorf("state file names canary %+v, want %s+%s", f.Canary, version, buildID())
	}
	wantExit(t, stop(), 0)
	lap("ui", start)

	if _, err := os.Stat(evPath); err != nil {
		t.Fatal(err)
	}
	t.Logf("gate: %d blocks, 2 servers; timings: %s", tip+1, strings.Join(timings, ", "))
}

// fieldStart returns the first 8 characters of a string field's value, as
// the file spells it, with the key and quote in front so the match is
// unique. For an array it takes the first element.
func fieldStart(t testing.TB, file []byte, key string) string {
	t.Helper()
	s := string(file)
	i := strings.Index(s, `"`+key+`": `)
	if i < 0 {
		t.Fatalf("no field %q", key)
	}
	j := strings.Index(s[i+len(key)+4:], `"`) + i + len(key) + 4
	return s[i : j+1+8]
}

// bump changes the last hex digit of s.
func bump(s string) string {
	last := s[len(s)-1]
	next := byte('0')
	if last == '0' {
		next = '1'
	}
	return s[:len(s)-1] + string(next)
}

// bumpBase64 changes the last character of s to another base64 letter.
func bumpBase64(s string) string {
	last := s[len(s)-1]
	next := byte('A')
	if last == 'A' {
		next = 'B'
	}
	return s[:len(s)-1] + string(next)
}

func countDiff(a, b []byte) int {
	if len(a) != len(b) {
		return -1
	}
	n := 0
	for i := range a {
		if a[i] != b[i] {
			n++
		}
	}
	return n
}
