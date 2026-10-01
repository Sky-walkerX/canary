package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// formatsDoc is the frozen v1 formats doc, the source of truth for the
// examples these tests check against.
const formatsDoc = "../../docs/design/2026-09-30-v1-formats.md"

// docExample returns the first JSON block under "### Example" in the section
// whose heading starts with heading.
func docExample(t testing.TB, heading string) []byte {
	t.Helper()
	s := string(readFile(t, formatsDoc))
	start := strings.Index(s, "\n"+heading)
	if start < 0 {
		t.Fatalf("no section %q in the formats doc", heading)
	}
	s = s[start+1:]
	if end := strings.Index(s[len(heading):], "\n## "); end >= 0 {
		s = s[:len(heading)+end]
	}
	s = s[strings.Index(s, "\n### Example"):]
	s = s[strings.Index(s, "```json\n")+len("```json\n"):]
	return []byte(s[:strings.Index(s, "\n```")+1])
}

// writeTemp writes b to a new file and returns its path.
func writeTemp(t testing.TB, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func docEvidence(t testing.TB) string {
	return writeTemp(t, "omission-regtest-205-01982d71-b1070620.json", docExample(t, "## 6. The evidence file"))
}

func TestVerifyTheDocExampleChecksOut(t *testing.T) {
	r := runCLI(t, "verify", docEvidence(t))
	wantExit(t, r, 0)
	lines := strings.Split(r.stdout, "\n")
	if lines[0] != wording.VerifyChecksOut {
		t.Errorf("first line %q, want %q", lines[0], wording.VerifyChecksOut)
	}
	for _, step := range wording.VerifySteps {
		if !strings.Contains(r.stdout, "  "+wording.VerifyStep(step)+": "+wording.StepPassed+". ") {
			t.Errorf("no passing line for step %s:\n%s", step, r.stdout)
		}
	}
	if !strings.Contains(r.stdout, "Block 205 on regtest, position 1, txid 01982d71…7c16.") {
		t.Errorf("the output does not name the block and entry:\n%s", r.stdout)
	}
}

// verify --json prints the doc's report example field for field, and the
// flag may come before or after the file.
func TestVerifyJSONIsTheDocReport(t *testing.T) {
	want := docExample(t, "## 7. VerifyReport")
	path := docEvidence(t)
	for _, args := range [][]string{{"verify", path, "--json"}, {"verify", "--json", path}} {
		r := runCLI(t, args...)
		wantExit(t, r, 0)
		var got, doc any
		if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
			t.Fatalf("%v: stdout is not JSON: %v\n%s", args, err, r.stdout)
		}
		_ = json.Unmarshal(want, &doc)
		if !reflect.DeepEqual(got, doc) {
			t.Errorf("%v: report differs from the doc example:\n%s", args, r.stdout)
		}
	}
}

// tamper returns the doc example with one byte changed.
func tamper(t testing.TB, b []byte, old, new string) []byte {
	t.Helper()
	i := strings.Index(string(b), old)
	if i < 0 || len(old) != len(new) {
		t.Fatalf("cannot find %q to tamper with", old)
	}
	out := append([]byte(nil), b...)
	copy(out[i:], new)
	return out
}

func TestVerifyOutcomes(t *testing.T) {
	doc := docExample(t, "## 6. The evidence file")
	var noReceipt map[string]any
	_ = json.Unmarshal(doc, &noReceipt)
	noReceipt["receipt"], noReceipt["served_base64"] = nil, nil
	noReceiptBytes, _ := json.Marshal(noReceipt)

	tests := []struct {
		name  string
		file  []byte
		code  int
		first string
		more  []string
	}{
		{"receipt signature byte", tamper(t, doc, "ed0b\"", "ed0c\""), 1,
			wording.VerifyDoesNotCheckOut("receipt"), []string{wording.VerifyNotHonest}},
		{"proof sibling byte", tamper(t, doc, "\"93625b68", "\"93625b69"), 1,
			wording.VerifyDoesNotCheckOut("inclusion"), []string{wording.VerifyNotHonest}},
		{"record signature byte", tamper(t, doc, "\"eb2d283d", "\"eb2d283e"), 1,
			wording.VerifyDoesNotCheckOut("record_signature"), []string{wording.VerifyNotHonest}},
		{"no receipt", noReceiptBytes, 4, wording.VerifyInclusionOnly, wording.VerifyInclusionOnlyDetail[:]},
		{"not JSON", []byte("{"), 3, wording.VerifyCantRead(wording.VerifyReasonMalformed), nil},
		{"newer format", tamper(t, doc, "canary-evidence/1", "canary-evidence/2"), 3,
			wording.VerifyCantRead(wording.VerifyReasonUnsupported), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runCLI(t, "verify", writeTemp(t, "e.json", tt.file))
			wantExit(t, r, tt.code)
			if first := strings.SplitN(r.stdout, "\n", 2)[0]; first != tt.first {
				t.Errorf("first line %q, want %q", first, tt.first)
			}
			for _, m := range tt.more {
				if !strings.Contains(r.stdout, m) {
					t.Errorf("output lacks %q:\n%s", m, r.stdout)
				}
			}
		})
	}
}

func TestVerifyUsageAndMissingFiles(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")
	r := runCLI(t, "verify", missing)
	wantExit(t, r, 3)
	if !strings.Contains(r.stdout, wording.VerifyCantRead(wording.VerifyReasonMissing)) {
		t.Errorf("missing file:\n%s", r)
	}
	r = runCLI(t, "verify", missing, "--json")
	wantExit(t, r, 3)
	if r.stdout != "" {
		t.Errorf("a missing file has no report to print, got:\n%s", r.stdout)
	}

	big := writeTemp(t, "big.json", make([]byte, maxEvidenceFile+1))
	r = runCLI(t, "verify", big)
	wantExit(t, r, 3)
	if !strings.Contains(r.stdout, wording.VerifyCantRead(wording.VerifyReasonTooLarge(maxEvidenceFile))) {
		t.Errorf("oversized file:\n%s", r)
	}

	wantExit(t, runCLI(t, "verify"), 2)
	wantExit(t, runCLI(t, "verify", "a.json", "b.json"), 2)
}

// blockNetwork replaces every dialer the standard library would use with one
// that fails and counts, until restore runs or the test ends. It first shows
// that the replacement catches a real request, or the count would prove
// nothing.
func blockNetwork(t *testing.T) (attempts *atomic.Int32, restore func()) {
	t.Helper()
	attempts = new(atomic.Int32)
	fail := func(ctx context.Context, network, addr string) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("canary test: this test allows no connections")
	}
	oldTransport, oldResolver := http.DefaultTransport, net.DefaultResolver
	http.DefaultTransport = &http.Transport{DialContext: fail, DialTLSContext: fail}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: fail}
	var once sync.Once
	restore = func() {
		once.Do(func() { http.DefaultTransport, net.DefaultResolver = oldTransport, oldResolver })
	}
	t.Cleanup(restore)

	if resp, err := http.Get("http://127.0.0.1:9/"); err == nil {
		resp.Body.Close()
		t.Fatal("a request succeeded with the failing transport installed")
	}
	if attempts.Load() == 0 {
		t.Fatal("the failing dialer was never called; the test cannot see a connection")
	}
	attempts.Store(0)
	return attempts, restore
}

func TestVerifyOpensNoConnection(t *testing.T) {
	path := docEvidence(t)
	attempts, _ := blockNetwork(t)
	wantExit(t, runCLI(t, "verify", path), 0)
	wantExit(t, runCLI(t, "verify", "--json", path), 0)
	if n := attempts.Load(); n != 0 {
		t.Errorf("canary verify tried to open %d connections", n)
	}
}
