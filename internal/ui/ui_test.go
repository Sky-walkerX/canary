package ui

import (
	"bytes"
	"encoding/json"
	"errors"
	"html"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

const (
	exampleBlock    = "cafb64b3cfa7d9c38917ab7fd88107ba27342cadee3dcf2f85138a8322dc09b8"
	exampleFinding  = "827a8d3f502e"
	exampleEvidence = "omission-regtest-205-01982d71-b1070620.json"
	testBuild       = "0.1.0+test123"
)

var ist = time.FixedZone("IST", 5*3600+1800)

// safeBuffer is an io.Writer tests can read while the handler writes.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fixture struct {
	t         *testing.T
	dir       string
	statePath string
	evDir     string
	log       *safeBuffer
	opts      Options
	h         http.Handler
}

func exampleState(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "state", "testdata", "example-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func exampleFile(t *testing.T) *state.File {
	t.Helper()
	f, err := state.Parse(exampleState(t))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// newFixture writes raw as the state file (nil means no file) and copies the
// example evidence file into the evidence directory.
func newFixture(t *testing.T, raw []byte, edit func(*Options)) *fixture {
	t.Helper()
	dir := t.TempDir()
	fx := &fixture{t: t, dir: dir, statePath: filepath.Join(dir, "state.json"), evDir: filepath.Join(dir, "evidence"), log: &safeBuffer{}}
	if err := os.MkdirAll(fx.evDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ev, err := os.ReadFile(filepath.Join("testdata", exampleEvidence))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fx.evDir, exampleEvidence), ev, 0o644); err != nil {
		t.Fatal(err)
	}
	if raw != nil {
		fx.write(raw)
	}
	generated := time.Date(2026, 10, 3, 8, 32, 11, 0, time.UTC)
	fx.opts = Options{
		StatePath:   fx.statePath,
		Version:     "0.1.0",
		Build:       "test123",
		EvidenceDir: fx.evDir,
		Now:         func() time.Time { return generated.Add(6 * time.Minute) },
		Location:    ist,
		ErrorLog:    fx.log,
	}
	if edit != nil {
		edit(&fx.opts)
	}
	h, err := New(fx.opts)
	if err != nil {
		t.Fatal(err)
	}
	fx.h = h
	return fx
}

func (fx *fixture) write(raw []byte) {
	fx.t.Helper()
	tmp := fx.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		fx.t.Fatal(err)
	}
	if err := os.Rename(tmp, fx.statePath); err != nil {
		fx.t.Fatal(err)
	}
}

func (fx *fixture) writeFile(f *state.File) {
	fx.t.Helper()
	b, err := state.Marshal(f)
	if err != nil {
		fx.t.Fatal(err)
	}
	fx.write(b)
}

func (fx *fixture) do(method, path string) *httptest.ResponseRecorder {
	fx.t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Host = "127.0.0.1:7352"
	rec := httptest.NewRecorder()
	fx.h.ServeHTTP(rec, req)
	return rec
}

func (fx *fixture) get(path string) (*httptest.ResponseRecorder, string) {
	fx.t.Helper()
	rec := fx.do(http.MethodGet, path)
	return rec, html.UnescapeString(rec.Body.String())
}

func checkSecurityHeaders(t *testing.T, path string, h http.Header) {
	t.Helper()
	want := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'none'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s: %s = %q, want %q", path, k, got, v)
		}
	}
}

func TestEveryRoute(t *testing.T) {
	fx := newFixture(t, exampleState(t), nil)
	tests := []struct {
		path   string
		status int
		ctype  string
	}{
		{"/", 200, "text/html"},
		{"/blocks", 200, "text/html"},
		{"/blocks/" + exampleBlock, 200, "text/html"},
		{"/findings", 200, "text/html"},
		{"/findings/" + exampleFinding, 200, "text/html"},
		{"/evidence/" + exampleEvidence, 200, "application/json"},
		{"/state.etag", 200, "application/json"},
		{"/assets/tokens.css", 200, "text/css"},
		{"/assets/ui.css", 200, "text/css"},
		{"/assets/app.js", 200, "text/javascript"},
		{"/assets/live.js", 200, "text/javascript"},
		{"/assets/glyphs.svg", 200, "image/svg+xml"},
		{"/assets/favicon.svg", 200, "image/svg+xml"},
		{"/assets/fonts/atkinson-hyperlegible-next-latin.woff2", 200, "font/woff2"},
		{"/assets/fonts/atkinson-hyperlegible-mono-latin.woff2", 200, "font/woff2"},
		{"/assets/fonts/OFL-atkinson-hyperlegible-next.txt", 200, "text/plain"},
		{"/favicon.ico", 200, "image/svg+xml"},
		{"/blocks?height=205", 303, ""},
		{"/blocks?height=7", 404, "text/html"},
		{"/blocks?height=abc", 404, "text/html"},
		{"/blocks/" + strings.Repeat("0", 64), 404, "text/html"},
		{"/blocks/not-a-hash", 404, "text/html"},
		{"/findings/000000000000", 404, "text/html"},
		{"/evidence/not-listed.json", 404, "text/html"},
		{"/evidence/..%2F..%2Fstate.json", 404, "text/html"},
		{"/assets/missing.css", 404, "text/plain"},
		{"/nope", 404, "text/html"},
		{"/blocks/", 404, "text/html"},
	}
	for _, tt := range tests {
		rec := fx.do(http.MethodGet, tt.path)
		if rec.Code != tt.status {
			t.Errorf("GET %s = %d, want %d", tt.path, rec.Code, tt.status)
		}
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), tt.ctype) {
			t.Errorf("GET %s Content-Type = %q, want %s", tt.path, rec.Header().Get("Content-Type"), tt.ctype)
		}
		checkSecurityHeaders(t, tt.path, rec.Header())
		if strings.HasPrefix(tt.ctype, "text/html") && rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("GET %s: HTML must not be cached", tt.path)
		}
	}
	if loc := fx.do(http.MethodGet, "/blocks?height=205").Header().Get("Location"); loc != "/blocks/"+exampleBlock {
		t.Errorf("height lookup redirected to %q", loc)
	}
}

func TestHead(t *testing.T) {
	fx := newFixture(t, exampleState(t), nil)
	for _, p := range []string{"/", "/findings/" + exampleFinding, "/state.etag", "/assets/ui.css"} {
		rec := fx.do(http.MethodHead, p)
		if rec.Code != 200 {
			t.Errorf("HEAD %s = %d", p, rec.Code)
		}
		checkSecurityHeaders(t, p, rec.Header())
	}
}

func TestOnlyGetAndHead(t *testing.T) {
	fx := newFixture(t, exampleState(t), nil)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		for _, p := range []string{"/", "/state.etag", "/evidence/" + exampleEvidence, "/nope"} {
			rec := fx.do(m, p)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 405", m, p, rec.Code)
			}
			if rec.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("%s %s: Allow = %q", m, p, rec.Header().Get("Allow"))
			}
			checkSecurityHeaders(t, p, rec.Header())
		}
	}
}

func TestHostHeader(t *testing.T) {
	fx := newFixture(t, exampleState(t), nil)
	tests := []struct {
		host string
		want int
	}{
		{"localhost", 200},
		{"localhost:7352", 200},
		{"LOCALHOST:7352", 200},
		{"127.0.0.1", 200},
		{"127.0.0.1:7352", 200},
		{"[::1]", 200},
		{"[::1]:7352", 200},
		{"example.com", 421},
		{"evil.example:7352", 421},
		{"localhost.evil.example", 421},
		{"127.0.0.1.nip.io:7352", 421},
		{"127.0.0.2:7352", 200},
		{"127.1.2.3", 200},
		{"[::ffff:127.0.0.1]:7352", 200},
		{"[127.0.0.1]:7352", 421},
		{"127.000.0.1:7352", 421},
		{"0.0.0.0:7352", 421},
		{"[::2]:7352", 421},
		{"192.168.1.10:7352", 421},
		{"", 400},
		{"localhost:", 400},
		{"localhost:99999", 400},
		{"localhost:80x", 400},
		{"[::1", 400},
		{"[::1]x", 400},
		{"::1", 400},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = tt.host
		rec := httptest.NewRecorder()
		fx.h.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Errorf("Host %q = %d, want %d", tt.host, rec.Code, tt.want)
		}
		checkSecurityHeaders(t, "Host "+tt.host, rec.Header())
		if tt.want != 200 && strings.Contains(rec.Body.String(), "withholder") {
			t.Errorf("Host %q: a rejected request leaked page content", tt.host)
		}
	}
}

func TestNotFoundPages(t *testing.T) {
	fx := newFixture(t, exampleState(t), nil)
	tests := []struct {
		path  string
		title string
	}{
		{"/nope", wording.PageNotFound.Title},
		{"/blocks/" + strings.Repeat("ab", 32), wording.BlockNotFound(0, 212).Title},
		{"/findings/ffffffffffff", wording.FindingNotFound("ffffffffffff").Title},
		{"/evidence/not-listed.json", wording.EvidenceNotFound("not-listed.json").Title},
	}
	for _, tt := range tests {
		rec, body := fx.get(tt.path)
		if rec.Code != 404 {
			t.Errorf("%s = %d", tt.path, rec.Code)
		}
		if !strings.Contains(body, "<h1 id=\"error-title\">"+tt.title+"</h1>") {
			t.Errorf("%s: page lacks the title %q", tt.path, tt.title)
		}
	}
}

// TestEvidenceIsConfinedToListedFiles serves only names listed in findings,
// from inside the evidence directory.
func TestEvidenceIsConfinedToListedFiles(t *testing.T) {
	f := exampleFile(t)
	fx := newFixture(t, nil, nil)
	// A listed file that is missing from disk, and a secret next to the directory.
	if err := os.WriteFile(filepath.Join(fx.dir, "secret.json"), []byte(`{"secret":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := "omission-regtest-206-aaaaaaaa-bbbbbbbb.json"
	f.Findings = append(f.Findings, f.Findings[0])
	f.Findings[1].ID = "aaaaaaaaaaaa"
	f.Findings[1].Evidence = &missing
	fx.writeFile(f)
	for _, p := range []string{"/evidence/" + missing, "/evidence/secret.json", "/evidence/..%2Fsecret.json", "/evidence/%2E%2E%2Fsecret.json"} {
		rec, body := fx.get(p)
		if rec.Code != 404 {
			t.Errorf("%s = %d, want 404", p, rec.Code)
		}
		if strings.Contains(body, `"secret":true`) {
			t.Errorf("%s leaked a file outside the evidence directory", p)
		}
	}
}

func TestEvidenceDownload(t *testing.T) {
	fx := newFixture(t, exampleState(t), nil)
	rec := fx.do(http.MethodGet, "/evidence/"+exampleEvidence)
	want, _ := os.ReadFile(filepath.Join("testdata", exampleEvidence))
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Error("downloaded bytes differ from the file")
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="`+exampleEvidence+`"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
}

func TestNoStatePage(t *testing.T) {
	fx := newFixture(t, nil, nil)
	for _, p := range []string{"/", "/blocks", "/blocks/" + exampleBlock, "/findings", "/findings/" + exampleFinding} {
		rec, body := fx.get(p)
		if rec.Code != 200 {
			t.Errorf("%s = %d, want 200", p, rec.Code)
		}
		if !strings.Contains(body, wording.NoCheckYet.Title) || !strings.Contains(body, wording.NoCheckYet.Action) {
			t.Errorf("%s: no-check page lacks its words", p)
		}
		if !strings.Contains(body, "canary check") || !strings.Contains(body, "--state "+fx.statePath) {
			t.Errorf("%s: no-check page lacks the command with this state path", p)
		}
		if !strings.Contains(body, `data-copy="canary check`) {
			t.Errorf("%s: the command has no copy button", p)
		}
	}
	if rec := fx.do(http.MethodGet, "/evidence/"+exampleEvidence); rec.Code != 404 {
		t.Errorf("evidence without a state file = %d, want 404", rec.Code)
	}

	custom := newFixture(t, nil, func(o *Options) { o.CheckCommand = "canary check --indexer http://127.0.0.1:8081=honest" })
	if _, body := custom.get("/"); !strings.Contains(body, "canary check --indexer http://127.0.0.1:8081=honest") {
		t.Error("CheckCommand is not shown")
	}
}

func TestNewerFormatPage(t *testing.T) {
	fx := newFixture(t, []byte(`{"format":"canary-state/2","whatever":[1,2,3]}`), nil)
	rec, body := fx.get("/")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d", rec.Code)
	}
	m := wording.NewerFormat("canary-state/2")
	for _, s := range []string{m.Title, m.Body, m.Action, "Technical details"} {
		if !strings.Contains(body, s) {
			t.Errorf("newer-format page lacks %q", s)
		}
	}
	if strings.Contains(body, wording.StateUnreadable(fx.statePath).Title) {
		t.Error("a newer format must not read as unreadable")
	}
}

func TestUnreadablePage(t *testing.T) {
	fx := newFixture(t, []byte(`{"format": "canary-state/1", "generated_at": `), nil)
	rec, body := fx.get("/findings")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d", rec.Code)
	}
	m := wording.StateUnreadable(fx.statePath)
	for _, s := range []string{m.Title, m.Action, "Technical details", "state: state file unreadable",
		"mv " + fx.statePath + " " + fx.statePath + ".bad", "won't carry into the new run"} {
		if !strings.Contains(body, s) {
			t.Errorf("unreadable page lacks %q", s)
		}
	}
}

// TestStateNotOpenedPage covers a state file the system will not let Canary
// read. Moving it aside would lose its findings, so the page offers no mv.
func TestStateNotOpenedPage(t *testing.T) {
	fx := newFixture(t, nil, nil)
	// A directory at the state path fails the read itself, as a permission
	// error does, and works the same when the tests run as root.
	if err := os.Mkdir(fx.statePath, 0o755); err != nil {
		t.Fatal(err)
	}
	rec, body := fx.get("/")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d", rec.Code)
	}
	m := wording.StateNotOpened(fx.statePath)
	for _, s := range []string{m.Title, m.Body, m.Action, "Technical details"} {
		if !strings.Contains(body, s) {
			t.Errorf("not-opened page lacks %q", s)
		}
	}
	if strings.Contains(body, "mv ") || strings.Contains(body, wording.StateUnreadable(fx.statePath).Title) {
		t.Error("a read error must not suggest moving the file aside")
	}
}

func TestServerErrorPage(t *testing.T) {
	fx := newFixture(t, exampleState(t), func(o *Options) {
		o.Verify = func([]byte) ([]byte, error) { panic("verify exploded") }
	})
	rec, body := fx.get("/findings/" + exampleFinding)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	checkSecurityHeaders(t, "500", rec.Header())
	m := regexp.MustCompile(`canary ui: error ([0-9a-f]{8}): GET /findings/` + exampleFinding + `: panic: verify exploded`).FindStringSubmatch(fx.log.String())
	if m == nil {
		t.Fatalf("error log lacks an id line: %q", fx.log.String())
	}
	if !strings.Contains(body, wording.ServerError(m[1]).Body) {
		t.Error("500 page does not show the logged error id")
	}
	if !strings.Contains(body, wording.ServerError(m[1]).Title) {
		t.Error("500 page lacks its title")
	}
}

func TestStateETag(t *testing.T) {
	raw := exampleState(t)
	fx := newFixture(t, raw, nil)
	rec := fx.do(http.MethodGet, "/state.etag")
	var got struct {
		ETag        string  `json:"etag"`
		Build       string  `json:"build"`
		State       string  `json:"state"`
		GeneratedAt *string `json:"generated_at"`
		Findings    int     `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := state.ETag(raw, testBuild)
	if got.ETag != want || got.Build != testBuild || got.State != "ok" || got.Findings != 1 ||
		got.GeneratedAt == nil || *got.GeneratedAt != "2026-10-03T08:32:11Z" {
		t.Errorf("etag response = %+v, want etag %s", got, want)
	}
	if rec.Header().Get("ETag") != `"`+want+`"` {
		t.Errorf("ETag header = %q", rec.Header().Get("ETag"))
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("etag response must not be cached")
	}
	if _, body := fx.get("/"); !strings.Contains(body, `data-etag="`+want+`"`) || !strings.Contains(body, `data-build="`+testBuild+`"`) || !strings.Contains(body, `data-findings="1"`) {
		t.Error("page does not embed the etag, build and findings it was rendered from")
	}

	// A new file changes the etag without restarting the handler.
	f := exampleFile(t)
	f.GeneratedAt = state.Time{Time: f.GeneratedAt.Add(time.Minute)}
	fx.writeFile(f)
	rec = fx.do(http.MethodGet, "/state.etag")
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.ETag == want {
		t.Error("etag did not change after the state file changed")
	}
	newRaw, _ := os.ReadFile(fx.statePath)
	if got.ETag != state.ETag(newRaw, testBuild) {
		t.Error("etag does not match the new file")
	}

	// Missing, unreadable and newer files.
	for _, tt := range []struct {
		raw  []byte
		want string
	}{
		{nil, "missing"},
		{[]byte("nope"), "unreadable"},
		{[]byte(`{"format":"canary-state/3"}`), "newer_format"},
	} {
		fx := newFixture(t, tt.raw, nil)
		rec := fx.do(http.MethodGet, "/state.etag")
		var r map[string]any
		json.Unmarshal(rec.Body.Bytes(), &r)
		if r["state"] != tt.want || r["generated_at"] != nil || r["findings"] != 0.0 {
			t.Errorf("%s: response = %v", tt.want, r)
		}
		if r["etag"] != state.ETag(tt.raw, testBuild) {
			t.Errorf("%s: etag = %v", tt.want, r["etag"])
		}
	}
}

// allChecked returns the example with every block Checked.
func allChecked(t *testing.T, st state.StateCode, reason state.Reason) *state.File {
	f := exampleFile(t)
	f.Coverage = []state.CoverageRange{{From: 0, To: 212, State: st, Reason: reason}}
	f.Counts = state.Counts{}
	switch st {
	case state.Verified:
		f.Counts.Verified = 213
	case state.Resolved:
		f.Counts.Resolved = 213
	}
	f.Blocks[0].State, f.Blocks[0].Reason = st, reason
	f.Blocks[0].Servers[1].State, f.Blocks[0].Servers[1].Reason = st, reason
	f.Findings = nil
	f.ExpectedPayments = nil
	return f
}

func TestLowerBoundSentence(t *testing.T) {
	mixed := func(t *testing.T, tail state.StateCode, reason state.Reason) *state.File {
		f := allChecked(t, state.Verified, state.RecordsAgree)
		f.Coverage = []state.CoverageRange{
			{From: 0, To: 200, State: state.Verified, Reason: state.RecordsAgree},
			{From: 201, To: 212, State: tail, Reason: reason},
		}
		f.Counts = state.Counts{Verified: 201}
		switch tail {
		case state.Resolved:
			f.Counts.Resolved = 12
		case state.Unresolvable:
			f.Counts.Unresolvable = 12
		case state.Unverified:
			f.Counts.Unverified = 12
		case state.Disputed:
			f.Counts.Disputed = 12
		case state.Compromised:
			f.Counts.Compromised = 12
		}
		return f
	}
	tests := []struct {
		name string
		file func(t *testing.T) *state.File
		want string
	}{
		{"all checked", func(t *testing.T) *state.File { return allChecked(t, state.Verified, state.RecordsAgree) }, ""},
		{"all gap filled", func(t *testing.T) *state.File { return allChecked(t, state.Resolved, state.HashRetained) }, ""},
		{"checked and gap filled", func(t *testing.T) *state.File { return mixed(t, state.Resolved, state.FilledFromServer) }, ""},
		{"some can't be checked", func(t *testing.T) *state.File { return mixed(t, state.Unresolvable, state.GapUnfilled) },
			wording.LowerBound(12, false)},
		{"some not checked", func(t *testing.T) *state.File { return mixed(t, state.Unverified, state.NoRecords) },
			wording.LowerBound(12, false)},
		{"some disputed", func(t *testing.T) *state.File { return mixed(t, state.Disputed, state.RecordsDiffer) },
			wording.LowerBound(12, true)},
		{"the example", exampleFile, wording.LowerBound(1, true)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newFixture(t, nil, nil)
			fx.writeFile(tt.file(t))
			for _, p := range []string{"/", "/blocks"} {
				rec, body := fx.get(p)
				if rec.Code != 200 {
					t.Fatalf("%s = %d", p, rec.Code)
				}
				has := strings.Contains(body, `class="lower-bound"`)
				if tt.want == "" && has {
					t.Errorf("%s shows a lower-bound sentence when every block passed", p)
				}
				if tt.want != "" && (!has || !strings.Contains(body, tt.want)) {
					t.Errorf("%s lacks the lower-bound sentence %q", p, tt.want)
				}
			}
		})
	}
}

func TestOverviewContent(t *testing.T) {
	fx := newFixture(t, exampleState(t), nil)
	_, body := fx.get("/")
	for _, s := range []string{
		"Server withholder left out an entry it had signed for.",
		"Block 205. You can prove this to others.",
		"Last check 2026-10-03 14:02 IST (6 min ago) · blocks 0–212 · regtest · canary 0.1.0 (abc1234)",
		wording.RegtestBadge,
		`role="img"`,
		`aria-label="Coverage of blocks 0 to 212: 212 Checked; 1 Data withheld."`,
		`id="servers"`,
		"Findings (1)",
		wording.Framing,
		"canary 0.1.0 (test123)",
		`<a class="skip-link" href="#main">`,
		`<main id="main"`,
	} {
		if !strings.Contains(body, s) {
			t.Errorf("overview lacks %q", s)
		}
	}
	if strings.Contains(body, "(1 min ago)") || strings.Contains(body, "These results are") {
		t.Error("fresh results must not read as stale")
	}
}

func TestStaleBanner(t *testing.T) {
	fx := newFixture(t, exampleState(t), func(o *Options) {
		o.Now = func() time.Time { return time.Date(2026, 10, 3, 11, 40, 0, 0, time.UTC) }
	})
	_, body := fx.get("/")
	m := wording.Stale("3 h")
	if !strings.Contains(body, m.Title) || !strings.Contains(body, m.Action) {
		t.Error("results three hours old show no stale banner")
	}
}

// TestStateLabelsComeFromWording checks that no template spells a state
// label itself, and that every label on screen is the wording table's.
func TestStateLabelsComeFromWording(t *testing.T) {
	err := fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := fs.ReadFile(templateFS, p)
		for _, label := range wording.Labels() {
			if strings.Contains(string(b), label) {
				t.Errorf("%s spells the state label %q itself", p, label)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	fx := newFixture(t, exampleState(t), nil)
	_, body := fx.get("/")
	badge := regexp.MustCompile(`<span class="badge s-([a-z]+)"><svg class="glyph"[^>]*><use href="#g-([a-z]+)"></use></svg><span>([^<]+)</span></span>`)
	found := map[string]bool{}
	for _, m := range badge.FindAllStringSubmatch(body, -1) {
		if m[1] != m[2] {
			t.Errorf("badge colour %s and glyph %s differ", m[1], m[2])
		}
		want := wording.State(m[1]).Label
		if m[3] != want {
			t.Errorf("badge %s reads %q, want %q", m[1], m[3], want)
		}
		found[m[1]] = true
	}
	for _, s := range wording.States() {
		if !found[s.Code] {
			t.Errorf("overview shows no %s badge", s.Code)
		}
		if !strings.Contains(body, s.Explain) {
			t.Errorf("overview lacks the %s explanation", s.Code)
		}
	}
}

func TestFindingPage(t *testing.T) {
	report, _ := os.ReadFile(filepath.Join("testdata", "example-report.json"))
	fx := newFixture(t, exampleState(t), func(o *Options) {
		o.Verify = func(b []byte) ([]byte, error) {
			if !bytes.Contains(b, []byte(`"canary-evidence/1"`)) {
				return nil, errors.New("not the example")
			}
			return report, nil
		}
	})
	_, body := fx.get("/findings/" + exampleFinding)
	for _, s := range []string{
		"Server withholder left out an entry it had signed for.",
		wording.Reason("absent_in_window"),
		wording.FindingShows("withheld", "absent_in_window", true, true),
		wording.FindingDoesNotShow("withheld", "absent_in_window"),
		wording.Provable("withheld", true, true),
		`href="/evidence/` + exampleEvidence + `"`,
		"canary verify " + filepath.Join(fx.evDir, exampleEvidence),
		wording.VerifyResultLabel("checks_out", "ok"),
		"The server's signed tip was 212, so the block was 7 blocks deep, inside the 144-block window.",
		wording.VerifyStep("served_list"),
		`data-copy="01982d712503c4e22cd00be57b905bacf4d8bff0533c23c276c8b738da217c16"`,
		`aria-label="Copy the transaction id"`,
	} {
		if !strings.Contains(body, s) {
			t.Errorf("finding page lacks %q", s)
		}
	}

	// A report that does not match the format shows an inline error, not a 500.
	bad := newFixture(t, exampleState(t), func(o *Options) {
		o.Verify = func([]byte) ([]byte, error) { return []byte(`{"result":"fine"}`), nil }
	})
	rec, body := bad.get("/findings/" + exampleFinding)
	if rec.Code != 200 || !strings.Contains(body, "Canary could not read the check's report") {
		t.Errorf("bad report: status %d", rec.Code)
	}

	// Without a Verify hook the page still offers the command.
	plain := newFixture(t, exampleState(t), nil)
	_, body = plain.get("/findings/" + exampleFinding)
	if !strings.Contains(body, "canary verify ") || strings.Contains(body, "report-steps") {
		t.Error("without Verify the page should show the command and no report")
	}
}

func TestNotProvableFinding(t *testing.T) {
	f := exampleFile(t)
	f.Findings[0].Provable = false
	f.Findings[0].Evidence = nil
	f.Findings[0].Reason = state.FalseChainClaim
	fx := newFixture(t, nil, nil)
	fx.writeFile(f)
	_, body := fx.get("/findings/" + exampleFinding)
	for _, s := range []string{wording.Provable("withheld", false, false), wording.FindingDoesNotShow("withheld", "false_chain_claim")} {
		if !strings.Contains(body, s) {
			t.Errorf("page lacks %q", s)
		}
	}
	if strings.Contains(body, "/evidence/") {
		t.Error("a finding with no evidence file links to one")
	}
}

func TestStripGeometry(t *testing.T) {
	if hatchPeriod-hatchStroke < 3 {
		t.Fatalf("hatch gap is %dpx, want at least 3px", hatchPeriod-hatchStroke)
	}
	f := exampleFile(t)
	f.Coverage = []state.CoverageRange{
		{From: 0, To: 9, State: state.Unverified, Reason: state.NoRecords},
		{From: 10, To: 99, State: state.Unresolvable, Reason: state.GapUnfilled},
		{From: 100, To: 204, State: state.Verified, Reason: state.RecordsAgree},
		{From: 205, To: 205, State: state.Compromised, Reason: state.AbsentInWindow},
		{From: 206, To: 212, State: state.Resolved, Reason: state.HashRetained},
	}
	f.Counts = state.Counts{Unverified: 10, Unresolvable: 90, Verified: 105, Compromised: 1, Resolved: 7}
	v := buildStrip("strip", f)
	if len(v.Segments) != 5 {
		t.Fatalf("%d segments", len(v.Segments))
	}
	if v.Segments[3].X != "96.2441" || v.Segments[3].W != "0.4695" {
		t.Errorf("block 205 drawn at x=%s w=%s", v.Segments[3].X, v.Segments[3].W)
	}
	if len(v.Markers) != 2 {
		t.Errorf("%d markers, want one for each problem range", len(v.Markers))
	}
	want := "Coverage of blocks 0 to 212: 105 Checked; 7 Checked, gap filled; 90 Can't be checked; 10 Not checked; 1 Data withheld."
	if v.Summary != want {
		t.Errorf("summary = %q", v.Summary)
	}
	fx := newFixture(t, nil, nil)
	fx.writeFile(f)
	_, body := fx.get("/blocks")
	for _, s := range []string{`patternUnits="userSpaceOnUse" width="6" height="6"`, `stroke-width="2"`, `fill="url(#strip-hatch)"`, `x="96.2441%"`} {
		if !strings.Contains(body, s) {
			t.Errorf("strip lacks %q", s)
		}
	}
}

// TestNoOutsideReferences keeps the dashboard to its own origin.
func TestNoOutsideReferences(t *testing.T) {
	fx := newFixture(t, exampleState(t), nil)
	outside := regexp.MustCompile(`(?i)(src|action)\s*=\s*"(https?:)?//|<link[^>]+href="(https?:)?//|url\(\s*["']?(https?:)?//|@import`)
	for _, p := range []string{"/", "/blocks", "/blocks/" + exampleBlock, "/findings", "/findings/" + exampleFinding, "/nope"} {
		_, body := fx.get(p)
		if m := outside.FindString(body); m != "" {
			t.Errorf("%s references an outside resource: %s", p, m)
		}
	}
	for name, a := range assets {
		if strings.HasSuffix(name, ".txt") || strings.HasSuffix(name, ".woff2") {
			continue
		}
		if m := outside.FindString(string(a.body)); m != "" {
			t.Errorf("asset %s references an outside resource: %s", name, m)
		}
		if strings.HasSuffix(name, ".js") && regexp.MustCompile(`https?://`).MatchString(string(a.body)) {
			t.Errorf("asset %s names an outside URL", name)
		}
	}
}

func TestAssetRevalidation(t *testing.T) {
	fx := newFixture(t, exampleState(t), nil)
	rec := fx.do(http.MethodGet, "/assets/ui.css")
	etag := rec.Header().Get("ETag")
	if etag == "" || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("asset headers: %v", rec.Header())
	}
	req := httptest.NewRequest(http.MethodGet, "/assets/ui.css", nil)
	req.Host = "localhost"
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	fx.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("revalidation = %d, want 304", rec.Code)
	}
}

func TestFontLicensesShipWithFonts(t *testing.T) {
	for _, f := range []string{"atkinson-hyperlegible-next", "atkinson-hyperlegible-mono"} {
		lic, ok := assets["fonts/OFL-"+f+".txt"]
		if !ok || !bytes.Contains(lic.body, []byte("SIL Open Font License")) {
			t.Errorf("no OFL text next to %s", f)
		}
		font, ok := assets["fonts/"+f+"-latin.woff2"]
		if !ok || !bytes.HasPrefix(font.body, []byte("wOF2")) {
			t.Errorf("%s is not a WOFF2 file", f)
		}
	}
}

// TestCheckAddrMatchesHostCheck pairs the two loopback checks. Every address
// canary ui agrees to listen on must also pass the Host header check, or the
// dashboard would answer every browser request with 421.
func TestCheckAddrMatchesHostCheck(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:7352", "127.0.0.2:7352", "127.255.255.254:80", "localhost:7352", "LOCALHOST:7352",
		"[::1]:7352", "[::ffff:127.0.0.1]:7352",
		"0.0.0.0:7352", "192.168.1.2:7352", "example.com:80", "[::]:7352", "[::2]:7352",
	} {
		listen := CheckAddr(addr) == nil
		host := hostStatus(addr) == 0
		if listen != host {
			t.Errorf("%s: CheckAddr accepts it = %v, Host check accepts it = %v", addr, listen, host)
		}
	}
}

func TestCheckAddr(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:7352": true, "localhost:7352": true, "[::1]:7352": true, "127.0.0.2:80": true,
		"0.0.0.0:7352": false, ":7352": false, "192.168.1.2:7352": false, "example.com:80": false, "127.0.0.1": false,
	} {
		if err := CheckAddr(addr); (err == nil) != ok {
			t.Errorf("CheckAddr(%q) = %v", addr, err)
		}
	}
}

func TestNewNeedsStatePath(t *testing.T) {
	if _, err := New(Options{}); err == nil || !strings.HasPrefix(err.Error(), "ui: ") {
		t.Errorf("New without a state path: %v", err)
	}
}

func TestParseVerifyReport(t *testing.T) {
	b, _ := os.ReadFile(filepath.Join("testdata", "example-report.json"))
	r, err := ParseVerifyReport(b)
	if err != nil {
		t.Fatalf("example report: %v", err)
	}
	if r.Result != "checks_out" || r.Code != "ok" || len(r.Checks) != 8 || r.ReceiptTip.Height != 212 || r.Missing.Index != 1 {
		t.Errorf("report = %+v", r)
	}
	v := buildReport(r)
	if v.Label != "Checks out" || len(v.Steps) != 8 || v.Steps[0].Status != "pass" {
		t.Errorf("view = %+v", v)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	m["verdict"] = "guilty"
	extra, _ := json.Marshal(m)
	if _, err := ParseVerifyReport(extra); err == nil {
		t.Error("a report with an unknown field parsed")
	}
	for _, s := range []string{`{}`, `not json`, `{"result":"checks_out","message":"x","checks":[]}`} {
		if _, err := ParseVerifyReport([]byte(s)); err == nil {
			t.Errorf("ParseVerifyReport(%s) succeeded", s)
		}
	}
}

// verdictSection returns the overview's verdict section.
func verdictSection(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, `<section class="verdict"`)
	if i < 0 {
		t.Fatal("overview has no verdict section")
	}
	j := strings.Index(body[i:], "</section>")
	return body[i : i+j]
}

var anyBadge = regexp.MustCompile(`<span class="badge s-([a-z]+)"><svg class="glyph"[^>]*><use href="#g-([a-z-]+)"></use></svg><span>([^<]+)</span></span>`)

// TestVerdictBadgeNamesItsState keeps a state glyph beside its own word. The
// verdict shows a full state badge only when the headline names one state.
func TestVerdictBadgeNamesItsState(t *testing.T) {
	someChecked := func(t *testing.T) *state.File {
		f := allChecked(t, state.Verified, state.RecordsAgree)
		f.Coverage = []state.CoverageRange{
			{From: 0, To: 200, State: state.Verified, Reason: state.RecordsAgree},
			{From: 201, To: 212, State: state.Unresolvable, Reason: state.GapUnfilled},
		}
		f.Counts = state.Counts{Verified: 201, Unresolvable: 12}
		return f
	}
	tests := []struct {
		name string
		file func(t *testing.T) *state.File
		want string // state code of the badge, or "" for none
	}{
		{"all checked", func(t *testing.T) *state.File { return allChecked(t, state.Verified, state.RecordsAgree) }, "verified"},
		{"all gap filled", func(t *testing.T) *state.File { return allChecked(t, state.Resolved, state.HashRetained) }, "resolved"},
		{"some checked", someChecked, ""},
		{"the example", exampleFile, "compromised"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newFixture(t, nil, nil)
			fx.writeFile(tt.file(t))
			_, body := fx.get("/")
			sec := verdictSection(t, body)
			if strings.Contains(sec, "verdict-glyph") {
				t.Error("the headline carries a bare glyph")
			}
			ms := anyBadge.FindAllStringSubmatch(sec, -1)
			if tt.want == "" {
				if len(ms) != 0 || strings.Contains(sec, `class="glyph"`) {
					t.Errorf("a mixed verdict shows a state glyph: %v", ms)
				}
				return
			}
			if len(ms) != 1 || ms[0][1] != tt.want || ms[0][2] != tt.want || ms[0][3] != wording.State(tt.want).Label {
				t.Errorf("verdict badges = %v, want one %s badge", ms, tt.want)
			}
		})
	}
}

// TestVerdictNamesOpenFindings covers a withholder caught earlier that served
// honestly on this run. Its finding is carried forward, so the headline must
// not read as all clear.
func TestVerdictNamesOpenFindings(t *testing.T) {
	f := allChecked(t, state.Verified, state.RecordsAgree)
	f.Findings = exampleFile(t).Findings
	fx := newFixture(t, nil, nil)
	fx.writeFile(f)
	_, body := fx.get("/")
	sec := verdictSection(t, body)
	want := wording.VerdictOpenFindings(wording.VerdictAllChecked(213), 1)
	if !strings.Contains(sec, `<h1 id="verdict" class="verdict-head">`+want.Headline+`</h1>`) {
		t.Errorf("verdict lacks the headline %q:\n%s", want.Headline, sec)
	}
	if !strings.Contains(sec, want.Lede) {
		t.Errorf("verdict lacks the lede %q", want.Lede)
	}
	ms := anyBadge.FindAllStringSubmatch(sec, -1)
	if len(ms) != 1 || ms[0][1] != "compromised" {
		t.Errorf("verdict badges = %v, want one Data withheld badge", ms)
	}

	// A disagreement alone shows the Servers disagree badge.
	f.Findings[0].Kind = state.KindDisagree
	f.Findings[0].Reason = state.RecordsDiffer
	f.Findings[0].Servers = append(f.Findings[0].Servers, state.ServerRef{Label: "honest"})
	f.Findings[0].Evidence, f.Findings[0].Provable, f.Findings[0].Position, f.Findings[0].Txid = nil, false, nil, nil
	fx.writeFile(f)
	_, body = fx.get("/")
	if ms := anyBadge.FindAllStringSubmatch(verdictSection(t, body), -1); len(ms) != 1 || ms[0][1] != "disputed" {
		t.Errorf("verdict badges = %v, want one Servers disagree badge", ms)
	}

	// Warnings alone leave the verdict as it was: they accuse nobody.
	f.Findings[0].Kind = state.KindWarning
	f.Findings[0].Reason = state.HashWithoutPolicy
	f.Findings[0].Servers = f.Findings[0].Servers[:1]
	fx.writeFile(f)
	_, body = fx.get("/")
	if !strings.Contains(verdictSection(t, body), `class="verdict-head">`+wording.VerdictAllChecked(213).Headline+`</h1>`) {
		t.Error("a warning changed the verdict")
	}
}

// TestAbsentInWindowWithoutReceipt renders the inclusion-only case: the list
// had no receipt, so there is no signed tip and no signed list to claim.
func TestAbsentInWindowWithoutReceipt(t *testing.T) {
	f := exampleFile(t)
	f.Findings[0].Provable = false
	fx := newFixture(t, nil, nil)
	fx.writeFile(f)
	_, body := fx.get("/findings/" + exampleFinding)
	for _, s := range []string{
		wording.FindingShows("withheld", "absent_in_window", false, true),
		wording.Provable("withheld", false, true),
		"your own node's tip",
		`href="/evidence/` + exampleEvidence + `"`,
	} {
		if !strings.Contains(body, s) {
			t.Errorf("finding page lacks %q", s)
		}
	}
	for _, s := range []string{"signed tip", "served and signed", "signed a list"} {
		if strings.Contains(body, s) {
			t.Errorf("a finding without a receipt claims %q", s)
		}
	}
	// The block page and the ranges table use the same reason sentence.
	for _, p := range []string{"/blocks", "/blocks/" + exampleBlock} {
		_, body := fx.get(p)
		if !strings.Contains(body, wording.Reason("absent_in_window")) {
			t.Errorf("%s lacks the absent_in_window reason", p)
		}
		if strings.Contains(wording.Reason("absent_in_window"), "signed tip") {
			t.Errorf("%s: the reason sentence claims a signed tip", p)
		}
	}
}

// TestFindingOutsideResults covers a finding carried forward for a block the
// results hold no detail for. Here it sits at the same height as block 205,
// as after a reorg. It has no block page, so nothing links to one.
func TestFindingOutsideResults(t *testing.T) {
	f := exampleFile(t)
	gone := strings.Repeat("ab", 32)
	old := f.Findings[0]
	old.ID = "aaaaaaaaaaaa"
	old.Block = state.BlockRef{Height: 205, Hash: gone}
	old.Evidence, old.Provable = nil, false
	f.Findings = append(f.Findings, old)
	fx := newFixture(t, nil, nil)
	fx.writeFile(f)

	for _, p := range []string{"/", "/findings", "/findings/aaaaaaaaaaaa"} {
		rec, body := fx.get(p)
		if rec.Code != 200 {
			t.Fatalf("%s = %d", p, rec.Code)
		}
		if strings.Contains(body, `href="/blocks/`+gone+`"`) {
			t.Errorf("%s links to a block page that does not exist", p)
		}
		if !strings.Contains(body, wording.BlockNotCovered) {
			t.Errorf("%s lacks the note for a block outside the results", p)
		}
		if !strings.Contains(body, `href="/blocks/`+exampleBlock+`"`) && p != "/findings/aaaaaaaaaaaa" {
			t.Errorf("%s lost the link to block 205", p)
		}
	}
	if rec := fx.do(http.MethodGet, "/blocks/"+gone); rec.Code != 404 {
		t.Errorf("the carried-forward block has a page: %d", rec.Code)
	}

	// Blocks are keyed by hash: the old finding at the same height is not
	// block 205's finding, so the verdict still names the one withholder.
	_, body := fx.get("/")
	if !strings.Contains(verdictSection(t, body), "Server withholder left out an entry it had signed for.") {
		t.Error("a finding for another block at the same height changed the verdict")
	}
}

// TestNotFoundPagesDoNotEchoTheAddress keeps arbitrary text from the address
// off the page users trust for accusations.
func TestNotFoundPagesDoNotEchoTheAddress(t *testing.T) {
	fx := newFixture(t, exampleState(t), nil)
	for _, p := range []string{
		"/findings/Server%20honest%20is%20the%20liar",
		"/evidence/Server%20honest%20is%20the%20liar",
	} {
		rec, body := fx.get(p)
		if rec.Code != 404 {
			t.Errorf("%s = %d", p, rec.Code)
		}
		if strings.Contains(body, "honest is the liar") {
			t.Errorf("%s echoes the address into the page", p)
		}
	}
	_, body := fx.get("/findings/ffffffffffff")
	if !strings.Contains(body, wording.FindingNotFound("ffffffffffff").Body) {
		t.Error("a well-formed finding id is not named on its 404 page")
	}
	_, body = fx.get("/evidence/not-listed.json")
	if !strings.Contains(body, wording.EvidenceNotFound("not-listed.json").Body) {
		t.Error("a plain evidence name is not named on its 404 page")
	}
}

// TestToneGlyphsAreNotStateGlyphs keeps payment outcomes and verify results
// from wearing a state's symbol, so Pending can't read as Not checked.
func TestToneGlyphsAreNotStateGlyphs(t *testing.T) {
	report, _ := os.ReadFile(filepath.Join("testdata", "example-report.json"))
	f := exampleFile(t)
	f.ExpectedPayments[0].Outcome = "pending"
	fx := newFixture(t, nil, func(o *Options) {
		o.Verify = func([]byte) ([]byte, error) { return report, nil }
	})
	fx.writeFile(f)
	tone := regexp.MustCompile(`class="(?:badge|badge badge-large|step-status) tone-([a-z]+)"><svg class="glyph"[^>]*><use href="#g-([a-z-]+)">`)
	for _, p := range []string{"/", "/blocks/" + exampleBlock, "/findings/" + exampleFinding} {
		_, body := fx.get(p)
		ms := tone.FindAllStringSubmatch(body, -1)
		if len(ms) == 0 {
			t.Errorf("%s shows no tone glyph", p)
		}
		for _, m := range ms {
			if m[2] != "tone-"+m[1] {
				t.Errorf("%s: tone %s wears glyph %s", p, m[1], m[2])
			}
		}
	}
	for _, g := range []string{"tone-good", "tone-bad", "tone-neutral"} {
		if !strings.Contains(string(sprite), `<symbol id="g-`+g+`"`) {
			t.Errorf("the sprite has no %s glyph", g)
		}
	}
}

// TestHeadlinesIntroduceTheServerLabel keeps a lower-case label from opening a
// heading bare. The overview, the findings list and the finding page all say
// "Server withholder left out…", never "withholder left out…".
func TestHeadlinesIntroduceTheServerLabel(t *testing.T) {
	fx := newFixture(t, exampleState(t), nil)
	want := wording.FindingHeadline("withheld", "absent_in_window", []string{"withholder"})
	for _, p := range []string{"/", "/findings", "/findings/" + exampleFinding} {
		_, body := fx.get(p)
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks the headline %q", p, want)
		}
		if strings.Contains(body, ">withholder left out") {
			t.Errorf("%s opens a heading with the bare label", p)
		}
	}
}

// serverRowHTML returns the servers-table row for one label, from the opening
// <tr> to its </tr>.
func serverRowHTML(t *testing.T, body, label string) string {
	t.Helper()
	at := strings.Index(body, `<span class="server-name">`+label+`</span>`)
	if at < 0 {
		t.Fatalf("no servers-table row for %s", label)
	}
	start := strings.LastIndex(body[:at], "<tr")
	end := strings.Index(body[at:], "</tr>")
	if start < 0 || end < 0 {
		t.Fatalf("row for %s is not closed", label)
	}
	return body[start : at+end]
}

// TestServerPolicyAndAnswered keeps a failed /info from reading as a server
// that declared nothing or answered nothing. A failed /info leaves the policy
// unknown. Whether the server answered comes from its records and lists too,
// not from /info alone. Only a server whose /info answered with no policy
// reads Not declared.
func TestServerPolicyAndAnswered(t *testing.T) {
	f := exampleFile(t)
	infoFailed := wording.ServerInfoFailed
	open := f.Servers[0].Policy

	// withholder: /info failed, but it signed records and receipts.
	f.Servers[1].Reachable, f.Servers[1].Policy, f.Servers[1].Error = false, nil, &infoFailed
	f.Servers = append(f.Servers,
		// silent: /info failed and it served nothing.
		state.Server{Label: "silent", URL: "http://127.0.0.1:8083", Pubkey: f.Servers[0].Pubkey, Error: &infoFailed},
		// listonly: pinned as none and /info failed, but it served a list.
		state.Server{Label: "listonly", URL: "http://127.0.0.1:8084", Error: &infoFailed},
		// bare: /info answered as canary-info/1 with no policy in it.
		state.Server{Label: "bare", URL: "http://127.0.0.1:8085", Pubkey: f.Servers[0].Pubkey, Reachable: true},
	)
	f.Blocks[0].Servers = append(f.Blocks[0].Servers, state.BlockServer{
		Label: "listonly", State: state.Unverified, Reason: state.NoRecords,
		Positions: &state.Positions{Full: 1},
	})

	policyOpen := wording.PolicyText(open.PrunesSpent, open.DustThresholdSat, open.Signed)
	tests := []struct {
		label, answered, policy string
	}{
		{"honest", "Yes", policyOpen},
		{"withholder", "Yes", wording.PolicyUnknown},
		{"silent", "No", wording.PolicyUnknown},
		{"listonly", "Yes", wording.PolicyUnknown},
		{"bare", "Yes", wording.PolicyNotDeclared},
	}

	// The view model, field by field.
	rows := map[string]serverRow{}
	for _, r := range buildServers(f) {
		rows[r.Label] = r
	}
	for _, tt := range tests {
		r := rows[tt.label]
		if r.Reachable != tt.answered || r.Policy != tt.policy {
			t.Errorf("%s: answered %q, policy %q; want %q, %q", tt.label, r.Reachable, r.Policy, tt.answered, tt.policy)
		}
	}

	// The rendered table, cell by cell.
	fx := newFixture(t, nil, nil)
	fx.writeFile(f)
	_, body := fx.get("/")
	for _, tt := range tests {
		row := serverRowHTML(t, body, tt.label)
		for _, cell := range []string{
			`data-label="Answered">` + tt.answered + `</td>`,
			`data-label="Declared policy">` + tt.policy + `</td>`,
		} {
			if !strings.Contains(row, cell) {
				t.Errorf("%s's row lacks %q", tt.label, cell)
			}
		}
	}
	if n := strings.Count(body, ">"+wording.PolicyNotDeclared+"<"); n != 1 {
		t.Errorf("%d servers read %q, want only bare", n, wording.PolicyNotDeclared)
	}
}
