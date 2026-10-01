package ui

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// The recorded run committed in docs/runs. These tests render it as the
// public site does, so a change to the dashboard that breaks the recording
// fails here first.
var (
	recordedRun      = filepath.Join("..", "..", "docs", "runs", "2026-10-01")
	recordedEvidence = filepath.Join("..", "..", "evidence", "omission-regtest-351-ad56b9bb-db614560.json")
)

const recordedBase = "/runs/2026-10-01/"

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// verifyJSON is what canary verify --json prints for a file.
func verifyJSON(b []byte) ([]byte, error) {
	rep, _ := evidence.Verify(b)
	return json.Marshal(rep)
}

func recordedOptions(t *testing.T, statePath string) StaticOptions {
	t.Helper()
	ev := readFile(t, recordedEvidence)
	name := filepath.Base(recordedEvidence)
	return StaticOptions{
		State:         readFile(t, statePath),
		Base:          recordedBase,
		EvidenceURL:   func(n string) string { return "/evidence/" + n },
		VerifyCommand: func(n string) string { return "./canary verify evidence/" + n },
		Evidence: func(n string) ([]byte, error) {
			if n != name {
				return nil, fs.ErrNotExist
			}
			return ev, nil
		},
		Verify: verifyJSON,
	}
}

var hrefRe = regexp.MustCompile(`\shref="([^"]*)"`)

// checkStaticPage holds every recorded page to the rules of a recording: no
// live parts, and every link inside the recording or to its evidence file.
func checkStaticPage(t *testing.T, p StaticPage) {
	t.Helper()
	body := string(p.Content) + string(p.Nav)
	for _, bad := range []string{"<form", "update-bar", "data-etag", "/state.etag", " ago)", "min ago", "just now"} {
		if strings.Contains(body, bad) {
			t.Errorf("page %q holds %q, a live part a recording must not show", p.Path, bad)
		}
	}
	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		h := m[1]
		if !strings.HasPrefix(h, recordedBase) && !strings.HasPrefix(h, "/evidence/") && !strings.HasPrefix(h, "#") {
			t.Errorf("page %q links %q, outside the recording", p.Path, h)
		}
	}
}

func TestRenderStaticRecordedRun(t *testing.T) {
	run, err := RenderStatic(recordedOptions(t, filepath.Join(recordedRun, "state.json")))
	if err != nil {
		t.Fatal(err)
	}
	f := run.File
	if want := 3 + len(f.Blocks) + len(f.Findings); len(run.Pages) != want {
		t.Fatalf("got %d pages, want %d", len(run.Pages), want)
	}
	// The status line reads as canary status printed it after the run.
	status := strings.SplitN(string(readFile(t, filepath.Join(recordedRun, "status.txt"))), "\n", 2)[0]
	if run.StatusLine != status {
		t.Errorf("status line\n got %q\nwant %q, the first line of status.txt", run.StatusLine, status)
	}
	if run.NetworkBadge != wording.RecordedRegtestBadge {
		t.Errorf("network badge %q", run.NetworkBadge)
	}

	pages := map[string]StaticPage{}
	for _, p := range run.Pages {
		if _, dup := pages[p.Path]; dup {
			t.Errorf("two pages at %q", p.Path)
		}
		pages[p.Path] = p
		checkStaticPage(t, p)
	}

	// Every link inside the recording names a page it rendered.
	for _, p := range run.Pages {
		for _, m := range hrefRe.FindAllStringSubmatch(string(p.Content)+string(p.Nav), -1) {
			target, _, _ := strings.Cut(m[1], "#")
			if rel, ok := strings.CutPrefix(target, recordedBase); ok {
				if _, ok := pages[rel]; !ok {
					t.Errorf("page %q links %q, which the recording did not render", p.Path, m[1])
				}
			}
		}
	}

	ov := string(pages[""].Content)
	for _, want := range []string{
		htmlEsc("Server withholder left out an entry it had signed for."),
		`href="` + recordedBase + `blocks/"`,
		`href="` + recordedBase + `findings/79ec3cb71656/"`,
		`href="` + recordedBase + `blocks/72ef80792f8633d70f19945464df62f82a267b68ee3e113199e9d11a5e41d58a/"`,
		`id="servers"`,
	} {
		if !strings.Contains(ov, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	nav := string(pages[""].Nav)
	for _, want := range []string{`aria-label="` + wording.RecordedNavLabel + `"`, `href="` + recordedBase + `" aria-current="page"`, `href="` + recordedBase + `#servers"`, "Findings (1)"} {
		if !strings.Contains(nav, want) {
			t.Errorf("overview links lack %q:\n%s", want, nav)
		}
	}

	fp := string(pages["findings/79ec3cb71656/"].Content)
	name := filepath.Base(recordedEvidence)
	for _, want := range []string{
		`href="/evidence/` + name + `"`,
		"./canary verify evidence/" + name,
		htmlEsc(wording.VerifyResultLabel("checks_out", "ok")),
		htmlEsc("Entry 0 of 5 proves into the signed root."),
		htmlEsc("covers these 269 bytes"),
		"2026-10-01 12:35 UTC",
	} {
		if !strings.Contains(fp, want) {
			t.Errorf("finding page lacks %q", want)
		}
	}
	if n := strings.Count(fp, `class="step step-pass"`); n != 8 {
		t.Errorf("finding page shows %d passed steps, want 8", n)
	}
	if strings.Contains(fp, "demo-out") {
		t.Error("finding page names the run's demo-out directory, which a reader's clone lacks")
	}
}

func htmlEsc(s string) string { return template.HTMLEscapeString(s) }

func TestRenderStaticAct5(t *testing.T) {
	run, err := RenderStatic(recordedOptions(t, filepath.Join(recordedRun, "act5", "state.json")))
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Pages) != 4 || len(run.File.Findings) != 0 {
		t.Fatalf("got %d pages and %d findings, want 4 pages and none", len(run.Pages), len(run.File.Findings))
	}
	for _, p := range run.Pages {
		checkStaticPage(t, p)
	}
	block := run.Pages[2]
	if block.Title != "Block 201" {
		t.Fatalf("third page is %q, want Block 201", block.Title)
	}
	for _, want := range []string{
		htmlEsc(wording.State("unresolvable").Label),
		htmlEsc(wording.Reason("gap_unfilled")),
	} {
		if !strings.Contains(string(block.Content), want) {
			t.Errorf("block 201 lacks %q", want)
		}
	}
	// Can't be checked is no accusation: the overview lists no finding.
	ov := string(run.Pages[0].Content)
	if strings.Contains(ov, `class="finding-item"`) || !strings.Contains(ov, htmlEsc(wording.NoFindings)) {
		t.Error("act 5's overview lists a finding")
	}
}

func TestRenderStaticRefuses(t *testing.T) {
	o := recordedOptions(t, filepath.Join(recordedRun, "state.json"))
	for name, mutate := range map[string]func(*StaticOptions){
		"base without slashes": func(o *StaticOptions) { o.Base = "runs/x" },
		"no evidence link":     func(o *StaticOptions) { o.EvidenceURL = nil },
		"unreadable evidence": func(o *StaticOptions) {
			o.Evidence = func(string) ([]byte, error) { return nil, errors.New("gone") }
		},
		"not a state file": func(o *StaticOptions) { o.State = []byte(`{}`) },
	} {
		c := o
		mutate(&c)
		if _, err := RenderStatic(c); err == nil {
			t.Errorf("%s: RenderStatic gave no error", name)
		}
	}
}

// TestDashboardKeepsItsLinks keeps the live dashboard's addresses as they
// were, and its update check in live.js, which the public site never loads.
func TestDashboardKeepsItsLinks(t *testing.T) {
	fx := newFixture(t, exampleState(t), nil)
	_, body := fx.get("/")
	for _, want := range []string{`<a href="/blocks">Range table</a>`, `<script src="/assets/live.js" defer></script>`,
		`aria-label="` + wording.DashboardNavLabel + `"`, `<a href="/#servers">Servers</a>`} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard overview lacks %q", want)
		}
	}
	app, _ := fs.ReadFile(Assets(), "app.js")
	live, _ := fs.ReadFile(Assets(), "live.js")
	if strings.Contains(string(app), "/state.etag") || !strings.Contains(string(live), "/state.etag") {
		t.Error("the update check is not in live.js alone")
	}
}
