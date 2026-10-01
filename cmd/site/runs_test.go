package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// The run recorded on 1 October 2026, as committed. Every fact these tests
// check comes from these files, never from a copy typed into the test.
var (
	committedRun      = filepath.Join("..", "..", "docs", "runs", "2026-10-01")
	committedEvidence = filepath.Join("..", "..", "evidence", "omission-regtest-351-ad56b9bb-db614560.json")
)

const runURL = "/runs/2026-10-01/"

// withCommittedEvidence copies the committed evidence file into the build's
// evidence directory and leaves -evidence unset, as a release build from a
// clone does. The build must find the file on its own.
func withCommittedEvidence(t *testing.T) func(*config) {
	return func(c *config) {
		t.Helper()
		b, err := os.ReadFile(committedEvidence)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(filepath.Dir(c.Docs), "evidence", filepath.Base(committedEvidence))
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatal(err)
		}
		c.Evidence = ""
	}
}

// withRuns publishes the committed recorded runs, with the evidence file
// their finding names.
func withRuns(t *testing.T) func(*config) {
	return both(withCommittedEvidence(t), func(c *config) { c.Runs = filepath.Join(c.Docs, "runs") })
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func readCommitted(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(committedRun, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDefaultEvidence takes the checker's sample from the evidence file the
// repository commits, and falls back to the formats document's example only
// when none is committed.
func TestDefaultEvidence(t *testing.T) {
	root := testRoot(t)
	if got, err := defaultEvidence(root); err != nil || got != "" {
		t.Errorf("with no committed file: got %q, %v; want the example's fallback", got, err)
	}
	name := filepath.Base(committedEvidence)
	b, _ := os.ReadFile(committedEvidence)
	os.WriteFile(filepath.Join(root, "evidence", name), b, 0o644)
	// Files that are not omission evidence do not count.
	os.WriteFile(filepath.Join(root, "evidence", "README.md"), []byte("x"), 0o644)
	if got, err := defaultEvidence(root); err != nil || got != filepath.Join(root, "evidence", name) {
		t.Errorf("with one committed file: got %q, %v", got, err)
	}
	os.WriteFile(filepath.Join(root, "evidence", "omission-regtest-1-aaaaaaaa-bbbbbbbb.json"), b, 0o644)
	if _, err := defaultEvidence(root); err == nil || !strings.Contains(err.Error(), "-evidence") {
		t.Errorf("with two committed files: got %v, want a request to choose with -evidence", err)
	}

	// Through the build: no committed file gives the example, with words that
	// say it is one.
	home := read(t, buildSite(t, nil), "index.html")
	if !strings.Contains(home, htmlText(wording.Site.CheckerSourceExample)) || strings.Contains(home, htmlText(wording.Site.CheckerDownloadReal)) {
		t.Error("a build with no committed evidence file does not offer the formats document's example")
	}
	// The committed file, with -evidence unset, gives the real one.
	dist := buildSite(t, withCommittedEvidence(t))
	if got := read(t, dist, "evidence/"+name); got != string(b) {
		t.Error("the default build does not publish the committed evidence file as it is")
	}
	home = read(t, dist, "index.html")
	if !strings.Contains(home, htmlText(wording.Site.CheckerDownloadReal)) || strings.Contains(home, htmlText(wording.Site.CheckerSourceExample)) {
		t.Error("the default build does not offer the committed evidence file")
	}
}

// TestCheckerUsesTheRecordedRun publishes the real evidence file and a copy
// with one byte changed, and names the run it came from.
func TestCheckerUsesTheRecordedRun(t *testing.T) {
	dist := buildSite(t, both(withRuns(t), withWasm(t, fakeWasm(goodWasm), fakeExec)))
	name := filepath.Base(committedEvidence)
	orig, _ := os.ReadFile(committedEvidence)
	real := read(t, dist, "evidence/"+name)
	if real != string(orig) {
		t.Fatal("the published evidence file differs from the committed one")
	}
	tampered := read(t, dist, "evidence/"+strings.TrimSuffix(name, ".json")+"-tampered.json")
	diff := oneByteDiff(t, real, tampered)

	// The real file checks out and the copy fails at inclusion, as the note
	// says.
	if rep, _ := evidence.Verify([]byte(real)); rep.Result != evidence.ResultChecksOut {
		t.Errorf("the real file reads %s", rep.Result)
	}
	rep, _ := evidence.Verify([]byte(tampered))
	if rep.Result != evidence.ResultDoesNotCheckOut {
		t.Errorf("the tampered copy reads %s", rep.Result)
	}
	checkInclusion(t, []byte(real), true)
	checkInclusion(t, []byte(tampered), false)
	var v, r evidenceProof
	if err := json.Unmarshal([]byte(tampered), &v); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal([]byte(real), &r)
	if v.Proof.Siblings[0] == r.Proof.Siblings[0] || v.Proof.Siblings[1] != r.Proof.Siblings[1] {
		t.Error("the changed byte is not in proof.siblings[0]")
	}

	// The Bitcoin Core release comes from the run's own output.
	out := string(readCommitted(t, "demo-regtest-output.txt"))
	core := coreVersion.FindStringSubmatch(out)
	if core == nil {
		t.Fatal("demo-regtest-output.txt names no Bitcoin Core release")
	}
	home := read(t, dist, "index.html")
	checker := section(t, home, "checker")
	for _, want := range []string{
		htmlText(wording.Site.CheckerSourceRun("regtest", "1 Oct 2026", core[1])),
		`<a href="` + runURL + `">` + htmlText(wording.Site.CheckerSeeRun) + `</a>`,
		htmlText(wording.Site.CheckerTryReal),
		htmlText(wording.Site.CheckerDownloadReal),
		`data-evidence="/evidence/` + name + `"`,
		htmlText(wording.Site.TamperNote(diff+1, "proof.siblings[0]", string(real[diff]), string(tampered[diff]), "inclusion")),
	} {
		if !strings.Contains(checker, want) {
			t.Errorf("the checker lacks %q", want)
		}
	}
	// One spelling of the run's date on every page: the banner's.
	if strings.Contains(home, "October") {
		t.Error("the home page spells the run's date in full, and the run's own pages write 1 Oct 2026")
	}
	if core[1] != "v31.1.0" {
		t.Errorf("the run's output names Bitcoin Core %s; the checker's label names it", core[1])
	}
}

// recordedPages returns every page of the committed run in dist, by its
// path below the run.
func recordedPages(t *testing.T, dist string) map[string]string {
	t.Helper()
	pages := map[string]string{}
	dir := filepath.Join(dist, "runs", "2026-10-01")
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "index.html" {
			return err
		}
		b, err := os.ReadFile(p)
		rel, _ := filepath.Rel(dir, filepath.Dir(p))
		rel = filepath.ToSlash(rel)
		if rel == "." {
			rel = ""
		} else {
			rel += "/"
		}
		pages[rel] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return pages
}

var titleRe = regexp.MustCompile(`<title>([^<]*)</title>`)

// TestRecordedRunPages renders the committed run with the dashboard's
// templates, under a banner on every page, with the state files' hashes,
// absolute times and no live parts.
func TestRecordedRunPages(t *testing.T) {
	dist := buildSite(t, withRuns(t))
	pages := recordedPages(t, dist)

	mainState := readCommitted(t, "state.json")
	act5State := readCommitted(t, "act5/state.json")
	mainSHA, act5SHA := sha256Hex(mainState), sha256Hex(act5State)

	// One page per block and finding in each state file, plus the overview,
	// the blocks page and the findings page.
	for _, want := range []string{"", "blocks/", "findings/", "findings/79ec3cb71656/",
		"blocks/72ef80792f8633d70f19945464df62f82a267b68ee3e113199e9d11a5e41d58a/",
		"act5/", "act5/blocks/", "act5/findings/",
		"act5/blocks/43b08197547822e4a36cc701b4c3d30040c1e4cef990ab60ca83447fbbe9b851/"} {
		if _, ok := pages[want]; !ok {
			t.Errorf("the recording has no page %s%s", runURL, want)
		}
	}

	lead, body := wording.Site.RecordedBanner("regtest", "1 Oct 2026")
	banner := regexp.MustCompile(`(?s)<div class="rec-banner" role="note">(.*?)</div>`)
	statusMain := strings.SplitN(string(readCommitted(t, "status.txt")), "\n", 2)[0]
	statusAct5 := strings.SplitN(string(readCommitted(t, "act5/status.txt")), "\n", 2)[0]
	for rel, page := range pages {
		m := banner.FindStringSubmatch(page)
		if m == nil {
			t.Errorf("%s has no banner", rel)
			continue
		}
		if !strings.Contains(m[1], "<strong>"+htmlText(lead)+"</strong> "+htmlText(body)) {
			t.Errorf("%s: banner reads %q", rel, m[1])
		}
		if strings.Contains(m[1], "<button") {
			t.Errorf("%s: the banner has a button, and nothing may dismiss it", rel)
		}
		if strings.Index(page, `class="rec-banner"`) > strings.Index(page, "<h1") {
			t.Errorf("%s: the banner comes after the page's heading", rel)
		}
		if tm := titleRe.FindStringSubmatch(page); tm == nil || !strings.HasPrefix(tm[1], "Recorded: ") {
			t.Errorf("%s: title %v does not start with Recorded:", rel, tm)
		}
		for _, live := range []string{"live.js", "data-etag", `id="update-bar"`, "/state.etag", "<form", " ago)", "min ago", "just now"} {
			if strings.Contains(page, live) {
				t.Errorf("%s holds %q, a live part a recording must not show", rel, live)
			}
		}
		sha, status := mainSHA, statusMain
		if strings.HasPrefix(rel, "act5/") {
			sha, status = act5SHA, statusAct5
		}
		if !strings.Contains(page, sha) {
			t.Errorf("%s does not show the SHA-256 of the state file it renders", rel)
		}
		if !strings.Contains(page, htmlText(status)) {
			t.Errorf("%s lacks the status line %q, as canary status printed it", rel, status)
		}
	}

	// The overview lists every file of the run, with its hash, and the
	// evidence file the finding names.
	ov := pages[""]
	err := filepath.WalkDir(committedRun, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(committedRun, p)
		rel = filepath.ToSlash(rel)
		b, _ := os.ReadFile(p)
		if got := read(t, dist, "runs/2026-10-01/"+rel); got != string(b) {
			t.Errorf("the site's copy of %s differs from the committed file", rel)
		}
		if !strings.Contains(ov, `href="`+runURL+rel+`"`) || !strings.Contains(ov, sha256Hex(b)) {
			t.Errorf("the overview does not link %s with its SHA-256", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	evName := filepath.Base(committedEvidence)
	ev, _ := os.ReadFile(committedEvidence)
	for _, want := range []string{
		`href="/evidence/` + evName + `"`, sha256Hex(ev),
		`href="` + runURL + `act5/"`,
		htmlText(wording.Site.RecordedNoAccusation),
		htmlText(wording.Reason("gap_unfilled")),
		"shasum -a 256 docs/runs/2026-10-01/state.json docs/runs/2026-10-01/act5/state.json",
	} {
		if !strings.Contains(ov, want) {
			t.Errorf("the overview lacks %q", want)
		}
	}

	// The finding page carries Canary's check of the committed file.
	fp := pages["findings/79ec3cb71656/"]
	verify := string(readCommitted(t, "verify.txt"))
	for _, want := range []string{"Entry 0 of 5 proves into the signed root.", "covers these 269 bytes",
		"The server's signed tip was 351, so the block was 0 blocks deep"} {
		if !strings.Contains(verify, want) {
			t.Fatalf("verify.txt no longer says %q; this test reads its facts from there", want)
		}
		if !strings.Contains(fp, htmlText(want)) {
			t.Errorf("the finding page lacks %q", want)
		}
	}
	if !strings.Contains(fp, "./canary verify evidence/"+evName) || !strings.Contains(fp, `href="/evidence/`+evName+`"`) {
		t.Error("the finding page does not offer the committed evidence file")
	}

	// Act 5's block reads Can't be checked, and its run names no finding.
	a5 := pages["act5/blocks/43b08197547822e4a36cc701b4c3d30040c1e4cef990ab60ca83447fbbe9b851/"]
	if !strings.Contains(a5, htmlText(wording.State("unresolvable").Label)) {
		t.Error("act 5's block 201 does not read Can't be checked")
	}
	if strings.Contains(pages["act5/"], `class="finding-item"`) {
		t.Error("act 5 lists a finding")
	}

	// No asset the site ships polls a server.
	walkDist(t, dist, []string{".js"}, func(rel, body string) {
		if path.Base(rel) == "live.js" || strings.Contains(body, "/state.etag") {
			t.Errorf("the site ships %s, which polls the dashboard's server", rel)
		}
	})
}

// TestRunsIndexListsTheRun keeps the committed run on the runs index, with
// what it checked and found.
func TestRunsIndexListsTheRun(t *testing.T) {
	dist := buildSite(t, withRuns(t))
	page := read(t, dist, "runs/index.html")
	for _, want := range []string{
		`href="` + runURL + `"`,
		htmlText(wording.Site.RecordedRunTitle("1 Oct 2026")),
		htmlText(wording.Site.RunsAbout),
		sha256Hex(readCommitted(t, "state.json")),
		`href="` + runURL + `findings/79ec3cb71656/"`,
		`href="` + runURL + `act5/"`,
		htmlText(wording.Site.RecordedRange("", 0, 351, 2)),
		htmlText(wording.Site.RecordedRange("Act 5", 201, 201, 1)),
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the runs index lacks %q", want)
		}
	}
	if strings.Contains(page, htmlText(wording.Site.RunsEmpty)) {
		t.Error("the runs index says no run is published")
	}
	// Without runs it says so.
	if !strings.Contains(read(t, buildSite(t, nil), "runs/index.html"), htmlText(wording.Site.RunsEmpty)) {
		t.Error("with no run, the runs index does not say none is published")
	}
}
