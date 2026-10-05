package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"html"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/nbd-wtf/go-nostr"
)

const testRepo = "https://github.com/Sky-walkerX/canary"

// exampleEvidence is the formats document's example file. Tests use it as a
// fixture only. A release build takes the real file from the recorded run.
const exampleEvidence = "../../internal/ui/testdata/omission-regtest-205-01982d71-b1070620.json"

// testRoot lays out a repository for one build. Its docs directory links to
// the real docs, cmd/canary holds a stub, and evidence/ starts empty. A
// release build checks that the last two exist.
func testRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	docs, err := filepath.Abs(filepath.Join("..", "..", "docs"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(docs, filepath.Join(root, "docs")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(root, "cmd", "canary"), filepath.Join(root, "evidence")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "cmd", "canary", "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func testConfig(t *testing.T) config {
	t.Helper()
	return config{
		Out:     filepath.Join(t.TempDir(), "dist"),
		Docs:    filepath.Join(testRoot(t), "docs"),
		Headers: filepath.Join("..", "..", "site", "_headers"),
		Repo:    testRepo,
		NoIndex: true,
	}
}

// withEvidence copies an evidence file into the build's evidence directory,
// where a release keeps it, and points the build at the copy.
func withEvidence(t *testing.T, src string) func(*config) {
	return func(c *config) {
		t.Helper()
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(filepath.Dir(c.Docs), "evidence", filepath.Base(src))
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatal(err)
		}
		c.Evidence = dst
	}
}

func buildSite(t *testing.T, mutate func(*config)) string {
	t.Helper()
	cfg := testConfig(t)
	if mutate != nil {
		mutate(&cfg)
	}
	if err := build(cfg); err != nil {
		t.Fatalf("build: %v", err)
	}
	return cfg.Out
}

func read(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var pagesWant = map[string]wording.SitePage{
	"index.html":              wording.Site.Home,
	"how-it-works/index.html": wording.Site.HowItWorks,
	"faq/index.html":          wording.Site.FAQ,
	"glossary/index.html":     wording.Site.Glossary,
	"runs/index.html":         wording.Site.Runs,
	"404.html":                wording.Site.NotFound,
}

func TestEveryPageRenders(t *testing.T) {
	dist := buildSite(t, nil)
	for name, meta := range pagesWant {
		body := read(t, dist, name)
		for _, want := range []string{
			`<html lang="en">`,
			`<meta name="robots" content="noindex">`,
			`<meta name="description" content="` + attr(meta.Description) + `">`,
			`<meta property="og:title" content="` + attr(meta.Title) + `">`,
			`<meta property="og:description" content="` + attr(meta.Description) + `">`,
			`<link rel="icon" href="/favicon.svg" type="image/svg+xml">`,
			`<link rel="icon" href="/favicon.png" type="image/png" sizes="32x32">`,
			`<main id="main"`,
			`<a class="wordmark" href="/">Canary</a>`,
			wording.Framing,
			`href="` + testRepo + `"`,
			wording.Site.FooterNoRequests,
			`id="g-verified"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
		if !strings.Contains(body, "<title>"+htmlText(meta.Title)) {
			t.Errorf("%s has the wrong title", name)
		}
		if n := strings.Count(body, "<h1"); n != 1 {
			t.Errorf("%s has %d h1 elements, want 1", name, n)
		}
	}
	for _, name := range []string{"_headers", "favicon.svg", "favicon.png", "apple-touch-icon.png"} {
		if _, err := os.Stat(filepath.Join(dist, name)); err != nil {
			t.Errorf("dist lacks %s", name)
		}
	}
}

func attr(s string) string {
	return strings.NewReplacer(`&`, "&amp;", `"`, "&#34;", `'`, "&#39;", `<`, "&lt;", `>`, "&gt;").Replace(s)
}

func htmlText(s string) string {
	return strings.NewReplacer(`&`, "&amp;", `"`, "&#34;", `'`, "&#39;", `<`, "&lt;", `>`, "&gt;").Replace(s)
}

func TestNoindexFlag(t *testing.T) {
	dist := buildSite(t, both(withWasm(t, fakeWasm(goodWasm), fakeExec), func(c *config) { c.NoIndex = false }))
	for name := range pagesWant {
		if strings.Contains(read(t, dist, name), `name="robots"`) {
			t.Errorf("%s keeps a robots meta tag with -noindex=false", name)
		}
	}
	if strings.Contains(read(t, dist, "_headers"), "X-Robots-Tag") {
		t.Error("_headers keeps X-Robots-Tag with -noindex=false")
	}
	if !strings.Contains(read(t, buildSite(t, nil), "_headers"), "X-Robots-Tag: noindex") {
		t.Error("_headers lacks X-Robots-Tag: noindex by default")
	}
}

func TestHeadersFile(t *testing.T) {
	h := read(t, buildSite(t, nil), "_headers")
	// One rule per pattern. A second /* block, which the -noindex build used to
	// append, made Cloudflare Pages drop the first block's security headers.
	if n := strings.Count(h, "\n/*\n"); n != 1 {
		t.Errorf("_headers has %d \"/*\" blocks, want 1", n)
	}
	for _, want := range []string{
		"Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; " +
			"style-src 'self'; font-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
		"Strict-Transport-Security: max-age=",
		"X-Content-Type-Options: nosniff",
		"Referrer-Policy: no-referrer",
		"/*.wasm\n  Content-Type: application/wasm",
		"/assets/*\n  Cache-Control: public, max-age=31536000, immutable",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("_headers lacks %q", want)
		}
	}
	for i, line := range strings.Split(h, "\n") {
		if len(line) > 2000 {
			t.Errorf("_headers line %d is %d characters; Cloudflare Pages allows 2,000", i+1, len(line))
		}
	}
}

// walkDist calls fn for every file in dist with the given extensions.
func walkDist(t *testing.T, dist string, exts []string, fn func(rel, body string)) {
	t.Helper()
	err := filepath.WalkDir(dist, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		for _, e := range exts {
			if strings.HasSuffix(p, e) {
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(dist, p)
				fn(filepath.ToSlash(rel), string(b))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestNoExternalURLs keeps the site to its own origin. The one outside
// address allowed is the repository, as a link.
func TestNoExternalURLs(t *testing.T) {
	dist := buildSite(t, both(withRuns(t), withWasm(t, fakeWasm(goodWasm), fakeExec)))
	url := regexp.MustCompile(`(?i)(https?:)?//[a-z0-9.-]+\.[a-z]{2,}[^\s"'<>)]*`)
	allowed := []string{testRepo, "http://www.w3.org/2000/svg", "http://www.w3.org/1999/xlink"}
	n := 0
	walkDist(t, dist, []string{".html", ".css", ".js", ".svg", ".json", ".txt", "_headers"}, func(rel, body string) {
		n++
		// The font licences must ship as written, and they cite their own
		// addresses. Nothing loads them.
		if strings.Contains(rel, "/fonts/OFL-") {
			return
		}
		for _, m := range url.FindAllString(body, -1) {
			ok := false
			for _, a := range allowed {
				if strings.HasPrefix(m, a) {
					ok = true
				}
			}
			// The evidence file names the regtest indexer it came from, on
			// the checker's own machine. It is data, never loaded.
			if strings.HasPrefix(rel, "evidence/") && strings.HasPrefix(m, "http://127.0.0.1") {
				ok = true
			}
			if !ok {
				t.Errorf("%s refers to %s", rel, m)
			}
		}
	})
	if n < 8 {
		t.Errorf("checked only %d files", n)
	}
}

var (
	attrRe = regexp.MustCompile(`\s(href|src)="([^"]*)"`)
	idRe   = regexp.MustCompile(`\sid="([^"]+)"`)
)

// TestInternalLinksResolve follows every same-site link and checks that its
// file exists in dist and that its fragment names an element on that page.
func TestInternalLinksResolve(t *testing.T) {
	dist := buildSite(t, both(withRuns(t), withWasm(t, fakeWasm(goodWasm), fakeExec)))
	ids := map[string]map[string]bool{}
	pageIDs := func(rel string) map[string]bool {
		if m, ok := ids[rel]; ok {
			return m
		}
		m := map[string]bool{}
		for _, x := range idRe.FindAllStringSubmatch(read(t, dist, rel), -1) {
			m[x[1]] = true
		}
		ids[rel] = m
		return m
	}
	links := 0
	reached := map[string]bool{}
	walkDist(t, dist, []string{".html"}, func(rel, body string) {
		for _, m := range attrRe.FindAllStringSubmatch(body, -1) {
			ref := strings.ReplaceAll(m[2], "&amp;", "&")
			if strings.HasPrefix(ref, "http") || strings.HasPrefix(ref, "mailto:") {
				continue
			}
			links++
			target, frag, _ := strings.Cut(ref, "#")
			var file string
			switch {
			case target == "":
				file = rel
			case strings.HasPrefix(target, "/"):
				file = strings.TrimPrefix(target, "/")
				if file == "" || strings.HasSuffix(file, "/") {
					file += "index.html"
				}
			default:
				t.Errorf("%s has a relative link %q; the site links from its root", rel, ref)
				continue
			}
			if _, err := os.Stat(filepath.Join(dist, filepath.FromSlash(file))); err != nil {
				t.Errorf("%s links to %q, which is not in dist", rel, ref)
				continue
			}
			reached[file] = true
			if frag != "" && path.Ext(file) == ".html" && !pageIDs(file)[frag] {
				t.Errorf("%s links to %q, and %s has no id %q", rel, ref, file, frag)
			}
		}
	})
	if links < 50 {
		t.Errorf("followed only %d links", links)
	}
	// The recorded run is part of the walk: its pages, raw files and the
	// evidence file its finding names.
	for _, rel := range []string{"runs/2026-10-01/index.html", "runs/2026-10-01/act5/index.html",
		"runs/2026-10-01/check.txt", "runs/2026-10-01/verify.txt", "runs/2026-10-01/status.txt",
		"runs/2026-10-01/act5/check.txt", "runs/2026-10-01/act5/state.json",
		"runs/2026-10-01/findings/79ec3cb71656/index.html",
		"evidence/omission-regtest-351-ad56b9bb-db614560.json"} {
		if !reached[rel] {
			t.Errorf("no link leads to %s", rel)
		}
	}
}

// TestPagesFollowTheCSP keeps every page inside style-src 'self' and
// script-src 'self': no inline styles, scripts or event handlers. A JSON
// data block is not a script, never runs, and the CSP does not cover it.
func TestPagesFollowTheCSP(t *testing.T) {
	dist := buildSite(t, both(withRuns(t), withWasm(t, fakeWasm(goodWasm), fakeExec)))
	inline := regexp.MustCompile(`(?i)<style|\sstyle="|\son[a-z]+="|javascript:`)
	inlineScript := regexp.MustCompile(`(?is)<script(\s[^>]*)?>([^<]*)</script>`)
	script := regexp.MustCompile(`<script[^>]*src="([^"]+)"`)
	blocks := 0
	walkDist(t, dist, []string{".html"}, func(rel, body string) {
		if m := inline.FindString(body); m != "" {
			t.Errorf("%s has inline code the CSP blocks: %q", rel, m)
		}
		for _, m := range inlineScript.FindAllStringSubmatch(body, -1) {
			switch {
			case strings.TrimSpace(m[2]) == "":
			case strings.Contains(m[1], `type="application/json"`):
				blocks++
			default:
				t.Errorf("%s has an inline script the CSP blocks: %q", rel, m[0][:min(len(m[0]), 80)])
			}
		}
		for _, m := range script.FindAllStringSubmatch(body, -1) {
			if !strings.HasPrefix(m[1], "/assets/") {
				t.Errorf("%s loads a script from %s", rel, m[1])
			}
		}
	})
	if blocks != 1 {
		t.Errorf("found %d JSON data blocks, want the checker's one", blocks)
	}
}

func TestAssetsAreFingerprinted(t *testing.T) {
	dist := buildSite(t, nil)
	home := read(t, dist, "index.html")
	css := regexp.MustCompile(`href="(/assets/[0-9a-f]{12}/tokens\.css)"`).FindStringSubmatch(home)
	if css == nil {
		t.Fatalf("home does not load tokens.css from a hashed directory")
	}
	dir := path.Dir(css[1])
	for _, name := range []string{"tokens.css", "ui.css", "site.css", "app.js",
		"fonts/geist-latin.woff2", "fonts/jetbrains-mono-latin.woff2",
		"fonts/OFL-geist.txt", "fonts/OFL-jetbrains-mono.txt"} {
		if _, err := os.Stat(filepath.Join(dist, filepath.FromSlash(dir), name)); err != nil {
			t.Errorf("%s lacks %s", dir, name)
		}
	}
	// The same inputs give the same directory, so a redeploy of unchanged
	// assets keeps browsers' cached copies.
	if again := read(t, buildSite(t, nil), "index.html"); !strings.Contains(again, css[1]) {
		t.Error("the asset directory changes between identical builds")
	}
}

var (
	svgElem    = regexp.MustCompile(`(?s)<svg\b.*?</svg>`)
	scriptElem = regexp.MustCompile(`(?s)<script\b.*?</script>`)
)

// hiddenElems match an element rendered hidden, one pattern per tag name, so
// the match ends at that element's own closing tag. The site never nests an
// element inside another of the same name within a hidden one, so the first
// closing tag of that name is the element's own.
var hiddenElems = func() []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, tag := range []string{"section", "div", "label", "p", "span", "button"} {
		out = append(out, regexp.MustCompile(`(?s)<`+tag+`\b[^>]*\shidden\b[^>]*>.*?</`+tag+`>`))
	}
	return out
}()

// withoutHidden returns the markup with every hidden element cut out.
func withoutHidden(page string) string {
	for _, re := range hiddenElems {
		page = re.ReplaceAllString(page, " ")
	}
	return page
}

// visibleText is the text a reader sees before any script runs: the page
// without its hidden elements, scripts, drawings and tags.
func visibleText(page string) string {
	page = withoutHidden(page)
	page = scriptElem.ReplaceAllString(page, " ")
	page = svgElem.ReplaceAllString(page, " ")
	page = anyTag.ReplaceAllString(page, " ")
	return spaces.ReplaceAllString(html.UnescapeString(page), " ")
}

// section returns the element that opens with the given id, up to its first
// closing section tag.
func section(t *testing.T, page, id string) string {
	t.Helper()
	at := strings.Index(page, `id="`+id+`"`)
	if at < 0 {
		t.Fatalf("the page has no section %q", id)
	}
	rest := page[at:]
	return rest[:strings.Index(rest, "</section>")]
}

// TestCheckerClaimsOnlyWhatExists keeps the page from saying the browser
// checks a file before it can. Those sentences wait in hidden elements that
// the checker script reveals once the module is ready, and a page built
// without the module never reveals them.
func TestCheckerClaimsOnlyWhatExists(t *testing.T) {
	builds := map[string]func(*config){
		"example":             nil,
		"recorded":            withEvidence(t, exampleEvidence),
		"example with module": withWasm(t, fakeWasm(goodWasm), fakeExec),
	}
	for name, mutate := range builds {
		home := read(t, buildSite(t, mutate), "index.html")
		shown := strings.ToLower(visibleText(home))
		if strings.Contains(shown, "browser") {
			i := strings.Index(shown, "browser")
			t.Errorf("%s: the page shows a claim about the browser before the checker exists: %q", name, shown[max(0, i-80):i+20])
		}
		for _, live := range []string{wording.Site.CheckerInBrowser, wording.Site.CheckerPrivacy} {
			re := regexp.MustCompile(`<[a-z]+[^>]*\sdata-checker-live\s[^>]*hidden[^>]*>` + regexp.QuoteMeta(htmlText(live)))
			if !re.MatchString(home) {
				t.Errorf("%s: %q is not in a hidden data-checker-live element", name, live)
			}
		}
		// The sentence that is always true stays in view.
		if !strings.Contains(visibleText(home), wording.Site.CheckerIntro) {
			t.Errorf("%s: the checker's intro is not visible", name)
		}
	}
}

func TestCheckerWithEvidence(t *testing.T) {
	dist := buildSite(t, withEvidence(t, exampleEvidence))
	name := filepath.Base(exampleEvidence)
	real := read(t, dist, "evidence/"+name)
	orig, _ := os.ReadFile(exampleEvidence)
	if real != string(orig) {
		t.Fatal("the published evidence file differs from its source")
	}
	tampered := read(t, dist, "evidence/"+strings.TrimSuffix(name, ".json")+"-tampered.json")
	diff := oneByteDiff(t, real, tampered)
	var v, r evidenceProof
	if err := json.Unmarshal([]byte(tampered), &v); err != nil {
		t.Fatalf("the tampered copy is not JSON: %v", err)
	}
	json.Unmarshal([]byte(real), &r)
	if v.Proof.Siblings[0] == r.Proof.Siblings[0] || v.Proof.Siblings[1] != r.Proof.Siblings[1] {
		t.Error("the flipped byte is not in proof.siblings[0]")
	}
	note := wording.Site.TamperNote(diff+1, "proof.siblings[0]", string(real[diff]), string(tampered[diff]), "inclusion")
	home := read(t, dist, "index.html")
	if !strings.Contains(home, htmlText(note)) {
		t.Errorf("home lacks the exact tamper note %q", note)
	}
	for _, want := range []string{
		`data-evidence="/evidence/` + name + `"`,
		`href="/evidence/` + name + `"`,
		`data-copy="./canary verify evidence/` + name + `"`,
		htmlText(wording.Site.CheckerPending),
		htmlText(wording.Site.CheckerNoScript),
		htmlText(wording.Site.CheckerSourceRecorded("3 Oct 2026")),
		htmlText(wording.Site.RunIntro),
		htmlText(wording.Site.RunAfter),
	} {
		if !strings.Contains(home, want) {
			t.Errorf("home lacks %q", want)
		}
	}
	for _, gone := range []string{
		wording.Site.CheckerSourceExample,
		wording.Site.RunIntroNoEvidence,
		wording.Site.RunPlaceholderNote,
	} {
		if strings.Contains(home, htmlText(gone)) {
			t.Errorf("home shows %q although an evidence file was given", gone)
		}
	}
	if n := strings.Count(section(t, home, "run-h"), `data-copy="`); n != 3 {
		t.Errorf("the run section offers %d commands to copy, want 3", n)
	}
	checkInclusion(t, []byte(real), true)
	checkInclusion(t, []byte(tampered), false)
}

// oneByteDiff returns the offset of the one byte where a and b differ, and
// fails the test unless exactly one byte differs.
func oneByteDiff(t *testing.T, a, b string) int {
	t.Helper()
	if len(a) != len(b) {
		t.Fatal("the tampered copy has a different length")
	}
	diff := -1
	for i := range a {
		if a[i] != b[i] {
			if diff >= 0 {
				t.Fatal("the tampered copy changes more than one byte")
			}
			diff = i
		}
	}
	if diff < 0 {
		t.Fatal("the tampered copy changes nothing")
	}
	return diff
}

type evidenceProof struct {
	Proof struct {
		Siblings []string `json:"siblings"`
	} `json:"proof"`
	Missing struct {
		Txid string `json:"txid"`
	} `json:"missing"`
}

// checkInclusion runs the evidence file's inclusion step: the proof must
// carry the left-out entry to the root the server signed. It is the step a
// tampered copy fails, whichever value the copy changed.
func checkInclusion(t *testing.T, file []byte, want bool) {
	t.Helper()
	var ev struct {
		Event   nostr.Event `json:"commitment_event"`
		Missing struct {
			Txid  string `json:"txid"`
			Tweak string `json:"tweak"`
		} `json:"missing"`
		Proof struct {
			Index    uint32   `json:"index"`
			N        uint32   `json:"n"`
			Siblings []string `json:"siblings"`
		} `json:"proof"`
	}
	if err := json.Unmarshal(file, &ev); err != nil {
		t.Fatalf("evidence file: %v", err)
	}
	c, err := feed.FromEvent(ev.Event)
	if err != nil {
		t.Fatalf("evidence file's record: %v", err)
	}
	var leaf canonical.Leaf
	if leaf.TxID, err = core.ParseDisplayHash(ev.Missing.Txid); err != nil {
		t.Fatalf("evidence file's txid: %v", err)
	}
	tweak, err := hex.DecodeString(ev.Missing.Tweak)
	if err != nil || copy(leaf.Tweak[:], tweak) != 33 {
		t.Fatalf("evidence file's tweak %q", ev.Missing.Tweak)
	}
	p := commit.Proof{Index: ev.Proof.Index, N: ev.Proof.N}
	for _, s := range ev.Proof.Siblings {
		var h [32]byte
		if b, err := hex.DecodeString(s); err != nil || copy(h[:], b) != 32 {
			t.Fatalf("evidence file's sibling %q", s)
		}
		p.Siblings = append(p.Siblings, h)
	}
	if got := p.N == c.N && commit.VerifyProof(c.Network, c.BlockHash, c.Root, leaf, p); got != want {
		t.Errorf("inclusion step: got %v, want %v", got, want)
	}
}

// oneEntryEvidence writes an evidence file for a block whose signed record
// holds a single entry. Its proof has no siblings, as the evidence package
// writes it for n = 1. It carries no receipt, which the format allows.
func oneEntryEvidence(t *testing.T) string {
	t.Helper()
	var leaf canonical.Leaf
	leaf.TxID[0], leaf.TxID[31] = 0x16, 0x01
	leaf.Tweak[0], leaf.Tweak[1] = 0x02, 0xb8
	var blockHash [32]byte
	blockHash[0] = 0xb8
	net := canonical.Network(chaincfg.RegressionNetParams.Net)
	leaves := []canonical.Leaf{leaf}
	proof, err := commit.Prove(leaves, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Siblings) != 0 {
		t.Fatalf("a one-entry proof has %d siblings", len(proof.Siblings))
	}
	var sk [32]byte
	sk[31] = 7
	ev, err := feed.Commitment{
		Network: net, BlockHash: blockHash, BlockHeight: 206, N: 1,
		Root: commit.Root(net, blockHash, leaves),
	}.ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}
	file := map[string]any{
		"format":           "canary-evidence/1",
		"claim":            "omission",
		"accused":          ev.PubKey,
		"network":          map[string]any{"name": "regtest", "magic": uint32(net)},
		"block":            map[string]any{"hash": core.DisplayHex(blockHash), "height": 206},
		"commitment_event": ev,
		"receipt":          nil,
		"served_base64":    nil,
		"missing":          map[string]any{"txid": core.DisplayHex(leaf.TxID), "tweak": hex.EncodeToString(leaf.Tweak[:])},
		"proof":            map[string]any{"index": 0, "n": 1, "siblings": []string{}},
		"context":          map[string]any{"server_label": "withholder", "written_at": "2026-10-03T08:32:11Z"},
	}
	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "omission-regtest-206-01000000-"+ev.PubKey[:8]+".json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestTamperOneEntryBlock covers a block with one entry, a likely shape on
// regtest. Its proof has no sibling to change, so the copy changes the
// left-out entry's txid, and the inclusion step still fails.
func TestTamperOneEntryBlock(t *testing.T) {
	src := oneEntryEvidence(t)
	orig, _ := os.ReadFile(src)
	checkInclusion(t, orig, true)

	dist := buildSite(t, withEvidence(t, src))
	name := filepath.Base(src)
	real := read(t, dist, "evidence/"+name)
	tampered := read(t, dist, "evidence/"+strings.TrimSuffix(name, ".json")+"-tampered.json")
	diff := oneByteDiff(t, real, tampered)
	var v, r evidenceProof
	if err := json.Unmarshal([]byte(tampered), &v); err != nil {
		t.Fatalf("the tampered copy is not JSON: %v", err)
	}
	json.Unmarshal([]byte(real), &r)
	if v.Missing.Txid == r.Missing.Txid || len(v.Missing.Txid) != 64 {
		t.Errorf("the flipped byte is not in missing.txid: %q", v.Missing.Txid)
	}
	checkInclusion(t, []byte(tampered), false)
	note := wording.Site.TamperNote(diff+1, "missing.txid", string(real[diff]), string(tampered[diff]), "inclusion")
	if home := read(t, dist, "index.html"); !strings.Contains(home, htmlText(note)) {
		t.Errorf("home lacks the exact tamper note %q", note)
	}
}

// TestReleaseBuildNeedsWhatItPublishes refuses a build whose "Run it
// yourself" commands would fail in a fresh clone.
func TestReleaseBuildNeedsWhatItPublishes(t *testing.T) {
	// An evidence file outside the repository's evidence directory.
	cfg := testConfig(t)
	cfg.Evidence = exampleEvidence
	err := build(cfg)
	if err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Errorf("a build with an evidence file outside evidence/ gave %v", err)
	}
	if _, statErr := os.Stat(cfg.Out); statErr == nil {
		t.Error("a refused build still wrote its output directory")
	}

	// A repository with no ./cmd/canary, for an evidence build and for a
	// public one.
	for name, mutate := range map[string]func(*config){
		"evidence": withEvidence(t, exampleEvidence),
		"public":   func(c *config) { c.NoIndex = false },
	} {
		cfg := testConfig(t)
		mutate(&cfg)
		if err := os.RemoveAll(filepath.Join(filepath.Dir(cfg.Docs), "cmd")); err != nil {
			t.Fatal(err)
		}
		if err := build(cfg); err == nil || !strings.Contains(err.Error(), "cmd/canary") {
			t.Errorf("%s build without ./cmd/canary gave %v", name, err)
		}
	}

	// A preview build publishes neither, so it needs neither.
	cfg = testConfig(t)
	os.RemoveAll(filepath.Join(filepath.Dir(cfg.Docs), "cmd"))
	if err := build(cfg); err != nil {
		t.Errorf("a preview build failed without ./cmd/canary: %v", err)
	}
}

func TestMermaidBecomesDrawings(t *testing.T) {
	how := read(t, buildSite(t, nil), "how-it-works/index.html")
	for _, bad := range []string{"language-mermaid", "flowchart", "classDef", "-->"} {
		if strings.Contains(how, bad) {
			t.Errorf("how-it-works still carries Mermaid source: %q", bad)
		}
	}
	for _, want := range []string{`class="flow flow-parts"`, `class="flow flow-checks"`, `href="#g-compromised"`} {
		if !strings.Contains(how, want) {
			t.Errorf("how-it-works lacks %q", want)
		}
	}
}

// TestDrawingsTrackTheDocs fails when a diagram in the docs gains a label its
// drawing lacks, so the site never shows a stale picture.
func TestDrawingsTrackTheDocs(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "docs", "how-canary-works.md"))
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile("(?s)```mermaid\n(.*?)```").FindAllStringSubmatch(string(src), -1)
	if len(blocks) == 0 {
		t.Fatal("no Mermaid blocks in how-canary-works.md")
	}
	parts, err := partials()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range blocks {
		if _, err := drawing(parts, b[1]); err != nil {
			t.Errorf("drawing: %v", err)
		}
		changed := strings.Replace(b[1], `-- "`, `-- "a label nobody drew, `, 1)
		if _, err := drawing(parts, changed); err == nil || !strings.Contains(err.Error(), "a label nobody drew") {
			t.Errorf("a new label did not fail the drawing check: %v", err)
		}
	}
	if _, err := drawing(parts, "flowchart LR\n  x --> y\n"); err == nil {
		t.Error("an unknown diagram rendered")
	}
	// A change with no new label, such as a new edge, also fails, so the
	// drawing gets a deliberate look. Spacing alone does not count.
	for _, b := range blocks {
		edge := b[1] + "    extra --> start\n"
		if _, err := drawing(parts, edge); err == nil || !strings.Contains(err.Error(), "changed") {
			t.Errorf("a new edge did not fail the drawing check: %v", err)
		}
		respaced := strings.ReplaceAll(b[1], "    ", "  ")
		if _, err := drawing(parts, respaced); err != nil {
			t.Errorf("a change of spacing failed the drawing check: %v", err)
		}
	}
}

// TestDrawingWordsComeFromTheWordingTable keeps the drawings' own words in
// copy.go. The labels they share with the docs are held to the docs above.
func TestDrawingWordsComeFromTheWordingTable(t *testing.T) {
	how := read(t, buildSite(t, nil), "how-it-works/index.html")
	d := wording.Site.Diagram
	for _, want := range []string{
		d.IfNo, d.IfYes, d.IfNoOmission, d.IfNoNoOmission, d.GoOn,
		d.ToEachIndexer, d.CoreAlsoSends, d.Writes, d.FilesGoTo, d.PassesOn, d.Publishes,
	} {
		if !strings.Contains(how, htmlText(want)) {
			t.Errorf("how-it-works lacks the drawing's words %q", want)
		}
	}
	// Each lane takes its name from its visible title, not a second copy.
	if strings.Contains(how, `class="flow-lane" aria-label=`) || strings.Contains(how, `flow-later" aria-label=`) {
		t.Error("a lane carries its own aria-label rather than pointing at its title")
	}
	// The doc tables' labels come from the wording table too.
	if !regexp.MustCompile(`class="table-wrap doc-table" role="region" tabindex="0" aria-label="` + regexp.QuoteMeta(attr(wording.Site.TableLabel(""))) + `[:"]`).MatchString(how) {
		t.Error("the doc tables' labels do not come from the wording table")
	}
}

func TestDocLinks(t *testing.T) {
	s := &site{cfg: config{Docs: filepath.Join("..", "..", "docs"), Repo: testRepo}}
	tests := []struct{ in, want string }{
		{"#tweak", "#tweak"},
		{"glossary.md#tweak", "/glossary/#tweak"},
		{"how-canary-works.md", "/how-it-works/"},
		{"how-canary-works.md#prior-art", "/how-it-works/#prior-art"},
		{"faq.md", "/faq/"},
		{"design/2026-09-30-v1-formats.md#reasons", testRepo + "/blob/main/docs/design/2026-09-30-v1-formats.md#reasons"},
		{"research/prior-art.md", testRepo + "/blob/main/docs/research/prior-art.md"},
		{"https://www.rfc-editor.org/rfc/rfc6962", ""},
		{testRepo + "/releases", testRepo + "/releases"},
	}
	for _, tt := range tests {
		got, err := s.docLink(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("docLink(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
	if _, err := s.docLink("missing-file.md"); err == nil {
		t.Error("a link to a missing file passed")
	}
}

func TestExternalLinksBecomeText(t *testing.T) {
	dist := buildSite(t, nil)
	how := read(t, dist, "how-it-works/index.html")
	if !strings.Contains(how, "RFC 6962") || strings.Contains(how, "rfc-editor.org") {
		t.Error("the RFC 6962 citation did not become plain text")
	}
}

func TestStateLabelsInDocTablesAreBadges(t *testing.T) {
	how := read(t, buildSite(t, nil), "how-it-works/index.html")
	for _, s := range wording.States() {
		if !strings.Contains(how, `<span class="badge s-`+s.Code+`">`) {
			t.Errorf("how-it-works shows no badge for %s", s.Label)
		}
	}
}

func TestDocPagesTakeTheirTitleFromTheDoc(t *testing.T) {
	dist := buildSite(t, nil)
	for page, h1 := range map[string]string{
		"how-it-works/index.html": "How Canary works",
		"faq/index.html":          "Questions and answers",
		"glossary/index.html":     "Glossary",
	} {
		body := read(t, dist, page)
		if !regexp.MustCompile(`<h1[^>]*>` + regexp.QuoteMeta(h1) + `</h1>`).MatchString(body) {
			t.Errorf("%s lacks the h1 %q", page, h1)
		}
	}
}

func TestRefusesToClearAForeignDirectory(t *testing.T) {
	cfg := testConfig(t)
	if err := os.MkdirAll(cfg.Out, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(cfg.Out, "keep.txt")
	os.WriteFile(keep, []byte("mine"), 0o644)
	if err := build(cfg); err == nil {
		t.Fatal("build cleared a directory it did not write")
	}
	if b, _ := os.ReadFile(keep); !bytes.Equal(b, []byte("mine")) {
		t.Error("build touched a file it did not write")
	}
	// A directory the generator wrote is cleared and rebuilt.
	cfg2 := testConfig(t)
	if err := build(cfg2); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(cfg2.Out, "stale.html"), nil, 0o644)
	if err := build(cfg2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg2.Out, "stale.html")); err == nil {
		t.Error("a rebuild kept a stale file")
	}
	// The mark lives in _headers, so the deployed tree holds no file of its
	// own for it, and no dotfile at all.
	walkDist(t, cfg2.Out, []string{""}, func(rel, _ string) {
		if strings.HasPrefix(path.Base(rel), ".") {
			t.Errorf("dist holds %s, which would deploy as a public file", rel)
		}
	})
	// A _headers file this generator did not write is no mark.
	cfg3 := testConfig(t)
	os.MkdirAll(cfg3.Out, 0o755)
	os.WriteFile(filepath.Join(cfg3.Out, "_headers"), []byte("/*\n  X-Frame-Options: DENY\n"), 0o644)
	if err := build(cfg3); err == nil {
		t.Error("build cleared a directory whose _headers it did not write")
	}
}
