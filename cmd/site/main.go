// Command site renders Canary's public site to static files.
//
// The site uses the dashboard's design system: the same partials, stylesheets,
// fonts, glyphs and wording table, all from internal/ui. The how-it-works,
// FAQ and glossary pages come from the Markdown files in docs/. The output
// loads nothing from another origin and runs under the CSP in site/_headers.
//
// Run it from the repository root:
//
//	make wasm                           # the browser checker, into bin/wasm
//	go run ./cmd/site                   # writes site/dist, with noindex
//	go run ./cmd/site -evidence evidence/FILE.json
//	go run ./cmd/site -noindex=false    # after submission
//
// Then deploy site/dist to Cloudflare Pages.
//
// The home page's checker loads canary.wasm, which make wasm builds. Without
// it the page says this build has no checker, and the generator says to run
// make wasm. Until a run is recorded, the checker's sample is the formats
// document's example evidence file, and the page says so.
//
// A build with -evidence, or with -noindex=false, publishes commands that a
// fresh clone must be able to run. So it refuses an evidence file outside the
// repository's evidence directory, and a repository without ./cmd/canary.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Sky-walkerX/canary/internal/ui"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// config is what one build needs.
type config struct {
	Out      string // output directory, cleared first
	Docs     string // the docs directory; its parent is the repository root
	Headers  string // the _headers source file
	Evidence string // optional: the real evidence file for the checker
	Wasm     string // the directory make wasm writes canary.wasm and wasm_exec.js to
	Repo     string // the repository's address, the one outside link
	BaseURL  string // optional: the site's own address, for canonical and og:url
	NoIndex  bool   // ask search engines to stay away

	Log io.Writer // where notes for the builder go; nil drops them
}

const defaultRepo = "https://github.com/Sky-walkerX/canary"

// marker is the first line of every _headers file this generator writes. It
// shows that the directory is the generator's own, so a rebuild may clear it.
// It lives in a file the site needs anyway, so the deployed tree carries no
// extra file for it.
const marker = "# Written by go run ./cmd/site. The next build clears this directory."

func main() {
	cfg := config{}
	flag.StringVar(&cfg.Out, "out", filepath.Join("site", "dist"), "output directory; cleared before each build")
	flag.StringVar(&cfg.Docs, "docs", "docs", "docs directory, inside the repository")
	flag.StringVar(&cfg.Headers, "headers", filepath.Join("site", "_headers"), "Cloudflare Pages _headers source")
	flag.StringVar(&cfg.Evidence, "evidence", "", "the real evidence file, committed in the repository's evidence directory, to publish with a tampered copy (optional; needs ./cmd/canary)")
	flag.StringVar(&cfg.Wasm, "wasm", filepath.Join("bin", "wasm"), "the directory where make wasm wrote canary.wasm and wasm_exec.js")
	flag.StringVar(&cfg.Repo, "repo", defaultRepo, "repository address for source links")
	flag.StringVar(&cfg.BaseURL, "base-url", "", "the site's own address, such as https://canary.pages.dev (optional)")
	flag.BoolVar(&cfg.NoIndex, "noindex", true, "ask search engines not to index the site")
	flag.Parse()
	cfg.Log = os.Stderr
	if err := build(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("site: wrote", cfg.Out)
}

// site is one build in progress.
type site struct {
	cfg      config
	parts    *template.Template // the shared partials, for badges and drawings
	pages    map[string]*template.Template
	assetDir string  // "/assets/<hash>"
	module   *module // the browser checker, or nil when the build has none
	checker  checkerView
}

func build(cfg config) error {
	cfg.Repo = strings.TrimSuffix(cfg.Repo, "/")
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")
	if cfg.Repo == "" {
		return errors.New("site: build: no repository address")
	}
	if err := checkPublishable(cfg); err != nil {
		return err
	}
	if err := prepareOut(cfg.Out); err != nil {
		return err
	}
	parts, err := partials()
	if err != nil {
		return err
	}
	pages, err := parsePages()
	if err != nil {
		return err
	}
	s := &site{cfg: cfg, parts: parts, pages: pages}
	for _, step := range []func() error{s.readModule, s.writeAssets, s.writeIcons, s.writeEvidence, s.writePages, s.writeHeaders} {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// repoRoot is the repository the build reads from: the docs directory's
// parent.
func repoRoot(docs string) string {
	return filepath.Dir(filepath.Clean(docs))
}

// checkPublishable refuses a release build whose "Run it yourself" commands
// would fail in a fresh clone. Those commands build ./cmd/canary and verify
// evidence/<name>, so both must be in the repository. A preview build, with
// noindex and no evidence file, publishes neither and skips the check.
func checkPublishable(cfg config) error {
	if cfg.Evidence == "" && cfg.NoIndex {
		return nil
	}
	root := repoRoot(cfg.Docs)
	cmd := filepath.Join(root, "cmd", "canary")
	if files, _ := filepath.Glob(filepath.Join(cmd, "*.go")); len(files) == 0 {
		return fmt.Errorf("site: release build: %s holds no Go files, and the page tells readers to go build ./cmd/canary", cmd)
	}
	if cfg.Evidence == "" {
		return nil
	}
	want, err := realDir(filepath.Join(root, "evidence"))
	if err != nil {
		return fmt.Errorf("site: evidence: the repository has no evidence directory: %w", err)
	}
	got, err := realDir(filepath.Dir(cfg.Evidence))
	if err != nil {
		return fmt.Errorf("site: evidence: %w", err)
	}
	if got != want {
		return fmt.Errorf("site: evidence: %s is not in %s, and the page tells readers to verify evidence/%s in their clone",
			cfg.Evidence, want, filepath.Base(cfg.Evidence))
	}
	return nil
}

// realDir returns a directory's absolute path with symbolic links resolved,
// so two spellings of one directory compare equal.
func realDir(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// prepareOut empties the output directory. It clears only a directory this
// generator wrote, marked by the first line of its _headers, or an empty one.
// It writes the marker first, so a build that fails halfway leaves a
// directory the next build may clear.
func prepareOut(out string) error {
	entries, err := os.ReadDir(out)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("site: read output directory: %w", err)
	case len(entries) > 0:
		b, err := os.ReadFile(filepath.Join(out, "_headers"))
		if first, _, _ := strings.Cut(string(b), "\n"); err != nil || first != marker {
			return fmt.Errorf("site: output directory %s holds files this generator did not write; choose an empty directory", out)
		}
		if err := os.RemoveAll(out); err != nil {
			return fmt.Errorf("site: clear output directory: %w", err)
		}
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("site: create output directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(out, "_headers"), []byte(marker+"\n"), 0o644); err != nil {
		return fmt.Errorf("site: write _headers: %w", err)
	}
	return nil
}

func (s *site) write(rel string, b []byte) error {
	p := filepath.Join(s.cfg.Out, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("site: write %s: %w", rel, err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		return fmt.Errorf("site: write %s: %w", rel, err)
	}
	return nil
}

// writeAssets copies the design system's files and the site's own stylesheet
// into one directory named by a hash of them all. The stylesheets refer to
// the fonts by relative paths, which stay valid inside that directory. With
// the browser checker, its folder holds checker.js beside the canary.wasm and
// wasm_exec.js it loads, so one hash covers all three and a browser never
// pairs the script with a module from another build.
func (s *site) writeAssets() error {
	files := map[string][]byte{}
	err := fs.WalkDir(ui.Assets(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch {
		case p == "glyphs.svg" || p == "favicon.svg":
			// The sprite is inlined in each page, and the favicon sits at the root.
			return nil
		case p == "fonts/SOURCE.txt":
			// The download record names the fonts' origin, which the site never
			// contacts. The licences ship; the record stays in the repository.
			return nil
		case strings.HasPrefix(p, "checker/") && s.module == nil:
			// Without its module the checker can't run, so the page never
			// loads its script.
			return nil
		case strings.HasSuffix(p, ".css"), strings.HasSuffix(p, ".js"), strings.HasSuffix(p, ".woff2"), strings.HasSuffix(p, ".txt"):
		default:
			return nil
		}
		b, err := fs.ReadFile(ui.Assets(), p)
		files[p] = b
		return err
	})
	if err != nil {
		return fmt.Errorf("site: read design system assets: %w", err)
	}
	css, err := siteAssets.ReadFile("assets/site.css")
	if err != nil {
		return fmt.Errorf("site: read site.css: %w", err)
	}
	files["site.css"] = css
	if s.module != nil {
		files["checker/canary.wasm"] = s.module.Wasm
		files["checker/wasm_exec.js"] = s.module.Exec
	}

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		fmt.Fprintf(h, "%s %x\n", n, sum)
	}
	s.assetDir = "/assets/" + hex.EncodeToString(h.Sum(nil))[:12]
	for _, n := range names {
		if err := s.write(strings.TrimPrefix(s.assetDir, "/")+"/"+n, files[n]); err != nil {
			return err
		}
	}
	return nil
}

func (s *site) writeIcons() error {
	for name, b := range map[string][]byte{
		"favicon.svg":          ui.FaviconSVG(),
		"favicon.png":          ui.FaviconPNG(32, false),
		"apple-touch-icon.png": ui.FaviconPNG(180, true),
	} {
		if err := s.write(name, b); err != nil {
			return err
		}
	}
	return nil
}

// writeHeaders copies the _headers source under the generator's marker. With
// noindex it adds a rule that asks search engines to skip every path, the
// header form of the meta tag.
func (s *site) writeHeaders() error {
	src, err := os.ReadFile(s.cfg.Headers)
	if err != nil {
		return fmt.Errorf("site: read headers: %w", err)
	}
	b := append([]byte(marker+"\n\n"), src...)
	if s.cfg.NoIndex {
		b = append(bytes.TrimRight(b, "\n"), "\n\n# Added by -noindex, the default until submission.\n/*\n  X-Robots-Tag: noindex\n"...)
	}
	return s.write("_headers", b)
}

// page is what every page template receives.
type page struct {
	Meta      wording.SitePage
	Title     string
	Path      string
	Canonical string
	NoIndex   bool
	Assets    string
	Nav       []navItem
	Sprite    template.HTML
	Text      wording.SiteText
	Framing   string
	Repo      string
	License   string
	Styles    []string // extra stylesheets, after the site's own
	Scripts   []string // extra scripts, loaded with defer
	Main      any
}

type navItem struct {
	Href, Label string
	Current     bool
}

func (s *site) page(meta wording.SitePage, pathname string, main any) page {
	items := []navItem{
		{Href: "/how-it-works/", Label: wording.Site.NavHowItWorks},
		{Href: "/faq/", Label: wording.Site.NavFAQ},
		{Href: "/glossary/", Label: wording.Site.NavGlossary},
		{Href: "/runs/", Label: wording.Site.NavRuns},
	}
	for i := range items {
		items[i].Current = items[i].Href == pathname
	}
	title := meta.Title
	if pathname != "/" {
		title += " · Canary"
	}
	p := page{
		Meta:    meta,
		Title:   title,
		Path:    pathname,
		NoIndex: s.cfg.NoIndex,
		Assets:  s.assetDir,
		Nav:     items,
		Sprite:  ui.Sprite(),
		Text:    wording.Site,
		Framing: wording.Framing,
		Repo:    s.cfg.Repo,
		License: s.cfg.Repo + "/blob/main/LICENSE",
		Main:    main,
	}
	if s.cfg.BaseURL != "" && pathname != "" {
		p.Canonical = s.cfg.BaseURL + pathname
	}
	return p
}

func (s *site) render(tmpl, rel string, pg page) error {
	t, ok := s.pages[tmpl]
	if !ok {
		return fmt.Errorf("site: render %s: no template %q", rel, tmpl)
	}
	var b bytes.Buffer
	if err := t.ExecuteTemplate(&b, "layout", pg); err != nil {
		return fmt.Errorf("site: render %s: %w", rel, err)
	}
	return s.write(rel, b.Bytes())
}

// docPages maps each rendered doc to its address.
var docPages = []struct {
	file, path, out string
	meta            wording.SitePage
	toc             bool
}{
	{"how-canary-works.md", "/how-it-works/", "how-it-works/index.html", wording.Site.HowItWorks, true},
	{"faq.md", "/faq/", "faq/index.html", wording.Site.FAQ, false},
	{"glossary.md", "/glossary/", "glossary/index.html", wording.Site.Glossary, false},
}

func (s *site) writePages() error {
	home := homeView{
		Checker:  s.checker,
		States:   wording.States(),
		Steps:    verifySteps(),
		Commands: s.runCommands(),
	}
	homePage := s.page(wording.Site.Home, "/", home)
	if m := s.module; m != nil {
		home.Checker.Module = &moduleView{
			Size:  len(m.Wasm),
			Build: wording.CheckerBuildLine(m.Revision, m.GoRelease, m.Modified),
			Text:  wording.Checker,
		}
		homePage.Main = home
		homePage.Styles = []string{s.assetDir + "/checker/checker.css"}
		homePage.Scripts = []string{s.assetDir + "/checker/checker.js"}
	}
	if err := s.render("home", "index.html", homePage); err != nil {
		return err
	}
	for _, d := range docPages {
		src, err := os.ReadFile(filepath.Join(s.cfg.Docs, d.file))
		if err != nil {
			return fmt.Errorf("site: read %s: %w", d.file, err)
		}
		doc, err := s.renderDoc(d.file, src)
		if err != nil {
			return err
		}
		if !d.toc {
			doc.TOC = nil
		}
		doc.Source = s.cfg.Repo + "/blob/main/docs/" + d.file
		doc.SourcePath = "docs/" + d.file
		if err := s.render("doc", d.out, s.page(d.meta, d.path, doc)); err != nil {
			return err
		}
	}
	if err := s.render("runs", "runs/index.html", s.page(wording.Site.Runs, "/runs/", nil)); err != nil {
		return err
	}
	// The 404 page is served at any address, so it has no canonical one.
	return s.render("notfound", "404.html", s.page(wording.Site.NotFound, "", nil))
}

// homeView is the home page: the checker, the six states, and the commands
// that run Canary on your own machine.
type homeView struct {
	Checker  checkerView
	States   []wording.StateText
	Steps    []string
	Commands []command
}

// command is one shell command under "Run it yourself". A command with a
// Placeholder ends in a word the reader must replace, so the page shows that
// word as a placeholder and offers nothing to copy.
type command struct {
	Value, Label, Placeholder string
}

func verifySteps() []string {
	out := make([]string, len(wording.VerifySteps))
	for i, st := range wording.VerifySteps {
		out[i] = wording.VerifyStep(st)
	}
	return out
}

// runCommands are the three commands under "Run it yourself": clone, build,
// and check the evidence file with the network off. checkPublishable has
// already made sure a release build's evidence file sits in evidence/.
func (s *site) runCommands() []command {
	verify := command{Value: "./canary verify ", Placeholder: wording.Site.RunFilePlaceholder}
	if s.checker.Recorded {
		verify = command{Value: "./canary verify evidence/" + s.checker.RealName, Label: wording.Site.RunVerifyLabel}
	}
	return []command{
		{Value: "git clone " + s.cfg.Repo + " && cd " + path.Base(s.cfg.Repo), Label: wording.Site.RunCloneLabel},
		{Value: "go build -o canary ./cmd/canary", Label: wording.Site.RunBuildLabel},
		verify,
	}
}
