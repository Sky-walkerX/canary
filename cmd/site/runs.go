package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// A recorded run is one directory under -runs, named for the day it ran,
// such as docs/runs/2026-10-01. It holds what scripts/demo-regtest.sh wrote:
// the state file, the output of each command, and the indexers' logs. A
// subdirectory with its own state file, such as act5/, holds a later check
// in the same run.
//
// The site shows each state file the way canary ui showed it, with the
// dashboard's own templates, under a banner that says it is a recording. It
// publishes every file of the run beside those pages, with its SHA-256, and
// the evidence file each finding names.

// runSlug is the name of a run's directory, and its address on the site.
var runSlug = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(-[a-z0-9]+)*$`)

// partDir is the name of a later check's directory, such as act5.
var partDir = regexp.MustCompile(`^[a-z]+[0-9]*$`)

// runFileTypes are the files a run may hold. Anything else stops the build,
// so nothing unexpected deploys.
var runFileTypes = map[string]bool{".json": true, ".txt": true, ".log": true}

// coreVersion finds the Bitcoin Core release in the demo script's output,
// from the line where it prints bitcoind -version.
var coreVersion = regexp.MustCompile(`Bitcoin Core (?:daemon )?version (v?\d+\.\d+(?:\.\d+)?)`)

// The demo script's output file, and the one later check it can add.
const (
	demoOutput = "demo-regtest-output.txt"
	demoScript = "scripts/demo-regtest.sh"
	demoAct5   = "act5"
)

type recordedRun struct {
	Slug    string
	URL     string // "/runs/<slug>/"
	RepoDir string // the run's directory in a clone, such as docs/runs/2026-10-01
	Date    time.Time
	Network string
	Core    string // the Bitcoin Core release, or "" when the output names none
	Script  string // the command that made the run, or ""

	Main     *recording
	Parts    []*recording
	Files    []*runFile
	Evidence []*runEvidence
}

// recording is one state file and the pages rendered from it.
type recording struct {
	Dir   string // "" for the run's own state file, or a later check's directory
	Label string // "" or a later check's name, such as "Act 5"
	URL   string
	State *runFile
	Run   *ui.StaticRun
}

// runFile is one file of a run, published at its own path below the run.
type runFile struct {
	Rel    string // slash-separated, inside the run's directory
	URL    string
	Size   int
	SHA256 string
	About  string
	body   []byte
}

// runEvidence is an evidence file a finding names. It lives in the
// repository's evidence directory, and the site publishes it under
// /evidence/.
type runEvidence struct {
	Name      string
	FindingID string
	URL       string
	Size      int
	SHA256    string
	body      []byte
}

// date formats a run's day the way its pages name it.
func (r *recordedRun) date() string { return r.Date.Format("2 Jan 2006") }

// readRuns reads every recorded run under -runs and renders its pages. A
// missing directory means no run is recorded yet.
func (s *site) readRuns() error {
	if s.cfg.Runs == "" {
		return nil
	}
	entries, err := os.ReadDir(s.cfg.Runs)
	if errors.Is(err, fs.ErrNotExist) {
		s.note("site: no recorded runs in %s, so the runs page says none is published.", s.cfg.Runs)
		return nil
	}
	if err != nil {
		return fmt.Errorf("site: read runs: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if !runSlug.MatchString(e.Name()) {
			return fmt.Errorf("site: runs: %s is not named for its day, such as 2026-10-01", e.Name())
		}
		r, err := s.readRun(filepath.Join(s.cfg.Runs, e.Name()), e.Name())
		if err != nil {
			return err
		}
		s.runs = append(s.runs, r)
	}
	// The newest run comes first.
	sort.SliceStable(s.runs, func(i, j int) bool { return s.runs[i].Slug > s.runs[j].Slug })
	return nil
}

func (s *site) readRun(dir, slug string) (*recordedRun, error) {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("site: run %s: "+format, append([]any{slug}, args...)...)
	}
	r := &recordedRun{Slug: slug, URL: "/runs/" + slug + "/", RepoDir: s.repoPath(dir)}
	byRel := map[string]*runFile{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fail("%w", err)
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return fail("%w", err)
		}
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() {
			return fail("%s is not a regular file", rel)
		}
		if !runFileTypes[path.Ext(rel)] {
			return fail("%s: the site publishes only .json, .txt and .log files from a run", rel)
		}
		if strings.Count(rel, "/") > 1 {
			return fail("%s sits more than one directory deep", rel)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return fail("%w", err)
		}
		sum := sha256.Sum256(b)
		f := &runFile{Rel: rel, URL: r.URL + rel, Size: len(b), SHA256: hex.EncodeToString(sum[:]),
			About: wording.Site.RecordedFileAbout(path.Base(rel)), body: b}
		byRel[rel] = f
		r.Files = append(r.Files, f)
		return nil
	})
	if err != nil {
		return nil, err
	}

	main, ok := byRel["state.json"]
	if !ok {
		return nil, fail("no state.json")
	}
	r.Main = &recording{URL: r.URL, State: main}
	for _, f := range r.Files {
		d, name := path.Split(f.Rel)
		if name != "state.json" || d == "" {
			continue
		}
		d = strings.TrimSuffix(d, "/")
		if !partDir.MatchString(d) {
			return nil, fail("%s: a later check's directory needs a short name, such as act5", f.Rel)
		}
		r.Parts = append(r.Parts, &recording{Dir: d, Label: partLabel(d), URL: r.URL + d + "/", State: f})
	}
	sort.Slice(r.Parts, func(i, j int) bool { return r.Parts[i].Dir < r.Parts[j].Dir })

	if out, ok := byRel[demoOutput]; ok {
		if m := coreVersion.FindSubmatch(out.body); m != nil {
			r.Core = string(m[1])
		}
		r.Script = demoScript
		for _, p := range r.Parts {
			if p.Dir == demoAct5 {
				r.Script += " --act5"
			}
		}
	}

	for _, rec := range append([]*recording{r.Main}, r.Parts...) {
		if err := s.renderRecording(r, rec); err != nil {
			return nil, fail("%s: %w", rec.State.Rel, err)
		}
	}
	f := r.Main.Run.File
	r.Date = f.GeneratedAt.Time.UTC()
	r.Network = f.Network.Name
	if day := r.Date.Format("2006-01-02"); !strings.HasPrefix(slug, day) {
		return nil, fail("state.json says the run finished on %s, and the directory names another day", day)
	}
	sortRunFiles(r.Files)
	return r, nil
}

// renderRecording renders one state file's pages, with each finding's
// evidence file read from the repository and checked the way canary verify
// checks it.
func (s *site) renderRecording(r *recordedRun, rec *recording) error {
	root := repoRoot(s.cfg.Docs)
	var probe struct {
		Findings []struct {
			ID       string  `json:"id"`
			Evidence *string `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(rec.State.body, &probe); err != nil {
		return fmt.Errorf("not JSON: %w", err)
	}
	files := map[string][]byte{}
	for _, x := range probe.Findings {
		if x.Evidence == nil {
			continue
		}
		name := *x.Evidence
		if !state.ValidEvidenceName(name) {
			return fmt.Errorf("finding %s names evidence %q, which is not a plain file name", x.ID, name)
		}
		if err := requireCanaryCmd(root); err != nil {
			return err
		}
		b, err := os.ReadFile(filepath.Join(root, "evidence", name))
		if err != nil {
			return fmt.Errorf("finding %s names evidence/%s, and the page links it: %w", x.ID, name, err)
		}
		files[name] = b
		if !r.hasEvidence(name) {
			sum := sha256.Sum256(b)
			r.Evidence = append(r.Evidence, &runEvidence{Name: name, FindingID: x.ID, URL: "/evidence/" + name,
				Size: len(b), SHA256: hex.EncodeToString(sum[:]), body: b})
		}
	}
	run, err := ui.RenderStatic(ui.StaticOptions{
		State:         rec.State.body,
		Base:          rec.URL,
		EvidenceURL:   func(name string) string { return "/evidence/" + name },
		VerifyCommand: func(name string) string { return "./canary verify evidence/" + name },
		Evidence: func(name string) ([]byte, error) {
			if b, ok := files[name]; ok {
				return b, nil
			}
			return nil, fs.ErrNotExist
		},
		Verify:   verifyJSON,
		Location: time.UTC,
	})
	if err != nil {
		return err
	}
	rec.Run = run
	return nil
}

func (r *recordedRun) hasEvidence(name string) bool {
	for _, e := range r.Evidence {
		if e.Name == name {
			return true
		}
	}
	return false
}

// verifyJSON is what canary verify --json prints for an evidence file.
func verifyJSON(b []byte) ([]byte, error) {
	rep, _ := evidence.Verify(b)
	return json.Marshal(rep)
}

// requireCanaryCmd refuses a build whose pages tell readers to build
// ./cmd/canary in a repository that lacks it.
func requireCanaryCmd(root string) error {
	cmd := filepath.Join(root, "cmd", "canary")
	if files, _ := filepath.Glob(filepath.Join(cmd, "*.go")); len(files) == 0 {
		return fmt.Errorf("site: release build: %s holds no Go files, and the page tells readers to go build ./cmd/canary", cmd)
	}
	return nil
}

// repoPath names a directory the way a clone names it, relative to the
// repository root. A directory outside the repository keeps its own name.
func (s *site) repoPath(dir string) string {
	root := repoRoot(s.cfg.Docs)
	for _, resolve := range []func(string) (string, error){filepath.Abs, realDir} {
		r, err1 := resolve(root)
		d, err2 := resolve(dir)
		if err1 != nil || err2 != nil {
			continue
		}
		if rel, err := filepath.Rel(r, d); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(dir)
}

// partLabel names a later check after its directory: act5 becomes "Act 5".
func partLabel(dir string) string {
	i := strings.IndexFunc(dir, func(c rune) bool { return c >= '0' && c <= '9' })
	word, num := dir, ""
	if i > 0 {
		word, num = dir[:i], dir[i:]
	}
	label := strings.ToUpper(word[:1]) + word[1:]
	if num != "" {
		label += " " + num
	}
	return label
}

// sortRunFiles orders a run's files the way a reader checks them: the state
// file and the command output first, then each later check's files, then
// the run's notes and logs.
func sortRunFiles(files []*runFile) {
	rank := func(f *runFile) int {
		if n, ok := runFileOrder[path.Base(f.Rel)]; ok {
			return n
		}
		return len(runFileOrder)
	}
	sort.SliceStable(files, func(i, j int) bool {
		a, b := files[i], files[j]
		if ga, gb := runFileGroup(a), runFileGroup(b); ga != gb {
			return ga < gb
		}
		if da, db := path.Dir(a.Rel), path.Dir(b.Rel); da != db {
			return da < db
		}
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra < rb
		}
		return a.Rel < b.Rel
	})
}

// runFileOrder is the order of the files the demo script writes.
var runFileOrder = map[string]int{"state.json": 0, "check.txt": 1, "verify.txt": 2, "status.txt": 3, "run.txt": 4, demoOutput: 5}

// runFileGroup puts a run's state file and command output first (0), then
// each later check's (1), then the run's other files (2), then its logs (3).
func runFileGroup(f *runFile) int {
	d, name := path.Split(f.Rel)
	n, known := runFileOrder[name]
	switch {
	case d == "" && known && n <= 3:
		return 0
	case d != "" && known:
		return 1
	case d == "":
		return 2
	}
	return 3
}

// writeRuns publishes each run's files, the evidence files its findings
// name, and its pages.
func (s *site) writeRuns() error {
	for _, r := range s.runs {
		for _, f := range r.Files {
			if err := s.write("runs/"+r.Slug+"/"+f.Rel, f.body); err != nil {
				return err
			}
		}
		for _, e := range r.Evidence {
			if err := s.writeOnce("evidence/"+e.Name, e.body); err != nil {
				return err
			}
		}
		for _, rec := range append([]*recording{r.Main}, r.Parts...) {
			for _, p := range rec.Run.Pages {
				if err := s.writeRecordedPage(r, rec, p); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// recordedView is what the recorded template receives: one dashboard page,
// and what the site says around it.
type recordedView struct {
	BannerLead, BannerBody string
	FilesURL               string
	RunURL, RunTitle, Part string

	Nav          template.HTML
	NetworkBadge string
	StatusLine   string
	StateURL     string
	StateRel     string
	StateSHA     string
	PartIntro    string

	Content template.HTML

	// Only the run's own overview carries these.
	Files *filesView
	Parts []partView
}

type filesView struct {
	RanWith, Rendered, Fetched string
	Rows                       []fileRow
	Hash                       string // the shasum command for a clone
}

type fileRow struct {
	Path, URL, Size, SHA256, About string
}

type partView struct {
	ID, Label, URL, Intro, Depth, Reason, Open string
	Counts                                     []countView
	NoAccusation                               bool
}

type countView struct {
	State wording.StateText
	Count uint32
}

func (s *site) writeRecordedPage(r *recordedRun, rec *recording, p ui.StaticPage) error {
	f := rec.Run.File
	lead, body := wording.Site.RecordedBanner(r.Network, r.date())
	v := recordedView{
		BannerLead: lead, BannerBody: body,
		FilesURL: r.URL + "#files",
		RunURL:   r.URL, RunTitle: wording.Site.RecordedRunTitle(r.date()), Part: rec.Label,
		Nav: p.Nav, NetworkBadge: rec.Run.NetworkBadge, StatusLine: rec.Run.StatusLine,
		StateURL: rec.State.URL, StateRel: rec.State.Rel, StateSHA: rec.State.SHA256,
		Content: p.Content,
	}
	if rec.Dir != "" {
		v.PartIntro = wording.Site.RecordedPartIntro(rec.Label, f.Checked.From, f.Checked.To, serverLabels(f))
	}
	if rec.Dir == "" && p.Path == "" {
		v.Files = s.filesView(r)
		for _, part := range r.Parts {
			v.Parts = append(v.Parts, newPartView(part))
		}
	}
	meta := wording.SitePage{
		Title:       wording.Site.RecordedTitle(p.Title, r.date(), rec.Label),
		Description: wording.Site.RecordedDescription(r.Network, r.date(), countsLine(f.Counts)),
	}
	pathname := rec.URL + p.Path
	return s.render("recorded", strings.TrimPrefix(pathname, "/")+"index.html", s.page(meta, pathname, v))
}

func (s *site) filesView(r *recordedRun) *filesView {
	v := &filesView{
		RanWith:  wording.Site.RecordedRanWith(r.Script, r.Network, r.date(), r.Core),
		Rendered: wording.Site.RecordedRendered,
		Fetched:  wording.Site.RecordedFetched,
	}
	hashed := []string{r.RepoDir + "/" + r.Main.State.Rel}
	// The evidence files follow the run's state file and command output.
	evidenceDone := false
	addEvidence := func() {
		if evidenceDone {
			return
		}
		evidenceDone = true
		for _, e := range r.Evidence {
			v.Rows = append(v.Rows, fileRow{Path: "evidence/" + e.Name, URL: e.URL, Size: thousands(e.Size),
				SHA256: e.SHA256, About: wording.Site.RecordedEvidenceAbout(e.FindingID)})
		}
	}
	for _, f := range r.Files {
		if runFileGroup(f) > 0 {
			addEvidence()
		}
		v.Rows = append(v.Rows, fileRow{Path: f.Rel, URL: f.URL, Size: thousands(f.Size), SHA256: f.SHA256, About: f.About})
	}
	addEvidence()
	for _, p := range r.Parts {
		hashed = append(hashed, r.RepoDir+"/"+p.State.Rel)
	}
	v.Hash = "shasum -a 256 " + strings.Join(hashed, " ")
	return v
}

func newPartView(p *recording) partView {
	f := p.Run.File
	v := partView{
		ID:    "part-" + p.Dir,
		Label: p.Label,
		URL:   p.URL,
		Intro: wording.Site.RecordedPartIntro(p.Label, f.Checked.From, f.Checked.To, serverLabels(f)),
		Open:  wording.Site.RecordedOpenPart(p.Label),
	}
	for _, st := range state.States {
		if n := f.Counts.Get(st); n > 0 {
			v.Counts = append(v.Counts, countView{State: wording.State(string(st)), Count: n})
		}
	}
	if len(f.Coverage) == 1 {
		v.Reason = wording.Reason(string(f.Coverage[0].Reason))
	}
	if len(f.Blocks) == 1 && len(f.Blocks[0].Servers) == 1 {
		b, sv := f.Blocks[0], f.Blocks[0].Servers[0]
		if sv.Tip != nil && sv.Tip.Height >= b.Height {
			v.Depth = wording.Site.RecordedDepth(sv.Label, sv.Tip.Height, b.Height)
		}
	}
	v.NoAccusation = f.Counts.Unresolvable > 0 && len(f.Findings) == 0
	return v
}

func serverLabels(f *state.File) []string {
	out := make([]string, len(f.Servers))
	for i, sv := range f.Servers {
		out[i] = sv.Label
	}
	return out
}

func countsLine(c state.Counts) string {
	m := map[string]int{}
	for _, st := range state.States {
		m[string(st)] = int(c.Get(st))
	}
	return wording.CountsLine(m)
}

// thousands writes n with commas, as in 512,790.
func thousands(n int) string {
	s := strconv.Itoa(n)
	var b bytes.Buffer
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// runsView is the runs index: one card per run.
type runsView struct {
	Runs []runCard
}

type runCard struct {
	Slug, URL, Title, StatusLine, RanWith string
	Checks                                []checkLine
	Findings                              []findingLine
	StateSHA                              string
}

type checkLine struct {
	Label, URL string
	Counts     []countView
}

type findingLine struct {
	Sentence, URL string
	Height        uint32
}

func (s *site) runsView() runsView {
	var v runsView
	for _, r := range s.runs {
		c := runCard{
			Slug:       r.Slug,
			URL:        r.URL,
			Title:      wording.Site.RecordedRunTitle(r.date()),
			StatusLine: r.Main.Run.StatusLine,
			RanWith:    wording.Site.RecordedRanWith(r.Script, r.Network, r.date(), r.Core),
			StateSHA:   r.Main.State.SHA256,
		}
		for _, rec := range append([]*recording{r.Main}, r.Parts...) {
			f := rec.Run.File
			line := checkLine{Label: wording.Site.RecordedRange(rec.Label, f.Checked.From, f.Checked.To, len(f.Servers)), URL: rec.URL}
			for _, st := range state.States {
				if n := f.Counts.Get(st); n > 0 {
					line.Counts = append(line.Counts, countView{State: wording.State(string(st)), Count: n})
				}
			}
			c.Checks = append(c.Checks, line)
			for _, x := range f.Findings {
				c.Findings = append(c.Findings, findingLine{
					Sentence: wording.FindingHeadline(x.Kind, string(x.Reason), findingServers(x)),
					URL:      rec.URL + "findings/" + x.ID + "/",
					Height:   x.Block.Height,
				})
			}
		}
		v.Runs = append(v.Runs, c)
	}
	return v
}

func findingServers(x state.Finding) []string {
	out := make([]string, len(x.Servers))
	for i, sv := range x.Servers {
		out[i] = sv.Label
	}
	return out
}

// runFor returns the recorded run whose findings name the evidence file, or
// nil.
func (s *site) runFor(evidenceName string) *recordedRun {
	for _, r := range s.runs {
		if r.hasEvidence(evidenceName) {
			return r
		}
	}
	return nil
}
