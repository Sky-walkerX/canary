// Package ui serves the local Canary dashboard, the pages canary ui shows.
//
// The dashboard reads one state file (format canary-state/1) and renders it
// with html/template. It makes no outside requests: fonts, glyphs, styles and
// its one script are embedded in the binary. It answers only GET and HEAD, and
// only for localhost and loopback-address Host headers, so a web page in
// another tab cannot use a DNS name that points at 127.0.0.1 to read it.
//
// Every word a state or finding shows comes from the wording package, the
// table the CLI and the browser checker share.
package ui

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// Options configures the dashboard.
type Options struct {
	// StatePath is the state file to read. Required.
	StatePath string

	// Version and Build identify the running canary ui, for example "0.1.0"
	// and "abc1234". The build id "<Version>+<Build>" feeds the update check,
	// so an upgraded binary tells open pages to reload.
	Version string
	Build   string

	// EvidenceDir overrides the state file's evidence_dir. Leave it empty to
	// use the directory the state file names.
	EvidenceDir string

	// CheckCommand is the command the "No check yet" page shows. Leave it
	// empty for a generic canary check command with this state path.
	CheckCommand string

	// Verify checks one evidence file and returns its VerifyReport as JSON,
	// the output of canary verify --json. When it is nil, a finding page
	// shows the command to run instead of a report.
	Verify func(evidenceFile []byte) ([]byte, error)

	// StaleAfter is the age after which results carry a stale banner.
	// Zero means one hour.
	StaleAfter time.Duration

	// ReleaseNotesURL is linked from the footer. Empty leaves the link out,
	// so the footer never points at a releases page that may hold nothing.
	// The dashboard never fetches it.
	ReleaseNotesURL string

	// Now and Location set the clock and time zone for the status line.
	// Zero values mean time.Now and time.Local.
	Now      func() time.Time
	Location *time.Location

	// ErrorLog receives one line per server error, keyed by the error id
	// the page shows. Nil means os.Stderr.
	ErrorLog io.Writer
}

// maxEvidenceBytes bounds how much of an evidence file the finding page reads
// for a check. A list of 2,000 entries is about 180 KB of base64.
const maxEvidenceBytes = 16 << 20

// csp is the Content-Security-Policy every response carries.
const csp = "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; " +
	"img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'none'"

type handler struct {
	opts    Options
	buildID string
	mux     *http.ServeMux
	logMu   sync.Mutex

	mu    sync.Mutex
	cache snapshot
}

// snapshot is one read of the state file.
type snapshot struct {
	info os.FileInfo
	raw  []byte
	etag string
	file *state.File
	err  error
}

// status names the snapshot for /state.etag.
func (s snapshot) status() string {
	switch {
	case s.err == nil && s.file != nil:
		return "ok"
	case errors.Is(s.err, state.ErrMissing):
		return "missing"
	case errors.Is(s.err, state.ErrNewerFormat):
		return "newer_format"
	}
	return "unreadable"
}

// New returns the dashboard's http.Handler. Mount it at the root of a
// listener bound to a loopback address; CheckAddr tests one.
func New(opts Options) (http.Handler, error) {
	if opts.StatePath == "" {
		return nil, errors.New("ui: new dashboard: no state path")
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	if opts.Build == "" {
		opts.Build = "unknown"
	}
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Location == nil {
		opts.Location = time.Local
	}
	if opts.ErrorLog == nil {
		opts.ErrorLog = os.Stderr
	}
	h := &handler{opts: opts, buildID: opts.Version + "+" + opts.Build}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.overview)
	mux.HandleFunc("GET /blocks", h.blocks)
	mux.HandleFunc("GET /blocks/{hash}", h.block)
	mux.HandleFunc("GET /findings", h.findings)
	mux.HandleFunc("GET /findings/{id}", h.finding)
	mux.HandleFunc("GET /evidence/{name}", h.evidence)
	mux.HandleFunc("GET /state.etag", h.etag)
	mux.HandleFunc("GET /assets/{file...}", serveAsset)
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		serveAssetNamed(w, r, "favicon.svg")
	})
	mux.HandleFunc("/", h.notFound)
	h.mux = mux
	return h, nil
}

// CheckAddr reports an error unless addr is a host:port on localhost or a
// loopback address. canary ui refuses to listen anywhere else. Every host it
// accepts is one the Host header check accepts too, so a page served from
// that address can always load.
func CheckAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("ui: listen address %q: %w", addr, err)
	}
	if !loopbackHost(host) {
		return fmt.Errorf("ui: listen address %q: not a loopback address", addr)
	}
	return nil
}

// loopbackHost reports whether host, with no port or brackets, is localhost
// or a loopback IP literal such as 127.0.0.1, 127.0.0.2 or ::1.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ServeHTTP applies the security headers and checks, then routes.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hdr := w.Header()
	hdr.Set("Content-Security-Policy", csp)
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Referrer-Policy", "no-referrer")
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("Cross-Origin-Opener-Policy", "same-origin")
	hdr.Set("Cross-Origin-Resource-Policy", "same-origin")

	if code := hostStatus(r.Host); code != 0 {
		http.Error(w, "canary ui answers only requests addressed to localhost or a loopback address, such as 127.0.0.1 or [::1].", code)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		hdr.Set("Allow", "GET, HEAD")
		http.Error(w, "canary ui accepts only GET and HEAD requests.", http.StatusMethodNotAllowed)
		return
	}
	defer func() {
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler {
				panic(v)
			}
			h.fail(w, r, fmt.Errorf("panic: %v", v))
		}
	}()
	h.mux.ServeHTTP(w, r)
}

// hostStatus returns 0 for an allowed Host header, 400 for a malformed one
// and 421 for any other host. Allowed hosts are localhost and loopback IP
// literals, such as 127.0.0.1 and [::1], each with or without a port. These
// are the hosts CheckAddr accepts. A DNS rebinding page cannot send one,
// because its Host header carries its own domain name.
func hostStatus(host string) int {
	if host == "" {
		return http.StatusBadRequest
	}
	name, port := host, ""
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return http.StatusBadRequest
		}
		inner, rest := host[1:end], host[end+1:]
		if rest != "" {
			if rest[0] != ':' || !validPort(rest[1:]) {
				return http.StatusBadRequest
			}
		}
		// Brackets hold IPv6 syntax only, as in [::1]. An IPv4-mapped address
		// such as [::ffff:127.0.0.1] is IPv6 syntax, and CheckAddr accepts it.
		if strings.ContainsRune(inner, ':') && loopbackHost(inner) {
			return 0
		}
		return http.StatusMisdirectedRequest
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		name, port = host[:i], host[i+1:]
		if strings.ContainsRune(name, ':') || !validPort(port) {
			return http.StatusBadRequest
		}
	}
	if loopbackHost(name) {
		return 0
	}
	return http.StatusMisdirectedRequest
}

func validPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
	}
	n, _ := strconv.Atoi(p)
	return n > 0 && n <= 65535
}

// load returns the current state file, reading it again only when it
// changed. canary check replaces the file by rename, so a new inode, size or
// modification time means new contents.
func (h *handler) load() snapshot {
	info, statErr := os.Stat(h.opts.StatePath)
	h.mu.Lock()
	defer h.mu.Unlock()
	if statErr == nil && h.cache.info != nil &&
		os.SameFile(info, h.cache.info) &&
		info.ModTime().Equal(h.cache.info.ModTime()) &&
		info.Size() == h.cache.info.Size() {
		return h.cache
	}
	raw, err := state.Read(h.opts.StatePath)
	s := snapshot{raw: raw, etag: state.ETag(raw, h.buildID)}
	if err != nil {
		s.err = err
	} else {
		s.file, s.err = state.Parse(raw)
	}
	if statErr == nil {
		s.info = info
	}
	h.cache = s
	return s
}

// newErrorID returns 8 random hex characters.
func newErrorID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano()&0xffffffff, 16)
	}
	return hex.EncodeToString(b[:])
}

// fail logs err under a new error id and shows the 500 page with that id.
func (h *handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	id := newErrorID()
	h.logMu.Lock()
	fmt.Fprintf(h.opts.ErrorLog, "canary ui: error %s: %s %s: %v\n", id, r.Method, r.URL.Path, err)
	h.logMu.Unlock()

	m := wording.ServerError(id)
	pg := h.page(r, h.load(), m.Title, "")
	pg.Main = errorView{Moment: m, Tech: err.Error(), HomeLink: true}
	var buf bytes.Buffer
	if rerr := pages["error"].ExecuteTemplate(&buf, "layout", pg); rerr != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s\n%s\n", m.Title, m.Body)
		return
	}
	writeHTML(w, http.StatusInternalServerError, buf.Bytes())
}

// render executes one page into a buffer first, so a template error becomes a
// clean 500 page instead of half a page.
func (h *handler) render(w http.ResponseWriter, r *http.Request, status int, name string, pg page) {
	t, ok := pages[name]
	if !ok {
		h.fail(w, r, fmt.Errorf("ui: render: no page template %q", name))
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", pg); err != nil {
		h.fail(w, r, fmt.Errorf("ui: render %s: %w", name, err))
		return
	}
	writeHTML(w, status, buf.Bytes())
}

func writeHTML(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	w.Write(body)
}

// withState renders the full-page state for a missing, unreadable or newer
// state file and returns nil. Otherwise it returns the parsed file.
func (h *handler) withState(w http.ResponseWriter, r *http.Request, s snapshot) *state.File {
	if s.err == nil && s.file != nil {
		return s.file
	}
	var nf *state.NewerFormatError
	switch {
	case errors.Is(s.err, state.ErrMissing):
		m := wording.NoCheckYet
		pg := h.page(r, s, m.Title, "")
		pg.Main = errorView{Moment: m, Command: h.checkCommand(), CommandLabel: "Copy the canary check command"}
		h.render(w, r, http.StatusOK, "error", pg)
	case errors.As(s.err, &nf):
		m := wording.NewerFormat(nf.Found)
		pg := h.page(r, s, m.Title, "")
		pg.Main = errorView{Moment: m, Tech: s.err.Error()}
		h.render(w, r, http.StatusServiceUnavailable, "error", pg)
	case isReadError(s.err):
		// The system refused the read. Moving the file aside would lose its
		// findings and fix nothing, so this page offers no mv command.
		m := wording.StateNotOpened(h.opts.StatePath)
		pg := h.page(r, s, m.Title, "")
		pg.Main = errorView{Moment: m, Tech: fmt.Sprint(s.err)}
		h.render(w, r, http.StatusServiceUnavailable, "error", pg)
	default:
		m := wording.StateUnreadable(h.opts.StatePath)
		pg := h.page(r, s, m.Title, "")
		mv := h.opts.StatePath + ".bad"
		pg.Main = errorView{Moment: m, Tech: fmt.Sprint(s.err),
			Command: "mv " + shellQuote(h.opts.StatePath) + " " + shellQuote(mv), CommandLabel: "Copy the command that moves the file aside"}
		h.render(w, r, http.StatusServiceUnavailable, "error", pg)
	}
	return nil
}

// isReadError reports whether err came from the operating system while
// reading the state file, such as a permission error, rather than from
// parsing its contents.
func isReadError(err error) bool {
	var pe *fs.PathError
	return errors.As(err, &pe)
}

func (h *handler) checkCommand() string {
	if h.opts.CheckCommand != "" {
		return h.opts.CheckCommand
	}
	return "canary check \\\n" +
		"  --indexer URL=label --pubkey label=HEX \\\n" +
		"  --core-rest http://127.0.0.1:18443/rest \\\n" +
		"  --state " + shellQuote(h.opts.StatePath)
}

// shellQuote quotes s for a POSIX shell when it holds anything but safe
// characters.
func shellQuote(s string) string {
	safe := true
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/._-+:@%=,", c)) {
			safe = false
			break
		}
	}
	if safe && s != "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (h *handler) notFound(w http.ResponseWriter, r *http.Request) {
	s := h.load()
	m := wording.PageNotFound
	pg := h.page(r, s, m.Title, "")
	pg.Main = errorView{Moment: m, HomeLink: true}
	h.render(w, r, http.StatusNotFound, "error", pg)
}

func (h *handler) overview(w http.ResponseWriter, r *http.Request) {
	s := h.load()
	f := h.withState(w, r, s)
	if f == nil {
		return
	}
	pg := h.page(r, s, "Overview", "overview")
	pg.Main = buildOverview(f, h.opts.Location)
	h.render(w, r, http.StatusOK, "overview", pg)
}

func (h *handler) blocks(w http.ResponseWriter, r *http.Request) {
	s := h.load()
	f := h.withState(w, r, s)
	if f == nil {
		return
	}
	v := buildBlocks(f)
	if q := r.URL.Query().Get("height"); q != "" {
		v.Query = q
		height, err := strconv.ParseUint(strings.TrimSpace(q), 10, 32)
		if err == nil {
			for _, b := range f.Blocks {
				if uint64(b.Height) == height {
					http.Redirect(w, r, "/blocks/"+b.Hash, http.StatusSeeOther)
					return
				}
			}
		}
		v.QueryMiss = true
		v.QueryError = wording.HeightNotFound(q, v.Detailed, v.Total)
	}
	pg := h.page(r, s, "Blocks", "blocks")
	pg.Main = v
	status := http.StatusOK
	if v.QueryMiss {
		status = http.StatusNotFound
	}
	h.render(w, r, status, "blocks", pg)
}

func (h *handler) block(w http.ResponseWriter, r *http.Request) {
	s := h.load()
	f := h.withState(w, r, s)
	if f == nil {
		return
	}
	hash := r.PathValue("hash")
	for i := range f.Blocks {
		if f.Blocks[i].Hash == hash {
			pg := h.page(r, s, "Block "+strconv.FormatUint(uint64(f.Blocks[i].Height), 10), "blocks")
			pg.Main = buildBlock(f, i, h.opts.Location)
			h.render(w, r, http.StatusOK, "block", pg)
			return
		}
	}
	m := wording.BlockNotFound(f.Checked.From, f.Checked.To)
	pg := h.page(r, s, m.Title, "blocks")
	pg.Main = errorView{Moment: m, BackLink: "/blocks", BackText: "All blocks"}
	h.render(w, r, http.StatusNotFound, "error", pg)
}

func (h *handler) findings(w http.ResponseWriter, r *http.Request) {
	s := h.load()
	f := h.withState(w, r, s)
	if f == nil {
		return
	}
	pg := h.page(r, s, "Findings", "findings")
	pg.Main = buildFindings(f, h.opts.Location)
	h.render(w, r, http.StatusOK, "findings", pg)
}

func (h *handler) finding(w http.ResponseWriter, r *http.Request) {
	s := h.load()
	f := h.withState(w, r, s)
	if f == nil {
		return
	}
	id := r.PathValue("id")
	for i := range f.Findings {
		if f.Findings[i].ID != id {
			continue
		}
		v := buildFinding(f, i, h.opts.Location)
		if v.Evidence != nil {
			v.Evidence.Path = filepath.Join(h.shownEvidenceDir(f), v.Evidence.Name)
			v.Evidence.VerifyCommand = "canary verify " + shellQuote(v.Evidence.Path)
			if h.opts.Verify != nil {
				v.Report, v.ReportErr = h.verifyEvidence(f, v.Evidence.Name)
			}
		}
		pg := h.page(r, s, "Finding "+id, "findings")
		pg.Main = v
		h.render(w, r, http.StatusOK, "finding", pg)
		return
	}
	if !state.ValidFindingID(id) {
		id = ""
	}
	m := wording.FindingNotFound(id)
	pg := h.page(r, s, m.Title, "findings")
	pg.Main = errorView{Moment: m, BackLink: "/findings", BackText: "All findings"}
	h.render(w, r, http.StatusNotFound, "error", pg)
}

// evidenceDir is the directory the dashboard opens evidence files in. The
// EvidenceDir option wins. A relative evidence_dir in the state file is read
// from the state file's own directory, so a run copied elsewhere, such as a
// recorded run in a clone, still finds its files.
func (h *handler) evidenceDir(f *state.File) string {
	if h.opts.EvidenceDir != "" {
		return h.opts.EvidenceDir
	}
	if f.EvidenceDir == "" || filepath.IsAbs(f.EvidenceDir) {
		return f.EvidenceDir
	}
	return filepath.Join(filepath.Dir(h.opts.StatePath), f.EvidenceDir)
}

// shownEvidenceDir is the directory the finding page's verify command
// names. It is evidenceDir, except that a relative evidence_dir stays
// relative to the state file's directory, as the state file wrote it.
func (h *handler) shownEvidenceDir(f *state.File) string {
	if h.opts.EvidenceDir == "" && f.EvidenceDir != "" && !filepath.IsAbs(f.EvidenceDir) {
		return f.EvidenceDir
	}
	return h.evidenceDir(f)
}

// openEvidence opens a listed evidence file inside the evidence directory.
// os.Root keeps the open inside that directory, symlinks included.
func (h *handler) openEvidence(f *state.File, name string) (*os.File, os.FileInfo, error) {
	if !state.ValidEvidenceName(name) {
		// The name came from the address, so the error leaves it out.
		return nil, nil, errors.New("ui: evidence: not a plain file name")
	}
	listed := false
	for _, x := range f.Findings {
		if x.Evidence != nil && *x.Evidence == name {
			listed = true
			break
		}
	}
	if !listed {
		return nil, nil, fmt.Errorf("ui: evidence %q: %w", name, fs.ErrNotExist)
	}
	root, err := os.OpenRoot(h.evidenceDir(f))
	if err != nil {
		return nil, nil, fmt.Errorf("ui: open evidence directory: %w", err)
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, fmt.Errorf("ui: open evidence %q: %w", name, err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, fmt.Errorf("ui: evidence %q: not a regular file", name)
	}
	return file, info, nil
}

func (h *handler) verifyEvidence(f *state.File, name string) (*reportView, *errorView) {
	file, _, err := h.openEvidence(f, name)
	if err != nil {
		m := wording.EvidenceNotFound(name)
		return nil, &errorView{Moment: m, Tech: err.Error()}
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, maxEvidenceBytes+1))
	if err == nil && len(b) > maxEvidenceBytes {
		err = fmt.Errorf("ui: evidence %q: larger than %d bytes", name, maxEvidenceBytes)
	}
	if err != nil {
		m := wording.EvidenceNotFound(name)
		return nil, &errorView{Moment: m, Tech: err.Error()}
	}
	out, err := h.opts.Verify(b)
	if err != nil {
		return nil, &errorView{Moment: wording.Moment{
			Title:  "Canary could not check this file",
			Body:   "The check stopped before it produced a report.",
			Action: "Run the canary verify command above in a terminal to see the full result.",
		}, Tech: err.Error()}
	}
	rep, err := ParseVerifyReport(out)
	if err != nil {
		return nil, &errorView{Moment: wording.Moment{
			Title:  "Canary could not read the check's report",
			Body:   "The report did not match the VerifyReport format.",
			Action: "Run the canary verify command above in a terminal to see the full result.",
		}, Tech: err.Error()}
	}
	v := buildReport(rep)
	return &v, nil
}

func (h *handler) evidence(w http.ResponseWriter, r *http.Request) {
	s := h.load()
	name := r.PathValue("name")
	if s.file == nil {
		h.evidenceMissing(w, r, s, name, "no readable state file")
		return
	}
	file, info, err := h.openEvidence(s.file, name)
	if err != nil {
		h.evidenceMissing(w, r, s, name, err.Error())
		return
	}
	defer file.Close()
	hdr := w.Header()
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	hdr.Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func (h *handler) evidenceMissing(w http.ResponseWriter, r *http.Request, s snapshot, name, tech string) {
	if !state.ValidEvidenceName(name) {
		name = ""
	}
	m := wording.EvidenceNotFound(name)
	pg := h.page(r, s, m.Title, "findings")
	pg.Main = errorView{Moment: m, Tech: tech, BackLink: "/findings", BackText: "All findings"}
	h.render(w, r, http.StatusNotFound, "error", pg)
}

// etag answers the update check. Its shape is fixed by the formats document.
func (h *handler) etag(w http.ResponseWriter, r *http.Request) {
	s := h.load()
	type response struct {
		ETag        string      `json:"etag"`
		Build       string      `json:"build"`
		State       string      `json:"state"`
		GeneratedAt *state.Time `json:"generated_at"`
		Findings    int         `json:"findings"`
	}
	resp := response{ETag: s.etag, Build: h.buildID, State: s.status()}
	if s.file != nil {
		resp.GeneratedAt = &s.file.GeneratedAt
		resp.Findings = len(s.file.Findings)
	}
	b, err := json.Marshal(resp)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	hdr := w.Header()
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("ETag", `"`+s.etag+`"`)
	hdr.Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}
