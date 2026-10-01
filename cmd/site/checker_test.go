package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/ui"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

const testRevision = "05de74dd2f8698efdb163ab6ed00f3efa09e27fc"

// wasmOpts shapes a stand-in for canary.wasm. Only the parts the site reads
// are real: the WebAssembly header, the producers section that names the Go
// release, and the module information block the go command embeds.
type wasmOpts struct {
	goVersion string // "" leaves out the producers section
	path      string // "" leaves out the module information block
	revision  string
	modified  bool
}

func leb(n int) []byte { return binary.AppendUvarint(nil, uint64(n)) }

func lebString(s string) []byte { return append(leb(len(s)), s...) }

func customSection(name string, body []byte) []byte {
	payload := append(lebString(name), body...)
	return append(append([]byte{0}, leb(len(payload))...), payload...)
}

func fakeWasm(o wasmOpts) []byte {
	b := []byte("\x00asm\x01\x00\x00\x00")
	// A type section with no types, so the stand-in is not all custom sections.
	b = append(b, 1, 1, 0)
	if o.goVersion != "" {
		var p []byte
		p = append(p, leb(2)...)
		p = append(p, lebString("language")...)
		p = append(p, leb(1)...)
		p = append(p, lebString("Go")...)
		p = append(p, lebString(o.goVersion)...)
		p = append(p, lebString("processed-by")...)
		p = append(p, leb(1)...)
		p = append(p, lebString("Go cmd/compile")...)
		p = append(p, lebString(o.goVersion)...)
		b = append(b, customSection("producers", p)...)
	}
	if o.path != "" {
		info := "path\t" + o.path + "\nmod\tgithub.com/Sky-walkerX/canary\t(devel)\t\nbuild\tGOOS=js\nbuild\tGOARCH=wasm\n"
		if o.revision != "" {
			info += "build\tvcs=git\nbuild\tvcs.revision=" + o.revision + "\nbuild\tvcs.modified=" + strconv.FormatBool(o.modified) + "\n"
		}
		data := append(append(append([]byte{}, modInfoStart...), info...), modInfoEnd...)
		// The block sits inside other bytes, as it does in a data segment.
		data = append(append([]byte("\x00\x01data before"), data...), "data after\x00"...)
		b = append(b, customSection("test-data", data)...)
	}
	return b
}

var goodWasm = wasmOpts{goVersion: "go1.26.4", path: checkerPackage, revision: testRevision}

const fakeExec = "// wasm_exec.js stand-in for the site tests.\n"

// withWasm writes a module directory, as make wasm leaves bin/wasm, and
// points the build at it.
func withWasm(t *testing.T, wasm []byte, exec string) func(*config) {
	dir := t.TempDir()
	if wasm != nil {
		if err := os.WriteFile(filepath.Join(dir, "canary.wasm"), wasm, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if exec != "" {
		if err := os.WriteFile(filepath.Join(dir, "wasm_exec.js"), []byte(exec), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return func(c *config) { c.Wasm = dir }
}

func both(fns ...func(*config)) func(*config) {
	return func(c *config) {
		for _, f := range fns {
			if f != nil {
				f(c)
			}
		}
	}
}

func TestParseModule(t *testing.T) {
	for name, tt := range map[string]struct {
		in   wasmOpts
		want module
	}{
		"committed":   {goodWasm, module{GoRelease: "Go 1.26.4", Path: checkerPackage, Revision: testRevision}},
		"uncommitted": {wasmOpts{goVersion: "go1.26.4", path: checkerPackage, revision: testRevision, modified: true}, module{GoRelease: "Go 1.26.4", Path: checkerPackage, Revision: testRevision, Modified: true}},
		"no commit":   {wasmOpts{goVersion: "go1.26.4", path: checkerPackage}, module{GoRelease: "Go 1.26.4", Path: checkerPackage}},
		"devel":       {wasmOpts{goVersion: "devel go1.27-abc", path: checkerPackage}, module{GoRelease: "devel go1.27-abc", Path: checkerPackage}},
	} {
		got, err := parseModule(fakeWasm(tt.in))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.GoRelease != tt.want.GoRelease || got.Path != tt.want.Path || got.Revision != tt.want.Revision || got.Modified != tt.want.Modified {
			t.Errorf("%s: got %+v, want %+v", name, got, tt.want)
		}
	}
	for name, b := range map[string][]byte{
		"not wasm":        []byte("<!doctype html>"),
		"empty":           nil,
		"no Go producer":  fakeWasm(wasmOpts{path: checkerPackage}),
		"no module info":  fakeWasm(wasmOpts{goVersion: "go1.26.4"}),
		"cut short":       fakeWasm(goodWasm)[:20],
		"section too big": append([]byte("\x00asm\x01\x00\x00\x00\x00"), leb(1<<30)...),
	} {
		if _, err := parseModule(b); err == nil {
			t.Errorf("%s: parsed without an error", name)
		}
	}
}

// TestParseModuleFromARealBuild builds a small program for the browser with
// the go command on PATH, and reads its release back. The stand-ins above are
// only as good as this agreement.
func TestParseModuleFromARealBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a WebAssembly module")
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":  "module example.com/hello\n\ngo 1.22\n",
		"main.go": "package main\n\nfunc main() { println(\"hello\") }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The go command on PATH builds the module, and the same command says
	// which release it is. runtime.GOROOT can name the toolchain that built
	// this test instead, which need not be the one on PATH.
	gocmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command on PATH")
	}
	env := append(os.Environ(), "GOOS=js", "GOARCH=wasm", "GOWORK=off", "GOFLAGS=")
	version := exec.Command(gocmd, "env", "GOVERSION")
	version.Dir, version.Env = dir, env
	v, err := version.Output()
	if err != nil {
		t.Fatalf("go env GOVERSION: %v", err)
	}
	out := filepath.Join(dir, "hello.wasm")
	cmd := exec.Command(gocmd, "build", "-trimpath", "-ldflags=-s -w", "-o", out, ".")
	cmd.Dir, cmd.Env = dir, env
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseModule(b)
	if err != nil {
		t.Fatalf("parseModule on a real build: %v", err)
	}
	if want := goRelease(strings.TrimSpace(string(v))); m.GoRelease != want {
		t.Errorf("Go release %q, want %q", m.GoRelease, want)
	}
	if m.Path != "example.com/hello" {
		t.Errorf("path %q, want example.com/hello", m.Path)
	}
}

func TestGoRelease(t *testing.T) {
	for in, want := range map[string]string{
		"go1.26.4":         "Go 1.26.4",
		"go1.27rc1":        "Go 1.27rc1",
		"devel go1.27-abc": "devel go1.27-abc",
		"gox":              "gox",
	} {
		if got := goRelease(in); got != want {
			t.Errorf("goRelease(%q) = %q, want %q", in, got, want)
		}
	}
}

// checkerAssets returns the hashed folder the page loads checker.js from.
func checkerAssets(t *testing.T, home string) string {
	t.Helper()
	m := regexp.MustCompile(`<script src="(/assets/[0-9a-f]{12}/checker/)checker\.js" defer></script>`).FindStringSubmatch(home)
	if m == nil {
		t.Fatal("the home page does not load checker.js from a hashed folder")
	}
	return m[1]
}

func TestCheckerWithModule(t *testing.T) {
	wasm := fakeWasm(goodWasm)
	dist := buildSite(t, withWasm(t, wasm, fakeExec))
	home := read(t, dist, "index.html")
	dir := checkerAssets(t, home)

	// The module, Go's loader and the script come from one build, in one
	// folder whose name is a hash of them all.
	if got := read(t, dist, dir+"canary.wasm"); got != string(wasm) {
		t.Error("the published canary.wasm differs from the built one")
	}
	if got := read(t, dist, dir+"wasm_exec.js"); got != fakeExec {
		t.Error("the published wasm_exec.js differs from the built one")
	}
	js, _ := fs.ReadFile(ui.Assets(), "checker/checker.js")
	if got := read(t, dist, dir+"checker.js"); got != string(js) {
		t.Error("the published checker.js differs from internal/ui's")
	}
	if !strings.Contains(home, `<link rel="stylesheet" href="`+dir+`checker.css">`) {
		t.Error("the home page does not link checker.css from the checker's folder")
	}
	tokens := regexp.MustCompile(`href="(/assets/[0-9a-f]{12}/)tokens\.css"`).FindStringSubmatch(home)
	if tokens == nil || tokens[1]+"checker/" != dir {
		t.Error("the checker's folder is not inside the one hashed asset folder")
	}
	other := read(t, buildSite(t, withWasm(t, fakeWasm(wasmOpts{goVersion: "go1.26.5", path: checkerPackage, revision: testRevision}), fakeExec)), "index.html")
	if strings.Contains(other, dir) {
		t.Error("a different module kept the same asset folder, so a browser could pair it with a cached script")
	}

	checker := section(t, home, "checker")
	build := wording.CheckerBuildLine(testRevision, "Go 1.26.4", false)
	for _, want := range []string{
		`data-wasm-size="` + strconv.Itoa(len(wasm)) + `"`,
		`data-wasm-build="` + attr(build) + `"`,
		`data-checker-build hidden>` + htmlText(build) + `</p>`,
		`<script type="application/json" data-checker-text>`,
	} {
		if !strings.Contains(checker, want) {
			t.Errorf("the checker lacks %q", want)
		}
	}
	// Until the script runs, the pending line is in view. It says the
	// checker needs JavaScript and gives the command, which stays true if
	// the script never runs. The script replaces it once it mounts. That
	// line covers a browser with JavaScript off, so no noscript repeats it.
	if !regexp.MustCompile(`<p class="checker-pending" data-checker-pending>`).MatchString(checker) {
		t.Error("the pending line is not in view before the script runs")
	}
	shown := visibleText(checker)
	for _, want := range []string{wording.Site.CheckerWaiting, wording.Checker.Command} {
		if !strings.Contains(shown, want) {
			t.Errorf("%q is not in view before the script runs", want)
		}
	}
	if strings.Contains(checker, "<noscript>") {
		t.Error("the checker repeats the pending line in a noscript element")
	}
	if strings.Contains(home, htmlText(wording.Site.CheckerPending)) {
		t.Error("the page says it has no checker although the module was built")
	}
	if strings.Contains(strings.ToLower(home), "not built yet") {
		t.Error("the page says the checker is not built yet")
	}
}

// pageCheckerText returns the words cmd/site writes for checker.js.
func pageCheckerText(t *testing.T, home string) map[string]string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<script type="application/json" data-checker-text>(.*?)</script>`).FindStringSubmatch(home)
	if m == nil {
		t.Fatal("the page has no checker text block")
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(m[1]), &out); err != nil {
		t.Fatalf("the checker text block is not a JSON object of strings: %v\n%s", err, m[1])
	}
	return out
}

// scriptTextKeys returns the keys of the TEXT object in checker.js: every
// word the script can show.
func scriptTextKeys(t *testing.T) []string {
	t.Helper()
	js, err := fs.ReadFile(ui.Assets(), "checker/checker.js")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)\n  const TEXT = \{\n(.*?)\n  \};\n`).FindSubmatch(js)
	if block == nil {
		t.Fatal("checker.js has no TEXT object")
	}
	var keys []string
	for _, m := range regexp.MustCompile(`(?m)^    (\w+):`).FindAllSubmatch(block[1], -1) {
		keys = append(keys, string(m[1]))
	}
	if len(keys) < 20 {
		t.Fatalf("found only %d keys in checker.js TEXT", len(keys))
	}
	return keys
}

// TestCheckerTextCoversTheScript holds what cmd/site writes to what
// checker.js reads: every key the script needs, with words from the wording
// table, and no key the script would ignore.
func TestCheckerTextCoversTheScript(t *testing.T) {
	home := read(t, buildSite(t, withWasm(t, fakeWasm(goodWasm), fakeExec)), "index.html")
	page := pageCheckerText(t, home)
	b, _ := json.Marshal(wording.Checker)
	var table map[string]string
	json.Unmarshal(b, &table)
	need := map[string]bool{}
	for _, k := range scriptTextKeys(t) {
		need[k] = true
		switch v, ok := page[k]; {
		case !ok:
			t.Errorf("the page's checker text lacks %q, which checker.js reads", k)
		case strings.TrimSpace(v) == "":
			t.Errorf("the page's checker text %q is empty", k)
		case v != table[k]:
			t.Errorf("the page's checker text %q = %q, not the wording table's %q", k, v, table[k])
		}
	}
	for k := range page {
		if !need[k] {
			t.Errorf("the page writes checker text %q, which checker.js never reads", k)
		}
	}
	// The block is data, so the page carries it escaped: no markup in it can
	// end the script element early.
	raw := regexp.MustCompile(`(?s)data-checker-text>(.*?)</script>`).FindStringSubmatch(home)[1]
	if strings.ContainsAny(raw, "<>") {
		t.Error("the checker text block carries a raw < or >")
	}
}

func TestCheckerWithoutModule(t *testing.T) {
	var log bytes.Buffer
	dist := buildSite(t, both(withWasm(t, nil, ""), func(c *config) { c.Log = &log }))
	home := read(t, dist, "index.html")
	if strings.Contains(home, "checker.js") || strings.Contains(home, "data-checker-text") || strings.Contains(home, "data-wasm") {
		t.Error("a site built without the module still loads the checker")
	}
	walkDist(t, dist, []string{".wasm", "wasm_exec.js", "checker.js"}, func(rel, _ string) {
		t.Errorf("a site built without the module publishes %s", rel)
	})
	// The honest placeholder stays, in view, and the builder hears why.
	if !strings.Contains(visibleText(home), wording.Site.CheckerPending) {
		t.Error("the page does not say it has no checker")
	}
	if msg := log.String(); !strings.Contains(msg, "make wasm") {
		t.Errorf("the build did not tell the builder to run make wasm: %q", msg)
	}
}

// controlElem matches a form control: something a reader would try to use.
var controlElem = regexp.MustCompile(`<(input|button|textarea|select)\b`)

// TestCheckerShowsNoDeadControls keeps controls that can't work out of view.
// With the module, the file input and the two Try buttons wait in hidden
// data-checker-control elements, which checker.js reveals as the last step
// of its mount. So a script that fails to load, or throws before it mounts,
// leaves the pending line and the command in view, not dead controls. A
// build without the module renders no controls at all.
func TestCheckerShowsNoDeadControls(t *testing.T) {
	home := read(t, buildSite(t, withWasm(t, fakeWasm(goodWasm), fakeExec)), "index.html")
	checker := section(t, home, "checker")
	if n := len(controlElem.FindAllString(checker, -1)); n != 3 {
		t.Errorf("the checker renders %d controls, want the file input and two Try buttons", n)
	}
	if m := controlElem.FindString(withoutHidden(checker)); m != "" {
		t.Errorf("a control is in view before checker.js runs: %s", m)
	}
	for _, want := range []string{
		`<label class="drop" data-checker-control hidden>`,
		`<div class="checker-tries" data-checker-control hidden>`,
	} {
		if !strings.Contains(checker, want) {
			t.Errorf("the checker lacks %q", want)
		}
	}

	builds := map[string]func(*config){
		"example":  nil,
		"recorded": withEvidence(t, exampleEvidence),
	}
	for name, mutate := range builds {
		dist := buildSite(t, mutate)
		checker := section(t, read(t, dist, "index.html"), "checker")
		if m := controlElem.FindString(checker); m != "" {
			t.Errorf("%s: a build without the module renders a control that can never work: %s", name, m)
		}
		for _, hook := range []string{"data-checker-file", "data-checker-try", "data-checker-control"} {
			if strings.Contains(checker, hook) {
				t.Errorf("%s: a build without the module renders %s", name, hook)
			}
		}
		// What works without the module stays: where the sample comes
		// from, which byte the copy changes, and both downloads.
		shown := visibleText(checker)
		for _, want := range []string{wording.Site.CheckerPending, wording.Site.CheckerDownloadTampered} {
			if !strings.Contains(shown, want) {
				t.Errorf("%s: %q is not in view", name, want)
			}
		}
		if n := strings.Count(checker, `" download>`); n != 2 {
			t.Errorf("%s: the checker offers %d downloads, want 2", name, n)
		}
	}
}

// TestCheckerHooksMatchTheScript holds every hook the page renders for
// checker.js to a selector the script uses, so a rename on one side can't
// leave the other waiting on an element nothing touches.
func TestCheckerHooksMatchTheScript(t *testing.T) {
	js, err := fs.ReadFile(ui.Assets(), "checker/checker.js")
	if err != nil {
		t.Fatal(err)
	}
	checker := section(t, read(t, buildSite(t, withWasm(t, fakeWasm(goodWasm), fakeExec)), "index.html"), "checker")
	hooks := map[string]bool{}
	for _, m := range regexp.MustCompile(`\s(data-checker-[a-z-]+)`).FindAllStringSubmatch(checker, -1) {
		hooks[m[1]] = true
	}
	if !hooks["data-checker-control"] {
		t.Fatal("the page renders no data-checker-control hook")
	}
	for h := range hooks {
		if !strings.Contains(string(js), "["+h) {
			t.Errorf("the page renders %s, which checker.js never selects", h)
		}
	}
	// The controls appear only once mount has wired every handler, so the
	// reveal is the last thing mount does.
	mount := regexp.MustCompile(`(?s)\n  function mount\(root\) \{\n(.*?)\n  \}\n`).FindSubmatch(js)
	if mount == nil {
		t.Fatal("checker.js has no mount function")
	}
	reveal := bytes.LastIndex(mount[1], []byte("[data-checker-control]"))
	for _, wiring := range []string{"addEventListener(", "function "} {
		if at := bytes.LastIndex(mount[1], []byte(wiring)); at > reveal {
			t.Errorf("mount reveals the controls before its last %q", wiring)
		}
	}
}

// TestReleaseBuildNeedsTheChecker refuses a release build without the
// browser checker. bin/ is not in git, so a fresh clone or a deploy that
// skips make wasm would otherwise publish the site with no checker. A
// preview build may go without it, and its page says so.
func TestReleaseBuildNeedsTheChecker(t *testing.T) {
	public := func(c *config) { c.NoIndex = false }
	for name, mutate := range map[string]func(*config){
		"public":               public,
		"public with evidence": both(withEvidence(t, exampleEvidence), public),
		"public, loader only":  both(withWasm(t, nil, fakeExec), public),
	} {
		cfg := testConfig(t)
		mutate(&cfg)
		if err := build(cfg); err == nil || !strings.Contains(err.Error(), "make wasm") {
			t.Errorf("%s: build gave %v, want a refusal that says to run make wasm", name, err)
		}
		if _, err := os.Stat(cfg.Out); err == nil {
			t.Errorf("%s: a refused build still wrote its output directory", name)
		}
	}
	dist := buildSite(t, both(withWasm(t, fakeWasm(goodWasm), fakeExec), public))
	checkerAssets(t, read(t, dist, "index.html"))
}

func TestCheckerNeedsAWholeModule(t *testing.T) {
	for name, mutate := range map[string]func(*config){
		"no loader": withWasm(t, fakeWasm(goodWasm), ""),
		"no module": withWasm(t, nil, fakeExec),
	} {
		cfg := testConfig(t)
		mutate(&cfg)
		if err := build(cfg); err == nil || !strings.Contains(err.Error(), "make wasm") {
			t.Errorf("%s: build gave %v, want an error that says to run make wasm", name, err)
		}
	}
	cfg := testConfig(t)
	withWasm(t, fakeWasm(wasmOpts{goVersion: "go1.26.4", path: "example.com/other"}), fakeExec)(&cfg)
	if err := build(cfg); err == nil || !strings.Contains(err.Error(), "example.com/other") {
		t.Errorf("a module built from another package gave %v", err)
	}
}

func TestCheckerNamesAnUnstampedBuild(t *testing.T) {
	var log bytes.Buffer
	home := read(t, buildSite(t, both(withWasm(t, fakeWasm(wasmOpts{goVersion: "go1.26.4", path: checkerPackage}), fakeExec),
		func(c *config) { c.Log = &log })), "index.html")
	if !strings.Contains(home, `data-wasm-build="Built with Go 1.26.4."`) {
		t.Error("a module with no commit does not get the line that names only its Go release")
	}
	if !strings.Contains(log.String(), "no commit") {
		t.Errorf("the build did not warn that the module carries no commit: %q", log.String())
	}
}

// formatsExample is the evidence file in the formats document, as the site
// reads it.
func formatsExample(t *testing.T) []byte {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", filepath.FromSlash(formatsDoc)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := docExample(doc, evidenceSection)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestExampleSample covers the site before any run is recorded. The checker
// offers the formats document's example, says so beside the buttons, and
// pairs it with a copy that differs by one byte.
func TestExampleSample(t *testing.T) {
	example := formatsExample(t)
	if fixture, _ := os.ReadFile(exampleEvidence); !bytes.Equal(example, fixture) {
		t.Fatal("the formats document's example and the test fixture differ")
	}
	// With the module, so the Try buttons and their labels are on the page.
	dist := buildSite(t, withWasm(t, fakeWasm(goodWasm), fakeExec))
	const name = "example-omission-regtest-205-01982d71-b1070620.json"
	const tname = "example-omission-regtest-205-01982d71-b1070620-tampered.json"
	real := read(t, dist, "evidence/"+name)
	if real != string(example) {
		t.Fatal("the published example differs from the formats document's")
	}
	tampered := read(t, dist, "evidence/"+tname)
	diff := oneByteDiff(t, real, tampered)

	home := read(t, dist, "index.html")
	checker := section(t, home, "checker")
	note := wording.Site.TamperNote(diff+1, "proof.siblings[0]", string(real[diff]), string(tampered[diff]), "inclusion")
	for _, want := range []string{
		`data-evidence="/evidence/` + name + `"`,
		`data-tampered="/evidence/` + tname + `"`,
		`href="/evidence/` + name + `" download`,
		`href="/evidence/` + tname + `" download`,
		htmlText(wording.Site.CheckerTryExample),
		htmlText(wording.Site.CheckerDownloadExample),
		htmlText(wording.Site.CheckerSourceExample),
		htmlText(note),
	} {
		if !strings.Contains(checker, want) {
			t.Errorf("the checker lacks %q", want)
		}
	}
	shown := visibleText(checker)
	for _, s := range []string{wording.Site.CheckerSourceExample, note} {
		if !strings.Contains(shown, s) {
			t.Errorf("%q is not in view", s)
		}
	}
	for _, gone := range []string{wording.Site.CheckerTryReal, wording.Site.CheckerDownloadReal} {
		if strings.Contains(checker, htmlText(gone)) {
			t.Errorf("the checker calls the example %q", gone)
		}
	}
	// The example is not in a clone's evidence directory, so the run section
	// keeps its placeholder.
	run := section(t, home, "run-h")
	if !strings.Contains(run, "./canary verify <var>"+wording.Site.RunFilePlaceholder+"</var>") || strings.Contains(run, name) {
		t.Error("the run section names a file a fresh clone does not have")
	}
	for _, want := range []string{wording.Site.RunIntroNoEvidence, wording.Site.RunAfterNoEvidence, wording.Site.RunPlaceholderNote} {
		if !strings.Contains(home, htmlText(want)) {
			t.Errorf("home lacks %q", want)
		}
	}

	// The pair does what the page says.
	if rep, _ := evidence.Verify([]byte(real)); rep.Result != evidence.ResultChecksOut || rep.Code != evidence.CodeOK {
		t.Errorf("the example reads %s/%s, want checks_out/ok", rep.Result, rep.Code)
	}
	rep, _ := evidence.Verify([]byte(tampered))
	if rep.Result != evidence.ResultDoesNotCheckOut {
		t.Errorf("the tampered copy reads %s, want does_not_check_out", rep.Result)
	}
	checkInclusion(t, []byte(tampered), false)
}

func TestRecordedSample(t *testing.T) {
	dist := buildSite(t, both(withEvidence(t, exampleEvidence), withWasm(t, fakeWasm(goodWasm), fakeExec)))
	home := read(t, dist, "index.html")
	checker := section(t, home, "checker")
	// The fixture's context says canary check wrote it at 2026-10-03T08:32:11Z.
	for _, want := range []string{
		htmlText(wording.Site.CheckerSourceRecorded("3 Oct 2026")),
		htmlText(wording.Site.CheckerTryReal),
		htmlText(wording.Site.CheckerDownloadReal),
	} {
		if !strings.Contains(checker, want) {
			t.Errorf("the checker lacks %q", want)
		}
	}
	for _, gone := range []string{wording.Site.CheckerSourceExample, wording.Site.CheckerTryExample} {
		if strings.Contains(home, htmlText(gone)) {
			t.Errorf("a recorded run's page still shows %q", gone)
		}
	}
	walkDist(t, dist, []string{".json"}, func(rel, _ string) {
		if strings.HasPrefix(path.Base(rel), "example-") {
			t.Errorf("a recorded run's site still publishes the example %s", rel)
		}
	})
}

func TestRecordedSampleNeedsItsDate(t *testing.T) {
	var f map[string]any
	if err := json.Unmarshal(formatsExample(t), &f); err != nil {
		t.Fatal(err)
	}
	delete(f["context"].(map[string]any), "written_at")
	b, _ := json.MarshalIndent(f, "", "  ")
	src := filepath.Join(t.TempDir(), "omission-regtest-205-01982d71-b1070620.json")
	os.WriteFile(src, b, 0o644)
	cfg := testConfig(t)
	withEvidence(t, src)(&cfg)
	if err := build(cfg); err == nil || !strings.Contains(err.Error(), "written_at") {
		t.Errorf("a recorded file with no date gave %v", err)
	}
}

// TestEvidenceThatIsNotJSON names the real problem when the -evidence file
// does not parse, not the date the page would have read from it.
func TestEvidenceThatIsNotJSON(t *testing.T) {
	src := filepath.Join(t.TempDir(), "omission-regtest-205-01982d71-b1070620.json")
	if err := os.WriteFile(src, []byte("{\"format\": \"canary-evidence/1\",\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	withEvidence(t, src)(&cfg)
	err := build(cfg)
	if err == nil || !strings.Contains(err.Error(), "not JSON") || strings.Contains(err.Error(), "written_at") {
		t.Errorf("an evidence file that is not JSON gave %v, want an error that says it is not JSON", err)
	}
}

// TestSampleMustCheckOut refuses to offer a file as the one that checks out
// when it does not.
func TestSampleMustCheckOut(t *testing.T) {
	b := formatsExample(t)
	sig := regexp.MustCompile(`"sig": "([0-9a-f])`).FindSubmatchIndex(b)
	b[sig[2]] = flipHexDigit(b[sig[2]])
	src := filepath.Join(t.TempDir(), "omission-regtest-205-01982d71-b1070620.json")
	os.WriteFile(src, b, 0o644)
	cfg := testConfig(t)
	withEvidence(t, src)(&cfg)
	if err := build(cfg); err == nil || !strings.Contains(err.Error(), "bad_signature") {
		t.Errorf("a file that does not check out gave %v", err)
	}
}

func TestDocExample(t *testing.T) {
	doc := []byte("# T\n\n## 5. Before\n\n### Example\n\n```json\n{\"no\": 1}\n```\n\n## 6. The evidence file\n\nText.\n\n```json\n{\"not\": \"this\"}\n```\n\n### Example\n\n```json\n{\"yes\": 1}\n```\n\n## 7. After\n")
	got, err := docExample(doc, "## 6. The evidence file")
	if err != nil || string(got) != "{\"yes\": 1}\n" {
		t.Errorf("docExample = %q, %v", got, err)
	}
	if _, err := docExample(doc, "## 8. Missing"); err == nil {
		t.Error("a missing section gave no error")
	}
	if _, err := docExample([]byte("## 6. The evidence file\n\nNo example.\n\n## 7. After\n\n### Example\n\n```json\n{}\n```\n"), "## 6. The evidence file"); err == nil {
		t.Error("an example from the next section was taken")
	}
}
