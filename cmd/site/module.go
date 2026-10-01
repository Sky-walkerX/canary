package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

// checkerPackage is the program canary.wasm must be built from.
const checkerPackage = "github.com/Sky-walkerX/canary/cmd/verify-wasm"

// module is the browser checker that make wasm builds: canary.wasm, and the
// wasm_exec.js from the same Go release, which loads it.
type module struct {
	Wasm, Exec []byte
	Path       string // the main package it was built from
	GoRelease  string // "Go 1.26.4", the way the page names it
	Revision   string // the git commit, empty when the build carries none
	Modified   bool   // built from a tree with uncommitted changes
}

// readModule reads the checker from the -wasm directory. A directory with
// neither file gives a site without the checker, and a note telling the
// builder to run make wasm. One file without the other is an error, because
// the page would load a pair that can't work together.
func (s *site) readModule() error {
	dir := s.cfg.Wasm
	wasmPath, execPath := filepath.Join(dir, "canary.wasm"), filepath.Join(dir, "wasm_exec.js")
	wasm, werr := os.ReadFile(wasmPath)
	exec, eerr := os.ReadFile(execPath)
	switch {
	case dir == "" || errors.Is(werr, fs.ErrNotExist) && errors.Is(eerr, fs.ErrNotExist):
		s.note("site: no browser checker in %s, so the home page says this build has no checker. "+
			"Run make wasm, then build the site again.", orDefault(dir))
		return nil
	case werr != nil:
		return fmt.Errorf("site: read checker: %w. Run make wasm, which writes canary.wasm and wasm_exec.js together", werr)
	case eerr != nil:
		return fmt.Errorf("site: read checker: %w. Run make wasm, which writes canary.wasm and wasm_exec.js together", eerr)
	}
	m, err := parseModule(wasm)
	if err != nil {
		return fmt.Errorf("site: read checker %s: %w. Run make wasm to rebuild it", wasmPath, err)
	}
	if m.Path != checkerPackage {
		return fmt.Errorf("site: read checker %s: it was built from %s, not %s. Run make wasm to rebuild it", wasmPath, m.Path, checkerPackage)
	}
	if m.Revision == "" {
		s.note("site: %s carries no commit, so the page names only its Go release. "+
			"Go stamps the commit only in a git checkout; a git worktree gets none.", wasmPath)
	} else if m.Modified {
		s.note("site: %s was built with uncommitted changes, and the page says so.", wasmPath)
	}
	m.Wasm, m.Exec = wasm, exec
	s.module = &m
	return nil
}

func orDefault(dir string) string {
	if dir == "" {
		return "the -wasm directory"
	}
	return dir
}

// note tells the builder something the build did not stop for.
func (s *site) note(format string, args ...any) {
	if s.cfg.Log != nil {
		fmt.Fprintf(s.cfg.Log, format+"\n", args...)
	}
}

// The go command wraps the module information it embeds in every binary in
// these two 16-byte markers. debug/buildinfo strips them the same way.
var (
	modInfoStart = []byte("\x30\x77\xaf\x0c\x92\x74\x08\x02\x41\xe1\xc1\x07\xe6\xd6\x18\xe6")
	modInfoEnd   = []byte("\xf9\x32\x43\x31\x86\x18\x20\x72\x00\x82\x42\x10\x41\x16\xd8\xf2")
)

// parseModule reads which build a Go WebAssembly module came from.
// debug/buildinfo can't read WebAssembly, so this reads the two places Go
// leaves that record. The Go release comes from the module's producers
// section, a WebAssembly tool convention the Go linker fills in. The main
// package and the commit come from the module information block the go
// command embeds in the data.
func parseModule(b []byte) (module, error) {
	if !bytes.HasPrefix(b, []byte("\x00asm\x01\x00\x00\x00")) {
		return module{}, errors.New("not a WebAssembly module")
	}
	goVersion, err := producersGo(b[8:])
	if err != nil {
		return module{}, err
	}
	m := module{GoRelease: goRelease(goVersion)}

	start := bytes.Index(b, modInfoStart)
	if start < 0 || bytes.Count(b, modInfoStart) != 1 {
		return module{}, errors.New("no Go module information, or more than one block of it")
	}
	n := bytes.Index(b[start:], modInfoEnd)
	if n < 0 {
		return module{}, errors.New("the Go module information has no end")
	}
	bi, err := debug.ParseBuildInfo(string(b[start+len(modInfoStart) : start+n]))
	if err != nil {
		return module{}, fmt.Errorf("the Go module information does not parse: %w", err)
	}
	m.Path = bi.Path
	for _, st := range bi.Settings {
		switch st.Key {
		case "vcs.revision":
			m.Revision = st.Value
		case "vcs.modified":
			m.Modified = st.Value == "true"
		}
	}
	return m, nil
}

// producersGo walks a module's sections, after its 8-byte header, to the
// producers custom section and returns the version it gives for the
// language Go.
func producersGo(b []byte) (string, error) {
	r := wasmReader{b: b}
	for r.more() {
		id := r.byte()
		body := r.bytes(r.uint())
		if r.err != nil {
			return "", r.err
		}
		if id != 0 {
			continue
		}
		sec := wasmReader{b: body}
		if sec.name() != "producers" {
			continue
		}
		for fields := sec.uint(); fields > 0 && sec.err == nil; fields-- {
			field := sec.name()
			for values := sec.uint(); values > 0 && sec.err == nil; values-- {
				name, version := sec.name(), sec.name()
				if field == "language" && name == "Go" && sec.err == nil {
					return version, nil
				}
			}
		}
		if sec.err != nil {
			return "", fmt.Errorf("the producers section does not parse: %w", sec.err)
		}
	}
	return "", errors.New("no producers section that names a Go release")
}

// wasmReader reads the LEB128 numbers and length-prefixed names of the
// WebAssembly binary format. Its first error sticks, and every later read
// returns zero values.
type wasmReader struct {
	b   []byte
	err error
}

var errWasmShort = errors.New("the module ends in the middle of a section")

func (r *wasmReader) more() bool { return r.err == nil && len(r.b) > 0 }

func (r *wasmReader) byte() byte {
	if r.err != nil || len(r.b) == 0 {
		r.err = errWasmShort
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

func (r *wasmReader) uint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.b)
	if n <= 0 || v > 1<<32 {
		r.err = errWasmShort
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *wasmReader) bytes(n uint64) []byte {
	if r.err != nil || n > uint64(len(r.b)) {
		r.err = errWasmShort
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *wasmReader) name() string { return string(r.bytes(r.uint())) }

// goRelease writes a Go version the way the page names it: "go1.26.4"
// becomes "Go 1.26.4", as cmd/verify-wasm reports it. A version that does
// not start that way, such as a development build's, comes back unchanged.
func goRelease(v string) string {
	if rest, ok := strings.CutPrefix(v, "go"); ok && rest != "" && rest[0] >= '0' && rest[0] <= '9' {
		return "Go " + rest
	}
	return v
}
