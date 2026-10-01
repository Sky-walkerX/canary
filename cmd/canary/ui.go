package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// defaultUIAddr is the dashboard's listen address when --addr is not given.
const defaultUIAddr = "127.0.0.1:7352"

// runUI serves the dashboard for the state file until ctx ends. It listens
// on a loopback address only. The dashboard also answers only requests
// addressed to localhost, so another machine could not use it anyway.
func runUI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	c := command{name: "ui", stdout: stdout, stderr: stderr}
	fs := newFlagSet("ui")
	addr := fs.String("addr", defaultUIAddr, "")
	statePath := fs.String("state", defaultPath("state.json"), "")
	pos, done, code := c.parse(fs, args, wording.UIUsage, wording.UIFlags)
	if done {
		return code
	}
	if len(pos) > 0 {
		return c.usage(wording.CLIUnexpectedArgument(pos[0]))
	}
	if _, _, err := net.SplitHostPort(*addr); err != nil {
		return c.usage(wording.UIBadAddr(*addr))
	}
	if err := ui.CheckAddr(*addr); err != nil {
		return c.usage(wording.UINotLoopback(*addr))
	}
	if *statePath == "" {
		return c.usage(wording.CheckNoHome("state file"))
	}

	h, err := newDashboard(ui.Options{
		StatePath: *statePath,
		Version:   version,
		Build:     buildID(),
		Verify:    verifyJSON,
		ErrorLog:  stderr,
	})
	if err != nil {
		return c.fail(exitFailure, wording.UICantListen(*addr), err)
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return c.fail(exitFailure, wording.UICantListen(*addr), err)
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	fmt.Fprintln(stdout, wording.UIServing("http://"+ln.Addr().String()+"/"))

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return c.fail(exitFailure, wording.UICantListen(*addr), err)
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	return exitOK
}

// dashboard serves the dashboard with the evidence directory read against the
// state file. canary check writes evidence_dir as an absolute path. A state
// file moved by hand, such as the recorded run committed under docs/runs,
// names it relative to itself instead, so it works from any clone.
//
// ui.Options takes one evidence directory for the dashboard's life. So the
// dashboard is rebuilt with the directory the state file names whenever the
// file changes, as when canary check rewrites it while canary ui runs.
type dashboard struct {
	opts ui.Options

	mu   sync.Mutex
	seen os.FileInfo // the state file when dir was read; nil when missing
	dir  string      // the evidence directory h was built with
	h    http.Handler
}

func newDashboard(opts ui.Options) (*dashboard, error) {
	d := &dashboard{opts: opts}
	if _, err := d.current(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h, err := d.current()
	if err != nil {
		// ui.New fails only on options that worked at start. Keep serving
		// the dashboard built then.
		d.mu.Lock()
		h = d.h
		d.mu.Unlock()
	}
	h.ServeHTTP(w, r)
}

// current returns the dashboard for the state file as it is now.
func (d *dashboard) current() (http.Handler, error) {
	info, err := os.Stat(d.opts.StatePath)
	if err != nil {
		info = nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.h != nil && sameFile(d.seen, info) {
		return d.h, nil
	}
	dir := relativeEvidenceDir(d.opts.StatePath)
	if d.h == nil || dir != d.dir {
		o := d.opts
		o.EvidenceDir = dir
		h, err := ui.New(o)
		if err != nil {
			return nil, err
		}
		d.h, d.dir = h, dir
	}
	d.seen = info
	return d.h, nil
}

// sameFile reports whether two looks at the state file saw the same
// version of it. canary check replaces the file by renaming a new one over
// it, so a new version is a new file, and its time or size differ too.
func sameFile(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

// relativeEvidenceDir returns the state file's evidence_dir read against the
// state file's own directory when it is relative. It returns "" otherwise,
// and the dashboard then uses the directory the state file names: an
// absolute path, as canary check writes it, or none when the file is
// missing or unreadable.
func relativeEvidenceDir(statePath string) string {
	f, err := state.Load(statePath)
	if err != nil || f.EvidenceDir == "" || filepath.IsAbs(f.EvidenceDir) {
		return ""
	}
	return filepath.Join(filepath.Dir(statePath), f.EvidenceDir)
}
