package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

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

	h, err := ui.New(ui.Options{
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
