package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A test can run one canary command in a child process that the operating
// system cuts off from the network. The child is this test binary again,
// started with offlineEnv set. Swapping http.DefaultTransport, as
// blockNetwork does, catches only requests that go through it. A cut made by
// the operating system catches every dialer the code could use.
const (
	offlineEnv      = "CANARY_TEST_OFFLINE_CHILD"
	offlineProbeEnv = "CANARY_TEST_OFFLINE_PROBE" // an address the child must fail to reach

	exitOfflineSetup  = 120 // the child could not cut itself off
	exitOfflineDialed = 121 // the child reached the probe address anyway
)

func TestMain(m *testing.M) {
	if os.Getenv(offlineEnv) == "1" {
		os.Exit(offlineChild())
	}
	os.Exit(m.Run())
}

// offlineChild cuts the process off from the network, shows the cut holds
// with a direct dial through net.Dialer, then runs the canary command in its
// arguments.
func offlineChild() int {
	if err := cutOffNetwork(); err != nil {
		fmt.Fprintln(os.Stderr, "offline child: cut off the network:", err)
		return exitOfflineSetup
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	if conn, err := d.Dial("tcp", os.Getenv(offlineProbeEnv)); err == nil {
		conn.Close()
		fmt.Fprintln(os.Stderr, "offline child: a direct dial reached the probe address")
		return exitOfflineDialed
	}
	return run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)
}

// errNoNetworkCut means this platform has no way, known to these tests, to
// cut a process off from the network.
var errNoNetworkCut = errors.New("no network cut on this platform")

// sandboxExitOSErr is sandbox-exec's exit code when it cannot apply its
// profile, as inside a process that is already sandboxed.
const sandboxExitOSErr = 71

// networkCutRefused reports whether the child never ran because the
// operating system refused the cut: sandbox-exec could not apply its
// profile, or the child could not cut itself off.
func networkCutRefused(r result) bool {
	return r.code == exitOfflineSetup ||
		r.code == sandboxExitOSErr && strings.Contains(r.stderr, "sandbox_apply")
}

// networkCutRequired reports whether a refused cut fails the test instead of
// skipping it. CI sets CI=true, so the cut stays enforced there.
func networkCutRequired() bool {
	return os.Getenv("CI") != "" || os.Getenv("CANARY_REQUIRE_OFFLINE") == "1"
}

// runOffline runs canary with args in a child process that the operating
// system cuts off from the network. Before the command runs, the child dials
// a listener in this process directly and must fail, so the cut is shown to
// hold for a dialer outside net/http. The listener must also see no
// connection at all.
func runOffline(t *testing.T, args ...string) result {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conn.Close()
		}
	}()
	defer ln.Close()

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := offlineCommand(self, args)
	if errors.Is(err, errNoNetworkCut) {
		t.Skipf("can't cut a process off from the network here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(os.Environ(), offlineEnv+"=1", offlineProbeEnv+"="+ln.Addr().String())
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	r := result{stdout: stdout.String(), stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		r.code = exit.ExitCode()
	case err != nil:
		t.Fatalf("start the offline child: %v", err)
	}
	switch {
	case networkCutRefused(r) && !networkCutRequired():
		t.Skipf("can't apply an operating-system network cut in this environment, which is likely sandboxed already. "+
			"Set CANARY_REQUIRE_OFFLINE=1 to fail instead:\n%s", r)
	case r.code == exitOfflineSetup:
		t.Fatalf("the child could not cut itself off from the network:\n%s", r)
	case networkCutRefused(r):
		t.Fatalf("the operating system refused the network cut:\n%s", r)
	case r.code == exitOfflineDialed:
		t.Fatalf("the network cut did not hold:\n%s", r)
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the offline child opened %d connections to the probe listener", n)
	}
	return r
}
