package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

func TestUIRefusesAnAddressOffThisComputer(t *testing.T) {
	// Port 0 and a deadline: if the refusal ever broke, the command would
	// serve briefly on a spare port and the test would fail, not hang.
	for _, addr := range []string{"0.0.0.0:0", "192.168.1.5:0", "[::]:0", "example.com:0"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var out, errb syncBuffer
		code := run(ctx, []string{"ui", "--addr", addr, "--state", filepath.Join(t.TempDir(), "s.json")}, &out, &errb)
		cancel()
		r := result{code: code, stdout: out.String(), stderr: errb.String()}
		wantExit(t, r, 2)
		if !strings.Contains(r.stderr, wording.UINotLoopback(addr)) {
			t.Errorf("%s: stderr lacks the refusal:\n%s", addr, r)
		}
	}
	r := runCLI(t, "ui", "--addr", "nonsense")
	wantExit(t, r, 2)
	if !strings.Contains(r.stderr, wording.UIBadAddr("nonsense")) {
		t.Errorf("stderr lacks the bad address:\n%s", r)
	}
}

// uiServer runs canary ui until the test ends and returns its base URL.
func uiServer(t *testing.T, statePath string) (string, func() result) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var out, errb syncBuffer
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"ui", "--addr", "127.0.0.1:0", "--state", statePath}, &out, &errb) }()

	re := regexp.MustCompile(`http://127\.0\.0\.1:\d+/`)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if u := re.FindString(out.String()); u != "" {
			stop := func() result {
				cancel()
				select {
				case code := <-done:
					return result{code: code, stdout: out.String(), stderr: errb.String()}
				case <-time.After(10 * time.Second):
					t.Fatal("canary ui did not stop")
				}
				return result{}
			}
			t.Cleanup(func() { cancel() })
			return u, stop
		}
		select {
		case code := <-done:
			cancel()
			t.Fatalf("canary ui exited %d before serving:\n%s\n%s", code, out.String(), errb.String())
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("canary ui printed no address:\n%s", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func TestUIServesWithNoStateFileYet(t *testing.T) {
	base, stop := uiServer(t, filepath.Join(t.TempDir(), "state.json"))
	code, body := get(t, base)
	if code != http.StatusOK || !strings.Contains(body, wording.NoCheckYet.Title) {
		t.Errorf("GET / = %d, want the No check yet page:\n%.300s", code, body)
	}
	r := stop()
	wantExit(t, r, 0)
	if !strings.Contains(r.stdout, "Serving the dashboard at "+base) {
		t.Errorf("stdout lacks the serving line:\n%s", r)
	}
}

func TestUICannotBindABusyPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	r := runCLI(t, "ui", "--addr", addr, "--state", filepath.Join(t.TempDir(), "s.json"))
	wantExit(t, r, 5)
	if !strings.Contains(r.stderr, wording.UICantListen(addr)) {
		t.Errorf("stderr lacks the listen failure:\n%s", r)
	}
}
