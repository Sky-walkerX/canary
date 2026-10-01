package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
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

// copyFile copies src to dst, creating dst's directory.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// setEvidenceDir rewrites the state file's evidence_dir.
func setEvidenceDir(t *testing.T, path, dir string) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(readFile(t, path), &m); err != nil {
		t.Fatal(err)
	}
	v, _ := json.Marshal(dir)
	m["evidence_dir"] = v
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// checksOut reports whether a finding page shows its evidence file checking
// out. The page prints the verdict without its full stop.
func checksOut(page string) bool {
	return strings.Contains(page, ">"+strings.TrimSuffix(wording.VerifyChecksOut, ".")+"<") &&
		!strings.Contains(page, wording.EvidenceNotFound("").Title)
}

// The recorded run in docs/runs/2026-10-01 names its evidence directory
// relative to its own state file, so it works from any clone. canary ui reads
// a relative evidence_dir against the state file's directory, not against
// the directory canary ui runs in. A later state file that names another
// directory, as canary check writes it, takes over without a restart.
func TestUIReadsARelativeEvidenceDirAgainstTheStateFile(t *testing.T) {
	const (
		run  = "../../docs/runs/2026-10-01"
		name = "omission-regtest-351-ad56b9bb-db614560.json"
		id   = "79ec3cb71656"
	)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "run", "state.json")
	copyFile(t, filepath.Join(run, "state.json"), statePath)
	copyFile(t, filepath.Join("../../evidence", name), filepath.Join(dir, "run", "evidence", name))
	setEvidenceDir(t, statePath, "evidence")
	if _, err := os.Stat(filepath.Join("evidence", name)); err == nil {
		t.Fatal("test setup: the evidence file must not sit under the working directory")
	}

	base, stop := uiServer(t, statePath)
	code, body := get(t, base+"evidence/"+name)
	if code != http.StatusOK || body != string(readFile(t, filepath.Join(dir, "run", "evidence", name))) {
		t.Errorf("GET /evidence/%s = %d, want the file", name, code)
	}
	code, body = get(t, base+"findings/"+id)
	if code != http.StatusOK || !checksOut(body) {
		t.Errorf("GET /findings/%s = %d, want the finding with its evidence checking out:\n%.400s", id, code, body)
	}

	// canary check writes an absolute path. The dashboard follows it.
	elsewhere := filepath.Join(dir, "elsewhere")
	copyFile(t, filepath.Join(dir, "run", "evidence", name), filepath.Join(elsewhere, name))
	if err := os.Remove(filepath.Join(dir, "run", "evidence", name)); err != nil {
		t.Fatal(err)
	}
	setEvidenceDir(t, statePath, elsewhere)
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(statePath, future, future); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, base+"evidence/"+name); code != http.StatusOK {
		t.Errorf("after the state file named an absolute directory, GET /evidence/%s = %d, want 200", name, code)
	}
	wantExit(t, stop(), 0)
}

// The committed run itself checks out in the dashboard, read from where it
// sits in the repository.
func TestUIShowsTheRecordedRunsEvidence(t *testing.T) {
	base, stop := uiServer(t, "../../docs/runs/2026-10-01/state.json")
	code, body := get(t, base+"findings/79ec3cb71656")
	if code != http.StatusOK || !checksOut(body) {
		t.Errorf("GET the recorded run's finding = %d, want its evidence checking out:\n%.400s", code, body)
	}
	wantExit(t, stop(), 0)
}
