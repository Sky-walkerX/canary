package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/evidence"
)

// The browser's headline is the first line canary verify prints. This test
// builds the CLI and holds the two together on real files, so a change to
// either one's first line fails here.
func TestHeadlineMatchesTheCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("builds cmd/canary")
	}
	gocmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to build cmd/canary with")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "canary")
	build := exec.Command(gocmd, "build", "-o", bin, "github.com/Sky-walkerX/canary/cmd/canary")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cmd/canary: %v\n%s", err, out)
	}

	good := docExample(t, "## 6. The evidence file")
	var f map[string]any
	if err := json.Unmarshal(good, &f); err != nil {
		t.Fatal(err)
	}
	f["receipt"], f["served_base64"] = nil, nil
	noReceipt, _ := json.Marshal(f)
	f["format"] = "canary-evidence/2"
	otherFormat, _ := json.Marshal(f)
	files := map[string][]byte{
		"good":         good,
		"no receipt":   noReceipt,
		"other format": otherFormat,
		"not JSON":     []byte("this is not JSON"),
		"empty":        nil,
	}
	// One file for each code a one-byte change reaches.
	seen := map[string]bool{}
	for i := range good {
		b := bytes.Clone(good)
		b[i] ^= 1
		rep, _ := evidence.Verify(b)
		if !seen[rep.Code] {
			seen[rep.Code] = true
			files["byte "+itoa(i)+" "+rep.Code] = b
		}
	}

	for name, file := range files {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, "evidence.json")
			if err := os.WriteFile(path, file, 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(bin, "verify", path).Output()
			var exit *exec.ExitError
			if err != nil && !errors.As(err, &exit) {
				t.Fatalf("run canary verify: %v", err)
			}
			cli, _, _ := strings.Cut(string(out), "\n")
			_, browser, _ := decode(t, file)
			if browser != cli {
				t.Errorf("browser headline %q, canary verify's first line %q", browser, cli)
			}
		})
	}
}
