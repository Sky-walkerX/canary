package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// exampleState is the state file example from the v1 formats doc.
const exampleState = "../../internal/state/testdata/example-state.json"

func TestStatusPrintsTheFormatsDocSummary(t *testing.T) {
	r := runCLI(t, "status", "--state", exampleState)
	wantExit(t, r, 0)
	want := "Last check 2026-10-03 08:32 UTC · blocks 0–212 · regtest · canary 0.1.0 (abc1234)\n" +
		"212 Checked · 1 Data withheld\n" +
		"withholder left out an entry it had signed for: block 205, txid 01982d71…7c16.\n" +
		"  Evidence: omission-regtest-205-01982d71-b1070620.json. You can prove this to others.\n"
	if r.stdout != want {
		t.Errorf("status printed\n%s\nwant\n%s", r.stdout, want)
	}
}

func TestStatusJSONPrintsTheFileUnchanged(t *testing.T) {
	r := runCLI(t, "status", "--json", "--state", exampleState)
	wantExit(t, r, 0)
	if r.stdout != string(readFile(t, exampleState)) {
		t.Error("status --json changed the state file's bytes")
	}
	// The flag may follow the path too.
	r = runCLI(t, "status", "--state", exampleState, "--json")
	wantExit(t, r, 0)
}

// Warnings print after every other finding, and each ends by saying it is
// not an accusation. A finding with no evidence file says what you can do
// with it.
func TestStatusOrdersWarningsLast(t *testing.T) {
	f := loadState(t, exampleState)
	seen := state.Time{Time: time.Date(2026, 10, 3, 8, 32, 11, 0, time.UTC)}
	pos := uint32(0)
	warning := state.Finding{
		ID: "aaaaaaaaaaaa", Kind: state.KindWarning, Reason: state.ListNotServed,
		Servers: f.Findings[0].Servers, Block: state.BlockRef{Height: 209, Hash: f.Blocks[0].Hash},
		FirstSeen: seen, LastSeen: seen,
	}
	noFile := f.Findings[0]
	noFile.ID, noFile.Evidence, noFile.Provable, noFile.Position = "bbbbbbbbbbbb", nil, false, &pos
	f.Findings = append([]state.Finding{warning}, append(f.Findings, noFile)...)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path, f); err != nil {
		t.Fatal(err)
	}

	r := runCLI(t, "status", "--state", path)
	wantExit(t, r, 0)
	lines := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, "Warning: ") || !strings.HasSuffix(last, wording.WarningSuffix) {
		t.Errorf("the last line is %q, want the warning", last)
	}
	if !strings.Contains(r.stdout, "  "+wording.ProvableShort("withheld", false, false)+"\n") {
		t.Errorf("a finding with no file must say you can't prove it:\n%s", r.stdout)
	}
}

func TestStatusCannotReadTheFile(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.json")
	newer := filepath.Join(dir, "newer.json")
	if err := os.WriteFile(garbage, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newer, []byte(`{"format":"canary-state/2"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.json")
	tests := []struct {
		path, want string
		json       bool
	}{
		{missing, wording.StatusMissing(missing), false},
		{garbage, wording.StatusUnreadable(garbage), false},
		{garbage, wording.StatusUnreadable(garbage), true},
		{newer, wording.StatusNewer(newer, "canary-state/2"), false},
		{newer, wording.StatusNewer(newer, "canary-state/2"), true},
	}
	for _, tt := range tests {
		args := []string{"status", "--state", tt.path}
		if tt.json {
			args = append(args, "--json")
		}
		r := runCLI(t, args...)
		wantExit(t, r, 3)
		if !strings.Contains(r.stderr, tt.want) || r.stdout != "" {
			t.Errorf("%v: want %q on stderr and nothing on stdout:\n%s", args, tt.want, r)
		}
	}
}
