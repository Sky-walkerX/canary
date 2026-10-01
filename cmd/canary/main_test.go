package main

import (
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

func TestCommandDispatch(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{"no command", nil, 2, "", wording.CLINoCommand},
		{"unknown command", []string{"chek"}, 2, "", wording.CLIUnknownCommand("chek")},
		{"help", []string{"help"}, 0, "Usage: canary <command>", ""},
		{"-h", []string{"-h"}, 0, "Usage: canary <command>", ""},
		{"version", []string{"--version"}, 0, "canary " + version + " (", ""},
		{"check help", []string{"check", "--help"}, 0, wording.CheckUsage, ""},
		{"verify help", []string{"verify", "-h"}, 0, wording.VerifyUsage, ""},
		{"status help", []string{"status", "--help"}, 0, wording.StatusUsage, ""},
		{"ui help", []string{"ui", "--help"}, 0, wording.UIUsage, ""},
		{"unknown flag", []string{"status", "--nope"}, 2, "", "Can't read the flags"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runCLI(t, tt.args...)
			wantExit(t, r, tt.code)
			if !strings.Contains(r.stdout, tt.stdout) {
				t.Errorf("stdout lacks %q:\n%s", tt.stdout, r)
			}
			if !strings.Contains(r.stderr, tt.stderr) {
				t.Errorf("stderr lacks %q:\n%s", tt.stderr, r)
			}
		})
	}
}

// Every flag in a command's help text is a flag the command accepts.
func TestHelpListsEveryFlag(t *testing.T) {
	for cmd, flags := range map[string][]wording.FlagHelp{
		"check": wording.CheckFlags, "verify": wording.VerifyFlags,
		"status": wording.StatusFlags, "ui": wording.UIFlags,
	} {
		r := runCLI(t, cmd, "--help")
		for _, f := range flags {
			if !strings.Contains(r.stdout, "--"+f.Name) || !strings.Contains(r.stdout, f.Text) {
				t.Errorf("%s --help lacks --%s:\n%s", cmd, f.Name, r.stdout)
			}
		}
	}
}

func TestBuildIDHasADefault(t *testing.T) {
	if id := buildID(); id == "" {
		t.Error("buildID() is empty; the state file needs a build id")
	}
	old := build
	build = "abc1234"
	defer func() { build = old }()
	if id := buildID(); id != "abc1234" {
		t.Errorf("buildID() = %q, want the -ldflags value", id)
	}
}
