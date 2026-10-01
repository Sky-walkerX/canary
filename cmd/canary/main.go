// Command canary is Canary's v1 command-line tool. It checks what tweak index
// servers serve against what they signed, and writes down what it finds.
//
//	canary check    checks a range of blocks against each server
//	canary verify   checks one evidence file offline
//	canary status   prints a summary of the state file
//	canary ui       serves the dashboard on this computer
//
// Canary makes tweak sourcing accountable. It does not remove the need to
// trust a server. It looks for entries a server left out of what it signed
// for, never for entries a server faked.
//
// The v1 formats doc fixes every flag, output line and exit code. Every word
// the tool prints comes from the shared wording table, so the terminal, the
// dashboard and the browser checker say the same thing.
//
// The version and build id come from the linker:
//
//	go build -ldflags "-X main.version=0.1.0 -X main.build=abc1234" ./cmd/canary
//
// Without them the build id is the git commit Go recorded, or "unknown".
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// version is the release version. build is the git commit. Both can be set
// at link time with -X.
var (
	version = "0.1.0"
	build   = ""
)

// now is the clock. Tests replace it to pin first_seen and last_seen.
var now = time.Now

// Exit codes, from the formats doc.
const (
	exitOK            = 0
	exitFound         = 1 // check: a finding; verify: does not check out
	exitUsage         = 2
	exitCantRead      = 3
	exitInclusionOnly = 4
	exitFailure       = 5
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run is the whole program behind main, so tests can call it in process.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "canary: "+wording.CLINoCommand)
		fmt.Fprintln(stderr, wording.CLIHelpHint)
		return exitUsage
	}
	switch args[0] {
	case "check":
		return runCheck(ctx, args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "ui":
		return runUI(ctx, args[1:], stdout, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprintln(stdout, wording.CLIUsage)
		return exitOK
	case "-version", "--version":
		fmt.Fprintln(stdout, wording.VersionLine(version, buildID()))
		return exitOK
	}
	fmt.Fprintln(stderr, "canary: "+wording.CLIUnknownCommand(args[0]))
	fmt.Fprintln(stderr, wording.CLIHelpHint)
	return exitUsage
}

// buildID returns the git commit the binary was built from, or "unknown".
func buildID() string {
	if build != "" {
		return build
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				return s.Value[:7]
			}
		}
	}
	return "unknown"
}

// writtenBy names this program in an evidence file's context.
func writtenBy() string {
	return "canary " + version + "+" + buildID()
}
