package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// command holds one subcommand's name and output streams, so every message
// it prints has the same shape.
type command struct {
	name           string
	stdout, stderr io.Writer
}

// usage prints a usage error and the pointer to --help, and returns exit
// code 2.
func (c command) usage(msg string) int {
	fmt.Fprintf(c.stderr, "canary %s: %s\n%s\n", c.name, msg, wording.CLICommandHelpHint(c.name))
	return exitUsage
}

// fail prints msg and, under it, the Go error's own text. It returns code.
func (c command) fail(code int, msg string, err error) int {
	fmt.Fprintf(c.stderr, "canary %s: %s\n", c.name, msg)
	if err != nil {
		fmt.Fprintln(c.stderr, wording.CLIDetails(err.Error()))
	}
	return code
}

// multiFlag collects a flag given more than once.
type multiFlag []string

func (m *multiFlag) String() string { return fmt.Sprint(*m) }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// newFlagSet returns a flag set that prints nothing on its own. The command
// prints its errors and help from the wording table.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// errHelp means the user asked for --help. The caller prints the help and
// exits 0.
var errHelp = flag.ErrHelp

// parseInterspersed parses args with fs, allowing flags after positional
// arguments, as in canary verify FILE --json. It returns the positional
// arguments in order.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// parseCommand parses args for c. On --help it prints the command's help to
// stdout. It returns done with an exit code when the command should stop.
func (c command) parse(fs *flag.FlagSet, args []string, usage string, flags []wording.FlagHelp) (pos []string, done bool, code int) {
	pos, err := parseInterspersed(fs, args)
	switch {
	case errors.Is(err, errHelp):
		printHelp(c.stdout, usage, flags)
		return nil, true, exitOK
	case err != nil:
		return nil, true, c.usage(wording.CLIFlagError(err.Error()))
	}
	return pos, false, 0
}

// printHelp prints a command's usage line and its flags.
func printHelp(w io.Writer, usage string, flags []wording.FlagHelp) {
	fmt.Fprintln(w, usage)
	fmt.Fprintln(w)
	fmt.Fprintln(w, wording.CLIFlagsHeading)
	for _, f := range flags {
		if f.Arg != "" {
			fmt.Fprintf(w, "  --%s %s\n", f.Name, f.Arg)
		} else {
			fmt.Fprintf(w, "  --%s\n", f.Name)
		}
		fmt.Fprintf(w, "        %s\n", f.Text)
	}
}

// defaultPath returns ~/.canary/<name>, or "" when the home directory is
// unknown.
func defaultPath(name string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".canary", name)
}
