package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// runStatus prints a summary of the state file, or with --json the file's
// bytes unchanged once it has checked the format is one it reads.
func runStatus(args []string, stdout, stderr io.Writer) int {
	c := command{name: "status", stdout: stdout, stderr: stderr}
	fs := newFlagSet("status")
	asJSON := fs.Bool("json", false, "")
	statePath := fs.String("state", defaultPath("state.json"), "")
	pos, done, code := c.parse(fs, args, wording.StatusUsage, wording.StatusFlags)
	if done {
		return code
	}
	if len(pos) > 0 {
		return c.usage(wording.CLIUnexpectedArgument(pos[0]))
	}
	if *statePath == "" {
		return c.usage(wording.CheckNoHome("state file"))
	}

	raw, err := state.Read(*statePath)
	var f *state.File
	if err == nil {
		f, err = state.Parse(raw)
	}
	if err != nil {
		var newer *state.NewerFormatError
		switch {
		case errors.Is(err, state.ErrMissing):
			return c.fail(exitCantRead, wording.StatusMissing(*statePath), nil)
		case errors.As(err, &newer):
			return c.fail(exitCantRead, wording.StatusNewer(*statePath, newer.Found), nil)
		}
		return c.fail(exitCantRead, wording.StatusUnreadable(*statePath), err)
	}

	if *asJSON {
		_, _ = stdout.Write(raw)
		return exitOK
	}
	printSummary(stdout, f)
	return exitOK
}

// printSummary prints the formats doc's summary of a state file: the status
// line in UTC, the counts, then each finding. Warnings come last, each on a
// line that says it is not an accusation.
func printSummary(w io.Writer, f *state.File) {
	when := f.GeneratedAt.UTC().Format(wording.StatusTimeLayout)
	fmt.Fprintln(w, wording.StatusLine(when, "", f.Checked.From, f.Checked.To, f.Network.Name, f.Canary.Version, f.Canary.Build))

	counts := make(map[string]int, len(state.States))
	for _, s := range state.States {
		counts[string(s)] = int(f.Counts.Get(s))
	}
	fmt.Fprintln(w, wording.CountsLine(counts))

	for _, warnings := range []bool{false, true} {
		for _, x := range f.Findings {
			if (x.Kind == state.KindWarning) != warnings {
				continue
			}
			labels := make([]string, len(x.Servers))
			for i, s := range x.Servers {
				labels[i] = s.Label
			}
			txid := ""
			if x.Txid != nil {
				txid = *x.Txid
			}
			fmt.Fprintln(w, wording.FindingStatusLine(x.Kind, string(x.Reason), labels, x.Block.Height, txid))
			switch {
			case warnings:
			case x.Evidence != nil:
				fmt.Fprintln(w, "  "+wording.EvidenceStatusLine(*x.Evidence, x.Provable))
			default:
				fmt.Fprintln(w, "  "+wording.ProvableShort(x.Kind, x.Provable, false))
			}
		}
	}
}

// utc formats t for a state file field.
func utc(t time.Time) state.Time {
	return state.Time{Time: t.UTC().Truncate(time.Second)}
}
