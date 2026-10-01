package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// maxEvidenceFile bounds how much of a file canary verify reads. A block of
// 2,000 entries gives a file near 180 KB, so 16 MiB leaves ample room while
// stopping a hostile file from holding the machine. It matches the limit the
// dashboard applies.
const maxEvidenceFile = 16 << 20

// runVerify checks one evidence file offline. It opens the file and nothing
// else: evidence.Verify recomputes every step from the file's bytes.
func runVerify(args []string, stdout, stderr io.Writer) int {
	c := command{name: "verify", stdout: stdout, stderr: stderr}
	flags := newFlagSet("verify")
	asJSON := flags.Bool("json", false, "")
	pos, done, code := c.parse(flags, args, wording.VerifyUsage, wording.VerifyFlags)
	if done {
		return code
	}
	switch {
	case len(pos) == 0:
		return c.usage(wording.VerifyNoFile)
	case len(pos) > 1:
		return c.usage(wording.CLIUnexpectedArgument(pos[1]))
	}

	// With --json there is no report without a file, so the reason goes to
	// stderr and stdout stays empty.
	b, reason, err := readEvidence(pos[0])
	if reason != "" {
		out := stdout
		if *asJSON {
			out = stderr
		}
		fmt.Fprintln(out, wording.VerifyCantRead(reason))
		if err != nil {
			fmt.Fprintln(stderr, wording.CLIDetails(err.Error()))
		}
		return exitCantRead
	}

	rep, _ := evidence.Verify(b)
	if *asJSON {
		out, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return c.fail(exitFailure, wording.VerifyCantRead(wording.VerifyReasonMalformed), err)
		}
		fmt.Fprintln(stdout, string(out))
		return rep.ExitCode()
	}
	printReport(stdout, rep)
	return rep.ExitCode()
}

// readEvidence reads a file up to maxEvidenceFile bytes. reason is set, from
// the wording table, when the file cannot be read at all.
func readEvidence(path string) (b []byte, reason string, err error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, wording.VerifyReasonMissing, nil
	}
	if err != nil {
		return nil, wording.VerifyReasonNotOpened, err
	}
	defer f.Close()
	b, err = io.ReadAll(io.LimitReader(f, maxEvidenceFile+1))
	if err != nil {
		return nil, wording.VerifyReasonNotOpened, err
	}
	if len(b) > maxEvidenceFile {
		return nil, wording.VerifyReasonTooLarge(maxEvidenceFile), nil
	}
	return b, "", nil
}

// printReport prints the report the way the formats doc lays it out: the
// outcome's first line, what it covers, then one line per step.
func printReport(w io.Writer, rep evidence.VerifyReport) {
	switch {
	case rep.Result == evidence.ResultChecksOut && rep.Code == evidence.CodeOK:
		fmt.Fprintln(w, wording.VerifyChecksOut)
		fmt.Fprintln(w, wording.VerifyChecksOutDetail)
		printSubject(w, rep)
	case rep.Result == evidence.ResultChecksOut:
		fmt.Fprintln(w, wording.VerifyInclusionOnly)
		for _, line := range wording.VerifyInclusionOnlyDetail {
			fmt.Fprintln(w, line)
		}
		printSubject(w, rep)
	case rep.Result == evidence.ResultDoesNotCheckOut:
		fmt.Fprintln(w, wording.VerifyDoesNotCheckOut(failedStep(rep)))
	default:
		reason := wording.VerifyReasonMalformed
		if rep.Code == evidence.CodeUnsupportedFormat {
			reason = wording.VerifyReasonUnsupported
		}
		fmt.Fprintln(w, wording.VerifyCantRead(reason))
	}
	for _, c := range rep.Checks {
		fmt.Fprintln(w, wording.VerifyCheckLine(c.OK, c.Step, c.Text))
	}
	if rep.Result == evidence.ResultDoesNotCheckOut {
		fmt.Fprintln(w, wording.VerifyNotHonest)
	}
}

// printSubject names the key, block and entry a file that checks out is
// about.
func printSubject(w io.Writer, rep evidence.VerifyReport) {
	if rep.Accused == nil || rep.Block == nil || rep.Missing == nil || rep.Network == nil {
		return
	}
	fmt.Fprintln(w, wording.VerifySubject(wording.ShortHash(rep.Accused.Pubkey, 8, 4), rep.Block.Height,
		rep.Network.Name, rep.Missing.Index, wording.ShortHash(rep.Missing.TxID, 8, 4)))
}

// failedStep returns the name of the step that failed.
func failedStep(rep evidence.VerifyReport) string {
	for _, c := range rep.Checks {
		if c.OK != nil && !*c.OK {
			return c.Step
		}
	}
	return rep.Code
}

// verifyJSON is the dashboard's check for one evidence file: the report
// canary verify --json prints. A file that does not check out is a report,
// not an error.
func verifyJSON(b []byte) ([]byte, error) {
	rep, _ := evidence.Verify(b)
	return json.Marshal(rep)
}
