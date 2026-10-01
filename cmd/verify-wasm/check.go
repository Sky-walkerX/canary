// Command verify-wasm is the browser evidence checker. Built with GOOS=js
// GOARCH=wasm, it gives the page one function, canaryVerify, that checks an
// evidence file with the same evidence.Verify that canary verify runs. The
// report comes back with the first line canary verify prints and the
// dashboard's markup for it, so the public site, the dashboard and the CLI
// show the same words. report.go writes that markup without html/template,
// which would nearly double the module.
//
// The checker opens no network connection. The page hands it the file's
// bytes, and it hands back a report. Nothing leaves the browser.
//
// Build it with make wasm, which writes canary.wasm and the matching
// wasm_exec.js to bin/wasm. smoke_test.mjs in this directory runs the built
// module under Node.
package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// maxFileBytes is the largest file the checker reads. It matches canary verify
// and the dashboard: a block of 2,000 entries gives a file near 180 KB.
const maxFileBytes = 16 << 20

// output is what canaryVerify returns: the VerifyReport, the first line
// canary verify prints for it, and the dashboard's markup for it. Error is
// set only when the markup could not be rendered, and html is then empty.
type output struct {
	evidence.VerifyReport
	Headline string `json:"headline"`
	HTML     string `json:"html"`
	Error    string `json:"error,omitempty"`
}

// check verifies one evidence file and returns the output as JSON. A file
// that does not check out, or cannot be read, still gives a report. The
// error is set only when the markup could not be rendered; the output then
// carries the report and names the error, with an empty html field.
func check(b []byte) ([]byte, error) {
	rep, _ := evidence.Verify(b)
	out := output{VerifyReport: rep, Headline: headline(rep)}
	html, renderErr := renderReport(rep)
	out.HTML = html
	if renderErr != nil {
		out.Error = renderErr.Error()
	}
	j, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("verify-wasm: encode output: %w", err)
	}
	return j, renderErr
}

// renderReport gives the dashboard's markup for a report. The dashboard
// renders the report it reads back from canary verify --json, so the report
// makes the same round trip through JSON here. That gives the markup the same
// values, down to how JSON replaces a byte that is not UTF-8.
func renderReport(rep evidence.VerifyReport) (string, error) {
	j, err := json.Marshal(rep)
	if err != nil {
		return "", fmt.Errorf("verify-wasm: encode report: %w", err)
	}
	var shown evidence.VerifyReport
	if err := json.Unmarshal(j, &shown); err != nil {
		return "", fmt.Errorf("verify-wasm: decode report: %w", err)
	}
	return reportHTML(shown)
}

// headline is the first line canary verify prints for a report. A file that
// does not check out names the step that failed.
func headline(rep evidence.VerifyReport) string {
	switch {
	case rep.Result == evidence.ResultChecksOut && rep.Code == evidence.CodeOK:
		return wording.VerifyChecksOut
	case rep.Result == evidence.ResultChecksOut:
		return wording.VerifyInclusionOnly
	case rep.Result == evidence.ResultDoesNotCheckOut:
		return wording.VerifyDoesNotCheckOut(failedStep(rep))
	case rep.Code == evidence.CodeUnsupportedFormat:
		return wording.VerifyCantRead(wording.VerifyReasonUnsupported)
	}
	return wording.VerifyCantRead(wording.VerifyReasonMalformed)
}

// failedStep returns the name of the step that failed, or the code when no
// step is marked failed.
func failedStep(rep evidence.VerifyReport) string {
	for _, c := range rep.Checks {
		if c.OK != nil && !*c.OK {
			return c.Step
		}
	}
	return rep.Code
}

// goRelease writes a Go version the way the page names it: "go1.26.4"
// becomes "Go 1.26.4". A version that does not start that way, such as a
// development build's, comes back unchanged.
func goRelease(v string) string {
	if rest, ok := strings.CutPrefix(v, "go"); ok && rest != "" && rest[0] >= '0' && rest[0] <= '9' {
		return "Go " + rest
	}
	return v
}

// buildInfo is what canaryCheckerInfo returns: which build the page runs, the
// size limit, and the two lines canary verify prints for a file it never
// gets to check. The page needs those before it hands the module a file.
type buildInfo struct {
	GoVersion    string `json:"go_version"`
	GoRelease    string `json:"go_release"`
	Revision     string `json:"revision"`
	Modified     bool   `json:"modified"`
	MaxFileBytes int    `json:"max_file_bytes"`
	TooLarge     string `json:"too_large"`
	NotOpened    string `json:"not_opened"`
}

func checkerInfo() []byte {
	info := buildInfo{
		GoVersion:    runtime.Version(),
		GoRelease:    goRelease(runtime.Version()),
		MaxFileBytes: maxFileBytes,
		TooLarge:     wording.VerifyCantRead(wording.VerifyReasonTooLarge(maxFileBytes)),
		NotOpened:    wording.VerifyCantRead(wording.VerifyReasonNotOpened),
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				info.Revision = s.Value
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
	}
	j, _ := json.Marshal(info)
	return j
}
