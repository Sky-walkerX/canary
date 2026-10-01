package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// checkerView is what the checker area on the home page shows. The page
// script that runs the checker reads the data attributes it renders.
type checkerView struct {
	// Recorded is true when the sample comes from the recorded run, given
	// with -evidence. Otherwise it is the formats document's example.
	Recorded     bool
	RealName     string
	RealURL      string
	TamperedName string
	TamperedURL  string

	// The words that depend on where the sample comes from.
	TryLabel, DownloadLabel, Source, TamperNote string

	// RunURL is the recorded run the sample comes from, or "" when no
	// recorded run on the site names it.
	RunURL string

	// Module is the browser checker, or nil when the site was built without
	// it.
	Module *moduleView
}

// moduleView is what the page tells checker.js about the module.
type moduleView struct {
	Size  int    // canary.wasm's size in bytes, which drives the progress bar
	Build string // the line that names its commit and Go release
	Text  wording.CheckerText
}

// The tampered copy flips one hex digit of one of these JSON values. Either
// change makes the inclusion step fail for a real reason: the proof no longer
// leads from the left-out entry to the signed root. A block with one entry
// has no sibling, so its copy changes the entry's txid instead.
const (
	tamperSibling = "proof.siblings[0]"
	tamperTxid    = "missing.txid"
)

// The formats document holds the example evidence file, as the first JSON
// block under "### Example" in this section.
const (
	formatsDoc      = "design/2026-09-30-v1-formats.md"
	evidenceSection = "## 6. The evidence file"
)

// writeEvidence publishes the sample evidence file unchanged, and a copy with
// one byte flipped. It records exactly which byte, so the page can say so.
// Before it publishes the pair, it runs both through the verifier the
// checker runs: the sample must check out, and the copy must not.
func (s *site) writeEvidence() error {
	file, name, view, err := s.sample()
	if err != nil {
		return err
	}
	tampered, offset, field, err := tamper(file)
	if err != nil {
		return fmt.Errorf("site: evidence %s: %w", name, err)
	}
	step, err := checkPair(file, tampered)
	if err != nil {
		return fmt.Errorf("site: evidence %s: %w", name, err)
	}
	tname := strings.TrimSuffix(name, ".json") + "-tampered.json"
	if err := s.writeOnce("evidence/"+name, file); err != nil {
		return err
	}
	if err := s.writeOnce("evidence/"+tname, tampered); err != nil {
		return err
	}
	view.RealName, view.RealURL = name, "/evidence/"+name
	view.TamperedName, view.TamperedURL = tname, "/evidence/"+tname
	view.TamperNote = wording.Site.TamperNote(offset+1, field, string(file[offset]), string(tampered[offset]), step)
	s.checker = view
	return nil
}

// sample returns the evidence file the checker offers, its published name,
// and the words that say where it comes from. A real file comes from a
// recorded run. When a run on the site names it, the page names that run's
// network, day and Bitcoin Core release, and links the run. Otherwise it is
// dated by the time canary check wrote it. Without a real file, the sample
// is the formats document's example, named for what it is.
func (s *site) sample() ([]byte, string, checkerView, error) {
	if s.cfg.Evidence == "" {
		doc, err := os.ReadFile(filepath.Join(s.cfg.Docs, filepath.FromSlash(formatsDoc)))
		if err != nil {
			return nil, "", checkerView{}, fmt.Errorf("site: read the formats document: %w", err)
		}
		file, err := docExample(doc, evidenceSection)
		if err != nil {
			return nil, "", checkerView{}, fmt.Errorf("site: example evidence file: %w", err)
		}
		parsed, err := evidence.Parse(file)
		if err != nil {
			return nil, "", checkerView{}, fmt.Errorf("site: example evidence file: %w", err)
		}
		return file, "example-" + parsed.Name(), checkerView{
			TryLabel:      wording.Site.CheckerTryExample,
			DownloadLabel: wording.Site.CheckerDownloadExample,
			Source:        wording.Site.CheckerSourceExample,
		}, nil
	}
	file, err := os.ReadFile(s.cfg.Evidence)
	if err != nil {
		return nil, "", checkerView{}, fmt.Errorf("site: read evidence: %w", err)
	}
	var ev struct {
		Context struct {
			WrittenAt string `json:"written_at"`
		} `json:"context"`
	}
	if err := json.Unmarshal(file, &ev); err != nil {
		return nil, "", checkerView{}, fmt.Errorf("site: evidence %s: not JSON: %w", s.cfg.Evidence, err)
	}
	when, err := time.Parse(time.RFC3339, ev.Context.WrittenAt)
	if err != nil {
		return nil, "", checkerView{}, fmt.Errorf("site: evidence %s: context.written_at %q is not an RFC 3339 time, and the page dates the recorded run from it",
			s.cfg.Evidence, ev.Context.WrittenAt)
	}
	name := filepath.Base(s.cfg.Evidence)
	view := checkerView{
		Recorded:      true,
		TryLabel:      wording.Site.CheckerTryReal,
		DownloadLabel: wording.Site.CheckerDownloadReal,
		Source:        wording.Site.CheckerSourceRecorded(when.UTC().Format("2 January 2006")),
	}
	if r := s.runFor(name); r != nil {
		view.Source = wording.Site.CheckerSourceRun(r.Network, r.Date.Format("2 January 2006"), r.Core)
		view.RunURL = r.URL
	}
	return file, name, view, nil
}

// docExample returns the first JSON block under "### Example" in the doc
// section whose heading line starts with heading, up to the next "## "
// heading. It reads the doc the way cmd/canary's tests and the checker's
// smoke test do, so all three use the same bytes.
func docExample(doc []byte, heading string) ([]byte, error) {
	s := string(doc)
	if !strings.HasPrefix(s, heading) {
		at := strings.Index(s, "\n"+heading)
		if at < 0 {
			return nil, fmt.Errorf("no section %q", heading)
		}
		s = s[at+1:]
	}
	if next := strings.Index(s[len(heading):], "\n## "); next >= 0 {
		s = s[:len(heading)+next]
	}
	ex := strings.Index(s, "\n### Example")
	if ex < 0 {
		return nil, fmt.Errorf("section %q has no example", heading)
	}
	s = s[ex:]
	open := strings.Index(s, "```json\n")
	if open < 0 {
		return nil, fmt.Errorf("section %q has no JSON example", heading)
	}
	s = s[open+len("```json\n"):]
	end := strings.Index(s, "\n```")
	if end < 0 {
		return nil, fmt.Errorf("the JSON example in section %q never ends", heading)
	}
	return []byte(s[:end+1]), nil
}

// checkPair runs the sample and its tampered copy through evidence.Verify,
// the function the browser checker and canary verify run. The sample must
// check out and the copy must not. It returns the step the copy fails, so
// the page can name it.
func checkPair(file, tampered []byte) (string, error) {
	if rep, _ := evidence.Verify(file); rep.Result != evidence.ResultChecksOut {
		return "", fmt.Errorf("it reads %s (%s), not checks_out, and the page offers it as a file that checks out", rep.Result, rep.Code)
	}
	rep, _ := evidence.Verify(tampered)
	if rep.Result != evidence.ResultDoesNotCheckOut {
		return "", fmt.Errorf("its tampered copy reads %s (%s), not does_not_check_out", rep.Result, rep.Code)
	}
	for _, c := range rep.Checks {
		if c.OK != nil && !*c.OK {
			return c.Step, nil
		}
	}
	return "", errors.New("its tampered copy fails no step")
}

// tamper returns a copy of an evidence file with one hex digit flipped, the
// offset of the byte it changed, and the JSON value that holds it. It changes
// the first proof sibling, or the left-out entry's txid when the proof has no
// sibling. XOR 1 on the value's first byte changes one hex digit, so exactly
// one byte of the file changes and the JSON stays valid.
func tamper(file []byte) ([]byte, int, string, error) {
	var ev struct {
		Format  string `json:"format"`
		Missing struct {
			Txid string `json:"txid"`
		} `json:"missing"`
		Proof struct {
			Siblings []string `json:"siblings"`
		} `json:"proof"`
	}
	if err := json.Unmarshal(file, &ev); err != nil {
		return nil, 0, "", fmt.Errorf("not JSON: %w", err)
	}
	if ev.Format != "canary-evidence/1" {
		return nil, 0, "", fmt.Errorf("format %q, want canary-evidence/1", ev.Format)
	}
	field, value := tamperTxid, ev.Missing.Txid
	if len(ev.Proof.Siblings) > 0 {
		field, value = tamperSibling, ev.Proof.Siblings[0]
	}
	if len(value) != 64 || flipHexDigit(value[1]) == value[1] {
		return nil, 0, "", fmt.Errorf("%s is missing or not 32 bytes of hex", field)
	}
	quoted := []byte(`"` + value + `"`)
	at := bytes.Index(file, quoted)
	if at < 0 || bytes.Index(file[at+1:], quoted) >= 0 {
		return nil, 0, "", fmt.Errorf("%s does not appear exactly once in the file", field)
	}
	// The low hex digit of the first byte sits after the quote and the high digit.
	offset := at + 2
	out := bytes.Clone(file)
	out[offset] = flipHexDigit(out[offset])
	return out, offset, field, nil
}

// flipHexDigit returns the hex digit for the value XOR 1, in the same case.
func flipHexDigit(c byte) byte {
	const lower, upper = "0123456789abcdef", "0123456789ABCDEF"
	if i := strings.IndexByte(lower, c); i >= 0 {
		return lower[i^1]
	}
	if i := strings.IndexByte(upper, c); i >= 0 {
		return upper[i^1]
	}
	return c
}
