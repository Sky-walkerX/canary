package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// formatsDoc is the frozen v1 formats doc, the source of the example evidence
// file and its report.
const formatsDoc = "../../docs/design/2026-09-30-v1-formats.md"

// docExample returns the first JSON block under "### Example" in the doc
// section whose heading starts with heading.
func docExample(t *testing.T, heading string) []byte {
	t.Helper()
	b, err := readDocExample(heading)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// readDocExample is docExample without a *testing.T, for a fuzz target's
// seeds.
func readDocExample(heading string) ([]byte, error) {
	doc, err := os.ReadFile(formatsDoc)
	if err != nil {
		return nil, fmt.Errorf("read the formats doc: %w", err)
	}
	s := string(doc)
	start := strings.Index(s, "\n"+heading)
	if start < 0 {
		return nil, fmt.Errorf("no section %q in the formats doc", heading)
	}
	s = s[start+1:]
	if end := strings.Index(s[len(heading):], "\n## "); end >= 0 {
		s = s[:len(heading)+end]
	}
	ex := strings.Index(s, "\n### Example")
	if ex < 0 {
		return nil, fmt.Errorf("section %q has no example", heading)
	}
	s = s[ex:]
	open := strings.Index(s, "```json\n")
	if open < 0 {
		return nil, fmt.Errorf("section %q's example has no JSON block", heading)
	}
	s = s[open+len("```json\n"):]
	end := strings.Index(s, "\n```")
	if end < 0 {
		return nil, fmt.Errorf("section %q's JSON block does not end", heading)
	}
	return []byte(s[:end+1]), nil
}

// decode runs check and splits its output into the report fields and the two
// fields the checker adds.
func decode(t *testing.T, file []byte) (report map[string]any, headline, html string) {
	t.Helper()
	out, err := check(file)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	headline, _ = report["headline"].(string)
	html, _ = report["html"].(string)
	delete(report, "headline")
	delete(report, "html")
	return report, headline, html
}

// The doc's example file gives the doc's example report, field for field,
// plus the CLI's first line and the dashboard's markup.
func TestDocExampleChecksOut(t *testing.T) {
	report, headline, html := decode(t, docExample(t, "## 6. The evidence file"))
	var want map[string]any
	if err := json.Unmarshal(docExample(t, "## 7. VerifyReport and error codes"), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report, want) {
		t.Errorf("report differs from the formats doc's example.\ngot:  %v\nwant: %v", report, want)
	}
	if headline != wording.VerifyChecksOut {
		t.Errorf("headline = %q, want %q", headline, wording.VerifyChecksOut)
	}
	if !strings.HasPrefix(html, `<div class="report">`) || strings.Count(html, `class="step step-pass"`) != 8 {
		t.Errorf("html is not the report partial with eight passed steps:\n%s", html)
	}
}

// Each outcome carries the headline canary verify prints, and markup.
func TestOutcomes(t *testing.T) {
	good := docExample(t, "## 6. The evidence file")

	// One hex digit of the first proof sibling, flipped, as the site's
	// tampered copy does it.
	sib := "93625b68eed841902dd2a682a9babbaa5f9fc073efb7214a28ca1ff3d4ef15d5"
	if bytes.Count(good, []byte(sib)) != 1 {
		t.Fatal("the doc example's first sibling is not where this test expects it")
	}
	tampered := bytes.Replace(good, []byte(sib), []byte("92"+sib[2:]), 1)

	var f map[string]any
	if err := json.Unmarshal(good, &f); err != nil {
		t.Fatal(err)
	}
	f["receipt"], f["served_base64"] = nil, nil
	noReceipt, _ := json.Marshal(f)

	f["format"] = "canary-evidence/2"
	otherFormat, _ := json.Marshal(f)

	tests := []struct {
		name, result, code, headline string
	}{
		{"tampered", evidence.ResultDoesNotCheckOut, evidence.CodeProofInvalid, wording.VerifyDoesNotCheckOut("inclusion")},
		{"no receipt", evidence.ResultChecksOut, evidence.CodeInclusionOnly, wording.VerifyInclusionOnly},
		{"not JSON", evidence.ResultUnreadable, evidence.CodeMalformed, wording.VerifyCantRead(wording.VerifyReasonMalformed)},
		{"other format", evidence.ResultUnreadable, evidence.CodeUnsupportedFormat, wording.VerifyCantRead(wording.VerifyReasonUnsupported)},
		{"empty", evidence.ResultUnreadable, evidence.CodeMalformed, wording.VerifyCantRead(wording.VerifyReasonMalformed)},
	}
	files := map[string][]byte{
		"tampered":     tampered,
		"no receipt":   noReceipt,
		"not JSON":     []byte("this is not JSON"),
		"other format": otherFormat,
		"empty":        nil,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, headline, html := decode(t, files[tt.name])
			if report["result"] != tt.result || report["code"] != tt.code {
				t.Errorf("result, code = %v, %v; want %s, %s", report["result"], report["code"], tt.result, tt.code)
			}
			if headline != tt.headline {
				t.Errorf("headline = %q, want %q", headline, tt.headline)
			}
			label := wording.VerifyResultLabel(tt.result, tt.code)
			if !strings.HasPrefix(html, `<div class="report">`) || !strings.Contains(html, template.HTMLEscapeString(label)) {
				t.Errorf("html lacks the report partial or the label %q:\n%s", label, html)
			}
		})
	}
}

func TestCheckerInfo(t *testing.T) {
	var info buildInfo
	if err := json.Unmarshal(checkerInfo(), &info); err != nil {
		t.Fatal(err)
	}
	if info.GoVersion == "" || info.MaxFileBytes != 16<<20 {
		t.Errorf("info = %+v", info)
	}
	if info.TooLarge != wording.VerifyCantRead(wording.VerifyReasonTooLarge(16<<20)) {
		t.Errorf("too_large = %q", info.TooLarge)
	}
	if info.NotOpened != wording.VerifyCantRead(wording.VerifyReasonNotOpened) {
		t.Errorf("not_opened = %q", info.NotOpened)
	}
}
