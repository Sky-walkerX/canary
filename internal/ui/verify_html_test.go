package ui

import (
	"bytes"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// TestVerifyReportHTML checks that the exported renderer gives the same
// partial the finding page shows, and refuses a report of the wrong shape.
func TestVerifyReportHTML(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "example-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyReportHTML(b)
	if err != nil {
		t.Fatalf("example report: %v", err)
	}
	r, err := ParseVerifyReport(b)
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	if err := pages["finding"].ExecuteTemplate(&want, "verifyReport", buildReport(r)); err != nil {
		t.Fatal(err)
	}
	if string(got) != want.String() {
		t.Errorf("VerifyReportHTML differs from the finding page's partial.\ngot:\n%s\nwant:\n%s", got, want.String())
	}
	html := string(got)
	if !strings.HasPrefix(html, `<div class="report">`) {
		t.Errorf("rendered report does not open with the report container:\n%s", html)
	}
	for _, s := range []string{
		wording.VerifyResultLabel("checks_out", "ok"),
		wording.VerifyStep("window"),
		"The server's signed tip was 212, so the block was 7 blocks deep, inside the 144-block window.",
	} {
		if !strings.Contains(html, template.HTMLEscapeString(s)) {
			t.Errorf("rendered report lacks %q", s)
		}
	}
	if strings.Count(html, `class="step step-pass"`) != 8 {
		t.Errorf("rendered report does not show eight passed steps:\n%s", html)
	}

	for _, s := range []string{`not json`, `{}`, `{"result":"checks_out","message":"x","checks":[]}`} {
		if h, err := VerifyReportHTML([]byte(s)); err == nil || h != "" {
			t.Errorf("VerifyReportHTML(%s) = %q, %v; want an error and no markup", s, h, err)
		}
	}
}
