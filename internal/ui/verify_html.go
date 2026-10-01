package ui

import (
	"bytes"
	"fmt"
	"html/template"
)

// VerifyReportHTML renders one VerifyReport, given as the JSON canary verify
// --json prints, with the verifyReport partial a finding page uses. The
// browser checker calls it, so the public site and the dashboard show a
// report in the same words and the same markup.
//
// The markup draws its glyphs from the sprite by id, so the page that shows
// it must inline the glyph sprite once. A report that fails
// ParseVerifyReport's shape checks renders nothing and returns that error.
func VerifyReportHTML(reportJSON []byte) (template.HTML, error) {
	rep, err := ParseVerifyReport(reportJSON)
	if err != nil {
		return "", err
	}
	// Every page template holds the shared partials; the finding page is the
	// one that shows this partial on the dashboard.
	var buf bytes.Buffer
	if err := pages["finding"].ExecuteTemplate(&buf, "verifyReport", buildReport(rep)); err != nil {
		return "", fmt.Errorf("ui: render verify report: %w", err)
	}
	return template.HTML(buf.String()), nil
}
