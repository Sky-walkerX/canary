package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"html/template"
	"regexp"
	"strings"

	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// The site draws each Mermaid diagram in the docs by hand, as HTML that
// reflows at any width and needs no script. A drawing is chosen by a node the
// diagram declares. Two checks tie it to the docs. Every label in the Mermaid
// source must appear in the drawing. And the source, with its spacing
// folded, must hash to the value recorded here, so a new edge or a changed
// direction fails too. Either way the build stops until someone redraws the
// diagram and records the new hash.
var drawings = []struct {
	marker   string // a node declaration only this diagram has
	template string
	source   string // sourceHash of the Mermaid source the drawing matches
}{
	{marker: `core[(`, template: "diagram-parts", source: "9e69ee2c79c1a5f1"},
	{marker: `start([`, template: "diagram-checks", source: "d7c3d5f8d9386f20"},
}

var (
	mermaidLabel = regexp.MustCompile(`"([^"]+)"`)
	anyTag       = regexp.MustCompile(`<[^>]*>`)
	spaces       = regexp.MustCompile(`\s+`)
	spaceBefore  = regexp.MustCompile(`\s+([,.;:])`)
)

// sourceHash is the first 16 hex digits of the SHA-256 of a Mermaid source,
// with each run of spaces and line breaks folded to one space.
func sourceHash(src string) string {
	sum := sha256.Sum256([]byte(strings.Join(strings.Fields(src), " ")))
	return hex.EncodeToString(sum[:8])
}

// drawing returns the hand-made drawing for one Mermaid diagram.
func drawing(parts *template.Template, src string) (string, error) {
	name, want := "", ""
	for _, d := range drawings {
		if strings.Contains(src, d.marker) {
			name, want = d.template, d.source
			break
		}
	}
	if name == "" {
		first, _, _ := strings.Cut(strings.TrimSpace(src), "\n")
		return "", fmt.Errorf("no drawing for the Mermaid diagram that starts %q; add one to cmd/site/templates/diagrams.html", first)
	}
	var b bytes.Buffer
	if err := parts.ExecuteTemplate(&b, name, wording.Site.Diagram); err != nil {
		return "", fmt.Errorf("draw %s: %w", name, err)
	}
	have := normalize(anyTag.ReplaceAllString(b.String(), " "))
	var missing []string
	for _, m := range mermaidLabel.FindAllStringSubmatch(src, -1) {
		label := strings.ReplaceAll(m[1], "<br/>", " ")
		if !strings.Contains(have, normalize(label)) {
			missing = append(missing, label)
		}
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("the drawing %s lacks labels the Mermaid diagram has: %q; update cmd/site/templates/diagrams.html", name, missing)
	}
	if got := sourceHash(src); got != want {
		return "", fmt.Errorf("the Mermaid diagram drawn by %s changed in the docs (hash %s, drawn from %s); "+
			"redraw it in cmd/site/templates/diagrams.html, then record the new hash in cmd/site/diagrams.go", name, got, want)
	}
	return b.String(), nil
}

// normalize folds case, question marks and spacing, so a label matches the
// drawing's text however the drawing breaks or punctuates it.
func normalize(s string) string {
	s = strings.ToLower(html.UnescapeString(s))
	s = strings.ReplaceAll(s, "?", "")
	s = spaces.ReplaceAllString(s, " ")
	return strings.TrimSpace(spaceBefore.ReplaceAllString(s, "$1"))
}
