package main

import (
	"embed"
	"fmt"
	"html/template"
	"strings"

	"github.com/Sky-walkerX/canary/internal/ui"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

//go:embed templates/*.html
var siteTemplates embed.FS

//go:embed assets/site.css
var siteAssets embed.FS

// pageNames are the site's page templates. Each defines "content" and is
// parsed on its own copy of the layout and the partials.
var pageNames = []string{"home", "doc", "runs", "recorded", "notfound"}

var siteFuncs = template.FuncMap{
	"state":     wording.State,
	"inc":       func(i int) int { return i + 1 },
	"keepWords": keepWords,
}

// keepWords escapes s and keeps each hyphenated word on one line, so a large
// title never breaks "silent-payments" at its hyphen. The self-hosted font
// has no non-breaking hyphen, so a span does the job.
func keepWords(s string) template.HTML {
	words := strings.Split(s, " ")
	for i, w := range words {
		w = template.HTMLEscapeString(w)
		if strings.Contains(w, "-") {
			w = `<span class="nobr">` + w + `</span>`
		}
		words[i] = w
	}
	return template.HTML(strings.Join(words, " "))
}

// partials returns the dashboard's partials plus the site's drawings, which
// draw states with the same badges.
func partials() (*template.Template, error) {
	t, err := ui.Partials()
	if err != nil {
		return nil, fmt.Errorf("site: load partials: %w", err)
	}
	t, err = t.Funcs(siteFuncs).ParseFS(siteTemplates, "templates/diagrams.html")
	if err != nil {
		return nil, fmt.Errorf("site: parse drawings: %w", err)
	}
	return t, nil
}

func parsePages() (map[string]*template.Template, error) {
	base, err := partials()
	if err != nil {
		return nil, err
	}
	if base, err = base.ParseFS(siteTemplates, "templates/layout.html"); err != nil {
		return nil, fmt.Errorf("site: parse layout: %w", err)
	}
	out := map[string]*template.Template{}
	for _, name := range pageNames {
		t, err := base.Clone()
		if err != nil {
			return nil, fmt.Errorf("site: clone layout: %w", err)
		}
		if t, err = t.ParseFS(siteTemplates, "templates/"+name+".html"); err != nil {
			return nil, fmt.Errorf("site: parse %s: %w", name, err)
		}
		out[name] = t
	}
	return out, nil
}
