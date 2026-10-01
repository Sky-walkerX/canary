package ui

import (
	"html/template"
	"io/fs"
)

// This file exports the design system to other programs. cmd/site renders the
// public site with it, so the site and the dashboard share one set of
// partials, one stylesheet and one wording table.

// Partials returns a new template set holding the shared partials and the
// functions they call. Each call returns a separate set, so a caller can add
// its own layout and pages without touching the dashboard's.
//
// The set defines glyph, icon, stateBadge, explain, copyButton, hashShort,
// hashFull, command, errorPanel, verifyReport, coverageStrip, wordmark and
// themeToggle, among others. A page that uses a glyph or an icon must inline
// Sprite once.
func Partials() (*template.Template, error) {
	return template.New("partials").Funcs(funcs).ParseFS(templateFS, "templates/partials.html")
}

// Sprite returns the glyph and icon sprite, ready to inline once at the top of
// a page's body. Every glyph and icon partial refers to it by id.
func Sprite() template.HTML { return sprite }

// Assets returns the design system's static files, rooted at the assets
// directory: tokens.css, ui.css, app.js, favicon.svg, glyphs.svg, and the
// fonts with their licences under fonts/.
func Assets() fs.FS {
	sub, err := fs.Sub(assetFS, "assets")
	if err != nil {
		// assets is embedded at build time, so this cannot fail.
		panic(err)
	}
	return sub
}
