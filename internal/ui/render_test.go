package ui

import (
	"bytes"
	"image/png"
	"io/fs"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// TestPartialsRenderOutsideTheDashboard covers the helpers the public site
// uses, so it draws states, commands and the header from the same templates.
func TestPartialsRenderOutsideTheDashboard(t *testing.T) {
	tmpl, err := Partials()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"glyph", "icon", "stateBadge", "explain", "command", "wordmark", "themeToggle", "verifyReport"} {
		if tmpl.Lookup(name) == nil {
			t.Errorf("Partials() lacks %q", name)
		}
	}
	// Each call returns its own set, so one caller's pages never leak into
	// another's.
	other, _ := Partials()
	if _, err := tmpl.New("extra").Parse(`x`); err != nil {
		t.Fatal(err)
	}
	if other.Lookup("extra") != nil {
		t.Error("Partials() shares one template set between callers")
	}

	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "stateBadge", wording.State("compromised")); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); !strings.Contains(got, `href="#g-compromised"`) || !strings.Contains(got, "Data withheld") {
		t.Errorf("stateBadge = %s", got)
	}

	b.Reset()
	if err := tmpl.ExecuteTemplate(&b, "themeToggle", nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{wording.ThemeAuto, wording.ThemeLight, wording.ThemeDark, "data-theme-toggle"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("themeToggle lacks %q", want)
		}
	}
}

func TestSpriteAndAssetsExported(t *testing.T) {
	if s := string(Sprite()); !strings.Contains(s, `id="g-verified"`) || strings.Contains(s, "<?xml") {
		t.Errorf("Sprite() is not the inlinable glyph sprite")
	}
	a := Assets()
	for _, name := range []string{"tokens.css", "ui.css", "app.js", "fonts/atkinson-hyperlegible-next-latin.woff2",
		"fonts/atkinson-hyperlegible-mono-latin.woff2", "fonts/OFL-atkinson-hyperlegible-next.txt"} {
		if _, err := fs.Stat(a, name); err != nil {
			t.Errorf("Assets() lacks %s: %v", name, err)
		}
	}
}

// TestFaviconHasOneSource keeps the dashboard's favicon file, the site's SVG
// and its PNG fallbacks drawn from the same geometry.
func TestFaviconHasOneSource(t *testing.T) {
	b, err := fs.ReadFile(Assets(), "favicon.svg")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(FaviconSVG()) {
		t.Errorf("assets/favicon.svg differs from FaviconSVG(). Write FaviconSVG() to the file.\nfile: %s\nwant: %s", b, FaviconSVG())
	}
	for _, tt := range []struct {
		size      int
		fullBleed bool
	}{{32, false}, {180, true}} {
		img, err := png.Decode(bytes.NewReader(FaviconPNG(tt.size, tt.fullBleed)))
		if err != nil {
			t.Fatalf("FaviconPNG(%d): %v", tt.size, err)
		}
		if got := img.Bounds().Dx(); got != tt.size || img.Bounds().Dy() != tt.size {
			t.Fatalf("FaviconPNG(%d) is %dx%d", tt.size, got, img.Bounds().Dy())
		}
		_, _, _, a := img.At(0, 0).RGBA()
		if tt.fullBleed && a != 0xffff {
			t.Errorf("FaviconPNG(%d, full bleed) has a transparent corner", tt.size)
		}
		if !tt.fullBleed && a != 0 {
			t.Errorf("FaviconPNG(%d) has an opaque corner, want the rounded square's transparent one", tt.size)
		}
		// The perch runs under the letter in canary yellow.
		r, g, bl, _ := img.At(tt.size/2, tt.size*265/320).RGBA()
		if r>>8 < 0xe0 || g>>8 < 0xd0 || bl>>8 > 0x80 {
			t.Errorf("FaviconPNG(%d) has no yellow perch under the letter: %d %d %d", tt.size, r>>8, g>>8, bl>>8)
		}
	}
}
