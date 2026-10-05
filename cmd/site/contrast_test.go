package main

import (
	"fmt"
	"io/fs"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/internal/ui"
)

// The site declares its own Material 3 scheme inside body.site: a light scheme,
// then the dark scheme twice, once per route. This test recomputes the same
// 4.5:1 floor that internal/ui/contrast_test.go holds the dashboard to, on the
// values the site actually uses, and checks the two dark routes agree.

// siteSchemeBlocks returns the declarations of every body.site block in
// site.css, in file order: light first, then the two dark routes.
func siteSchemeBlocks(t *testing.T) []map[string]string {
	t.Helper()
	b, err := fs.ReadFile(siteAssets, "assets/site.css")
	if err != nil {
		t.Fatal(err)
	}
	css := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(string(b), "")
	var blocks []map[string]string
	for _, m := range regexp.MustCompile(`(?s)body\.site\s*\{(.*?)\}`).FindAllStringSubmatch(css, -1) {
		vars := map[string]string{}
		for _, d := range regexp.MustCompile(`(--[a-z0-9-]+)\s*:\s*(#[0-9A-Fa-f]{6})`).FindAllStringSubmatch(m[1], -1) {
			vars[d[1]] = d[2]
		}
		if len(vars) > 0 {
			blocks = append(blocks, vars)
		}
	}
	return blocks
}

// tokenDarkBlock returns the dashboard's dark tokens, which the site starts from.
func tokenDarkBlock(t *testing.T) map[string]string {
	t.Helper()
	b, err := fs.ReadFile(ui.Assets(), "tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	css := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(string(b), "")
	m := regexp.MustCompile(`(?s):root:not\(\[data-theme="light"\]\)\s*\{(.*?)\}`).FindStringSubmatch(css)
	if m == nil {
		t.Fatal("tokens.css has no prefers-color-scheme dark block")
	}
	vars := map[string]string{}
	for _, d := range regexp.MustCompile(`(--[a-z0-9-]+)\s*:\s*(#[0-9A-Fa-f]{6})`).FindAllStringSubmatch(m[1], -1) {
		vars[d[1]] = d[2]
	}
	return vars
}

func siteLuminance(hex string) (float64, error) {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return 0, fmt.Errorf("colour %q is not #rrggbb", hex)
	}
	var c [3]float64
	for i := range c {
		v, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
		if err != nil {
			return 0, err
		}
		s := float64(v) / 255
		if s <= 0.03928 {
			c[i] = s / 12.92
		} else {
			c[i] = math.Pow((s+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*c[0] + 0.7152*c[1] + 0.0722*c[2], nil
}

func siteContrast(a, b string) (float64, error) {
	la, err := siteLuminance(a)
	if err != nil {
		return 0, err
	}
	lb, err := siteLuminance(b)
	if err != nil {
		return 0, err
	}
	hi, lo := math.Max(la, lb), math.Min(la, lb)
	return (hi + 0.05) / (lo + 0.05), nil
}

func TestSitePaletteContrast(t *testing.T) {
	blocks := siteSchemeBlocks(t)
	if len(blocks) != 3 {
		t.Fatalf("site.css has %d body.site blocks, want 3: the light scheme, then the two dark routes", len(blocks))
	}
	if fmt.Sprint(blocks[1]) != fmt.Sprint(blocks[2]) {
		t.Fatalf("the two dark schemes differ:\nmedia: %v\nattr:  %v", blocks[1], blocks[2])
	}
	// The dashboard's tokens are the base; the site's scheme overrides them.
	base := tokenDarkBlock(t)
	schemes := []struct {
		name  string
		theme map[string]string
	}{
		{"light", merge(base, blocks[0])},
		{"dark", merge(base, blocks[1])},
	}
	text := []string{
		"--ink", "--ink-muted", "--canary-text",
		"--state-verified", "--state-resolved", "--state-unresolvable",
		"--state-unverified", "--state-disputed", "--state-compromised",
	}
	for _, s := range schemes {
		for _, want := range []string{"--bg", "--surface", "--surface-low", "--surface-high", "--ink", "--ink-muted", "--primary", "--on-primary", "--primary-container", "--on-primary-container"} {
			if s.theme[want] == "" {
				t.Fatalf("%s scheme has no %s", s.name, want)
			}
		}
		for _, fg := range text {
			for _, bg := range []string{"--bg", "--surface"} {
				r, err := siteContrast(s.theme[fg], s.theme[bg])
				if err != nil {
					t.Fatalf("%s %s on %s: %v", s.name, fg, bg, err)
				}
				if r < 4.5 {
					t.Errorf("%s: %s %s on %s %s is %.2f:1, want at least 4.5:1", s.name, fg, s.theme[fg], bg, s.theme[bg], r)
				}
			}
		}
		// M3 role pairs the components paint: filled buttons, chips, the
		// navigation indicator, and the amber on-canary pair kept for the
		// dashboard's badge.
		for _, pair := range [][2]string{
			{"--on-primary", "--primary"},
			{"--on-primary-container", "--primary-container"},
			{"--on-secondary-container", "--secondary-container"},
			{"--on-tertiary-container", "--tertiary-container"},
			{"--on-error-container", "--error-container"},
			{"--on-canary", "--canary"},
		} {
			r, err := siteContrast(s.theme[pair[0]], s.theme[pair[1]])
			if err != nil {
				t.Fatalf("%s %s on %s: %v", s.name, pair[0], pair[1], err)
			}
			if r < 4.5 {
				t.Errorf("%s: %s %s on %s %s is %.2f:1, want at least 4.5:1", s.name, pair[0], s.theme[pair[0]], pair[1], s.theme[pair[1]], r)
			}
		}
		// A filled card must separate from the ground it sits on. M3's own
		// tonal step is small; the guard is against flattening it to nothing.
		if r, _ := siteContrast(s.theme["--surface-high"], s.theme["--bg"]); r < 1.05 {
			t.Errorf("%s: filled cards are %.2f:1 against the ground, too close to separate", s.name, r)
		}
	}
}

// merge returns base with over overlaid.
func merge(base, over map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}
