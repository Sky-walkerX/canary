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

// The site re-declares the neutrals inside body.site, because the client mock
// is warm where the dashboard mock is cool. This test recomputes the same
// 4.5:1 floor that internal/ui/contrast_test.go holds the dashboard to, on the
// values the site actually uses, and checks the two dark routes agree.

// siteDarkBlocks returns the declarations of every body.site block in
// site.css, in file order.
func siteDarkBlocks(t *testing.T) []map[string]string {
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
		blocks = append(blocks, vars)
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
	blocks := siteDarkBlocks(t)
	if len(blocks) != 2 {
		t.Fatalf("site.css has %d body.site blocks, want 2, one per dark route", len(blocks))
	}
	if fmt.Sprint(blocks[0]) != fmt.Sprint(blocks[1]) {
		t.Fatalf("the two body.site blocks differ:\nmedia: %v\nattr:  %v", blocks[0], blocks[1])
	}
	theme := tokenDarkBlock(t)
	for k, v := range blocks[0] {
		theme[k] = v
	}
	for _, want := range []string{"--bg", "--surface", "--surface-low", "--ink", "--ink-muted", "--canary-text"} {
		if theme[want] == "" {
			t.Fatalf("the site palette has no %s", want)
		}
	}
	text := []string{
		"--ink", "--ink-muted", "--canary-text",
		"--state-verified", "--state-resolved", "--state-unresolvable",
		"--state-unverified", "--state-disputed", "--state-compromised",
	}
	for _, fg := range text {
		for _, bg := range []string{"--bg", "--surface"} {
			r, err := siteContrast(theme[fg], theme[bg])
			if err != nil {
				t.Fatalf("%s on %s: %v", fg, bg, err)
			}
			if r < 4.5 {
				t.Errorf("%s %s on %s %s is %.2f:1, want at least 4.5:1", fg, theme[fg], bg, theme[bg], r)
			}
		}
	}
	if r, _ := siteContrast(theme["--on-canary"], theme["--canary"]); r < 4.5 {
		t.Errorf("text on the amber fill is %.2f:1", r)
	}
	// The site's ground is lighter than the dashboard's, so the panels must
	// still read as panels above it rather than as the same surface. The
	// mock's own step is 1.08:1, and the 1px rules carry the rest, so the
	// guard is only against someone flattening the scale to nothing.
	if r, _ := siteContrast(theme["--surface"], theme["--bg"]); r < 1.05 {
		t.Errorf("panels are %.2f:1 against the ground, too close to separate", r)
	}
}
