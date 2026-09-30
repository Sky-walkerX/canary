package ui

import (
	"fmt"
	"io/fs"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// tokenBlocks parses tokens.css into its light block and its two dark blocks:
// the one under prefers-color-scheme and the data-theme override.
func tokenBlocks(t *testing.T) (light, darkMedia, darkAttr map[string]string) {
	t.Helper()
	b, err := fs.ReadFile(assetFS, "assets/tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	css := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(string(b), "")
	block := func(start string) map[string]string {
		i := strings.Index(css, start)
		if i < 0 {
			t.Fatalf("tokens.css has no %q block", start)
		}
		body := css[i+len(start):]
		body = body[:strings.Index(body, "}")]
		m := map[string]string{}
		for _, d := range regexp.MustCompile(`(--[a-z0-9-]+)\s*:\s*([^;]+);`).FindAllStringSubmatch(body, -1) {
			m[d[1]] = strings.TrimSpace(d[2])
		}
		return m
	}
	return block(":root {"), block(`:root:not([data-theme="light"]) {`), block(`:root[data-theme="dark"] {`)
}

func luminance(hex string) (float64, error) {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return 0, fmt.Errorf("colour %q is not #rrggbb", hex)
	}
	var c [3]float64
	for i := range c {
		v, err := strconv.ParseUint(hex[2*i:2*i+2], 16, 8)
		if err != nil {
			return 0, err
		}
		s := float64(v) / 255
		if s <= 0.04045 {
			c[i] = s / 12.92
		} else {
			c[i] = math.Pow((s+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*c[0] + 0.7152*c[1] + 0.0722*c[2], nil
}

// contrast returns the WCAG 2 contrast ratio of two #rrggbb colours.
func contrast(a, b string) (float64, error) {
	la, err := luminance(a)
	if err != nil {
		return 0, err
	}
	lb, err := luminance(b)
	if err != nil {
		return 0, err
	}
	hi, lo := math.Max(la, lb), math.Min(la, lb)
	return (hi + 0.05) / (lo + 0.05), nil
}

func TestContrastFormula(t *testing.T) {
	got, _ := contrast("#000000", "#FFFFFF")
	if math.Abs(got-21) > 0.01 {
		t.Fatalf("black on white = %.2f, want 21", got)
	}
}

// TestStateColoursContrast checks every state colour, and every text colour,
// at 4.5:1 or more against both surfaces in both themes.
func TestStateColoursContrast(t *testing.T) {
	light, darkMedia, darkAttr := tokenBlocks(t)
	if len(darkMedia) == 0 || fmt.Sprint(darkMedia) != fmt.Sprint(darkAttr) {
		t.Fatalf("the two dark blocks differ:\nmedia: %v\nattr:  %v", darkMedia, darkAttr)
	}
	text := []string{
		"--ink", "--ink-muted", "--canary-text",
		"--state-verified", "--state-resolved", "--state-unresolvable",
		"--state-unverified", "--state-disputed", "--state-compromised",
	}
	for name, theme := range map[string]map[string]string{"light": light, "dark": darkMedia} {
		for _, fg := range text {
			for _, bg := range []string{"--bg", "--surface"} {
				r, err := contrast(theme[fg], theme[bg])
				if err != nil {
					t.Fatalf("%s %s on %s: %v", name, fg, bg, err)
				}
				if r < 4.5 {
					t.Errorf("%s: %s %s on %s %s is %.2f:1, want at least 4.5:1", name, fg, theme[fg], bg, theme[bg], r)
				}
			}
		}
		// Text on the canary fill: the badge, the skip link, the update bar.
		if r, _ := contrast(theme["--on-canary"], theme["--canary"]); r < 4.5 {
			t.Errorf("%s: text on canary is %.2f:1", name, r)
		}
	}
}

// TestPinnedIdentity keeps the brief's fixed colours.
func TestPinnedIdentity(t *testing.T) {
	light, dark, _ := tokenBlocks(t)
	pinned := []struct {
		theme             map[string]string
		name, token, want string
	}{
		{light, "light", "--ink", "#17160F"},
		{light, "light", "--bg", "#F5F3EC"},
		{light, "light", "--canary", "#F4E13A"},
		{light, "light", "--canary-text", "#5E5700"},
		{dark, "dark", "--bg", "#121210"},
		{dark, "dark", "--canary", "#F4E13A"},
	}
	for _, p := range pinned {
		if !strings.EqualFold(p.theme[p.token], p.want) {
			t.Errorf("%s %s = %s, want %s", p.name, p.token, p.theme[p.token], p.want)
		}
	}
	// Canary yellow is never a state colour.
	for _, theme := range []map[string]string{light, dark} {
		for k, v := range theme {
			if strings.HasPrefix(k, "--state-") && strings.EqualFold(v, theme["--canary"]) {
				t.Errorf("%s uses the brand yellow", k)
			}
		}
	}
}
