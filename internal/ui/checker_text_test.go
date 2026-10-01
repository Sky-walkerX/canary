package ui

import (
	"encoding/json"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

var (
	checkerTextBlock = regexp.MustCompile(`(?s)\n  const TEXT = \{\n(.*?)\n  \};\n`)
	checkerTextKey   = regexp.MustCompile(`^    (\w+): (.*)$`)
	jsStringLiteral  = regexp.MustCompile(`'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"`)
	jsJoinOnly       = regexp.MustCompile(`^[\s+]*,?\s*$`)
)

// checkerFallbacks reads the TEXT object in checker.js: each key and the
// string its literals join to. It fails on any value that is not plain
// string literals joined with +, so a fallback can't hide behind code.
func checkerFallbacks(t *testing.T) map[string]string {
	t.Helper()
	src, err := fs.ReadFile(Assets(), "checker/checker.js")
	if err != nil {
		t.Fatal(err)
	}
	m := checkerTextBlock.FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("checker.js has no TEXT object")
	}
	exprs := map[string]string{}
	var order []string
	for _, line := range strings.Split(m[1], "\n") {
		if k := checkerTextKey.FindStringSubmatch(line); k != nil {
			order = append(order, k[1])
			exprs[k[1]] = k[2]
			continue
		}
		if len(order) == 0 {
			t.Fatalf("checker.js TEXT starts with a line that is not a key: %q", line)
		}
		exprs[order[len(order)-1]] += "\n" + line
	}
	out := map[string]string{}
	unescape := strings.NewReplacer(`\'`, `'`, `\"`, `"`, `\\`, `\`)
	for k, expr := range exprs {
		var b strings.Builder
		for _, lit := range jsStringLiteral.FindAllStringSubmatch(expr, -1) {
			b.WriteString(unescape.Replace(lit[1] + lit[2]))
		}
		if rest := jsStringLiteral.ReplaceAllString(expr, ""); !jsJoinOnly.MatchString(rest) {
			t.Errorf("checker.js TEXT.%s is not plain string literals: %q", k, expr)
		}
		out[k] = b.String()
	}
	return out
}

// TestCheckerFallbacksMatchTheWordingTable keeps checker.js's built-in words
// equal to the wording table. They show only on a page that carries no text
// block, and even then a reader sees the same words the site writes.
func TestCheckerFallbacksMatchTheWordingTable(t *testing.T) {
	js := checkerFallbacks(t)
	b, err := json.Marshal(wording.Checker)
	if err != nil {
		t.Fatal(err)
	}
	var table map[string]string
	if err := json.Unmarshal(b, &table); err != nil {
		t.Fatal(err)
	}
	for k, want := range table {
		got, ok := js[k]
		switch {
		case !ok:
			t.Errorf("checker.js TEXT lacks %s, which the wording table has", k)
		case got != want:
			t.Errorf("checker.js TEXT.%s\n got  %q\n want %q (the wording table)", k, got, want)
		}
	}
	for k := range js {
		if _, ok := table[k]; !ok {
			t.Errorf("checker.js TEXT has %s, which the wording table lacks", k)
		}
	}
}
