package wording

import (
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// placeholderRe finds the {name} slots checker.js fills.
var placeholderRe = regexp.MustCompile(`\{(\w+)\}`)

// TestCheckerTextIsComplete keeps every word the browser checker shows in
// this table, with exactly the slots checker.js fills for it.
func TestCheckerTextIsComplete(t *testing.T) {
	slots := map[string][]string{
		"loading":         {"size"},
		"source":          {"name"},
		"build":           {"go", "revision"},
		"buildModified":   {"go", "revision"},
		"buildNoRevision": {"go"},
	}
	var m map[string]string
	b, err := json.Marshal(Checker)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if n := reflect.TypeOf(Checker).NumField(); len(m) != n {
		t.Fatalf("Checker has %d fields and %d JSON keys; every field needs its own key", n, len(m))
	}
	for k, v := range m {
		if strings.TrimSpace(v) == "" {
			t.Errorf("Checker %s is empty", k)
		}
		var got []string
		for _, s := range placeholderRe.FindAllStringSubmatch(v, -1) {
			got = append(got, s[1])
		}
		sort.Strings(got)
		if want := slots[k]; !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Errorf("Checker %s has slots %v, want %v: %q", k, got, want, v)
		}
	}
	// The command the checker offers is the one the run section shows.
	if Checker.Command != "canary verify "+Site.RunFilePlaceholder {
		t.Errorf("Checker.Command = %q, want the run section's verify command", Checker.Command)
	}
	if Checker.Choose != Site.CheckerChoose {
		t.Errorf("Checker.Choose = %q, want the page's own %q", Checker.Choose, Site.CheckerChoose)
	}
	// The two lines for a file the module never sees match canary verify.
	if Checker.TooLarge != VerifyCantRead(VerifyReasonTooLarge(16<<20)) || Checker.NotOpened != VerifyCantRead(VerifyReasonNotOpened) {
		t.Error("Checker.TooLarge or Checker.NotOpened differs from what canary verify prints")
	}
}

// TestCheckerBuildLine fills the build line the way checker.js does, so the
// line the site writes and the line the module reports read the same.
func TestCheckerBuildLine(t *testing.T) {
	const rev = "05de74dd2f8698efdb163ab6ed00f3efa09e27fc"
	for _, tt := range []struct {
		rev      string
		modified bool
		want     string
	}{
		{rev, false, "Built from commit 05de74d with Go 1.26.4."},
		{rev, true, "Built from commit 05de74d plus uncommitted changes, with Go 1.26.4."},
		{"", false, "Built with Go 1.26.4."},
		{"", true, "Built with Go 1.26.4."},
		{"abc", false, "Built from commit abc with Go 1.26.4."},
	} {
		if got := CheckerBuildLine(tt.rev, "Go 1.26.4", tt.modified); got != tt.want {
			t.Errorf("CheckerBuildLine(%q, %v) = %q, want %q", tt.rev, tt.modified, got, tt.want)
		}
	}
}

// TestSampleLabels keeps the example file from passing as a recorded run,
// and names the date of a recorded one.
func TestSampleLabels(t *testing.T) {
	ex := strings.ToLower(Site.CheckerSourceExample)
	for _, want := range []string{"example file from the formats document", "not from a recorded run"} {
		if !strings.Contains(ex, want) {
			t.Errorf("CheckerSourceExample %q lacks %q", Site.CheckerSourceExample, want)
		}
	}
	for _, s := range []string{Site.CheckerTryExample, Site.CheckerDownloadExample} {
		if strings.Contains(strings.ToLower(s), "real") {
			t.Errorf("%q calls the example file real", s)
		}
	}
	if got, want := Site.CheckerSourceRecorded("3 Oct 2026"), "The sample is an evidence file canary check wrote on 3 Oct 2026."; got != want {
		t.Errorf("CheckerSourceRecorded = %q, want %q", got, want)
	}
}

func TestTamperNote(t *testing.T) {
	got := Site.TamperNote(1843, "proof.siblings[0]", "3", "2", "inclusion")
	want := `The tampered copy changes one byte of the original. Byte 1843, inside proof.siblings[0], reads "2" where the original has "3". ` +
		`That one change makes the Inclusion step fail.`
	if got != want {
		t.Errorf("TamperNote\n got  %q\n want %q", got, want)
	}
}
