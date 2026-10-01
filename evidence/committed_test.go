package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCommittedEvidenceChecksOut keeps the evidence files committed beside this
// package verifying. They come from a real regtest run, and the README, the
// public site and the video all point at them, so a format change that breaks
// them must fail CI instead of breaking the judge path.
func TestCommittedEvidenceChecksOut(t *testing.T) {
	paths, err := filepath.Glob("omission-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no committed evidence file found beside the evidence package")
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			r, err := Verify(b)
			if err != nil {
				t.Fatalf("verify %s: %v", p, err)
			}
			if r.Result != ResultChecksOut || r.Code != CodeOK {
				t.Fatalf("%s: result %q code %q, want %q %q: %s", p, r.Result, r.Code, ResultChecksOut, CodeOK, r.Message)
			}
			if !r.HasReceipt {
				t.Fatalf("%s: carries no receipt, so it proves inclusion only", p)
			}
		})
	}
}
