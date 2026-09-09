package canary_test

import (
	"os"
	"strings"
	"testing"

	bip352 "github.com/setavenger/go-bip352"
)

func TestUsesRenamedBIP352Library(t *testing.T) {
	b, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	mod := string(b)

	if !strings.Contains(mod, "github.com/setavenger/go-bip352") {
		t.Error("go.mod must require github.com/setavenger/go-bip352 (§6.4)")
	}
	// The old path is a prefix-free distinct module. It is v0.1.4 and does not
	// export ExtractEligibleVins or ExtractPubKey — depending on it silently
	// removes the input-eligibility layer.
	for _, line := range strings.Split(mod, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "github.com/setavenger/gobip352" {
			t.Error("go.mod requires the OLD gobip352 path; it lacks ExtractEligibleVins (§6.4)")
		}
	}
}

// The check above reads go.mod as data, so an unused import cannot satisfy it.
// These two references are the complementary half: the old gobip352 path exports
// neither symbol, so aiming the module at it fails to compile here instead of
// silently deleting the eligibility layer (§6.4). They also give the dependency a
// real edge in the module graph before Task 2 imports it for the leaf hash, so
// `go mod tidy` cannot prune the very requirement the test above asserts.
var (
	_ = bip352.ExtractEligibleVins
	_ = bip352.ExtractPubKey
)

func TestNumsHIsThirtyTwoBytes(t *testing.T) {
	// §2.2 excludes script-path spends whose internal key is H. The exclusion is
	// only meaningful if the pinned library's H is the x-only 32-byte form.
	if len(bip352.NumsH) != 32 {
		t.Errorf("NumsH must be the 32-byte x-only NUMS point, got %d bytes", len(bip352.NumsH))
	}
}
