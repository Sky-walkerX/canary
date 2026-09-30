package core

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The pair comes from the tweak-list example in the v1 formats doc. The list
// carries the first txid in internal order, and an explorer prints the second.
const (
	exampleInternal = "75d59e36a1e1ccbbd5a47f129b923047268c580d6a09a9d63c3084bd397166ae"
	exampleDisplay  = "ae667139bd84303cd6a9096a0d588c264730929b127fa4d5bbcce1a1369ed575"
)

func TestParseDisplayHashReturnsInternalOrder(t *testing.T) {
	got, err := ParseDisplayHash(exampleDisplay)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != exampleInternal {
		t.Errorf("internal bytes = %x, want %s", got, exampleInternal)
	}
	if DisplayHex(got) != exampleDisplay {
		t.Errorf("DisplayHex = %s, want %s", DisplayHex(got), exampleDisplay)
	}
}

func TestParseDisplayHashRejectsEverySecondSpelling(t *testing.T) {
	cases := map[string]string{
		"uppercase":      strings.ToUpper(exampleDisplay),
		"63 characters":  exampleDisplay[:63],
		"65 characters":  exampleDisplay + "0",
		"0x prefix":      "0x" + exampleDisplay[:62],
		"not hex":        "zz" + exampleDisplay[2:],
		"empty":          "",
		"trailing space": exampleDisplay[:63] + " ",
	}
	for name, s := range cases {
		if _, err := ParseDisplayHash(s); err == nil {
			t.Errorf("%s: accepted %q, want an error", name, s)
		}
	}
}
