package core

import "testing"

// The decimal values are the ones the v1 formats doc prints for JSON and the
// Nostr network tag. Writing them as literals here pins them against btcd.
func TestNetworkFromChainUsesTheMessageStartMagic(t *testing.T) {
	cases := map[string]uint32{
		"regtest": 3669344250,
		"main":    3652501241,
	}
	for chain, want := range cases {
		got, err := NetworkFromChain(chain)
		if err != nil {
			t.Fatalf("%s: %v", chain, err)
		}
		if uint32(got) != want {
			t.Errorf("%s: magic %d, want %d", chain, uint32(got), want)
		}
		if NetworkName(got) != chain {
			t.Errorf("NetworkName(%d) = %q, want %q", uint32(got), NetworkName(got), chain)
		}
	}
}

// A custom signet's magic comes from its challenge, and Core's chain name does
// not say which signet it is. Mapping "signet" to the default magic would sign
// records for the wrong network without any error.
func TestNetworkFromChainRefusesNamesWithoutOneMagic(t *testing.T) {
	for _, chain := range []string{"signet", "test", "testnet4", "", "Regtest"} {
		if _, err := NetworkFromChain(chain); err == nil {
			t.Errorf("%q: accepted, want an error", chain)
		}
	}
}

func TestNetworkNameKnowsSignetAndNothingElse(t *testing.T) {
	if got := NetworkName(1087308554); got != "signet" {
		t.Errorf("NetworkName(signet magic) = %q, want signet", got)
	}
	if got := NetworkName(12345); got != "unknown" {
		t.Errorf("NetworkName(12345) = %q, want unknown", got)
	}
}
