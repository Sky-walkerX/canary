package policy

import (
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
)

const infoFullBasic = `{
  "network": "signet",
  "height": 834761,
  "tweaks_only": false,
  "tweaks_full_basic": true,
  "tweaks_full_with_dust_filter": false,
  "tweaks_cut_through_with_dust_filter": false
}`

const infoCutThrough = `{
  "network": "regtest",
  "height": 200,
  "tweaks_only": false,
  "tweaks_full_basic": false,
  "tweaks_full_with_dust_filter": false,
  "tweaks_cut_through_with_dust_filter": true
}`

func TestFromBlindBitInfoFullIndexDeclaresNoSubtraction(t *testing.T) {
	p, err := FromBlindBitInfo(strings.NewReader(infoFullBasic))
	if err != nil {
		t.Fatal(err)
	}
	if p.Network != canonical.Network(0x40cf030a) {
		t.Errorf("network = %08x, want signet magic 40cf030a", uint32(p.Network))
	}
	if p.PrunesSpent {
		t.Error("tweaks_full_basic does not prune spent transactions")
	}
	if p.DustThresholdSat != 0 {
		t.Error("no dust filter flag means no declared threshold")
	}
	// A server that declares a full index and then shows a gap contradicts
	// itself. Catching that is the first job of this struct.
}

func TestFromBlindBitInfoCutThroughDeclaresPruning(t *testing.T) {
	p, err := FromBlindBitInfo(strings.NewReader(infoCutThrough))
	if err != nil {
		t.Fatal(err)
	}
	if p.Network != canonical.Network(0xdab5bffa) {
		t.Errorf("network = %08x, want regtest magic dab5bffa", uint32(p.Network))
	}
	if !p.PrunesSpent {
		t.Error("tweaks_cut_through_with_dust_filter prunes spent transactions")
	}
	if p.DustThresholdSat == 0 {
		t.Error("a dust-filter flag must record that a threshold is in force")
	}
}

func TestFromBlindBitInfoRejectsUnknownNetwork(t *testing.T) {
	_, err := FromBlindBitInfo(strings.NewReader(`{"network":"testnet4"}`))
	if err == nil {
		t.Error("an unrecognized network must be an error, because comparison needs both servers on the same network")
	}
}

func TestFromBlindBitInfoRejectsMalformedJSON(t *testing.T) {
	if _, err := FromBlindBitInfo(strings.NewReader(`{`)); err == nil {
		t.Error("malformed /info must error rather than yield a zero-value policy")
	}
}
