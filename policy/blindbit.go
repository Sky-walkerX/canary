package policy

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/btcsuite/btcd/chaincfg"
)

type blindbitInfo struct {
	Network                        string `json:"network"`
	Height                         uint32 `json:"height"`
	TweaksOnly                     bool   `json:"tweaks_only"`
	TweaksFullBasic                bool   `json:"tweaks_full_basic"`
	TweaksFullWithDustFilter       bool   `json:"tweaks_full_with_dust_filter"`
	TweaksCutThroughWithDustFilter bool   `json:"tweaks_cut_through_with_dust_filter"`
}

// dustThresholdUnknown records that a dust filter is in force without claiming
// to know its value. /info does not report the number, and a client could never
// verify it anyway, because entries carry no amount. The declaration routes
// effort and gives an auditor holding the block something to check. No state
// takes it as an input.
const dustThresholdUnknown = 1

// networkFromName maps blindbit-oracle's network name to the 4-byte P2P magic.
// It reads the magic from chaincfg and never writes a literal, because the root
// binds this value.
func networkFromName(name string) (canonical.Network, error) {
	switch name {
	case "main", "mainnet", "bitcoin":
		return canonical.Network(chaincfg.MainNetParams.Net), nil
	case "signet":
		return canonical.Network(chaincfg.SigNetParams.Net), nil
	case "regtest":
		return canonical.Network(chaincfg.RegressionNetParams.Net), nil
	default:
		return 0, fmt.Errorf("policy: read network: unrecognized name %q", name)
	}
}

// FromBlindBitInfo derives a Policy from blindbit-oracle's GET /info body.
//
// This bridges to servers as they exist today. The body is unsigned and not per
// block, and the server can revise it after the fact. So it is weaker than the
// signed, per-block policy the design plans for later. It is also what lets the
// checker run against an unmodified blindbit-oracle today, with nobody's
// cooperation.
func FromBlindBitInfo(r io.Reader) (Policy, error) {
	var info blindbitInfo
	dec := json.NewDecoder(r)
	if err := dec.Decode(&info); err != nil {
		return Policy{}, fmt.Errorf("policy: decode /info: %w", err)
	}

	net, err := networkFromName(info.Network)
	if err != nil {
		return Policy{}, err
	}

	p := Policy{
		Network: net,
		// /info carries no start height. Zero is the honest value. Below a
		// real start height an absence proves nothing, and the height is
		// unknown here.
		StartHeight: 0,
		// Only the cut-through mode prunes spent transactions. The two full
		// modes keep them and differ only in dust handling.
		PrunesSpent: info.TweaksCutThroughWithDustFilter,
	}

	if info.TweaksFullWithDustFilter || info.TweaksCutThroughWithDustFilter {
		p.DustThresholdSat = dustThresholdUnknown
	}

	return p, nil
}
