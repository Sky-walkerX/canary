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
// to know its value. /info does not report the number, and §2.3 establishes
// that the number was never verifiable anyway — the declaration's job is to
// route effort and to create a contradiction rung 4 can check, not to be an
// input to any verdict.
const dustThresholdUnknown = 1

// networkFromName maps blindbit's display name onto the 4-byte P2P magic, read
// from chaincfg rather than written as a literal (§3.2).
func networkFromName(name string) (canonical.Network, error) {
	switch name {
	case "main", "mainnet", "bitcoin":
		return canonical.Network(chaincfg.MainNetParams.Net), nil
	case "signet":
		return canonical.Network(chaincfg.SigNetParams.Net), nil
	case "regtest":
		return canonical.Network(chaincfg.RegressionNetParams.Net), nil
	default:
		return 0, fmt.Errorf("policy: unrecognised network %q", name)
	}
}

// FromBlindBitInfo derives a Policy from blindbit-oracle's GET /info body.
//
// This is the tool-first bridge (§2.3): unsigned, not per-block, and revisable
// retroactively by the server, therefore strictly weaker than the signed
// per-block policy of the protocol layer. It is also what lets the differ run
// against unmodified blindbit today, which is the whole point of §0's layering.
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
		// /info carries no start height. Leaving it zero is honest: below a
		// real start height absence is not evidence, and we do not know it.
		StartHeight: 0,
		// Only the cut-through mode prunes spent transactions. The two full
		// modes keep them, differing solely in dust handling (§2.3).
		PrunesSpent: info.TweaksCutThroughWithDustFilter,
	}

	if info.TweaksFullWithDustFilter || info.TweaksCutThroughWithDustFilter {
		p.DustThresholdSat = dustThresholdUnknown
	}

	return p, nil
}
