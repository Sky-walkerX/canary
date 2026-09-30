package core

import (
	"fmt"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/btcsuite/btcd/chaincfg"
)

// NetworkFromChain returns the network magic for the chain name that Core
// reports in /rest/chaininfo.json.
//
// It accepts only names that fix one magic: "main" and "regtest". A custom
// signet derives its magic from its challenge, and the name "signet" does not
// say which challenge. Guessing the default magic would sign every record for
// the wrong network, and nothing would fail. So the indexer refuses instead.
func NetworkFromChain(chain string) (canonical.Network, error) {
	switch chain {
	case "main":
		return canonical.Network(chaincfg.MainNetParams.Net), nil
	case "regtest":
		return canonical.Network(chaincfg.RegressionNetParams.Net), nil
	default:
		return 0, fmt.Errorf("core: network: Core reports chain %q, and the reference indexer supports only regtest and main", chain)
	}
}

// NetworkName returns the name the v1 formats use for a network magic:
// "main", "signet", "regtest", or "unknown" for any other magic.
func NetworkName(net canonical.Network) string {
	switch uint32(net) {
	case uint32(chaincfg.MainNetParams.Net):
		return "main"
	case uint32(chaincfg.SigNetParams.Net):
		return "signet"
	case uint32(chaincfg.RegressionNetParams.Net):
		return "regtest"
	default:
		return "unknown"
	}
}
