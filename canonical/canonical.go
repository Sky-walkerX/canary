// Package canonical computes T_base(block) — the policy-free BIP-352 tweak set
// for a block. Spec §2.2.
package canonical

import (
	"errors"

	"github.com/btcsuite/btcd/wire"
)

// Network is the P2P message-start magic, per §3.2. Read it from
// chaincfg.Params.Net; never write a literal.
type Network uint32

// Leaf is one entry of the canonical set, in transaction-index order.
type Leaf struct {
	TxID  [32]byte // INTERNAL byte order (§3.2)
	Tweak [33]byte // compressed SEC
}

// PrevoutSource supplies the spent outputs a block does not carry itself.
type PrevoutSource interface {
	Prevout(op wire.OutPoint) (*wire.TxOut, error)
}

var errNotImplemented = errors.New("canonical: not implemented")

// Set returns the canonical leaves of blk in transaction-index order. §2.2.
func Set(net Network, blk *wire.MsgBlock, pv PrevoutSource) ([]Leaf, error) {
	return nil, errNotImplemented
}
