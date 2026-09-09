// Package canonical computes T_base(block) — the policy-free BIP-352 tweak set
// for a block. Spec §2.2.
package canonical

import (
	"fmt"

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

// Set returns the canonical leaves of blk in transaction-index order.
//
// Pure: no chain state after the block, no thresholds, no configuration. That
// is what makes it the thing servers commit to and clients recompute (§2.2).
//
// Ordering is block position, not lexicographic. Position i is a specific
// transaction, which is what attribution needs (§2.2).
func Set(net Network, blk *wire.MsgBlock, pv PrevoutSource) ([]Leaf, error) {
	leaves := make([]Leaf, 0, len(blk.Transactions))

	for i, tx := range blk.Transactions {
		tweak, eligible, err := tweakForTx(tx, pv)
		if err != nil {
			return nil, fmt.Errorf("tx %d (%s): %w", i, tx.TxHash(), err)
		}
		if !eligible {
			continue
		}
		leaves = append(leaves, Leaf{
			TxID:  txidInternal(tx.TxHash()), // INTERNAL byte order (§3.2)
			Tweak: tweak,
		})
	}
	return leaves, nil
}
