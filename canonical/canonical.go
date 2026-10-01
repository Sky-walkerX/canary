package canonical

import (
	"fmt"

	"github.com/btcsuite/btcd/wire"
)

// Network is the 4-byte P2P message-start magic, the value the root binds.
// Read it from chaincfg.Params.Net and never write a literal, because a wrong
// constant silently gives every root a different value.
type Network uint32

// Leaf is one entry of the canonical set: a txid and its tweak, 65 bytes.
// The design doc calls an entry a leaf, because it is a leaf of the Merkle
// tree.
type Leaf struct {
	TxID  [32]byte // internal byte order, as the leaf hash preimage requires
	Tweak [33]byte // compressed SEC
}

// PrevoutSource supplies the spent outputs a block does not carry itself.
type PrevoutSource interface {
	Prevout(op wire.OutPoint) (*wire.TxOut, error)
}

// Set returns the canonical set of blk: its entries in transaction order.
//
// Set is pure. It reads no chain state after the block, no thresholds and no
// configuration. That is why servers can sign its result and anyone holding
// the block and its spent outputs can recompute it.
//
// The order is block position, not a sort by tweak. Position i names one
// transaction, which is what naming a withheld transaction needs.
//
// An error means Set could not decide for some transaction, for example
// because a spent output was missing. Set never drops a transaction it could
// not decide, because a silently dropped entry looks exactly like the
// withholding Canary exists to catch.
func Set(net Network, blk *wire.MsgBlock, pv PrevoutSource) ([]Leaf, error) {
	leaves := make([]Leaf, 0, len(blk.Transactions))

	for i, tx := range blk.Transactions {
		tweak, eligible, err := tweakForTx(tx, pv)
		if err != nil {
			return nil, fmt.Errorf("canonical: tx %d (%s): %w", i, tx.TxHash(), err)
		}
		if !eligible {
			continue
		}
		leaves = append(leaves, Leaf{
			TxID:  txidInternal(tx.TxHash()), // internal byte order
			Tweak: tweak,
		})
	}
	return leaves, nil
}
