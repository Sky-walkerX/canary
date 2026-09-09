package canonical

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	bip352 "github.com/setavenger/go-bip352"
)

// txidInternal returns the txid in INTERNAL byte order — the bytes as they
// appear in the transaction serialization. This is what §3.2 pins for the
// leaf preimage. chainhash.Hash already stores this order.
func txidInternal(h chainhash.Hash) [32]byte {
	var out [32]byte
	copy(out[:], h[:])
	return out
}

// txidDisplay returns the txid in display order — the reversed form printed by
// block explorers and returned by Core's REST API.
//
// bip352.Vin.Txid must be in THIS order: the library documents it as "the
// normal human-readable format", and ComputeInputHash and FindSmallestOutpoint
// both depend on it. Every crossing between the two orders happens here (§6.4).
func txidDisplay(h chainhash.Hash) [32]byte {
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = h[31-i]
	}
	return out
}

// vinsForTx builds the bip352 input structures for tx, pulling each spent
// output from pv. The prevout is required for every input because eligibility
// is decided by the scriptPubKey being spent, not by the spending script alone.
func vinsForTx(tx *wire.MsgTx, pv PrevoutSource) ([]*bip352.Vin, error) {
	vins := make([]*bip352.Vin, 0, len(tx.TxIn))
	for _, in := range tx.TxIn {
		prev, err := pv.Prevout(in.PreviousOutPoint)
		if err != nil {
			return nil, fmt.Errorf("prevout %s: %w", in.PreviousOutPoint, err)
		}
		if prev == nil {
			return nil, fmt.Errorf("prevout %s: not found", in.PreviousOutPoint)
		}

		vins = append(vins, &bip352.Vin{
			Txid:         txidDisplay(in.PreviousOutPoint.Hash), // display order — library contract
			Vout:         in.PreviousOutPoint.Index,
			Amount:       uint64(prev.Value),
			ScriptPubKey: prev.PkScript,
			ScriptSig:    in.SignatureScript,
			Witness:      in.Witness,
		})
	}
	return vins, nil
}
