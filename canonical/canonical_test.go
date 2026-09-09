package canonical

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// blockWith assembles a block from a coinbase plus the given transactions. The
// caller owns the PrevoutSource; this only fixes block position.
func blockWith(t *testing.T, txs []*wire.MsgTx) *wire.MsgBlock {
	t.Helper()
	blk := &wire.MsgBlock{}
	cb := wire.NewMsgTx(2)
	cb.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}})
	cb.AddTxOut(wire.NewTxOut(50_000, p2wpkhScript()))
	if err := blk.AddTransaction(cb); err != nil {
		t.Fatal(err)
	}
	for _, tx := range txs {
		if err := blk.AddTransaction(tx); err != nil {
			t.Fatal(err)
		}
	}
	return blk
}

func TestSetEmptyBlockIsEmptyNotAnError(t *testing.T) {
	blk := blockWith(t, nil)
	leaves, err := Set(Network(0xdab5bffa), blk, mapPrevouts{})
	if err != nil {
		t.Fatalf("a block with no eligible transactions is not an error: %v", err)
	}
	if len(leaves) != 0 {
		t.Errorf("got %d leaves, want 0", len(leaves))
	}
}

func TestSetReturnsTransactionIndexOrder(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	var txs []*wire.MsgTx
	pv := mapPrevouts{}
	for i := 0; i < 3; i++ {
		var prevHash chainhash.Hash
		prevHash[0] = byte(0xA0 + i)
		op := wire.OutPoint{Hash: prevHash, Index: 0}

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Witness: [][]byte{make([]byte, 71), pk33}})
		tx.AddTxOut(wire.NewTxOut(10_000, p2trScript(t, testXOnly)))
		txs = append(txs, tx)
		pv[op] = wire.NewTxOut(50_000, p2wpkhScript())
	}

	blk := blockWith(t, txs)
	leaves, err := Set(Network(0xdab5bffa), blk, pv)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 3 {
		t.Fatalf("got %d leaves, want 3", len(leaves))
	}

	// Order must follow block position, and each TxID must be the INTERNAL
	// byte order of the transaction's own hash.
	for i, tx := range txs {
		want := txidInternal(tx.TxHash())
		if leaves[i].TxID != want {
			t.Errorf("leaf %d TxID = %x, want %x (transaction-index order, internal bytes)",
				i, leaves[i].TxID, want)
		}
	}
}

func TestSetSkipsIneligibleButKeepsOrder(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	pv := mapPrevouts{}

	mk := func(i int, outScript []byte) *wire.MsgTx {
		var prevHash chainhash.Hash
		prevHash[0] = byte(0xB0 + i)
		op := wire.OutPoint{Hash: prevHash, Index: 0}
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Witness: [][]byte{make([]byte, 71), pk33}})
		tx.AddTxOut(wire.NewTxOut(10_000, outScript))
		pv[op] = wire.NewTxOut(50_000, p2wpkhScript())
		return tx
	}

	eligibleA := mk(0, p2trScript(t, testXOnly))
	notEligible := mk(1, p2wpkhScript()) // no taproot output
	eligibleB := mk(2, p2trScript(t, testXOnly))

	blk := blockWith(t, []*wire.MsgTx{eligibleA, notEligible, eligibleB})
	leaves, err := Set(Network(0xdab5bffa), blk, pv)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 2 {
		t.Fatalf("got %d leaves, want 2", len(leaves))
	}
	if leaves[0].TxID != txidInternal(eligibleA.TxHash()) {
		t.Error("leaf 0 is not the first eligible transaction")
	}
	if leaves[1].TxID != txidInternal(eligibleB.TxHash()) {
		t.Error("leaf 1 is not the second eligible transaction")
	}
}

func TestSetPropagatesMissingPrevout(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	var prevHash chainhash.Hash
	prevHash[0] = 0xC0
	op := wire.OutPoint{Hash: prevHash, Index: 0}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Witness: [][]byte{make([]byte, 71), pk33}})
	tx.AddTxOut(wire.NewTxOut(10_000, p2trScript(t, testXOnly)))

	blk := blockWith(t, []*wire.MsgTx{tx})

	// The prevout map is deliberately empty. A missing prevout must be an
	// error, never a silently skipped transaction — silence here is the attack.
	if _, err := Set(Network(0xdab5bffa), blk, mapPrevouts{}); err == nil {
		t.Error("a missing prevout must surface as an error, not a dropped transaction")
	}
}
