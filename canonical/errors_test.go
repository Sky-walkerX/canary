package canonical

import (
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// houseStyle reports whether msg reads "<pkg>: <what failed>: <detail>".
func houseStyle(msg, pkg string) bool {
	return strings.HasPrefix(msg, pkg+": ") && strings.Count(msg, ": ") >= 2
}

// An error that leaves Set names the package first, so a caller several
// layers up can still tell which step failed.
func TestSetErrorsFollowHouseStyle(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	var prevHash chainhash.Hash
	prevHash[0] = 0xD0
	op := wire.OutPoint{Hash: prevHash, Index: 0}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Witness: [][]byte{make([]byte, 71), pk33}})
	tx.AddTxOut(wire.NewTxOut(10_000, p2trScript(t, testXOnly)))
	blk := blockWith(t, []*wire.MsgTx{tx})

	_, err := Set(Network(0xdab5bffa), blk, mapPrevouts{})
	if err == nil {
		t.Fatal("a missing prevout must be an error")
	}
	if !houseStyle(err.Error(), "canonical") {
		t.Errorf("error %q does not read \"canonical: <what failed>: <detail>\"", err)
	}
}
