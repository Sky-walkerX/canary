package canonical

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// mapPrevouts is a PrevoutSource backed by a map, so tests need no node.
type mapPrevouts map[wire.OutPoint]*wire.TxOut

func (m mapPrevouts) Prevout(op wire.OutPoint) (*wire.TxOut, error) {
	return m[op], nil
}

func p2trScript(t *testing.T, xonly string) []byte {
	return append([]byte{0x51, 0x20}, mustHex(t, xonly)...)
}

func p2wpkhScript() []byte {
	return append([]byte{0x00, 0x14}, make([]byte, 20)...)
}

// segwitV2Script is an anyone-can-spend v2 witness program: OP_2 <32 bytes>.
func segwitV2Script() []byte {
	return append([]byte{0x52, 0x20}, make([]byte, 32)...)
}

const testXOnly = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

// buildTx wires one input spending prevScript with the given witness, and the
// given output scripts.
func buildTx(t *testing.T, prevScript []byte, witness [][]byte, outScripts ...[]byte) (*wire.MsgTx, mapPrevouts) {
	t.Helper()
	var prevHash chainhash.Hash
	prevHash[0] = 0x99
	op := wire.OutPoint{Hash: prevHash, Index: 0}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Witness: witness})
	for _, s := range outScripts {
		tx.AddTxOut(wire.NewTxOut(10_000, s))
	}
	return tx, mapPrevouts{op: wire.NewTxOut(50_000, prevScript)}
}

func TestEligibleWithTaprootOutputAndWitnessInput(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	tx, pv := buildTx(t, p2wpkhScript(), [][]byte{make([]byte, 71), pk33}, p2trScript(t, testXOnly))

	tweak, ok, err := tweakForTx(tx, pv)
	if err != nil {
		t.Fatalf("tweakForTx: %v", err)
	}
	if !ok {
		t.Fatal("transaction should be eligible: taproot output + P2WPKH input")
	}
	if tweak[0] != 0x02 && tweak[0] != 0x03 {
		t.Errorf("tweak must be a compressed SEC point, got prefix %02x", tweak[0])
	}
}

func TestNotEligibleWithoutTaprootOutput(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	tx, pv := buildTx(t, p2wpkhScript(), [][]byte{make([]byte, 71), pk33}, p2wpkhScript())

	_, ok, err := tweakForTx(tx, pv)
	if err != nil {
		t.Fatalf("tweakForTx: %v", err)
	}
	if ok {
		t.Error("no BIP-341 taproot output means not eligible (eligibility rule 1)")
	}
}

func TestNotEligibleWhenSpendingSegWitV2(t *testing.T) {
	tx, pv := buildTx(t, segwitV2Script(), [][]byte{make([]byte, 64)}, p2trScript(t, testXOnly))

	_, ok, err := tweakForTx(tx, pv)
	if err != nil {
		t.Fatalf("tweakForTx: %v", err)
	}
	if ok {
		t.Error("spending a SegWit v>1 output excludes the whole transaction (eligibility rule 3)")
	}
}

func TestNotEligibleWithNoEligibleInputs(t *testing.T) {
	// Bare OP_RETURN-ish prevout: no extractable public key of any accepted type.
	tx, pv := buildTx(t, []byte{0x6a, 0x01, 0x00}, nil, p2trScript(t, testXOnly))

	_, ok, err := tweakForTx(tx, pv)
	if err != nil {
		t.Fatalf("tweakForTx: %v", err)
	}
	if ok {
		t.Error("no input from Inputs For Shared Secret Derivation means not eligible (eligibility rule 2)")
	}
}

func TestCoinbaseIsNotEligible(t *testing.T) {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}})
	tx.AddTxOut(wire.NewTxOut(50_000, p2trScript(t, testXOnly)))

	_, ok, err := tweakForTx(tx, mapPrevouts{})
	if err != nil {
		t.Fatalf("coinbase must be reported as ineligible, not as an error: %v", err)
	}
	if ok {
		t.Error("a coinbase has no prevouts and cannot be eligible")
	}
}

func TestTweakIsDeterministic(t *testing.T) {
	pk33 := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	tx, pv := buildTx(t, p2wpkhScript(), [][]byte{make([]byte, 71), pk33}, p2trScript(t, testXOnly))

	a, ok, err := tweakForTx(tx, pv)
	if err != nil || !ok {
		t.Fatalf("setup: ok=%v err=%v", ok, err)
	}
	b, _, _ := tweakForTx(tx, pv)
	if a != b {
		t.Error("tweak derivation must be deterministic")
	}
}

// go-bip352 v0.1.8 reads vin.Witness[len(vin.Witness)-1] for P2WPKH and
// P2SH-P2WPKH without checking the witness is non-empty, so a prevout of either
// shape with no witness panics with "index out of range [-1]". Spent outputs can
// come from a hostile source, so a crafted pair must not be able to crash the
// scanner. This was confirmed against the library before the guard was written.
func TestP2WPKHPrevoutWithEmptyWitnessDoesNotPanic(t *testing.T) {
	tx, pv := buildTx(t, p2wpkhScript(), nil, p2trScript(t, testXOnly))

	_, ok, err := tweakForTx(tx, pv)
	if err != nil {
		t.Fatalf("tweakForTx: %v", err)
	}
	if ok {
		t.Error("a P2WPKH prevout with no witness yields no public key, so the tx is not eligible")
	}
}

func TestP2SHP2WPKHPrevoutWithEmptyWitnessDoesNotPanic(t *testing.T) {
	spk := append(append([]byte{0xa9, 0x14}, make([]byte, 20)...), 0x87)
	scriptSig := append([]byte{0x16, 0x00, 0x14}, make([]byte, 20)...)

	var prevHash chainhash.Hash
	prevHash[0] = 0x77
	op := wire.OutPoint{Hash: prevHash, Index: 0}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, SignatureScript: scriptSig})
	tx.AddTxOut(wire.NewTxOut(10_000, p2trScript(t, testXOnly)))
	pv := mapPrevouts{op: wire.NewTxOut(50_000, spk)}

	if _, ok, err := tweakForTx(tx, pv); err != nil || ok {
		t.Errorf("expected ineligible with no error, got ok=%v err=%v", ok, err)
	}
}
