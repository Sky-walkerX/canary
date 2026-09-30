package core

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// goldenSpent is a /rest/spenttxouts/<hash>.bin body written out by hand from
// SerializeBlockUndo in Bitcoin Core's src/rest.cpp (v30.0). It describes a
// block of three transactions:
//
//	03                                     three transactions
//	00                                     the coinbase spends nothing
//	01                                     transaction 1 spends one output
//	  00f2052a01000000                       5,000,000,000 sat, int64 LE
//	  16 0014<20 bytes of 0x11>              22-byte P2WPKH script
//	02                                     transaction 2 spends two outputs
//	  e803000000000000                       1,000 sat
//	  22 5120<32 bytes of 0x22>              34-byte P2TR script
//	  0000000000000000                       0 sat
//	  00                                     empty script
var goldenSpent = "03" +
	"00" +
	"01" + "00f2052a01000000" + "16" + "0014" + strings.Repeat("11", 20) +
	"02" + "e803000000000000" + "22" + "5120" + strings.Repeat("22", 32) +
	"0000000000000000" + "00"

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeSpentOutputsReadsCoreLayout(t *testing.T) {
	got, err := DecodeSpentOutputs(mustDecodeHex(t, goldenSpent))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d transaction lists, want 3", len(got))
	}
	if len(got[0]) != 0 {
		t.Errorf("coinbase list has %d outputs, want 0", len(got[0]))
	}
	if len(got[1]) != 1 || len(got[2]) != 2 {
		t.Fatalf("list lengths %d and %d, want 1 and 2", len(got[1]), len(got[2]))
	}

	want := []*wire.TxOut{
		wire.NewTxOut(5_000_000_000, mustDecodeHex(t, "0014"+strings.Repeat("11", 20))),
		wire.NewTxOut(1_000, mustDecodeHex(t, "5120"+strings.Repeat("22", 32))),
		wire.NewTxOut(0, []byte{}),
	}
	gotFlat := []*wire.TxOut{got[1][0], got[2][0], got[2][1]}
	for i := range want {
		if gotFlat[i].Value != want[i].Value || !bytes.Equal(gotFlat[i].PkScript, want[i].PkScript) {
			t.Errorf("output %d = (%d, %x), want (%d, %x)", i,
				gotFlat[i].Value, gotFlat[i].PkScript, want[i].Value, want[i].PkScript)
		}
	}
}

// The genesis block has no undo data. Core then writes one list, for its
// coinbase, and that list is empty.
func TestDecodeSpentOutputsGenesisShape(t *testing.T) {
	got, err := DecodeSpentOutputs([]byte{0x01, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0]) != 0 {
		t.Errorf("got %v, want one empty list", got)
	}
}

func TestDecodeSpentOutputsRejectsMalformedBodies(t *testing.T) {
	golden := mustDecodeHex(t, goldenSpent)
	cases := map[string][]byte{
		"empty":                   {},
		"trailing byte":           append(append([]byte{}, golden...), 0x00),
		"truncated script":        golden[:len(golden)-10],
		"truncated value":         golden[:5],
		"count beyond the body":   {0x05, 0x00},
		"inputs beyond the body":  {0x01, 0x09, 0x00},
		"non-canonical count":     {0xfd, 0x01, 0x00, 0x00},
		"script beyond the body":  mustDecodeHex(t, "0201"+"0000000000000000"+"05"+"51"),
		"negative value":          mustDecodeHex(t, "0201"+"ffffffffffffffff"+"00"),
		"truncated compact size":  {0xfe, 0x01},
		"huge count, tiny body":   {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		"missing coinbase list":   {0x02, 0x00},
		"second list is too long": mustDecodeHex(t, "02"+"00"+"02"+"0000000000000000"+"00"),
	}
	for name, body := range cases {
		if _, err := DecodeSpentOutputs(body); err == nil {
			t.Errorf("%s: decoded %x without an error", name, body)
		}
	}
}

func pairingBlock() *wire.MsgBlock {
	cb := wire.NewMsgTx(2)
	cb.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: wire.MaxPrevOutIndex}})
	cb.AddTxOut(wire.NewTxOut(1, []byte{0x51}))

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xaa}, Index: 0}})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xbb}, Index: 3}})
	tx.AddTxOut(wire.NewTxOut(1, []byte{0x51}))

	blk := &wire.MsgBlock{}
	_ = blk.AddTransaction(cb)
	_ = blk.AddTransaction(tx)
	return blk
}

func TestBlockPrevoutsPairsEachInputWithItsOutput(t *testing.T) {
	blk := pairingBlock()
	a := wire.NewTxOut(10, []byte{0x00, 0x14})
	b := wire.NewTxOut(20, []byte{0x51, 0x20})

	pv, err := NewBlockPrevouts(blk, [][]*wire.TxOut{{}, {a, b}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := pv.Prevout(wire.OutPoint{Hash: chainhash.Hash{0xbb}, Index: 3})
	if err != nil {
		t.Fatal(err)
	}
	if got != b {
		t.Errorf("second input paired with %v, want %v", got, b)
	}
	if _, err := pv.Prevout(wire.OutPoint{Hash: chainhash.Hash{0xcc}}); err == nil {
		t.Error("an outpoint the block does not spend must be an error, not a nil output")
	}
}

func TestBlockPrevoutsRejectsAListThatDoesNotFitTheBlock(t *testing.T) {
	blk := pairingBlock()
	out := wire.NewTxOut(1, nil)
	cases := map[string][][]*wire.TxOut{
		"too few lists":          {{}},
		"too many lists":         {{}, {out, out}, {}},
		"coinbase spends":        {{out}, {out, out}},
		"too few outputs for tx": {{}, {out}},
	}
	for name, spent := range cases {
		if _, err := NewBlockPrevouts(blk, spent); err == nil {
			t.Errorf("%s: paired without an error", name)
		}
	}
}
