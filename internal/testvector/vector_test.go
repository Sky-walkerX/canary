package testvector

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// Every committed vector must load and pass. This is the whole CI contract for
// §7: hermetic, no node, no network.
func TestAllCommittedVectorsPass(t *testing.T) {
	paths, err := filepath.Glob("../../testdata/vectors/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no vectors committed — the suite asserts nothing")
	}

	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			v, err := Load(p)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if v.Name == "" {
				t.Error("vector has no name")
			}
			if v.Rationale == "" {
				t.Error("vector has no rationale — a vector nobody can explain is a vector nobody can fix")
			}
			if err := v.Run(); err != nil {
				t.Errorf("run: %v", err)
			}
		})
	}
}

func TestVectorDetectsAWrongExpectedRoot(t *testing.T) {
	v, err := Load("../../testdata/vectors/empty-block.json")
	if err != nil {
		t.Fatal(err)
	}
	v.Expected.Root = "00" + v.Expected.Root[2:]
	if err := v.Run(); err == nil {
		t.Error("a corrupted expected root must fail the vector")
	}
}

func TestLoadRejectsMalformed(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmp, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(tmp); err == nil {
		t.Error("malformed vector must fail to load")
	}
}

// TestLoadRejectsUnknownField is syntactically valid JSON — unlike
// TestLoadRejectsMalformed's bare "{", which fails identically whether or not
// dec.DisallowUnknownFields() is wired up. The "nam" key below is not one of
// Vector's json tags (the real field is "name"), so this fixture is rejected
// only because of DisallowUnknownFields — remove that call and this test
// starts failing, which is the regression it exists to catch.
func TestLoadRejectsUnknownField(t *testing.T) {
	const payload = `{
		"name": "typo-fixture",
		"network": "regtest",
		"block": "",
		"prevouts": {},
		"expected": {"n": 0, "leaves": [], "root": ""},
		"rationale": "exercises DisallowUnknownFields",
		"nam": "typo"
	}`
	tmp := filepath.Join(t.TempDir(), "typo.json")
	if err := os.WriteFile(tmp, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(tmp); err == nil {
		t.Error("a vector with a typo'd field name must fail to load")
	}
}

// oneEligibleTxVector builds a self-contained, valid Vector with exactly one
// eligible transaction (a P2WPKH-spend input paying a P2TR output — the same
// pattern canonical's own tests use), computing Expected from the
// implementation under test. Modeled on canonical/canonical_test.go's
// blockWith/mk helpers, kept local here since those are unexported.
func oneEligibleTxVector(t *testing.T) Vector {
	t.Helper()
	net := canonical.Network(chaincfg.RegressionNetParams.Net)

	var prevHash chainhash.Hash
	prevHash[0] = 0xAB
	op := wire.OutPoint{Hash: prevHash, Index: 0}

	pk33, err := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	if err != nil {
		t.Fatal(err)
	}
	xonly, err := hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	if err != nil {
		t.Fatal(err)
	}
	p2trScript := append([]byte{0x51, 0x20}, xonly...)
	p2wpkhScript := append([]byte{0x00, 0x14}, make([]byte, 20)...)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Witness: [][]byte{make([]byte, 71), pk33}})
	tx.AddTxOut(wire.NewTxOut(10_000, p2trScript))

	blk := &wire.MsgBlock{Header: wire.BlockHeader{Version: 1, Bits: 0x207fffff}}
	cb := wire.NewMsgTx(2)
	cb.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, SignatureScript: []byte{0x51}})
	cb.AddTxOut(wire.NewTxOut(5_000_000_000, []byte{0x51}))
	if err := blk.AddTransaction(cb); err != nil {
		t.Fatal(err)
	}
	if err := blk.AddTransaction(tx); err != nil {
		t.Fatal(err)
	}

	prevout := wire.NewTxOut(50_000, p2wpkhScript)
	pv := mapPrevouts{op: prevout}

	leaves, err := canonical.Set(net, blk, pv)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 1 {
		t.Fatalf("fixture construction bug: got %d leaves, want 1", len(leaves))
	}

	var buf bytes.Buffer
	if err := blk.Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	blockHash := blk.BlockHash()
	var bh [32]byte
	copy(bh[:], blockHash[:])
	root := commit.Root(net, bh, leaves)

	var disp [32]byte
	for i := 0; i < 32; i++ {
		disp[i] = leaves[0].TxID[31-i]
	}
	leafStr := hex.EncodeToString(disp[:]) + ":" + hex.EncodeToString(leaves[0].Tweak[:])

	return Vector{
		Name:    "one-eligible-tx (test fixture, not committed)",
		Network: "regtest",
		Block:   hex.EncodeToString(buf.Bytes()),
		Prevouts: map[string]Prevout{
			prevHash.String() + ":0": {
				ScriptPubKey: hex.EncodeToString(prevout.PkScript),
				Value:        prevout.Value,
			},
		},
		Expected: Expected{
			N:      1,
			Leaves: []string{leafStr},
			Root:   hex.EncodeToString(root[:]),
		},
		Rationale: "in-memory fixture exercising Run()'s per-leaf Expected.Leaves check",
	}
}

func TestVectorDetectsAWrongExpectedLeaf(t *testing.T) {
	v := oneEligibleTxVector(t)

	// The uncorrupted fixture must pass first, or a failure below could just
	// be a broken fixture rather than the check working.
	if err := v.Run(); err != nil {
		t.Fatalf("valid fixture must pass: %v", err)
	}

	corrupted := v.Expected.Leaves[0]
	v.Expected.Leaves[0] = "00" + corrupted[2:]
	if err := v.Run(); err == nil {
		t.Error("a corrupted expected leaf must fail the vector")
	}
}
