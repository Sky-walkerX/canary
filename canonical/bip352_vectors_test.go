package canonical

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	bip352 "github.com/setavenger/go-bip352"
)

const vectorPath = "../testdata/bip352/send_and_receive_test_vectors.json"

type bipVin struct {
	Txid      string `json:"txid"`
	Vout      uint32 `json:"vout"`
	ScriptSig string `json:"scriptSig"`
	Witness   string `json:"txinwitness"`
	Prevout   struct {
		ScriptPubKey struct {
			Hex string `json:"hex"`
		} `json:"scriptPubKey"`
	} `json:"prevout"`
}

type bipVectorFile []struct {
	Comment   string `json:"comment"`
	Receiving []struct {
		Given struct {
			Vin []bipVin `json:"vin"`
		} `json:"given"`
		// Both fields are null in JSON for the deliberately-ineligible cases,
		// which unmarshals to "" and is exactly the signal we want.
		Expected struct {
			Tweak          string `json:"tweak"`
			InputPubKeySum string `json:"input_pub_key_sum"`
		} `json:"expected"`
	} `json:"receiving"`
}

func loadVectors(t *testing.T) bipVectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Skipf("upstream vectors not present: %v", err)
	}
	var file bipVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file) == 0 {
		t.Fatal("vector file is empty")
	}
	return file
}

// parseWitness hex-decodes a vector witness. bip352.ParseWitnessScript reads
// data[0] with no length check, so an empty witness — 43 of the 62 vins in this
// file — must never reach it.
func parseWitness(t *testing.T, s string) [][]byte {
	t.Helper()
	if s == "" {
		return nil
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad witness hex: %v", err)
	}
	if len(raw) == 0 {
		return nil
	}
	w, err := bip352.ParseWitnessScript(raw)
	if err != nil {
		t.Fatalf("parse witness: %v", err)
	}
	return w
}

// txFromVector rebuilds a spending transaction and its prevouts from a vector's
// input list, then adds one taproot output so §2.2 rule 1 is satisfied and the
// vector exercises the rules it was written for rather than tripping rule 1.
//
// The vector txid is display order, matching bip352.Vin's contract. wire.OutPoint
// holds internal order, so it is reversed going in — and vinsForTx reverses it
// back on the way out. That round trip is Task 7's boundary under real data.
func txFromVector(t *testing.T, vins []bipVin) (*wire.MsgTx, mapPrevouts) {
	t.Helper()
	tx := wire.NewMsgTx(2)
	pv := mapPrevouts{}

	for _, v := range vins {
		display, err := hex.DecodeString(v.Txid)
		if err != nil || len(display) != 32 {
			t.Fatalf("bad txid %q: %v", v.Txid, err)
		}
		var h chainhash.Hash
		for i := 0; i < 32; i++ {
			h[i] = display[31-i]
		}
		op := wire.OutPoint{Hash: h, Index: v.Vout}

		ss, err := hex.DecodeString(v.ScriptSig)
		if err != nil {
			t.Fatalf("bad scriptSig: %v", err)
		}
		spk, err := hex.DecodeString(v.Prevout.ScriptPubKey.Hex)
		if err != nil {
			t.Fatalf("bad scriptPubKey: %v", err)
		}

		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: op,
			SignatureScript:  ss,
			Witness:          parseWitness(t, v.Witness),
		})
		pv[op] = wire.NewTxOut(50_000, spk)
	}

	tx.AddTxOut(wire.NewTxOut(10_000, p2trScript(t, testXOnly)))
	return tx, pv
}

// The authoritative check on the whole derivation. expected.tweak is
// input_hash · A_sum — exactly the 33 bytes §3.2 commits to in a leaf — so this
// compares our tweakForTx against the BIP's own published value rather than
// against our own reasoning.
func TestBIP352VectorsTweakMatchesUpstream(t *testing.T) {
	file := loadVectors(t)

	var positive, negative int
	for _, c := range file {
		for _, r := range c.Receiving {
			if len(r.Given.Vin) == 0 {
				continue
			}
			tx, pv := txFromVector(t, r.Given.Vin)

			got, eligible, err := tweakForTx(tx, pv)
			if err != nil {
				t.Errorf("%s: tweakForTx: %v", c.Comment, err)
				continue
			}

			if r.Expected.Tweak == "" {
				// "No valid inputs" and "input keys sum to the point at
				// infinity" — §2.2 rule 2 and rule 4a, from the BIP's vectors.
				if eligible {
					t.Errorf("%s: expected no tweak, got %x", c.Comment, got)
				}
				negative++
				continue
			}

			if !eligible {
				t.Errorf("%s: expected tweak %s, got none", c.Comment, r.Expected.Tweak)
				continue
			}
			if want := r.Expected.Tweak; hex.EncodeToString(got[:]) != want {
				t.Errorf("%s:\n  got  %x\n  want %s", c.Comment, got, want)
			}
			positive++
		}
	}

	if positive == 0 || negative == 0 {
		t.Fatalf("harness exercised nothing: %d positive, %d negative", positive, negative)
	}
	t.Logf("matched %d upstream tweaks and %d ineligible cases", positive, negative)
}

// input_pub_key_sum pins A_sum independently of input_hash, so it catches a
// wrong x-only lift that a tweak comparison alone could mask.
func TestBIP352VectorsInputPubKeySumMatchesUpstream(t *testing.T) {
	file := loadVectors(t)

	checked := 0
	for _, c := range file {
		for _, r := range c.Receiving {
			if r.Expected.InputPubKeySum == "" || len(r.Given.Vin) == 0 {
				continue
			}
			tx, pv := txFromVector(t, r.Given.Vin)
			vins, err := vinsForTx(tx, pv)
			if err != nil {
				t.Fatalf("%s: vinsForTx: %v", c.Comment, err)
			}

			eligible, err := bip352.ExtractEligibleVins(vins)
			if err != nil {
				t.Fatalf("%s: ExtractEligibleVins: %v", c.Comment, err)
			}

			keys := make([][33]byte, 0, len(eligible))
			for _, v := range eligible {
				pk, typ := bip352.ExtractPubKey(v)
				if typ == bip352.Unknown || len(pk) == 0 {
					continue
				}
				if len(pk) == 32 {
					pk = append([]byte{0x02}, pk...)
				}
				keys = append(keys, bip352.ConvertToFixedLength33(pk))
			}
			if len(keys) == 0 {
				t.Errorf("%s: expected A_sum %s but found no input keys", c.Comment, r.Expected.InputPubKeySum)
				continue
			}

			// Our summation, not the library's: bip352.SumPublicKeys cannot
			// represent a running sum that passes through infinity, and one
			// upstream vector does exactly that.
			sum, err := sumPublicKeys(keys)
			if err != nil {
				t.Errorf("%s: sumPublicKeys: %v", c.Comment, err)
				continue
			}
			if hex.EncodeToString(sum[:]) != r.Expected.InputPubKeySum {
				t.Errorf("%s: A_sum\n  got  %x\n  want %s", c.Comment, sum, r.Expected.InputPubKeySum)
			}
			checked++
		}
	}

	if checked == 0 {
		t.Fatal("no vector produced an input public key sum — the harness is not exercising anything")
	}
	t.Logf("matched %d upstream input public key sums", checked)
}
