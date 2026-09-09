package canonical

import (
	"fmt"

	"github.com/btcsuite/btcd/wire"
	bip352 "github.com/setavenger/go-bip352"
)

// isTaprootOutput reports whether pkScript is a BIP-341 v1 witness program:
// OP_1 <32 bytes>. §2.2 rule 1 uses this WITHOUT the optional unspent clause —
// that clause is exactly the cut-through policy §2.1 refuses to bake in.
func isTaprootOutput(pkScript []byte) bool {
	return len(pkScript) == 34 && pkScript[0] == 0x51 && pkScript[1] == 0x20
}

// isSegWitVersionAbove1 reports whether pkScript is a witness program of
// version 2..16. Spending one excludes the whole transaction (§2.2 rule 3).
func isSegWitVersionAbove1(pkScript []byte) bool {
	if len(pkScript) < 4 || len(pkScript) > 42 {
		return false
	}
	op := pkScript[0]
	// OP_2..OP_16 are 0x52..0x60.
	if op < 0x52 || op > 0x60 {
		return false
	}
	pushLen := int(pkScript[1])
	return pushLen >= 2 && pushLen <= 40 && len(pkScript) == pushLen+2
}

// dereferencesEmptyWitness reports whether bip352.ExtractPubKey would index past
// the start of an empty witness for this vin.
//
// go-bip352 v0.1.8 reads vin.Witness[len(vin.Witness)-1] on the P2WPKH and
// P2SH-P2WPKH paths without checking the witness is non-empty, panicking with
// "index out of range [-1]". Its P2TR path guards, and its P2PKH path reads only
// the scriptSig, so those two are safe.
//
// A block and its prevouts arrive from a source §1.2 treats as hostile, so this
// is reachable input, not a theoretical case. Filtering is the honest fix rather
// than recover(): a witness-spending prevout with no witness yields no public
// key, which is precisely the Unknown the library would return if it checked.
func dereferencesEmptyWitness(v *bip352.Vin) bool {
	if len(v.Witness) > 0 {
		return false
	}
	spk := v.ScriptPubKey

	if len(spk) == 22 && spk[0] == 0x00 && spk[1] == 0x14 { // P2WPKH
		return true
	}

	// The P2SH path only reaches the witness after matching a P2SH-P2WPKH
	// scriptSig, so both shapes have to line up for the panic to be reachable.
	isP2SH := len(spk) == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87
	return isP2SH && len(v.ScriptSig) == 23 &&
		v.ScriptSig[0] == 0x16 && v.ScriptSig[1] == 0x00 && v.ScriptSig[2] == 0x14
}

// tweakForTx decides eligibility and, when eligible, derives the 33-byte tweak.
//
// eligible == false with err == nil means the transaction is legitimately
// outside T_base. A non-nil error means we could not decide — the caller must
// surface it rather than silently dropping the transaction, because a dropped
// transaction is indistinguishable from the attack this project detects.
func tweakForTx(tx *wire.MsgTx, pv PrevoutSource) (tweak [33]byte, eligible bool, err error) {
	if len(tx.TxIn) == 0 {
		return tweak, false, nil
	}
	// A coinbase spends a null outpoint and has no prevout to fetch.
	if len(tx.TxIn) == 1 && tx.TxIn[0].PreviousOutPoint.Index == 0xffffffff {
		return tweak, false, nil
	}

	// Rule 1: at least one BIP-341 taproot output.
	hasTaprootOut := false
	for _, out := range tx.TxOut {
		if isTaprootOutput(out.PkScript) {
			hasTaprootOut = true
			break
		}
	}
	if !hasTaprootOut {
		return tweak, false, nil
	}

	vins, err := vinsForTx(tx, pv)
	if err != nil {
		return tweak, false, err
	}

	// Rule 3: no input spending a SegWit v>1 output. This runs over every input,
	// before any filtering, because one such input excludes the transaction.
	for _, v := range vins {
		if isSegWitVersionAbove1(v.ScriptPubKey) {
			return tweak, false, nil
		}
	}

	safe := make([]*bip352.Vin, 0, len(vins))
	for _, v := range vins {
		if dereferencesEmptyWitness(v) {
			continue
		}
		safe = append(safe, v)
	}

	// Rule 2: at least one input from Inputs For Shared Secret Derivation.
	// v0.1.8's ExtractEligibleVins always returns a nil error, but the declared
	// signature allows one, so a future version's verdict is handled as a verdict.
	eligibleVins, err := bip352.ExtractEligibleVins(safe)
	if err != nil {
		if err == bip352.ErrNoEligibleVins || err == bip352.ErrVinsEmpty {
			return tweak, false, nil
		}
		return tweak, false, fmt.Errorf("extract eligible vins: %w", err)
	}
	if len(eligibleVins) == 0 {
		return tweak, false, nil
	}

	// Sum the input public keys. ExtractPubKey returns 33 bytes for
	// P2WPKH/P2PKH/P2SH and 32 x-only bytes for P2TR, and signals failure with
	// TypeUTXO == Unknown rather than an error (verified against v0.1.8).
	keys := make([][33]byte, 0, len(eligibleVins))
	for _, v := range eligibleVins {
		pk, typ := bip352.ExtractPubKey(v)
		if typ == bip352.Unknown || len(pk) == 0 {
			continue
		}
		if len(pk) == 32 {
			pk = append([]byte{0x02}, pk...) // lift x-only to even-Y compressed
		}
		if len(pk) != 33 {
			return tweak, false, fmt.Errorf("unexpected public key length %d", len(pk))
		}
		keys = append(keys, bip352.ConvertToFixedLength33(pk))
	}
	if len(keys) == 0 {
		return tweak, false, nil
	}

	// Rule 4a: A_sum must not be the point at infinity. SumPublicKeys errors
	// when the sum does not lie on the curve, which is that condition.
	sum, err := bip352.SumPublicKeys(keys)
	if err != nil {
		return tweak, false, nil
	}

	// Rule 4b: input_hash must be a valid scalar.
	inputHash, err := bip352.ComputeInputHash(eligibleVins, sum)
	if err != nil {
		return tweak, false, nil
	}

	// The served tweak is A_tweaked = input_hash · A_sum — the public component
	// a light client scans with (BIP-352 light-client scenario).
	t, err := bip352.TweakPubkey(sum, inputHash)
	if err != nil {
		return tweak, false, nil
	}
	return t, true, nil
}
