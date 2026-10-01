package canonical

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	bip352 "github.com/setavenger/go-bip352"
)

// isTaprootOutput reports whether pkScript is a BIP-341 v1 witness program:
// OP_1 <32 bytes>. Eligibility rule 1 uses it without BIP-352's optional
// "unspent" clause. That clause is cut-through, a server policy, and the
// canonical set leaves every policy out.
func isTaprootOutput(pkScript []byte) bool {
	return len(pkScript) == 34 && pkScript[0] == 0x51 && pkScript[1] == 0x20
}

// isSegWitVersionAbove1 reports whether pkScript is a witness program of
// version 2 to 16. Spending one excludes the whole transaction (eligibility
// rule 3).
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
// P2SH-P2WPKH paths without checking that the witness is non-empty, and panics
// with "index out of range [-1]". Its P2TR path checks, and its P2PKH path
// reads only the scriptSig, so those two are safe.
//
// A block and its spent outputs can come from a hostile source, so this input
// is reachable. Filtering is the honest fix, not recover(). A witness spend
// with no witness yields no public key, which is the Unknown the library would
// return if it checked.
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
// outside the canonical set. A non-nil error means tweakForTx could not
// decide. The caller must return that error and never drop the transaction
// silently, because a dropped transaction looks exactly like the withholding
// Canary detects.
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

	// Rule 3: no input spends a SegWit v>1 output. This runs over every input,
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

	// Sum the input public keys. ExtractPubKey returns 33 bytes for P2WPKH,
	// P2PKH and P2SH, and 32 x-only bytes for P2TR. It signals failure with
	// TypeUTXO == Unknown, not an error (checked by running v0.1.8).
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

	// Rule 4a: A_sum must not be the point at infinity.
	sum, err := sumPublicKeys(keys)
	if errors.Is(err, errPointAtInfinity) {
		return tweak, false, nil // a verdict, not a failure
	}
	if err != nil {
		return tweak, false, fmt.Errorf("sum input public keys: %w", err)
	}

	// Rule 4b: input_hash must be a valid scalar. outpoint_L is the smallest
	// outpoint "used in the transaction" (BIP-352), so this takes every input,
	// not only the ones that contribute a key. Passing only the eligible vins
	// silently changes the tweak of any transaction with mixed inputs, and two
	// upstream vectors catch exactly that.
	inputHash, err := bip352.ComputeInputHash(vins, sum)
	if err != nil {
		return tweak, false, nil
	}

	// The served tweak is input_hash · A_sum, the public value a light client
	// scans with (BIP-352's light-client scenario).
	t, err := bip352.TweakPubkey(sum, inputHash)
	if err != nil {
		return tweak, false, nil
	}
	return t, true, nil
}
