package canonical

import (
	"errors"

	btcec "github.com/btcsuite/btcd/btcec/v2"
)

// errPointAtInfinity reports that A_sum is the point at infinity. The
// transaction is then outside the canonical set (eligibility rule 4a).
var errPointAtInfinity = errors.New("canonical: sum input public keys: point at infinity")

// sumPublicKeys adds compressed public keys and returns A_sum.
//
// It replaces bip352.SumPublicKeys. That function folds left through 33-byte
// serializations, so it fails whenever an intermediate sum is the point at
// infinity, even when the final sum is a valid point. BIP-352 ships a vector
// for that shape, "Input keys intermediate sum is zero but final sum is
// non-zero", because rule 4a is about the final sum alone.
//
// This matters beyond conformance. A running sum through infinity is cheap to
// arrange: spend P and -P in the same transaction. A library that rejects it
// lets anyone build a transaction that Canary scores differently from every
// honest server. That is a false accusation on demand. Accumulating in
// Jacobian coordinates represents infinity natively and never serializes a
// partial sum.
func sumPublicKeys(keys [][33]byte) ([33]byte, error) {
	var acc btcec.JacobianPoint // the zero value is the point at infinity

	for _, k := range keys {
		pub, err := btcec.ParsePubKey(k[:])
		if err != nil {
			return [33]byte{}, err
		}
		var p, res btcec.JacobianPoint
		pub.AsJacobian(&p)
		btcec.AddNonConst(&acc, &p, &res)
		acc = res
	}

	if acc.Z.IsZero() {
		return [33]byte{}, errPointAtInfinity
	}
	acc.ToAffine()

	var out [33]byte
	copy(out[:], btcec.NewPublicKey(&acc.X, &acc.Y).SerializeCompressed())
	return out, nil
}
