package canonical

import (
	"errors"

	btcec "github.com/btcsuite/btcd/btcec/v2"
)

// errPointAtInfinity is §2.2 rule 4a: A_sum is the point at infinity, so the
// transaction is outside T_base.
var errPointAtInfinity = errors.New("canonical: input public keys sum to the point at infinity")

// sumPublicKeys adds compressed public keys and returns A_sum.
//
// It replaces bip352.SumPublicKeys, which folds left through 33-byte
// serialisations and so fails whenever an INTERMEDIATE sum is the point at
// infinity, even when the final sum is a perfectly good point. BIP-352 ships a
// vector for exactly that shape — "Input keys intermediate sum is zero but
// final sum is non-zero" — because rule 4a is about the final sum alone.
//
// This matters past conformance. A running sum that passes through infinity is
// cheap to arrange: spend P and -P in the same transaction. A library that
// rejects it lets anyone mint a transaction that Canary scores differently from
// every honest indexer, which is a false accusation on demand, and a canary
// that cries wolf on request is worse than no canary. Accumulating in Jacobian
// coordinates represents infinity natively and never serialises a partial sum.
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
