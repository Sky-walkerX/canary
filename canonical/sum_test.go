package canonical

import (
	"encoding/hex"
	"errors"
	"testing"
)

// Flipping the compressed prefix between 0x02 and 0x03 selects the other Y root,
// which is the negation of the point. So P and negP below are P and -P.
const (
	genX = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	pHex = "02" + genX
	nHex = "03" + genX
)

func key(t *testing.T, s string) [33]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	var out [33]byte
	copy(out[:], b)
	return out
}

func TestSumPublicKeysRejectsPointAtInfinity(t *testing.T) {
	_, err := sumPublicKeys([][33]byte{key(t, pHex), key(t, nHex)})
	if !errors.Is(err, errPointAtInfinity) {
		t.Errorf("P + (-P) must report the point at infinity (eligibility rule 4a), got %v", err)
	}
}

// The case bip352.SumPublicKeys gets wrong: the running sum is infinity after
// two terms, but the final sum is P and the transaction is eligible.
func TestSumPublicKeysSurvivesIntermediateInfinity(t *testing.T) {
	p := key(t, pHex)
	got, err := sumPublicKeys([][33]byte{p, key(t, nHex), p})
	if err != nil {
		t.Fatalf("an intermediate infinity is not a failure: %v", err)
	}
	if got != p {
		t.Errorf("P + (-P) + P = %x, want %x", got, p)
	}
}

func TestSumPublicKeysSingleAndEmpty(t *testing.T) {
	p := key(t, pHex)
	got, err := sumPublicKeys([][33]byte{p})
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Errorf("sum of one key = %x, want %x", got, p)
	}

	// No keys is the identity, which is infinity: rule 4a, not a crash.
	if _, err := sumPublicKeys(nil); !errors.Is(err, errPointAtInfinity) {
		t.Errorf("the empty sum is the point at infinity, got %v", err)
	}
}

func TestSumPublicKeysRejectsGarbage(t *testing.T) {
	var bad [33]byte
	bad[0] = 0x02 // valid prefix, X not on the curve
	if _, err := sumPublicKeys([][33]byte{bad}); err == nil {
		t.Error("a key that is not a curve point must be an error, not a silent skip")
	}
}
