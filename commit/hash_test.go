package commit

import (
	"crypto/sha256"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
)

// bip340 recomputes the tagged hash from first principles so the test does not
// simply agree with whatever our implementation does.
func bip340(tag string, msg []byte) [32]byte {
	t := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(t[:])
	h.Write(t[:])
	h.Write(msg)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func TestLeafHashMatchesTaggedPreimage(t *testing.T) {
	var l canonical.Leaf
	for i := range l.TxID {
		l.TxID[i] = byte(i)
	}
	for i := range l.Tweak {
		l.Tweak[i] = byte(0x40 + i)
	}

	preimage := append(append([]byte{}, l.TxID[:]...), l.Tweak[:]...)
	if len(preimage) != 65 {
		t.Fatalf("preimage must be 32+33=65 bytes, got %d", len(preimage))
	}
	want := bip340("canary/leaf/v1", preimage)

	if got := LeafHash(l); got != want {
		t.Errorf("LeafHash = %x, want %x", got, want)
	}
}

func TestNodeHashIsOrderSensitive(t *testing.T) {
	a := [32]byte{1}
	b := [32]byte{2}
	if nodeHash(a, b) == nodeHash(b, a) {
		t.Error("nodeHash must not be commutative — order carries position")
	}
}

func TestLeafAndNodeTagsAreDistinct(t *testing.T) {
	// A 65-byte node preimage is impossible, but the point is that the two
	// domains never collide even if an attacker contrives equal inputs.
	var l canonical.Leaf
	lh := LeafHash(l)
	var zero [32]byte
	if lh == nodeHash(zero, zero) {
		t.Error("leaf and node domains collide")
	}
}
