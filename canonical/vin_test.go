package canonical

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// chainhash.Hash stores INTERNAL byte order; its String() reverses for display.
func TestTxidByteOrderConversions(t *testing.T) {
	var h chainhash.Hash
	for i := range h {
		h[i] = byte(i)
	}

	internal := txidInternal(h)
	if !bytes.Equal(internal[:], h[:]) {
		t.Errorf("txidInternal must be the raw hash bytes: got %x want %x", internal, h)
	}

	display := txidDisplay(h)
	want, err := hex.DecodeString(h.String())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(display[:], want) {
		t.Errorf("txidDisplay = %x, want %x (chainhash.String order)", display, want)
	}

	if internal == display {
		t.Error("a palindromic test vector proves nothing — pick asymmetric bytes")
	}
}

func TestDisplayIsTheReverseOfInternal(t *testing.T) {
	var h chainhash.Hash
	for i := range h {
		h[i] = byte(i * 7)
	}
	in, disp := txidInternal(h), txidDisplay(h)
	for i := 0; i < 32; i++ {
		if in[i] != disp[31-i] {
			t.Fatalf("byte %d: internal %02x, display[%d] %02x", i, in[i], 31-i, disp[31-i])
		}
	}
}
