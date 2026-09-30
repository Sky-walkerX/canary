package wire

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
)

func TestEncodeIsSelfDescribingAtLengthN(t *testing.T) {
	var leaf canonical.Leaf
	leaf.TxID[0] = 0x11
	leaf.Tweak[0] = 0x02

	var hash [32]byte
	hash[0] = 0x22

	positions := []Position{
		{Kind: KindFull, Leaf: leaf},
		{Kind: KindAbsent},
		{Kind: KindHash, Hash: hash},
	}

	out, err := EncodeResponse(positions)
	if err != nil {
		t.Fatal(err)
	}

	if n := binary.LittleEndian.Uint32(out[0:4]); n != 3 {
		t.Errorf("declared n = %d, want 3", n)
	}
	// 4 + (1+65) + (1) + (1+32) = 104 bytes.
	if len(out) != 104 {
		t.Fatalf("encoded length = %d, want 104", len(out))
	}
	if out[4] != byte(KindFull) || out[4+66] != byte(KindAbsent) || out[4+66+1] != byte(KindHash) {
		t.Error("position tags are wrong: the client must read each kind, never infer it")
	}
	if !bytes.Equal(out[5:37], leaf.TxID[:]) || !bytes.Equal(out[37:70], leaf.Tweak[:]) {
		t.Error("the full leaf is not txid then tweak, 32 + 33 bytes")
	}
	if !bytes.Equal(out[72:104], hash[:]) {
		t.Error("the hash record does not carry the 32-byte leaf hash")
	}
}

// The txid travels in internal byte order, exactly as canonical.Leaf holds it.
// Reversing it into display order here would change every leaf hash the
// client recomputes, so no root would ever match.
func TestEncodeKeepsTxIDInInternalByteOrder(t *testing.T) {
	var leaf canonical.Leaf
	for i := range leaf.TxID {
		leaf.TxID[i] = byte(i)
	}
	out, err := EncodeResponse([]Position{{Kind: KindFull, Leaf: leaf}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out[5:37], leaf.TxID[:]) {
		t.Errorf("txid bytes = %x, want %x unreversed", out[5:37], leaf.TxID[:])
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	var leaf canonical.Leaf
	for i := range leaf.TxID {
		leaf.TxID[i] = byte(i)
	}
	leaf.Tweak[0] = 0x03

	var hash [32]byte
	for i := range hash {
		hash[i] = byte(0xff - i)
	}

	in := []Position{
		{Kind: KindFull, Leaf: leaf},
		{Kind: KindAbsent},
		{Kind: KindHash, Hash: hash},
		{Kind: KindFull, Leaf: leaf},
	}
	out, err := EncodeResponse(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeResponse(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(in) {
		t.Fatalf("decoded %d positions, want %d", len(got), len(in))
	}
	for i := range in {
		if got[i] != in[i] {
			t.Errorf("position %d: got %+v, want %+v", i, got[i], in[i])
		}
	}
}

// A block with no eligible transactions still gets a response, and that
// response says n = 0. Treating it as "nothing to send" would make an empty
// block look the same as a server that sent nothing.
func TestEmptyBlockEncodesAsNZero(t *testing.T) {
	out, err := EncodeResponse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte{0, 0, 0, 0}) {
		t.Fatalf("empty response = %x, want 00000000", out)
	}
	got, err := DecodeResponse(out)
	if err != nil {
		t.Fatalf("an empty block must decode, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("decoded %d positions from an empty block", len(got))
	}
}

func TestEncodeRejectsUnknownKind(t *testing.T) {
	// The zero Position has kind 0. Rejecting it means a caller that forgot to
	// set a kind gets an error, not a silently well-formed response.
	for _, k := range []PositionKind{0, 4, 0x7f} {
		if _, err := EncodeResponse([]Position{{Kind: k}}); err == nil {
			t.Errorf("kind %d must fail to encode", k)
		}
	}
}

func TestDecodeRejectsTruncation(t *testing.T) {
	var leaf canonical.Leaf
	out, err := EncodeResponse([]Position{{Kind: KindFull, Leaf: leaf}, {Kind: KindFull, Leaf: leaf}})
	if err != nil {
		t.Fatal(err)
	}
	// The declared n catches truncation, not trailing-byte luck. A shorter
	// response that decoded cleanly would look exactly like a smaller block.
	if _, err := DecodeResponse(out[:len(out)-10]); err == nil {
		t.Error("a truncated response must fail to decode")
	}
}

func TestDecodeRejectsEveryProperPrefix(t *testing.T) {
	var leaf canonical.Leaf
	leaf.Tweak[0] = 0x02
	var hash [32]byte
	hash[31] = 0x01
	out, err := EncodeResponse([]Position{
		{Kind: KindHash, Hash: hash},
		{Kind: KindFull, Leaf: leaf},
		{Kind: KindAbsent},
	})
	if err != nil {
		t.Fatal(err)
	}
	for k := 0; k < len(out); k++ {
		if _, err := DecodeResponse(out[:k]); err == nil {
			t.Errorf("prefix of %d of %d bytes decoded without error", k, len(out))
		}
	}
}

// One position list has exactly one encoding. Extra bytes after the last
// record would let two different byte strings decode to the same response,
// and a signature over the served bytes must pin down what the client read.
func TestDecodeRejectsTrailingBytes(t *testing.T) {
	out, err := EncodeResponse([]Position{{Kind: KindAbsent}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(append(out, 0x00)); err == nil {
		t.Error("bytes after the last declared position must fail to decode")
	}
}

func TestDecodeRejectsUnknownKind(t *testing.T) {
	buf := make([]byte, 5)
	binary.LittleEndian.PutUint32(buf[0:4], 1)
	buf[4] = 0x7f
	if _, err := DecodeResponse(buf); err == nil {
		t.Error("an unknown position kind must fail rather than be skipped")
	}
}

// A 4-byte response that claims a million positions must fail before the
// decoder allocates anything for them. Without the size check, the decoder
// reserves about 98 MB and only then finds the body missing. It still returns
// an error, so the error alone cannot show the check ran first. The test
// therefore measures the allocation.
//
// It declares a million rather than the uint32 maximum on purpose. Without the
// check, the maximum reserves some 420 GB. macOS grants that, and under the
// race detector the process was then sometimes killed for memory after about
// 15 seconds. A million fails at once, every time, with a clear message.
func TestDecodeRejectsAnOverlongDeclaredN(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf[0:4], 1_000_000)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := DecodeResponse(buf)
	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatal("a declared n with no body must fail to decode")
	}
	// The checked path allocates only the error, a few hundred bytes. The
	// limit leaves room for background noise. An unchecked decoder allocates
	// 98 bytes for every declared position, far past it.
	const limit = 64 << 10
	if got := after.TotalAlloc - before.TotalAlloc; got > limit {
		t.Errorf("decoding a 4-byte response allocated %d bytes, want at most %d: the size check must run before the allocation", got, limit)
	}
}
