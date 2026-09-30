// Package wire encodes and decodes the list of entries an indexer serves for
// one block.
//
// The list follows the block's canonical order: every eligible transaction, in
// the order the block holds them. Each position carries one of three things.
// It can carry the full entry (the txid and its tweak), only that entry's
// 32-byte hash, or nothing. The encoding states the length and each position's
// kind, so the client never has to guess.
//
// The indexer encodes this format and the client decodes it. It lives in the
// protocol core, not in either program, because Go does not let one module
// import another module's internal packages.
package wire

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/Sky-walkerX/canary/canonical"
)

// PositionKind says what one position in a response carries.
type PositionKind byte

// The zero value is not a kind. EncodeResponse rejects a Position whose kind
// was never set.
const (
	// KindFull carries the whole 65-byte entry: the 32-byte txid, then the
	// 33-byte tweak.
	KindFull PositionKind = 1

	// KindHash carries only the entry's 32-byte hash, as commit.LeafHash
	// computes it. A server sends this when it no longer stores the full
	// entry but kept its hash. The client can still recompute the block's
	// root from this server's response alone. It gets no tweak for this
	// position, though, so it cannot scan that transaction. A matching root
	// shows that the list agrees with the server's signed record. It does not
	// show that the client received every tweak.
	KindHash PositionKind = 2

	// KindAbsent carries nothing. A server may send it only for a block
	// outside the 144-block retention window, where
	// depth = tip_height - block_height and depth >= 144. The tip height comes
	// from the server's signed receipt, and the block height from its signed
	// record. Inside the window the server must keep at least the hash, so an
	// absent entry there counts as withholding. The decoder cannot see a
	// block's depth, so the caller must enforce this rule. Section 4 of the v1
	// formats doc defines the window. The client cannot recompute the root
	// until it recovers the entry from another source.
	KindAbsent PositionKind = 3
)

// Field sizes in bytes. A record's 1-byte kind tag comes before leafSize or
// hashSize and is not counted in them.
const (
	prefixSize = 4       // n, little-endian uint32
	leafSize   = 32 + 33 // txid, then tweak
	hashSize   = 32
)

// Position is one entry of a response. Kind decides which field holds data:
// Leaf for KindFull, Hash for KindHash, neither for KindAbsent. The encoder
// ignores the other field, and the decoder leaves it zero.
//
// Leaf.TxID is in internal byte order, the order a serialized block holds it.
// Block explorers print the reverse. The encoding carries the bytes unchanged.
type Position struct {
	Kind PositionKind
	Leaf canonical.Leaf
	Hash [32]byte
}

// EncodeResponse writes positions as a self-describing list: a 4-byte
// little-endian count n, then n records. Each record is a 1-byte kind followed
// by 65 bytes (KindFull), 32 bytes (KindHash) or nothing (KindAbsent).
//
// The count and the per-record kind are what let a client detect truncation.
// Without them a shorter response looks exactly like a smaller block, and a
// client talking to one server has nothing else to compare against.
//
// An empty block encodes as n = 0, four zero bytes. The server still sends it.
func EncodeResponse(positions []Position) ([]byte, error) {
	if uint64(len(positions)) > math.MaxUint32 {
		return nil, fmt.Errorf("wire: too many positions: %d exceeds the 4-byte count", len(positions))
	}

	out := make([]byte, prefixSize, prefixSize+len(positions)*(1+leafSize))
	binary.LittleEndian.PutUint32(out[0:prefixSize], uint32(len(positions)))

	for i, p := range positions {
		switch p.Kind {
		case KindFull:
			out = append(out, byte(KindFull))
			out = append(out, p.Leaf.TxID[:]...)
			out = append(out, p.Leaf.Tweak[:]...)
		case KindHash:
			out = append(out, byte(KindHash))
			out = append(out, p.Hash[:]...)
		case KindAbsent:
			out = append(out, byte(KindAbsent))
		default:
			return nil, fmt.Errorf("wire: unknown position kind: position %d has kind %d", i, p.Kind)
		}
	}
	return out, nil
}

// DecodeResponse reads a list written by EncodeResponse. It fails on a
// truncated list, an unknown kind, or bytes left over after the last record.
// It never skips a record it does not understand.
//
// Each 1-byte absent record becomes a full Position in memory, about 98 bytes.
// A caller reading from the network should cap the response size first.
func DecodeResponse(buf []byte) ([]Position, error) {
	if len(buf) < prefixSize {
		return nil, fmt.Errorf("wire: response too short: %d bytes, the count alone needs %d", len(buf), prefixSize)
	}
	n := binary.LittleEndian.Uint32(buf[0:prefixSize])

	// The smallest record is one tag byte, so n cannot exceed the bytes that
	// follow. Checking this before allocating stops a 4-byte response from
	// claiming a million positions.
	if uint64(n) > uint64(len(buf)-prefixSize) {
		return nil, fmt.Errorf("wire: declared count too large: n=%d but only %d bytes follow", n, len(buf)-prefixSize)
	}

	off := prefixSize
	positions := make([]Position, 0, n)
	for i := uint32(0); i < n; i++ {
		if off >= len(buf) {
			return nil, fmt.Errorf("wire: truncated response: position %d of %d is missing", i, n)
		}
		kind := PositionKind(buf[off])
		off++

		switch kind {
		case KindFull:
			if len(buf)-off < leafSize {
				return nil, fmt.Errorf("wire: truncated entry: position %d needs %d bytes, %d remain", i, leafSize, len(buf)-off)
			}
			p := Position{Kind: KindFull}
			copy(p.Leaf.TxID[:], buf[off:off+32])
			copy(p.Leaf.Tweak[:], buf[off+32:off+leafSize])
			off += leafSize
			positions = append(positions, p)
		case KindHash:
			if len(buf)-off < hashSize {
				return nil, fmt.Errorf("wire: truncated hash: position %d needs %d bytes, %d remain", i, hashSize, len(buf)-off)
			}
			p := Position{Kind: KindHash}
			copy(p.Hash[:], buf[off:off+hashSize])
			off += hashSize
			positions = append(positions, p)
		case KindAbsent:
			positions = append(positions, Position{Kind: KindAbsent})
		default:
			return nil, fmt.Errorf("wire: unknown position kind: position %d has kind %d", i, kind)
		}
	}

	// One list has one encoding. Leftover bytes would let two different byte
	// strings decode to the same positions, and a signature over the served
	// bytes has to pin down exactly what the client read.
	if off != len(buf) {
		return nil, fmt.Errorf("wire: trailing bytes: %d bytes after the last of %d positions", len(buf)-off, n)
	}
	return positions, nil
}
