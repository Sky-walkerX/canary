package core

import (
	"encoding/hex"
	"fmt"
)

// Txids and block hashes have two byte orders. Internal order is how the
// bytes sit in a serialized transaction or block header. Display order
// reverses them, as bitcoin-cli, block explorers and Core's REST paths print
// them. Canary's URLs, JSON and Nostr tags also use display order, while its
// binary formats and hash preimages use internal order.
//
// These two functions are the one place Canary's programs convert between
// the orders: the reference indexer, canary check and the evidence package
// all call them. Everything else holds hashes in internal order.

// ParseDisplayHash reads a hash written in display order and returns its
// bytes in internal order. It accepts exactly 64 lowercase hex characters, so
// every hash has one spelling.
func ParseDisplayHash(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) != 64 {
		return out, fmt.Errorf("core: parse hash: %d characters, want 64", len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return out, fmt.Errorf("core: parse hash: character %d is %q, want lowercase hex", i, c)
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("core: parse hash: %w", err)
	}
	for i := 0; i < 32; i++ {
		out[i] = b[31-i]
	}
	return out, nil
}

// DisplayHex returns h, held in internal order, as 64 lowercase hex
// characters in display order.
func DisplayHex(h [32]byte) string {
	var rev [32]byte
	for i := 0; i < 32; i++ {
		rev[i] = h[31-i]
	}
	return hex.EncodeToString(rev[:])
}
