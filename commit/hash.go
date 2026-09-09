package commit

import (
	"github.com/Sky-walkerX/canary/canonical"
	bip352 "github.com/setavenger/go-bip352"
)

// Tag strings are fixed by §3.2. Changing one is a protocol fork.
const (
	tagLeaf = "canary/leaf/v1"
	tagNode = "canary/node/v1"
	tagRoot = "canary/root/v1"
)

// LeafHash hashes one canonical leaf. The preimage is txid ‖ tweak, 32+33
// bytes, with the txid in INTERNAL byte order (§3.2). Exported because gap
// resolution hashes candidate leaves recovered from other servers (§2.5).
func LeafHash(l canonical.Leaf) [32]byte {
	buf := make([]byte, 0, 65)
	buf = append(buf, l.TxID[:]...)
	buf = append(buf, l.Tweak[:]...)
	return bip352.TaggedHash(tagLeaf, buf)
}

// nodeHash hashes an internal node. A distinct tag from the leaf domain is
// what makes second-preimage substitution impossible (§3.2).
func nodeHash(left, right [32]byte) [32]byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, left[:]...)
	buf = append(buf, right[:]...)
	return bip352.TaggedHash(tagNode, buf)
}
