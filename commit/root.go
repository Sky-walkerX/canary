package commit

import (
	"encoding/binary"

	"github.com/Sky-walkerX/canary/canonical"
	bip352 "github.com/setavenger/go-bip352"
)

// rootFromInner builds §3.2's outer preimage and hashes it:
//
//	network ‖ block_hash ‖ n_le32 ‖ merkle_root      (4 + 32 + 4 + 32 = 72 bytes)
//
// every field fixed-width, so no length prefixes are needed. Binding network,
// block hash and n means a root cannot be replayed onto another block or
// reused with a different length (§3.2).
//
// Root and RootFromLeafHashes both go through here. The agreement test would
// catch the two drifting apart; sharing the construction means they cannot.
func rootFromInner(net canonical.Network, blockHash [32]byte, n int, inner [32]byte) [32]byte {
	buf := make([]byte, 0, 72)

	// The 4-byte P2P message-start magic, in the order it appears in a message
	// header — the little-endian encoding of wire.BitcoinNet (§3.2).
	var netBuf [4]byte
	binary.LittleEndian.PutUint32(netBuf[:], uint32(net))
	buf = append(buf, netBuf[:]...)

	buf = append(buf, blockHash[:]...) // INTERNAL byte order

	var nBuf [4]byte
	binary.LittleEndian.PutUint32(nBuf[:], uint32(n))
	buf = append(buf, nBuf[:]...)

	buf = append(buf, inner[:]...)

	return bip352.TaggedHash(tagRoot, buf)
}

// Root computes the commitment root over a block's canonical leaves. §3.2.
func Root(net canonical.Network, blockHash [32]byte, leaves []canonical.Leaf) [32]byte {
	return rootFromInner(net, blockHash, len(leaves), merkleRoot(leaves))
}

// RootFromLeafHashes is Root for a caller holding leaf hashes rather than
// leaves. §2.5's comparison needs it: a gap filled from a retained hash is
// verifiable without ever recovering the leaf.
func RootFromLeafHashes(net canonical.Network, blockHash [32]byte, leafHashes [][32]byte) [32]byte {
	return rootFromInner(net, blockHash, len(leafHashes), merkleRootFromHashes(leafHashes))
}
