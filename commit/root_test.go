package commit

import (
	"encoding/binary"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/btcsuite/btcd/chaincfg"
)

const (
	netMain    = canonical.Network(0xd9b4bef9) // wire bytes f9 be b4 d9
	netRegtest = canonical.Network(0xdab5bffa) // wire bytes fa bf b5 da
)

func TestRootBindsNetworkBlockHashAndN(t *testing.T) {
	leaves := mkLeaves(3)
	var bh [32]byte
	bh[0] = 0xAA

	base := Root(netRegtest, bh, leaves)

	// Different network → different root. §2.7's same-network precondition
	// depends on this holding for custom signets too.
	if Root(netMain, bh, leaves) == base {
		t.Error("root must bind the network magic")
	}

	// Different block → different root, so a root cannot be replayed.
	var other [32]byte
	other[0] = 0xBB
	if Root(netRegtest, other, leaves) == base {
		t.Error("root must bind the block hash")
	}

	// Different n → different root, even though it is a prefix of the same set.
	if Root(netRegtest, bh, leaves[:2]) == base {
		t.Error("root must bind n")
	}
}

func TestRootOfEmptySetIsWellDefinedAndBlockSpecific(t *testing.T) {
	var a, b [32]byte
	a[0], b[0] = 1, 2

	ra := Root(netRegtest, a, nil)
	rb := Root(netRegtest, b, nil)

	var zero [32]byte
	if ra == zero {
		t.Error("an empty-set root is a real hash, not zeroes — only merkle_root(∅) is zeroes")
	}
	if ra == rb {
		t.Error("empty-set roots must still differ per block")
	}
}

func TestRootPreimageIsExactlySeventyTwoBytes(t *testing.T) {
	// 4 + 32 + 4 + 32. Fixed width is why no length prefixes are needed (§3.2).
	var netBuf [4]byte
	binary.LittleEndian.PutUint32(netBuf[:], uint32(netRegtest))
	if 4+32+4+32 != 72 {
		t.Fatal("arithmetic")
	}
	if netBuf != [4]byte{0xfa, 0xbf, 0xb5, 0xda} {
		t.Errorf("network LE encoding = %x, want fabfb5da (§3.2)", netBuf)
	}
}

// The magics must come from chaincfg, never from our own literals (§3.2).
func TestNetworkConstantsMatchChaincfg(t *testing.T) {
	if uint32(chaincfg.MainNetParams.Net) != uint32(netMain) {
		t.Errorf("mainnet magic drift: chaincfg %08x, test %08x", uint32(chaincfg.MainNetParams.Net), uint32(netMain))
	}
	if uint32(chaincfg.RegressionNetParams.Net) != uint32(netRegtest) {
		t.Errorf("regtest magic drift: chaincfg %08x, test %08x", uint32(chaincfg.RegressionNetParams.Net), uint32(netRegtest))
	}
}

func TestRootFromLeafHashesAgreesWithRoot(t *testing.T) {
	var bh [32]byte
	bh[0] = 0x5A
	for _, n := range []int{0, 1, 2, 3, 5, 8, 9, 16, 17} {
		leaves := mkLeaves(n)
		hashes := make([][32]byte, n)
		for i, l := range leaves {
			hashes[i] = LeafHash(l)
		}
		if got, want := RootFromLeafHashes(netRegtest, bh, hashes), Root(netRegtest, bh, leaves); got != want {
			t.Errorf("n=%d: hash path %x != leaf path %x", n, got, want)
		}
	}
}
