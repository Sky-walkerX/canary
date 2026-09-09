package commit

import "github.com/Sky-walkerX/canary/canonical"

// levels builds the tree bottom-up and returns every level, level 0 being the
// leaf hashes. Prove walks this. An empty set has no levels at all.
//
// Unpaired nodes are PROMOTED to the next level untouched, never duplicated.
// Duplication is CVE-2012-2459 (§3.2).
func levels(leaves []canonical.Leaf) [][][32]byte {
	if len(leaves) == 0 {
		return nil
	}

	cur := make([][32]byte, len(leaves))
	for i, l := range leaves {
		cur[i] = LeafHash(l)
	}

	out := [][][32]byte{cur}
	for len(cur) > 1 {
		next := make([][32]byte, 0, (len(cur)+1)/2)
		for i := 0; i+1 < len(cur); i += 2 {
			next = append(next, nodeHash(cur[i], cur[i+1]))
		}
		if len(cur)%2 == 1 {
			next = append(next, cur[len(cur)-1]) // promotion
		}
		out = append(out, next)
		cur = next
	}
	return out
}

// merkleRoot is the inner root, before §3.2's outer tagged hash.
//
// The empty set is 32 zero bytes. That is safe rather than sloppy because the
// outer preimage binds n, so an n=0 root cannot collide with any n≥1 root for
// the same block — and it avoids inventing a fourth tag (§3.2).
func merkleRoot(leaves []canonical.Leaf) [32]byte {
	ls := levels(leaves)
	if len(ls) == 0 {
		return [32]byte{}
	}
	top := ls[len(ls)-1]
	return top[0]
}

// merkleRootFromHashes is merkleRoot starting from leaf hashes. Same promotion
// rule, same empty-set convention.
func merkleRootFromHashes(cur [][32]byte) [32]byte {
	if len(cur) == 0 {
		return [32]byte{}
	}
	level := make([][32]byte, len(cur))
	copy(level, cur)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i+1 < len(level); i += 2 {
			next = append(next, nodeHash(level[i], level[i+1]))
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1]) // promotion
		}
		level = next
	}
	return level[0]
}
