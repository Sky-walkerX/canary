package ladder

import (
	"bytes"
	"sort"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/wire"
)

// maxTrials caps how many vectors Canary recomputes while searching for one
// server's absent entries before a proven root is known. Past it, the
// positions stay unfilled unless another list proves the root.
const maxTrials = 256

// group is every server that signed the same record and served a list that
// matches it position by position. Only a server with the same root is a
// source for another's gaps.
type group struct {
	block    Block
	root     [32]byte
	n        int
	members  []*eval
	payments []Payment

	cands map[int][]candidate

	// ref is the leaf-hash vector the signed root commits to. It stays nil
	// until one member's recomputed root matches. The root binds every
	// position, so ref is the only vector that can match.
	ref [][32]byte

	// proofs holds each position's proof into the signed root, built from
	// ref the first time a gap needs it.
	proofs map[int]commit.Proof
}

// candidate is one entry offered for a position.
type candidate struct {
	leaf canonical.Leaf
	hash [32]byte
	// fromServer is true when some server's list carries this entry in
	// full at the position. Otherwise it came from a declared payment.
	fromServer bool
}

type recordKey struct {
	root [32]byte
	n    uint32
}

// groupByRecord sorts the servers that reached step 5 by the record they
// signed.
func groupByRecord(b Block, evals []*eval) []*group {
	var out []*group
	byKey := map[recordKey]*group{}
	for _, e := range evals {
		if e.stopped {
			continue
		}
		c := e.res.Record.Commitment
		k := recordKey{c.Root, c.N}
		g := byKey[k]
		if g == nil {
			g = &group{
				block: b, root: c.Root, n: int(c.N), payments: b.Payments,
				cands: map[int][]candidate{}, proofs: map[int]commit.Proof{},
			}
			byKey[k] = g
			out = append(out, g)
		}
		g.members = append(g.members, e)
	}
	return out
}

// own returns the member's vector as served, with zero hashes at its absent
// positions, and those positions.
func own(e *eval) ([][32]byte, []int) {
	vec := make([][32]byte, len(e.positions))
	var absent []int
	for i, p := range e.positions {
		switch p.Kind {
		case wire.KindFull:
			vec[i] = commit.LeafHash(p.Leaf)
		case wire.KindHash:
			vec[i] = p.Hash
		case wire.KindAbsent:
			absent = append(absent, i)
		}
	}
	return vec, absent
}

// candidatesAt returns every distinct entry offered for position i, sorted by
// hash. Other members' full entries come first in meaning, then every
// declared payment, because a payment's position is not known in advance.
func (g *group) candidatesAt(i int) []candidate {
	if c, ok := g.cands[i]; ok {
		return c
	}
	byHash := map[[32]byte]*candidate{}
	for _, m := range g.members {
		p := m.positions[i]
		if p.Kind != wire.KindFull {
			continue
		}
		h := commit.LeafHash(p.Leaf)
		if c, ok := byHash[h]; ok {
			c.fromServer = true
			continue
		}
		byHash[h] = &candidate{leaf: p.Leaf, hash: h, fromServer: true}
	}
	for _, p := range g.payments {
		h := commit.LeafHash(p.Entry)
		if _, ok := byHash[h]; !ok {
			byHash[h] = &candidate{leaf: p.Entry, hash: h}
		}
	}
	out := make([]candidate, 0, len(byHash))
	for _, c := range byHash {
		out = append(out, *c)
	}
	sort.Slice(out, func(a, b int) bool { return bytes.Compare(out[a].hash[:], out[b].hash[:]) < 0 })
	g.cands[i] = out
	return out
}

// find returns the candidate at position i whose hash is h.
func (g *group) find(i int, h [32]byte) *candidate {
	for _, c := range g.candidatesAt(i) {
		if c.hash == h {
			return &c
		}
	}
	return nil
}

func (g *group) recompute(vec [][32]byte) bool {
	return commit.RootFromLeafHashes(g.block.Core.Network, g.block.Hash, vec) == g.root
}

// fill runs steps 6 and 7 for the group. It fills every member's gaps, then
// recomputes each member's root over all n positions.
//
// A candidate is never trusted. Either the whole vector recomputes to the
// signed root, which proves every entry in it, or the candidate is checked
// against a vector some member already proved. A member is named for a root
// that differs only when its own data is the difference: every other value
// in its vector was proven. So a server serving a forged entry can never get
// an honest one accused.
//
// The result does not depend on the order of the members. Only one vector
// can match the root, and every member sees the same candidates.
func (g *group) fill() {
	settled := make([]bool, len(g.members))

	// Lists with nothing to fill go first. Their roots rest on the server's
	// own data alone, so a difference is the server's. One that matches
	// proves the root and spares every other member a search.
	for k, m := range g.members {
		vec, absent := own(m)
		if len(absent) > 0 {
			continue
		}
		m.recomputed, m.vector = true, vec
		m.matched = g.recompute(vec)
		settled[k] = true
		if m.matched && g.ref == nil {
			g.ref = vec
		}
	}

	for changed := true; changed; {
		changed = false
		for k, m := range g.members {
			if settled[k] {
				continue
			}
			vec, absent := own(m)
			if g.ref != nil {
				g.settleAgainstRef(m, vec, absent)
				settled[k] = true
				continue
			}
			if g.trial(m, vec, absent) {
				m.recomputed, m.matched, m.vector = true, true, vec
				settled[k] = true
				g.ref, changed = vec, true
			}
		}
	}
	for _, m := range g.members {
		g.describeGaps(m)
	}
}

// settleAgainstRef recomputes the member's root once another list proved it.
// Each absent position takes the proven hash, and the root is recomputed over
// all n positions.
//
// A root that still differs names the member, because its own data is the
// only value not proven. A root that matches passes only when a candidate
// supplied every absent entry. A proven hash says where an entry sits, not
// what it is, so a position no entry filled leaves the root uncomputed.
func (g *group) settleAgainstRef(m *eval, vec [][32]byte, absent []int) {
	filled := true
	for _, i := range absent {
		vec[i] = g.ref[i]
		if g.find(i, g.ref[i]) == nil {
			filled = false
		}
	}
	if !g.recompute(vec) {
		m.recomputed, m.vector = true, vec
		return
	}
	if filled {
		m.recomputed, m.matched, m.vector = true, true, vec
	}
}

// trial searches for the entries that belong at m's absent positions and
// keeps the vector whose root matches. vec is filled in place. It recomputes
// at most maxTrials vectors in all.
//
// It first tries each other member as the main source: where that member
// carries an absent position in full, only its entry is tried there. So a
// co-signer that offers a forged entry at every gap cannot hide a complete
// honest answer behind the cap. The search over every candidate comes last.
// Smaller searches go first, and ties go by label, so the order of the
// members never matters.
//
// A failed trial accuses nobody, because the candidates were never proven.
// A co-signer can still push a search past the cap where no single member
// carries enough of the gaps. The positions then stay unfilled, and the
// server reads Can't be checked: never a pass, and never an accusation.
func (g *group) trial(m *eval, vec [][32]byte, absent []int) bool {
	all := make([][]candidate, len(absent))
	for k, i := range absent {
		all[k] = g.candidatesAt(i)
		if len(all[k]) == 0 {
			return false
		}
	}

	type attempt struct {
		label   string
		options [][]candidate
		size    int
	}
	var attempts []attempt
	for _, s := range g.members {
		if s == m {
			continue
		}
		options, narrowed := restrictTo(s, absent, all)
		if !narrowed {
			continue
		}
		if size, ok := combinations(options, maxTrials); ok {
			attempts = append(attempts, attempt{s.in.Label, options, size})
		}
	}
	sort.Slice(attempts, func(a, b int) bool {
		if attempts[a].size != attempts[b].size {
			return attempts[a].size < attempts[b].size
		}
		return attempts[a].label < attempts[b].label
	})

	budget := maxTrials
	for _, a := range attempts {
		if a.size > budget {
			continue
		}
		budget -= a.size
		if g.search(vec, absent, a.options) {
			return true
		}
	}
	if _, ok := combinations(all, budget); ok {
		return g.search(vec, absent, all)
	}
	return false
}

// restrictTo narrows each absent position's candidates to the entry member s
// carries there in full, where it carries one. narrowed is false when s
// carries none of the positions, so the search would be the unrestricted one.
func restrictTo(s *eval, absent []int, all [][]candidate) (options [][]candidate, narrowed bool) {
	options = make([][]candidate, len(absent))
	for k, i := range absent {
		options[k] = all[k]
		p := s.positions[i]
		if p.Kind != wire.KindFull {
			continue
		}
		h := commit.LeafHash(p.Leaf)
		for _, c := range all[k] {
			if c.hash == h {
				options[k] = []candidate{c}
				narrowed = true
				break
			}
		}
	}
	return options, narrowed
}

// combinations returns how many vectors the options describe, and false when
// that is more than limit.
func combinations(options [][]candidate, limit int) (int, bool) {
	total := 1
	for _, o := range options {
		if len(o) == 0 || total > limit/len(o) {
			return 0, false
		}
		total *= len(o)
	}
	return total, true
}

// search tries every combination of the options at the absent positions and
// reports whether one recomputes to the signed root. vec keeps that one.
func (g *group) search(vec [][32]byte, absent []int, options [][]candidate) bool {
	pick := make([]int, len(absent))
	for {
		for k, i := range absent {
			vec[i] = options[k][pick[k]].hash
		}
		if g.recompute(vec) {
			return true
		}
		k := 0
		for ; k < len(pick); k++ {
			pick[k]++
			if pick[k] < len(options[k]) {
				break
			}
			pick[k] = 0
		}
		if k == len(pick) {
			return false
		}
	}
}

// describeGaps lists the member's gaps and the entries that belong in them.
// With a proven vector, data that differs from it is marked wrong.
//
// A recovered entry gets a proof into the signed root only where an evidence
// file can use it: a wrong position, or an absent position the window rule
// named. An absence the rule permits backs no evidence file. Each proof costs
// close to n node hashes, so a list the rule permits to leave everything out
// costs nothing here. A list accused at every position costs about n squared
// hashes, once for its group, because proofs are shared by position.
func (g *group) describeGaps(m *eval) {
	for i, p := range m.positions {
		gap := Gap{Position: uint32(i), Served: p.Kind}
		var want [32]byte
		known := false
		switch p.Kind {
		case wire.KindFull:
			if g.ref == nil || commit.LeafHash(p.Leaf) == g.ref[i] {
				continue
			}
			gap.Wrong = true
		case wire.KindHash:
			// Without a proven vector, the server's own hash is the best
			// guide to the entry it held back.
			want, known = p.Hash, true
			gap.Wrong = g.ref != nil && p.Hash != g.ref[i]
		}
		if g.ref != nil {
			want, known = g.ref[i], true
		}
		if known {
			if c := g.find(i, want); c != nil {
				leaf := c.leaf
				gap.Entry = &leaf
				gap.FoundBy = FoundByPayment
				if c.fromServer {
					gap.FoundBy = FoundByServer
				}
				backsEvidence := gap.Wrong || p.Kind == wire.KindAbsent && m.window == windowInside
				if g.ref != nil && backsEvidence {
					gap.Proof = g.proof(i)
				}
			}
		}
		m.res.Gaps = append(m.res.Gaps, gap)
	}
}

// proof returns position i's proof into the signed root, built from the
// proven vector once per group. Each caller gets its own copy.
func (g *group) proof(i int) *commit.Proof {
	p, ok := g.proofs[i]
	if !ok {
		var err error
		if p, err = commit.ProveFromLeafHashes(g.ref, uint32(i)); err != nil {
			return nil
		}
		g.proofs[i] = p
	}
	p.Siblings = append([][32]byte(nil), p.Siblings...)
	return &p
}
