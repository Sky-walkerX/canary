package ladder

import (
	"fmt"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/wire"
)

// gapAt returns the gap for position i, or fails.
func gapAt(t *testing.T, r ServerResult, i uint32) Gap {
	t.Helper()
	for _, g := range r.Gaps {
		if g.Position == i {
			return g
		}
	}
	t.Fatalf("%s: no gap at position %d, gaps are %+v", r.Label, i, r.Gaps)
	return Gap{}
}

// checkProof verifies that a gap's entry proves into the signed root.
func checkProof(t *testing.T, f *fixture, r ServerResult, g Gap, want canonical.Leaf) {
	t.Helper()
	if g.Entry == nil || *g.Entry != want {
		t.Fatalf("gap %d entry = %v, want the committed entry", g.Position, g.Entry)
	}
	if g.Proof == nil {
		t.Fatalf("gap %d has no proof", g.Position)
	}
	if !commit.VerifyProof(regtest, f.hash, r.Record.Commitment.Root, *g.Entry, *g.Proof) {
		t.Errorf("gap %d: the proof does not carry the entry to the signed root", g.Position)
	}
}

// checkEntry verifies that a gap recovered the committed entry.
func checkEntry(t *testing.T, g Gap, want canonical.Leaf) {
	t.Helper()
	if g.Entry == nil || *g.Entry != want {
		t.Errorf("gap %d entry = %v, want the committed entry", g.Position, g.Entry)
	}
}

// The ordering test. The server leaves position 1 out of a deep block and a
// second server has it. Filled first, the root recomputes and matches. Had
// the root been recomputed first, over the hole, it could not match: the
// block would read Data withheld against an honest server, or Can't be
// checked for good.
func TestFillHappensBeforeTheRootIsRecomputed(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(5, "a")
	served := absentAt(full(L), 1)
	res := evaluate(t, f.block(
		f.srv("a", newKey(t, 1), L, served),
		f.srv("b", newKey(t, 2), L, full(L)),
	))
	a := byLabel(t, res, "a")

	signed := commit.Root(regtest, f.hash, L)
	var withHole, skipped [][32]byte
	for _, p := range served {
		if p.Kind == wire.KindAbsent {
			withHole = append(withHole, [32]byte{})
			continue
		}
		h := commit.LeafHash(p.Leaf)
		withHole = append(withHole, h)
		skipped = append(skipped, h)
	}
	if commit.RootFromLeafHashes(regtest, f.hash, withHole) == signed ||
		commit.RootFromLeafHashes(regtest, f.hash, skipped) == signed {
		t.Fatal("test setup: a root over the hole must differ from the signed root")
	}

	if a.State != state.Resolved || a.Reason != state.FilledFromServer {
		t.Fatalf("a = %s/%s, want resolved/filled_from_server", a.State, a.Reason)
	}
	if !a.RootRecomputed || !a.RootMatched || a.Filled != 1 {
		t.Errorf("recomputed %v, matched %v, filled %d; want the root recomputed after one fill",
			a.RootRecomputed, a.RootMatched, a.Filled)
	}
	g := gapAt(t, a, 1)
	if g.FoundBy != FoundByServer {
		t.Errorf("found by %q, want %q", g.FoundBy, FoundByServer)
	}
	checkEntry(t, g, L[1])
}

// A gap nobody can fill leaves the root uncomputed, and such a block is never
// Checked.
func TestUnfilledGapIsNeverChecked(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(4, "a")
	a := byLabel(t, evaluate(t, f.block(f.srv("a", newKey(t, 1), L, absentAt(full(L), 0, 3)))), "a")
	if a.RootRecomputed || a.State.Passed() {
		t.Errorf("a = %s/%s with recomputed %v; an unfilled gap must never pass", a.State, a.Reason, a.RootRecomputed)
	}
	if g := gapAt(t, a, 0); g.Entry != nil {
		t.Errorf("gap 0 entry = %v, want none recovered", g.Entry)
	}
}

// Filling inside the window still happens. The block reads Data withheld,
// and the recovered entry, with its proof, names the transaction that was
// left out. That is what an evidence file carries.
func TestAbsentInWindowStillFillsAndRecomputes(t *testing.T) {
	t.Run("from another server", func(t *testing.T) {
		f := newFixture(t, recent)
		L := leaves(3, "a")
		res := evaluate(t, f.block(
			f.srv("honest", newKey(t, 1), L, full(L)),
			f.srv("withholder", newKey(t, 2), L, absentAt(full(L), 1)),
		))
		w := byLabel(t, res, "withholder")
		if w.State != state.Compromised || w.Reason != state.AbsentInWindow {
			t.Fatalf("withholder = %s/%s, want compromised/absent_in_window", w.State, w.Reason)
		}
		if !w.Signed || !w.RootRecomputed || !w.RootMatched || w.Filled != 1 {
			t.Errorf("signed %v, recomputed %v, matched %v, filled %d", w.Signed, w.RootRecomputed, w.RootMatched, w.Filled)
		}
		g := gapAt(t, w, 1)
		if g.Served != wire.KindAbsent || g.FoundBy != FoundByServer {
			t.Errorf("gap = %+v, want an absent position found by another server", g)
		}
		checkProof(t, f, w, g, L[1])
	})
	t.Run("from a declared payment", func(t *testing.T) {
		f := newFixture(t, recent)
		L := leaves(3, "a")
		f.payments = []Payment{{Entry: L[1], Outputs: []Output{unspent(5000)}}}
		w := byLabel(t, evaluate(t, f.block(f.srv("withholder", newKey(t, 2), L, absentAt(full(L), 1)))), "withholder")
		if w.Reason != state.AbsentInWindow {
			t.Fatalf("reason = %s, want absent_in_window", w.Reason)
		}
		g := gapAt(t, w, 1)
		if g.FoundBy != FoundByPayment {
			t.Errorf("found by %q, want %q", g.FoundBy, FoundByPayment)
		}
		checkProof(t, f, w, g, L[1])
		if len(w.Payments) != 1 || w.Payments[0].Outcome != PaymentWithheld || w.Payments[0].TxID != L[1].TxID {
			t.Errorf("payments = %+v, want the payment withheld", w.Payments)
		}
	})
}

// A candidate from a server whose own list does not check out proves
// nothing. A failed trial with it must not accuse the server being filled.
func TestUnprovenCandidateNeverAccuses(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(4, "a")
	liar := full(L)
	liar[1] = full(leaves(1, "forged"))[0]
	res := evaluate(t, f.block(
		f.srv("a", newKey(t, 1), L, absentAt(full(L), 1)),
		f.srv("liar", newKey(t, 2), L, liar),
	))
	if l := byLabel(t, res, "liar"); l.Reason != state.ServedContradictsRecord {
		t.Errorf("liar = %s/%s, want served_contradicts_record", l.State, l.Reason)
	}
	a := byLabel(t, res, "a")
	if a.State != state.Unresolvable || a.Reason != state.GapUnfilled || a.RootRecomputed {
		t.Errorf("a = %s/%s recomputed %v, want unresolvable/gap_unfilled without a root", a.State, a.Reason, a.RootRecomputed)
	}
	if g := gapAt(t, a, 1); g.Entry != nil {
		t.Errorf("a's gap was filled with an unproven entry %v", g.Entry)
	}
}

// With a third, honest server, the proven entry fills the gap and the forged
// one is ignored.
func TestProvenCandidateWinsOverAForgedOne(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(4, "a")
	liar := full(L)
	liar[1] = full(leaves(1, "forged"))[0]
	res := evaluate(t, f.block(
		f.srv("a", newKey(t, 1), L, absentAt(full(L), 1)),
		f.srv("liar", newKey(t, 2), L, liar),
		f.srv("honest", newKey(t, 3), L, full(L)),
	))
	a := byLabel(t, res, "a")
	if a.State != state.Resolved || a.Reason != state.FilledFromServer {
		t.Fatalf("a = %s/%s, want resolved/filled_from_server", a.State, a.Reason)
	}
	checkEntry(t, gapAt(t, a, 1), L[1])
	l := byLabel(t, res, "liar")
	g := gapAt(t, l, 1)
	if !g.Wrong || g.Served != wire.KindFull {
		t.Errorf("liar gap = %+v, want its forged full entry marked wrong", g)
	}
	checkProof(t, f, l, g, L[1])
}

// Two servers each leave out a different entry. Neither list is complete
// alone, but together they fill each other, and the root proves both.
func TestServersFillEachOther(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(5, "a")
	res := evaluate(t, f.block(
		f.srv("a", newKey(t, 1), L, absentAt(full(L), 1)),
		f.srv("b", newKey(t, 2), L, absentAt(full(L), 3)),
	))
	for _, label := range []string{"a", "b"} {
		r := byLabel(t, res, label)
		if r.State != state.Resolved || r.Reason != state.FilledFromServer || !r.RootMatched {
			t.Errorf("%s = %s/%s matched %v, want resolved/filled_from_server", label, r.State, r.Reason, r.RootMatched)
		}
	}
	if res.State != state.Resolved || res.Reason != state.FilledFromServer {
		t.Errorf("block = %s/%s, want resolved/filled_from_server", res.State, res.Reason)
	}
}

// Fills come only from a server that signed the same root. A server that
// signed a different record is no source, even where its entry would fit.
func TestFillNeedsTheSameRoot(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(4, "a")
	M := append([]canonical.Leaf(nil), L...)
	M[3] = leaves(1, "other")[0]
	res := evaluate(t, f.block(
		f.srv("a", newKey(t, 1), L, absentAt(full(L), 1)),
		f.srv("b", newKey(t, 2), M, full(M)),
	))
	a := byLabel(t, res, "a")
	if a.State != state.Unresolvable || a.Reason != state.GapUnfilled {
		t.Errorf("a = %s/%s, want unresolvable/gap_unfilled", a.State, a.Reason)
	}
	if b := byLabel(t, res, "b"); b.State != state.Disputed {
		t.Errorf("b = %s/%s, want disputed", b.State, b.Reason)
	}
	if res.State != state.Disputed || res.Reason != state.RecordsDiffer {
		t.Errorf("block = %s/%s, want disputed/records_differ", res.State, res.Reason)
	}
}

// Once another server proves the root, a server's own wrong data is
// attributable to it, even with a gap filled. The finding names the position
// and the entry that belongs there.
func TestRootMismatchAfterAProvenFillNamesThePosition(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(4, "a")
	served := absentAt(full(L), 2)
	served[0] = full(leaves(1, "swapped"))[0]
	res := evaluate(t, f.block(
		f.srv("w", newKey(t, 1), L, served),
		f.srv("b", newKey(t, 2), L, full(L)),
	))
	w := byLabel(t, res, "w")
	if w.State != state.Compromised || w.Reason != state.ServedContradictsRecord {
		t.Fatalf("w = %s/%s, want compromised/served_contradicts_record", w.State, w.Reason)
	}
	if !w.RootRecomputed || w.RootMatched {
		t.Errorf("recomputed %v, matched %v; want a recomputed root that differs", w.RootRecomputed, w.RootMatched)
	}
	g := gapAt(t, w, 0)
	if !g.Wrong {
		t.Errorf("gap 0 = %+v, want it marked wrong", g)
	}
	checkProof(t, f, w, g, L[0])
	checkEntry(t, gapAt(t, w, 2), L[2])
}

// A hash position needs no fill for the root, but Canary still recovers its
// entry where another server has it.
func TestHashPositionRecoversItsEntry(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(4, "a")
	res := evaluate(t, f.block(
		f.srv("p", newKey(t, 1), L, hashAt(full(L), 2), prunes()),
		f.srv("b", newKey(t, 2), L, full(L)),
	))
	p := byLabel(t, res, "p")
	if p.State != state.Resolved || p.Reason != state.HashRetained || p.Filled != 1 {
		t.Errorf("p = %s/%s filled %d, want resolved/hash_retained with one entry recovered", p.State, p.Reason, p.Filled)
	}
	g := gapAt(t, p, 2)
	if g.Served != wire.KindHash || g.FoundBy != FoundByServer || g.Wrong {
		t.Errorf("gap = %+v, want a correct hash whose entry another server supplied", g)
	}
	if g.Entry == nil || *g.Entry != L[2] {
		t.Errorf("gap entry = %v, want the committed entry", g.Entry)
	}
	if g.Proof != nil {
		t.Error("a correct hash backs no evidence file, so it needs no proof")
	}
}

// A hash that is not the entry's hash contradicts the record.
func TestWrongHashContradictsTheRecord(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(4, "a")
	served := full(L)
	served[2] = wire.Position{Kind: wire.KindHash, Hash: commit.LeafHash(leaves(1, "x")[0])}
	res := evaluate(t, f.block(
		f.srv("p", newKey(t, 1), L, served, prunes()),
		f.srv("b", newKey(t, 2), L, full(L)),
	))
	p := byLabel(t, res, "p")
	if p.State != state.Compromised || p.Reason != state.ServedContradictsRecord {
		t.Fatalf("p = %s/%s, want compromised/served_contradicts_record", p.State, p.Reason)
	}
	if g := gapAt(t, p, 2); !g.Wrong {
		t.Errorf("gap = %+v, want the hash marked wrong", g)
	}
}

// Declared payments tried at every unfilled position land only where the root
// matches, whatever order they were declared in.
func TestDeclaredPaymentLandsWhereTheRootMatches(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(6, "a")
	f.payments = []Payment{
		{Entry: L[4], Outputs: []Output{spent(1)}},
		{Entry: L[1], Outputs: []Output{spent(1)}},
	}
	a := byLabel(t, evaluate(t, f.block(f.srv("a", newKey(t, 1), L, absentAt(full(L), 1, 4)))), "a")
	if a.State != state.Resolved || a.Reason != state.FilledFromExpectedPayment {
		t.Fatalf("a = %s/%s, want resolved/filled_from_expected_payment", a.State, a.Reason)
	}
	checkEntry(t, gapAt(t, a, 1), L[1])
	checkEntry(t, gapAt(t, a, 4), L[4])
	for _, p := range a.Payments {
		if p.Outcome != PaymentHashOnly {
			t.Errorf("payment %x outcome = %s, want hash_only: spent outputs let pruning explain the gap", p.TxID[:4], p.Outcome)
		}
	}
}

// Once another list proves the root, a server's wrong data is its own, even
// where a gap of its own stays unfilled. Every other position takes a proven
// value, so the root still recomputes, differs, and names the server. The
// output never marks a position wrong on a server it then calls Can't be
// checked.
func TestProvenRootNamesWrongDataDespiteAnUnfilledGap(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(4, "a")
	served := absentAt(full(L), 2)
	served[0] = full(leaves(1, "forged"))[0]
	res := evaluate(t, f.block(
		f.srv("w", newKey(t, 1), L, served),
		f.srv("b", newKey(t, 2), L, hashAt(full(L), 2), prunes()),
	))
	w := byLabel(t, res, "w")
	if w.State != state.Compromised || w.Reason != state.ServedContradictsRecord {
		t.Fatalf("w = %s/%s, want compromised/served_contradicts_record", w.State, w.Reason)
	}
	if !w.RootRecomputed || w.RootMatched {
		t.Errorf("recomputed %v, matched %v; want a recomputed root that differs", w.RootRecomputed, w.RootMatched)
	}
	g := gapAt(t, w, 0)
	if !g.Wrong {
		t.Errorf("gap 0 = %+v, want it marked wrong", g)
	}
	checkProof(t, f, w, g, L[0])
	if g := gapAt(t, w, 2); g.Entry != nil || g.Proof != nil {
		t.Errorf("gap 2 = %+v, want no entry: nobody served it in full", g)
	}
	if b := byLabel(t, res, "b"); b.State != state.Resolved || b.Reason != state.HashRetained {
		t.Errorf("b = %s/%s, want resolved/hash_retained", b.State, b.Reason)
	}
	if res.State != state.Compromised || res.Reason != state.ServedContradictsRecord {
		t.Errorf("block = %s/%s, want compromised/served_contradicts_record", res.State, res.Reason)
	}
}

// A proven hash says where an entry sits, not what it is. It never fills an
// absent position, so a list whose only fault is a gap nobody served in full
// reads Can't be checked, with nothing marked wrong.
func TestProvenHashDoesNotFillAnAbsentPosition(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(4, "a")
	res := evaluate(t, f.block(
		f.srv("w", newKey(t, 1), L, absentAt(full(L), 2)),
		f.srv("b", newKey(t, 2), L, hashAt(full(L), 2), prunes()),
	))
	w := byLabel(t, res, "w")
	if w.State != state.Unresolvable || w.Reason != state.GapUnfilled || w.RootRecomputed || w.RootMatched {
		t.Errorf("w = %s/%s recomputed %v matched %v, want unresolvable/gap_unfilled with no root",
			w.State, w.Reason, w.RootRecomputed, w.RootMatched)
	}
	for _, g := range w.Gaps {
		if g.Wrong || g.Entry != nil || g.Proof != nil {
			t.Errorf("gap %+v on a server that is neither passed nor accused", g)
		}
	}
	if res.State != state.Resolved || res.Reason != state.HashRetained {
		t.Errorf("block = %s/%s, want resolved/hash_retained", res.State, res.Reason)
	}
}

// Inside the window the window rule has already named the server. A recovered
// entry still carries its proof, so an evidence file can back the finding,
// even where another gap left the root uncomputed.
func TestRecoveredEntryInTheWindowKeepsItsProof(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(4, "a")
	res := evaluate(t, f.block(
		f.srv("w", newKey(t, 1), L, absentAt(full(L), 1, 2)),
		f.srv("b", newKey(t, 2), L, hashAt(full(L), 2), prunes()),
	))
	w := byLabel(t, res, "w")
	if w.State != state.Compromised || w.Reason != state.AbsentInWindow || w.RootRecomputed {
		t.Fatalf("w = %s/%s recomputed %v, want compromised/absent_in_window with no root",
			w.State, w.Reason, w.RootRecomputed)
	}
	checkProof(t, f, w, gapAt(t, w, 1), L[1])
	if g := gapAt(t, w, 2); g.Entry != nil || g.Proof != nil {
		t.Errorf("gap 2 = %+v, want no entry", g)
	}
}

// A proof is built only where an evidence file can use it: an absent position
// inside the window, or a position whose data is wrong. An absence the rule
// permits, or one a false chain claim excuses, backs no evidence file, so it
// costs no proof.
func TestProofsOnlyWhereAnEvidenceFileCanUseThem(t *testing.T) {
	cases := []struct {
		name      string
		height    uint32
		opts      []opt
		wantProof bool
	}{
		{"absent inside the window", recent, nil, true},
		{"absent outside the window", deep, nil, false},
		{"absent behind a false chain claim", deep, []opt{recordHeight(deep - 50)}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.height)
			L := leaves(4, "a")
			res := evaluate(t, f.block(
				f.srv("w", newKey(t, 1), L, absentAt(full(L), 1), c.opts...),
				f.srv("b", newKey(t, 2), L, full(L)),
			))
			w := byLabel(t, res, "w")
			g := gapAt(t, w, 1)
			if c.wantProof {
				checkProof(t, f, w, g, L[1])
				return
			}
			checkEntry(t, g, L[1])
			if g.Proof != nil {
				t.Errorf("gap 1 carries a proof that no evidence file can use")
			}
		})
	}
}

// forgeAt returns a copy of pos with a distinct forged entry at each index.
func forgeAt(pos []wire.Position, salt string, idx ...int) []wire.Position {
	out := append([]wire.Position(nil), pos...)
	for _, i := range idx {
		out[i] = full(leaves(1, fmt.Sprint(salt, i)))[0]
	}
	return out
}

func span(lo, hi int) []int {
	var out []int
	for i := lo; i < hi; i++ {
		out = append(out, i)
	}
	return out
}

// A server that co-signs the record can offer a forged entry at every
// position two honest lists leave out. That doubles the candidates at each
// one, well past the search cap. The search tries each list as the main
// source first, so the honest lists still fill each other and the forger is
// named, with or without a hole of its own.
func TestCoSignerCannotBuryHonestFills(t *testing.T) {
	for _, forgerHole := range []bool{false, true} {
		t.Run(fmt.Sprintf("forger leaves a hole: %v", forgerHole), func(t *testing.T) {
			f := newFixture(t, deep)
			L := leaves(20, "a")
			aHoles, bHoles := span(0, 9), span(9, 18)
			forged := forgeAt(full(L), "forged", span(0, 18)...)
			if forgerHole {
				forged = absentAt(forged, 19)
			}
			if 1<<len(aHoles) <= maxTrials {
				t.Fatal("test setup: two candidates at every hole must exceed the cap")
			}
			a := f.srv("a", newKey(t, 1), L, absentAt(full(L), aHoles...))
			b := f.srv("b", newKey(t, 2), L, absentAt(full(L), bHoles...))
			c := f.srv("c", newKey(t, 3), L, forged)
			for _, order := range [][]Server{{a, b, c}, {c, b, a}} {
				res := evaluate(t, f.block(order...))
				for _, label := range []string{"a", "b"} {
					r := byLabel(t, res, label)
					if r.State != state.Resolved || r.Reason != state.FilledFromServer || !r.RootMatched {
						t.Errorf("%s = %s/%s matched %v, want resolved/filled_from_server", label, r.State, r.Reason, r.RootMatched)
					}
				}
				if r := byLabel(t, res, "c"); r.State != state.Compromised || r.Reason != state.ServedContradictsRecord {
					t.Errorf("c = %s/%s, want compromised/served_contradicts_record", r.State, r.Reason)
				}
			}
		})
	}
}

// Past the cap the search gives up. The positions stay unfilled, and the
// server reads Can't be checked: never a pass, and never an accusation. Here
// the only honest entries come from declared payments, and two forgers put
// eleven candidates at each of nine holes.
func TestSearchPastTheCapNeitherPassesNorAccuses(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(10, "a")
	holes := span(0, 9)
	for _, i := range holes {
		f.payments = append(f.payments, Payment{Entry: L[i], Outputs: []Output{spent(1)}})
	}
	res := evaluate(t, f.block(
		f.srv("a", newKey(t, 1), L, absentAt(full(L), holes...)),
		f.srv("c1", newKey(t, 2), L, forgeAt(full(L), "c1", holes...)),
		f.srv("c2", newKey(t, 3), L, forgeAt(full(L), "c2", holes...)),
	))
	a := byLabel(t, res, "a")
	if a.State != state.Unresolvable || a.Reason != state.GapUnfilled || a.RootRecomputed {
		t.Errorf("a = %s/%s recomputed %v, want unresolvable/gap_unfilled with no root", a.State, a.Reason, a.RootRecomputed)
	}
	for _, g := range a.Gaps {
		if g.Entry != nil || g.Wrong || g.Proof != nil {
			t.Errorf("gap %+v was filled or marked without a proven root", g)
		}
	}
	for _, p := range a.Payments {
		if p.Outcome != PaymentUnresolvable {
			t.Errorf("payment %x = %s, want unresolvable", p.TxID[:4], p.Outcome)
		}
	}
	for _, label := range []string{"c1", "c2"} {
		if r := byLabel(t, res, label); r.Reason != state.ServedContradictsRecord {
			t.Errorf("%s = %s/%s, want served_contradicts_record", label, r.State, r.Reason)
		}
	}
}
