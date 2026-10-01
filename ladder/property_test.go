package ladder

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/policy"
)

// behaviours a generated server can show.
const (
	bHonest = iota
	bAbsent
	bHash
	bWrongEntry
	bNoList
	bUnsigned
	bNoRecord
	bUnreachable
	bShort
	bOtherRecord
	bUnconfirmedTip
	bFalseHeight
	bAbsentAndWrong
	bCount
)

// randomBlock builds a block with one to four servers, each showing a random
// behaviour, and up to two declared payments. consistent names the servers
// whose list agrees with their own record wherever it carries data: it may
// leave positions out or send hashes, but it forges nothing.
func randomBlock(t testing.TB, r *rand.Rand) (b Block, consistent map[string]bool) {
	consistent = map[string]bool{}
	heights := []uint32{recent, deep, coreTip - 143, coreTip - 144}
	f := newFixture(t, heights[r.Intn(len(heights))])
	n := r.Intn(6)
	L := leaves(n, fmt.Sprint("set", r.Int()))
	alt := leaves(n+1, fmt.Sprint("alt", r.Int()))

	for p := r.Intn(3); p > 0; p-- {
		pay := Payment{Outputs: []Output{{ValueSat: uint64(r.Intn(3000)), Unspent: r.Intn(2) == 0}}}
		if n > 0 && r.Intn(4) > 0 {
			pay.Entry = L[r.Intn(n)]
		} else {
			pay.Entry = leaves(1, fmt.Sprint("foreign", r.Int()))[0]
		}
		f.payments = append(f.payments, pay)
	}

	servers := make([]Server, 1+r.Intn(4))
	for i := range servers {
		label := fmt.Sprintf("s%d", i)
		k := newKey(t, byte(i+1))
		var opts []opt
		if r.Intn(2) == 0 {
			opts = append(opts, prunes())
		}
		signed, served := L, full(L)
		pick := func() int { return r.Intn(n) }
		b := r.Intn(bCount)
		consistent[label] = !(n > 0 && (b == bWrongEntry || b == bShort) || n > 1 && b == bAbsentAndWrong)
		switch {
		case b == bAbsent && n > 0:
			served = absentAt(served, pick(), pick())
		case b == bHash && n > 0:
			served = hashAt(served, pick())
		case b == bWrongEntry && n > 0:
			served[pick()] = full(leaves(1, fmt.Sprint("forged", r.Int())))[0]
		case b == bNoList:
			opts = append(opts, noList())
		case b == bUnsigned && n > 0:
			served = absentAt(served, pick())
			opts = append(opts, noReceipt())
		case b == bNoRecord:
			opts = append(opts, noRecord(), noList())
		case b == bShort && n > 0:
			served = served[:n-1]
		case b == bOtherRecord:
			signed, served = alt, full(alt)
		case b == bUnconfirmedTip && n > 0:
			served = absentAt(served, pick())
			opts = append(opts, signedTip(coreTip-2, sha256.Sum256([]byte("orphan"))))
		case b == bFalseHeight && n > 0:
			served = absentAt(served, pick())
			opts = append(opts, recordHeight(f.height/2))
		case b == bAbsentAndWrong && n > 1:
			// A hole and a forged entry in one list. Whether the forgery is
			// attributable depends on another list proving the root, which
			// must not depend on the order the servers were listed in.
			hole := pick()
			forged := (hole + 1 + r.Intn(n-1)) % n
			served = absentAt(served, hole)
			served[forged] = full(leaves(1, fmt.Sprint("forged", r.Int())))[0]
		}
		s := f.srv(label, k, signed, served, opts...)
		if r.Intn(bCount) == bUnreachable {
			s.Unreachable = true
		}
		if s.Record == nil {
			s.RecordBelow, s.RecordAbove = r.Intn(2) == 0, r.Intn(2) == 0
			if r.Intn(3) == 0 {
				s.Tip = u32(f.height - 1)
			}
		}
		servers[i] = s
	}
	return f.block(servers...), consistent
}

// scenarioCount is how many generated blocks the property tests share.
// Signing records and receipts dominates their cost, so the set is built once.
const scenarioCount = 150

var (
	scenarioOnce       sync.Once
	scenarioSet        []Block
	scenarioResults    []BlockResult
	scenarioConsistent []map[string]bool
)

// scenarios returns the shared generated blocks and their results in the
// order generated. It builds them once, from a fixed seed, so a failure
// always reproduces.
func scenarios(t testing.TB) ([]Block, []BlockResult) {
	scenarioOnce.Do(func() {
		r := rand.New(rand.NewSource(352))
		for i := 0; i < scenarioCount; i++ {
			b, consistent := randomBlock(t, r)
			scenarioSet = append(scenarioSet, b)
			scenarioConsistent = append(scenarioConsistent, consistent)
			scenarioResults = append(scenarioResults, evaluate(t, b))
		}
	})
	return scenarioSet, scenarioResults
}

// view is the part of a server's result that must not depend on the order
// the servers were listed in.
type view struct {
	State      state.StateCode
	Reason     state.Reason
	Warnings   []state.Reason
	Signed     bool
	Filled     int
	Recomputed bool
	Matched    bool
	Positions  *state.Positions
	Gaps       []Gap
	Payments   []PaymentResult
}

func viewOf(s ServerResult) view {
	return view{s.State, s.Reason, s.Warnings, s.Signed, s.Filled, s.RootRecomputed, s.RootMatched, s.Positions, s.Gaps, s.Payments}
}

func pairSet(ds []Disagreement) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		a, b := d.First, d.Second
		if b < a {
			a, b = b, a
		}
		out = append(out, a+"|"+b)
	}
	sort.Strings(out)
	return out
}

// checkInvariants holds for every result, whatever the scenario.
func checkInvariants(t *testing.T, where string, res BlockResult) {
	t.Helper()
	for _, s := range append(res.Servers, ServerResult{Label: "block", State: res.State, Reason: res.Reason}) {
		if st, ok := state.StateOf(s.Reason); !ok || st != s.State {
			t.Errorf("%s: %s reads %s/%s, a pair the formats do not allow", where, s.Label, s.State, s.Reason)
		}
	}
	for _, s := range res.Servers {
		if s.State.Passed() && (!s.RootRecomputed || !s.RootMatched) {
			t.Errorf("%s: %s reads %s without a recomputed, matching root", where, s.Label, s.State)
		}
		if s.State == state.Verified && s.Positions != nil && (s.Positions.Hash > 0 || s.Positions.Absent > 0) {
			t.Errorf("%s: %s reads verified with %d hash and %d absent positions", where, s.Label, s.Positions.Hash, s.Positions.Absent)
		}
		if s.RootMatched && !s.RootRecomputed {
			t.Errorf("%s: %s matched a root it never recomputed", where, s.Label)
		}
	}
}

// Shuffling the servers changes nothing but which server's reason the block
// quotes, and that only where the formats say it may: the block's reason is
// the first deciding server's, in --indexer order.
func TestServerOrderDoesNotChangeTheResult(t *testing.T) {
	r := rand.New(rand.NewSource(1352))
	blocks, results := scenarios(t)
	for i, b := range blocks {
		want := results[i]
		where := fmt.Sprintf("scenario %d", i)
		checkInvariants(t, where, want)

		for shuffle := 0; shuffle < 3; shuffle++ {
			s := b
			s.Servers = append([]Server(nil), b.Servers...)
			r.Shuffle(len(s.Servers), func(i, j int) { s.Servers[i], s.Servers[j] = s.Servers[j], s.Servers[i] })
			got := evaluate(t, s)
			checkInvariants(t, where, got)

			if got.State != want.State {
				t.Errorf("%s: block state %s after a shuffle, %s before", where, got.State, want.State)
			}
			if !reflect.DeepEqual(pairSet(got.Disagreements), pairSet(want.Disagreements)) {
				t.Errorf("%s: disagreements %v after a shuffle, %v before", where, got.Disagreements, want.Disagreements)
			}
			for _, w := range want.Servers {
				if g := byLabel(t, got, w.Label); !reflect.DeepEqual(viewOf(g), viewOf(w)) {
					t.Errorf("%s: server %s changed with its position:\n got %+v\nwant %+v", where, w.Label, viewOf(g), viewOf(w))
				}
			}
			if st, rs := Aggregate(got.Servers); st != got.State || rs != got.Reason {
				t.Errorf("%s: Aggregate gives %s/%s, Evaluate gave %s/%s", where, st, rs, got.State, got.Reason)
			}
			if want := firstDecidingReason(got); got.Reason != want {
				t.Errorf("%s: block reason %s, want the first deciding server's %s", where, got.Reason, want)
			}
		}
	}
}

// firstDecidingReason restates the formats' rule for the block's reason.
func firstDecidingReason(res BlockResult) state.Reason {
	switch res.State {
	case state.Disputed:
		return state.RecordsDiffer
	case state.Verified:
		records := 0
		for _, s := range res.Servers {
			if s.Record != nil {
				records++
			}
		}
		if records >= 2 {
			return state.RecordsAgree
		}
	}
	for _, s := range res.Servers {
		if s.State == res.State {
			return s.Reason
		}
	}
	return state.NoRecords
}

// A hash position never yields Checked. The best it can read is Checked, gap
// filled, because Canary cannot tell pruning from hiding there.
func TestHashPositionNeverVerifies(t *testing.T) {
	L := leaves(4, "a")
	type setup struct {
		name     string
		policy   *policy.Policy
		second   bool
		payments []Payment
	}
	for _, c := range []setup{
		{name: "pruning, alone", policy: &policy.Policy{PrunesSpent: true}},
		{name: "not pruning, alone", policy: &policy.Policy{}},
		{name: "no policy, alone"},
		{name: "a second server agrees", policy: &policy.Policy{PrunesSpent: true}, second: true},
		{name: "a declared payment carried elsewhere", policy: &policy.Policy{PrunesSpent: true},
			payments: []Payment{{Entry: L[0], Outputs: []Output{unspent(1)}}}},
		{name: "a spent declared payment at the hash", policy: &policy.Policy{PrunesSpent: true},
			payments: []Payment{{Entry: L[3], Outputs: []Output{spent(1)}}}},
	} {
		for _, height := range []uint32{recent, deep} {
			t.Run(fmt.Sprintf("%s at height %d", c.name, height), func(t *testing.T) {
				f := newFixture(t, height)
				f.payments = c.payments
				servers := []Server{f.srv("p", newKey(t, 1), L, hashAt(full(L), 3), withPolicy(c.policy))}
				if c.second {
					servers = append(servers, f.srv("b", newKey(t, 2), L, full(L)))
				}
				p := byLabel(t, evaluate(t, f.block(servers...)), "p")
				if p.State != state.Resolved {
					t.Errorf("p = %s/%s, want resolved", p.State, p.Reason)
				}
			})
		}
	}

	_, results := scenarios(t)
	for i, res := range results {
		for _, s := range res.Servers {
			if s.State == state.Verified && s.Positions != nil && s.Positions.Hash > 0 {
				t.Errorf("scenario %d: %s reads verified with a hash position", i, s.Label)
			}
		}
	}
}

// The evaluator never hands out a pass for a block whose root it did not
// recompute, over any generated scenario.
func TestNoPassWithoutARecomputedRoot(t *testing.T) {
	_, results := scenarios(t)
	for i, res := range results {
		checkInvariants(t, fmt.Sprintf("scenario %d", i), res)
	}
}

// A server whose list forges nothing is never accused of contradicting its
// record, whatever the other servers send. Entries from a server that forged
// one are tried as fills, and a failed try must accuse nobody.
func TestForgedFillsNeverAccuseAnHonestList(t *testing.T) {
	_, results := scenarios(t)
	for i, res := range results {
		for _, s := range res.Servers {
			if scenarioConsistent[i][s.Label] && s.Reason == state.ServedContradictsRecord {
				t.Errorf("scenario %d: %s forged nothing, yet reads served_contradicts_record", i, s.Label)
			}
		}
	}
}

// Sanity for the generator: it must reach every state, or the properties
// above prove less than they claim.
func TestGeneratorReachesEveryState(t *testing.T) {
	seen := map[state.StateCode]bool{}
	_, results := scenarios(t)
	for _, res := range results {
		for _, s := range res.Servers {
			seen[s.State] = true
		}
	}
	for _, s := range state.States {
		if !seen[s] {
			t.Errorf("the generator never produced a server reading %s", s)
		}
	}
}
