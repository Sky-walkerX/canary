package ladder

import (
	"testing"

	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/internal/state"
)

// res builds a server result for the aggregation tests. root 0 means the
// server signed no record.
func res(label string, s state.StateCode, r state.Reason, root byte) ServerResult {
	out := ServerResult{Label: label, State: s, Reason: r}
	if root != 0 {
		out.Record = &Record{Commitment: feed.Commitment{Root: [32]byte{root}}}
	}
	return out
}

func TestAggregatePrecedence(t *testing.T) {
	cases := []struct {
		name    string
		servers []ServerResult
		state   state.StateCode
		reason  state.Reason
	}{
		{
			name:  "no servers reads Not checked",
			state: state.Unverified, reason: state.NoRecords,
		},
		{
			name: "compromised beats everything, first in order decides the reason",
			servers: []ServerResult{
				res("a", state.Verified, state.RecordsAgree, 1),
				res("b", state.Compromised, state.FalseChainClaim, 1),
				res("c", state.Compromised, state.AbsentInWindow, 1),
			},
			state: state.Compromised, reason: state.FalseChainClaim,
		},
		{
			name: "compromised beats servers disagreeing",
			servers: []ServerResult{
				res("a", state.Disputed, state.RecordsDiffer, 1),
				res("b", state.Compromised, state.ExpectedPaymentNotInRecord, 2),
			},
			state: state.Compromised, reason: state.ExpectedPaymentNotInRecord,
		},
		{
			name: "two different signed roots read Servers disagree, whatever the lists did",
			servers: []ServerResult{
				res("a", state.Unresolvable, state.ListNotServed, 1),
				res("b", state.Unresolvable, state.GapUnfilled, 2),
			},
			state: state.Disputed, reason: state.RecordsDiffer,
		},
		{
			name: "verified beats resolved",
			servers: []ServerResult{
				res("a", state.Resolved, state.HashRetained, 1),
				res("b", state.Verified, state.OwnRecord, 0),
			},
			state: state.Verified, reason: state.OwnRecord,
		},
		{
			name: "a verified block with two agreeing records carries records_agree",
			servers: []ServerResult{
				res("a", state.Resolved, state.FilledFromServer, 1),
				res("b", state.Verified, state.ExpectedPayment, 1),
			},
			state: state.Verified, reason: state.RecordsAgree,
		},
		{
			name: "resolved beats unresolvable",
			servers: []ServerResult{
				res("a", state.Unresolvable, state.GapUnfilled, 1),
				res("b", state.Resolved, state.FilledFromExpectedPayment, 0),
			},
			state: state.Resolved, reason: state.FilledFromExpectedPayment,
		},
		{
			name: "unresolvable beats unverified",
			servers: []ServerResult{
				res("a", state.Unverified, state.NoRecordForBlock, 0),
				res("b", state.Unresolvable, state.TipUnconfirmed, 1),
			},
			state: state.Unresolvable, reason: state.TipUnconfirmed,
		},
		{
			name: "unverified quotes the first server",
			servers: []ServerResult{
				res("a", state.Unverified, state.ServerUnreachable, 0),
				res("b", state.Unverified, state.NotIndexedYet, 0),
			},
			state: state.Unverified, reason: state.ServerUnreachable,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, r := Aggregate(c.servers)
			if s != c.state || r != c.reason {
				t.Errorf("Aggregate = %s/%s, want %s/%s", s, r, c.state, c.reason)
			}
		})
	}
}

// Every pair of servers with different signed roots is a disagreement, in
// --indexer order. Servers that agree with each other are not paired.
func TestDisagreementsNameEveryDifferingPair(t *testing.T) {
	f := newFixture(t, recent)
	L, M := leaves(3, "a"), leaves(3, "b")
	got := evaluate(t, f.block(
		f.srv("a", newKey(t, 1), L, full(L)),
		f.srv("b", newKey(t, 2), L, full(L)),
		f.srv("c", newKey(t, 3), M, full(M)),
		f.srv("d", newKey(t, 4), nil, nil, noRecord(), noList()),
	)).Disagreements
	want := []Disagreement{{First: "a", Second: "c"}, {First: "b", Second: "c"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("disagreements = %v, want %v", got, want)
	}
}

// Two servers may not share a label, because every result is keyed by it.
func TestDuplicateLabelsAreRefused(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(1, "a")
	if _, err := Evaluate(f.block(
		f.srv("a", newKey(t, 1), L, full(L)),
		f.srv("a", newKey(t, 2), L, full(L)),
	)); err == nil {
		t.Error("Evaluate accepted two servers labelled a")
	}
}
