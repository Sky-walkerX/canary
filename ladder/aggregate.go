package ladder

import "github.com/Sky-walkerX/canary/internal/state"

// Aggregate turns the servers' results for one block into the block's state
// and reason, in this order of precedence:
//
//  1. Data withheld, if any server's result is compromised.
//  2. Otherwise Servers disagree, if two servers signed different roots.
//  3. Otherwise Checked, if any server is verified, then Checked, gap
//     filled, if any is resolved.
//  4. Otherwise Can't be checked, if any server is unresolvable.
//  5. Otherwise Not checked.
//
// The reason is the deciding server's, taking servers in the order given.
// Servers disagree always carries records_differ. A Checked block with two
// agreeing records always carries records_agree. A block with no servers
// reads Not checked, with the reason no_records.
func Aggregate(servers []ServerResult) (state.StateCode, state.Reason) {
	if s, ok := first(servers, state.Compromised); ok {
		return state.Compromised, s.Reason
	}

	var roots [][32]byte
	for _, s := range servers {
		if s.Record != nil {
			roots = append(roots, s.Record.Commitment.Root)
		}
	}
	for _, r := range roots {
		if r != roots[0] {
			return state.Disputed, state.RecordsDiffer
		}
	}
	if _, ok := first(servers, state.Disputed); ok {
		return state.Disputed, state.RecordsDiffer
	}

	if s, ok := first(servers, state.Verified); ok {
		if len(roots) >= 2 {
			return state.Verified, state.RecordsAgree
		}
		return state.Verified, s.Reason
	}
	for _, st := range []state.StateCode{state.Resolved, state.Unresolvable, state.Unverified} {
		if s, ok := first(servers, st); ok {
			return st, s.Reason
		}
	}
	return state.Unverified, state.NoRecords
}

func first(servers []ServerResult, st state.StateCode) (ServerResult, bool) {
	for _, s := range servers {
		if s.State == st {
			return s, true
		}
	}
	return ServerResult{}, false
}
