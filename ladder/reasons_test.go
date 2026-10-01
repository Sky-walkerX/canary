package ladder

import (
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
	"github.com/Sky-walkerX/canary/policy"
	"github.com/Sky-walkerX/canary/wire"
)

// reasonCase is one row of the reason table: a block, the server whose result
// the row checks, and what that server and the block should read.
type reasonCase struct {
	reason   state.Reason // the reason code or warning this row exercises
	name     string
	build    func(t *testing.T) Block
	server   string
	state    state.StateCode
	want     state.Reason
	warnings []state.Reason
	// block is the block's state and reason, when the row pins them.
	blockState  state.StateCode
	blockReason state.Reason
}

func reasonCases() []reasonCase {
	return []reasonCase{
		// verified
		{
			reason: state.OwnRecord, name: "one server, full list",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				return f.block(f.srv("a", newKey(t, 1), L, full(L)))
			},
			server: "a", state: state.Verified, want: state.OwnRecord,
			blockState: state.Verified, blockReason: state.OwnRecord,
		},
		{
			reason: state.RecordsAgree, name: "two servers sign the same root",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				return f.block(
					f.srv("a", newKey(t, 1), L, full(L)),
					f.srv("b", newKey(t, 2), L, full(L)),
				)
			},
			server: "b", state: state.Verified, want: state.RecordsAgree,
			blockState: state.Verified, blockReason: state.RecordsAgree,
		},
		{
			reason: state.RecordsAgree, name: "agreement counts a record whose list was not served",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				return f.block(
					f.srv("a", newKey(t, 1), L, full(L)),
					f.srv("b", newKey(t, 2), L, nil, noList()),
				)
			},
			server: "a", state: state.Verified, want: state.RecordsAgree,
			blockState: state.Verified, blockReason: state.RecordsAgree,
		},
		{
			reason: state.ExpectedPayment, name: "one server carries a declared payment in full",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				f.payments = []Payment{{Entry: L[2], Outputs: []Output{unspent(5000)}}}
				return f.block(f.srv("a", newKey(t, 1), L, full(L)))
			},
			server: "a", state: state.Verified, want: state.ExpectedPayment,
			blockState: state.Verified, blockReason: state.ExpectedPayment,
		},

		// resolved
		{
			reason: state.FilledFromServer, name: "absent outside the window, another server has it",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				return f.block(
					f.srv("a", newKey(t, 1), L, absentAt(full(L), 1)),
					f.srv("b", newKey(t, 2), L, full(L)),
				)
			},
			server: "a", state: state.Resolved, want: state.FilledFromServer,
			blockState: state.Verified, blockReason: state.RecordsAgree,
		},
		{
			reason: state.FilledFromExpectedPayment, name: "absent outside the window, a spent declared payment fills it",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				f.payments = []Payment{{Entry: L[1], Outputs: []Output{spent(5000)}}}
				return f.block(f.srv("a", newKey(t, 1), L, absentAt(full(L), 1)))
			},
			server: "a", state: state.Resolved, want: state.FilledFromExpectedPayment,
			blockState: state.Resolved, blockReason: state.FilledFromExpectedPayment,
		},
		{
			reason: state.HashRetained, name: "a pruning server sends a hash",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				return f.block(f.srv("a", newKey(t, 1), L, hashAt(full(L), 2), prunes()))
			},
			server: "a", state: state.Resolved, want: state.HashRetained,
			blockState: state.Resolved, blockReason: state.HashRetained,
		},

		// unresolvable
		{
			reason: state.GapUnfilled, name: "absent outside the window, confirmed chain, nobody fills it",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				return f.block(f.srv("a", newKey(t, 1), L, absentAt(full(L), 1)))
			},
			server: "a", state: state.Unresolvable, want: state.GapUnfilled,
			blockState: state.Unresolvable, blockReason: state.GapUnfilled,
		},
		{
			reason: state.GapUnfilled, name: "unsigned list, absent outside the window by Core's tip",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				return f.block(f.srv("a", newKey(t, 1), L, absentAt(full(L), 1), noReceipt()))
			},
			server: "a", state: state.Unresolvable, want: state.GapUnfilled,
		},
		{
			reason: state.TipUnconfirmed, name: "signed tip near Core's tip but not on its chain",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				return f.block(f.srv("a", newKey(t, 1), L, absentAt(full(L), 1),
					signedTip(coreTip-2, sha256.Sum256([]byte("orphan")))))
			},
			server: "a", state: state.Unresolvable, want: state.TipUnconfirmed,
			blockState: state.Unresolvable, blockReason: state.TipUnconfirmed,
		},
		{
			reason: state.TipUnconfirmed, name: "signed tip a few blocks ahead of Core",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				return f.block(f.srv("a", newKey(t, 1), L, absentAt(full(L), 1),
					signedTip(coreTip+TipMargin, sha256.Sum256([]byte("ahead")))))
			},
			server: "a", state: state.Unresolvable, want: state.TipUnconfirmed,
		},
		{
			reason: state.ListNotServed, name: "record signed, list refused, inside the window",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				return f.block(f.srv("a", newKey(t, 1), L, nil, noList()))
			},
			server: "a", state: state.Unresolvable, want: state.ListNotServed,
			warnings:   []state.Reason{state.ListNotServed},
			blockState: state.Unresolvable, blockReason: state.ListNotServed,
		},
		{
			reason: state.ListNotServed, name: "record signed, list refused, outside the window, no warning",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				return f.block(f.srv("a", newKey(t, 1), L, nil, noList()))
			},
			server: "a", state: state.Unresolvable, want: state.ListNotServed,
		},
		{
			reason: state.ListUnreadable, name: "unsigned list fails the reader rules inside the window",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				return f.block(f.srv("a", newKey(t, 1), L, nil, rawBody([]byte{0x01}), noReceipt()))
			},
			server: "a", state: state.Unresolvable, want: state.ListUnreadable,
			warnings:   []state.Reason{state.ListUnreadable},
			blockState: state.Unresolvable, blockReason: state.ListUnreadable,
		},
		{
			reason: state.ListUnreadable, name: "a receipt that fails to verify leaves the list unsigned",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				s := f.srv("a", newKey(t, 1), L, nil, rawBody([]byte{0x01}))
				s.List.Receipt = signReceipt(t, newKey(t, 9), f.hash, coreTip, f.chain[coreTip], s.List.Body)
				return f.block(s)
			},
			server: "a", state: state.Unresolvable, want: state.ListUnreadable,
		},

		// unverified
		{
			reason: state.NoRecords, name: "no record and no neighbours",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				return f.block(f.srv("a", newKey(t, 1), nil, nil, noRecord(), noList()))
			},
			server: "a", state: state.Unverified, want: state.NoRecords,
			blockState: state.Unverified, blockReason: state.NoRecords,
		},
		{
			reason: state.NoRecords, name: "a record signed by another key counts as none",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				s := f.srv("a", newKey(t, 1), L, full(L))
				s.Record = signRecord(t, newKey(t, 9), f.hash, f.height, L)
				return f.block(s)
			},
			server: "a", state: state.Unverified, want: state.NoRecords,
		},
		{
			reason: state.NoRecords, name: "a record for another block counts as none",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				s := f.srv("a", newKey(t, 1), L, full(L))
				s.Record = signRecord(t, newKey(t, 1), blockHash(recent-1), recent-1, L)
				return f.block(s)
			},
			server: "a", state: state.Unverified, want: state.NoRecords,
		},
		{
			reason: state.NoRecords, name: "a server pinned as none reads Not checked",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				s := f.srv("a", newKey(t, 1), L, full(L))
				s.Pubkey = nil
				return f.block(s)
			},
			server: "a", state: state.Unverified, want: state.NoRecords,
		},
		{
			reason: state.NoRecordForBlock, name: "records on both sides, none here",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				s := f.srv("a", newKey(t, 1), nil, nil, noRecord(), noList())
				s.RecordBelow, s.RecordAbove = true, true
				return f.block(s)
			},
			server: "a", state: state.Unverified, want: state.NoRecordForBlock,
			warnings:   []state.Reason{state.NoRecordForBlock},
			blockState: state.Unverified, blockReason: state.NoRecordForBlock,
		},
		{
			reason: state.NoRecordForBlock, name: "a record on one side only is no_records",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				s := f.srv("a", newKey(t, 1), nil, nil, noRecord(), noList())
				s.RecordBelow = true
				return f.block(s)
			},
			server: "a", state: state.Unverified, want: state.NoRecords,
		},
		{
			reason: state.NotIndexedYet, name: "the server's tip is below the block",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				s := f.srv("a", newKey(t, 1), nil, nil, noRecord(), noList())
				s.Tip = u32(recent - 1)
				s.RecordBelow = true
				return f.block(s)
			},
			server: "a", state: state.Unverified, want: state.NotIndexedYet,
			blockState: state.Unverified, blockReason: state.NotIndexedYet,
		},
		{
			// The server's own signed records on both sides contradict its
			// unsigned tip, so the tip cannot excuse the missing record.
			reason: state.NoRecordForBlock, name: "a low tip does not excuse a gap between two signed records",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				s := f.srv("a", newKey(t, 1), nil, nil, noRecord(), noList())
				s.Tip = u32(recent - 1)
				s.RecordBelow, s.RecordAbove = true, true
				return f.block(s)
			},
			server: "a", state: state.Unverified, want: state.NoRecordForBlock,
			warnings:   []state.Reason{state.NoRecordForBlock},
			blockState: state.Unverified, blockReason: state.NoRecordForBlock,
		},
		{
			reason: state.NoRecords, name: "a signed record above the block outranks a low tip",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				s := f.srv("a", newKey(t, 1), nil, nil, noRecord(), noList())
				s.Tip = u32(recent - 1)
				s.RecordAbove = true
				return f.block(s)
			},
			server: "a", state: state.Unverified, want: state.NoRecords,
		},
		{
			reason: state.ServerUnreachable, name: "the server did not answer",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				s := f.srv("a", newKey(t, 1), L, full(L))
				s.Unreachable = true
				return f.block(s)
			},
			server: "a", state: state.Unverified, want: state.ServerUnreachable,
			blockState: state.Unverified, blockReason: state.ServerUnreachable,
		},

		// disputed
		{
			reason: state.RecordsDiffer, name: "two servers sign different roots",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L, M := leaves(4, "a"), leaves(4, "b")
				return f.block(
					f.srv("a", newKey(t, 1), L, full(L)),
					f.srv("b", newKey(t, 2), M, full(M)),
				)
			},
			server: "a", state: state.Disputed, want: state.RecordsDiffer,
			blockState: state.Disputed, blockReason: state.RecordsDiffer,
		},

		// compromised
		{
			reason: state.AbsentInWindow, name: "absent inside the window by the signed values",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				return f.block(
					f.srv("a", newKey(t, 1), L, full(L)),
					f.srv("w", newKey(t, 2), L, absentAt(full(L), 1)),
				)
			},
			server: "w", state: state.Compromised, want: state.AbsentInWindow,
			blockState: state.Compromised, blockReason: state.AbsentInWindow,
		},
		{
			reason: state.AbsentInWindow, name: "unsigned list, absent inside the window by Core's tip",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				return f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1), noReceipt()))
			},
			server: "w", state: state.Compromised, want: state.AbsentInWindow,
		},
		{
			reason: state.AbsentInWindow, name: "inside by the signed values, whatever Core says of the tip",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				return f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1),
					signedTip(coreTip+50, sha256.Sum256([]byte("nowhere")))))
			},
			server: "w", state: state.Compromised, want: state.AbsentInWindow,
		},
		{
			reason: state.FalseChainClaim, name: "the record understates the block's height",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				return f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1), recordHeight(deep-50)))
			},
			server: "w", state: state.Compromised, want: state.FalseChainClaim,
			blockState: state.Compromised, blockReason: state.FalseChainClaim,
		},
		{
			reason: state.FalseChainClaim, name: "the receipt overstates the tip far past Core's",
			build: func(t *testing.T) Block {
				f := newFixture(t, 250)
				L := leaves(4, "a")
				return f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1),
					signedTip(400, sha256.Sum256([]byte("fake tip")))))
			},
			server: "w", state: state.Compromised, want: state.FalseChainClaim,
		},
		{
			reason: state.FalseChainClaim, name: "the signed tip is on no chain and more than the margin behind Core",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				return f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1),
					signedTip(coreTip-TipMargin-1, sha256.Sum256([]byte("stale fork")))))
			},
			server: "w", state: state.Compromised, want: state.FalseChainClaim,
		},
		{
			reason: state.ServedContradictsRecord, name: "the list is shorter than n",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				return f.block(f.srv("w", newKey(t, 2), L, full(L[:3])))
			},
			server: "w", state: state.Compromised, want: state.ServedContradictsRecord,
			blockState: state.Compromised, blockReason: state.ServedContradictsRecord,
		},
		{
			reason: state.ServedContradictsRecord, name: "an unsigned list of the wrong length is still accused",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				return f.block(f.srv("w", newKey(t, 2), L, full(L[:3]), noReceipt()))
			},
			server: "w", state: state.Compromised, want: state.ServedContradictsRecord,
		},
		{
			reason: state.ServedContradictsRecord, name: "a signed list fails the reader rules",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				return f.block(f.srv("w", newKey(t, 2), L, nil, rawBody(append(le32(1), 0x07))))
			},
			server: "w", state: state.Compromised, want: state.ServedContradictsRecord,
		},
		{
			reason: state.ServedContradictsRecord, name: "the recomputed root differs from the signed root",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				served := full(L)
				served[2] = full(leaves(1, "other"))[0]
				return f.block(f.srv("w", newKey(t, 2), L, served))
			},
			server: "w", state: state.Compromised, want: state.ServedContradictsRecord,
		},
		{
			reason: state.ExpectedPaymentNotInRecord, name: "the signed record leaves a declared payment out",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				f.payments = []Payment{{Entry: leaves(1, "paid")[0], Outputs: []Output{spent(5000)}}}
				return f.block(f.srv("w", newKey(t, 2), L, full(L)))
			},
			server: "w", state: state.Compromised, want: state.ExpectedPaymentNotInRecord,
			blockState: state.Compromised, blockReason: state.ExpectedPaymentNotInRecord,
		},
		{
			reason: state.ExpectedPaymentNotInList, name: "a declared payment sent as a hash while its output is unspent",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				f.payments = []Payment{{Entry: L[2], Outputs: []Output{unspent(10000)}}}
				return f.block(f.srv("w", newKey(t, 2), L, hashAt(full(L), 2), prunes()))
			},
			server: "w", state: state.Compromised, want: state.ExpectedPaymentNotInList,
			blockState: state.Compromised, blockReason: state.ExpectedPaymentNotInList,
		},
		{
			reason: state.ExpectedPaymentNotInList, name: "a declared payment absent outside the window while its output is unspent",
			build: func(t *testing.T) Block {
				f := newFixture(t, deep)
				L := leaves(4, "a")
				f.payments = []Payment{{Entry: L[1], Outputs: []Output{spent(900), unspent(10000)}}}
				return f.block(
					f.srv("w", newKey(t, 2), L, absentAt(full(L), 1), prunes()),
					f.srv("b", newKey(t, 3), L, full(L)),
				)
			},
			server: "w", state: state.Compromised, want: state.ExpectedPaymentNotInList,
			blockState: state.Compromised, blockReason: state.ExpectedPaymentNotInList,
		},
		{
			reason: state.ExpectedPaymentNotInList, name: "an unspent output below the declared dust threshold is hash only",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				f.payments = []Payment{{Entry: L[2], Outputs: []Output{unspent(300)}}}
				return f.block(f.srv("w", newKey(t, 2), L, hashAt(full(L), 2),
					withPolicy(&policy.Policy{Network: regtest, PrunesSpent: true, DustThresholdSat: 1000})))
			},
			server: "w", state: state.Resolved, want: state.HashRetained,
		},

		// the warning
		{
			reason: state.HashWithoutPolicy, name: "a server that declares no pruning sends a hash",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				return f.block(f.srv("a", newKey(t, 1), L, hashAt(full(L), 1, 2)))
			},
			server: "a", state: state.Resolved, want: state.HashRetained,
			warnings:   []state.Reason{state.HashWithoutPolicy},
			blockState: state.Resolved, blockReason: state.HashRetained,
		},
		{
			reason: state.HashWithoutPolicy, name: "a server whose /info did not answer declared nothing, so no warning",
			build: func(t *testing.T) Block {
				f := newFixture(t, recent)
				L := leaves(4, "a")
				return f.block(f.srv("a", newKey(t, 1), L, hashAt(full(L), 1), withPolicy(nil)))
			},
			server: "a", state: state.Resolved, want: state.HashRetained,
		},
	}
}

func TestEveryReason(t *testing.T) {
	for _, c := range reasonCases() {
		t.Run(string(c.reason)+"/"+c.name, func(t *testing.T) {
			res := evaluate(t, c.build(t))
			got := byLabel(t, res, c.server)
			if got.State != c.state || got.Reason != c.want {
				t.Errorf("server %s = %s/%s, want %s/%s (record err %v, receipt err %v, list err %v)",
					c.server, got.State, got.Reason, c.state, c.want, got.RecordErr, got.ReceiptErr, got.ListErr)
			}
			if !slices.Equal(got.Warnings, c.warnings) {
				t.Errorf("server %s warnings = %v, want %v", c.server, got.Warnings, c.warnings)
			}
			if c.blockState != "" && (res.State != c.blockState || res.Reason != c.blockReason) {
				t.Errorf("block = %s/%s, want %s/%s", res.State, res.Reason, c.blockState, c.blockReason)
			}
		})
	}
}

// The table must exercise every reason the wording table explains, so a new
// reason cannot ship without a row that produces it.
func TestReasonTableCoversEveryReason(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range reasonCases() {
		covered[string(c.reason)] = true
	}
	for _, code := range wording.ReasonCodes() {
		if !covered[code] {
			t.Errorf("no row in the reason table exercises %q", code)
		}
	}
}

// Every reason the ladder records belongs to the state it records with it,
// and every warning is one the formats allow.
func TestReasonsBelongToTheirStates(t *testing.T) {
	allowed := map[state.Reason]bool{
		state.NoRecordForBlock: true, state.ListNotServed: true,
		state.ListUnreadable: true, state.HashWithoutPolicy: true,
	}
	for _, c := range reasonCases() {
		res := evaluate(t, c.build(t))
		for _, s := range append(res.Servers, ServerResult{Label: "block", State: res.State, Reason: res.Reason}) {
			if st, ok := state.StateOf(s.Reason); !ok || st != s.State {
				t.Errorf("%s: %s carries %s/%s, which the formats do not pair", c.name, s.Label, s.State, s.Reason)
			}
			for _, w := range s.Warnings {
				if !allowed[w] {
					t.Errorf("%s: %s carries warning %s, which is not a warning reason", c.name, s.Label, w)
				}
			}
		}
	}
}

// The branch scene: an attacker signs a record without the payment, so its
// root differs from the honest server's. A declared payment turns the block
// into Data withheld, which outranks Servers disagree.
func TestDeclaredPaymentOutranksServersDisagree(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(4, "a")
	paid := L[2]
	withoutPaid := append(append([]canonical.Leaf(nil), L[:2]...), L[3])
	f.payments = []Payment{{Entry: paid, Outputs: []Output{unspent(5000)}}}
	res := evaluate(t, f.block(
		f.srv("honest", newKey(t, 1), L, full(L)),
		f.srv("withholder", newKey(t, 2), withoutPaid, full(withoutPaid)),
	))
	if res.State != state.Compromised || res.Reason != state.ExpectedPaymentNotInRecord {
		t.Errorf("block = %s/%s, want compromised/expected_payment_not_in_record", res.State, res.Reason)
	}
	h := byLabel(t, res, "honest")
	if h.State != state.Disputed || h.Reason != state.RecordsDiffer {
		t.Errorf("honest = %s/%s, want disputed/records_differ", h.State, h.Reason)
	}
	if len(res.Disagreements) != 1 || res.Disagreements[0] != (Disagreement{First: "honest", Second: "withholder"}) {
		t.Errorf("disagreements = %v, want one between honest and withholder", res.Disagreements)
	}
	if got := byLabel(t, res, "withholder").Payments; len(got) != 1 || got[0].Outcome != PaymentWithheld {
		t.Errorf("withholder payment outcomes = %v, want withheld", got)
	}
	if got := h.Payments; len(got) != 1 || got[0].Outcome != PaymentFound {
		t.Errorf("honest payment outcomes = %v, want found", got)
	}
}

// A list whose positions cannot be matched to the record stops at decoding:
// no window, no fill, no root.
func TestWrongLengthStopsBeforeTheWindow(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(4, "a")
	res := evaluate(t, f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L[:3]), 1))))
	w := byLabel(t, res, "w")
	if w.Reason != state.ServedContradictsRecord {
		t.Errorf("reason = %s, want served_contradicts_record, not absent_in_window", w.Reason)
	}
	if w.RootRecomputed || len(w.Gaps) != 0 {
		t.Errorf("a wrong-length list must not be filled or recomputed: recomputed %v, gaps %v", w.RootRecomputed, w.Gaps)
	}
	if w.Positions == nil || *w.Positions != (state.Positions{Full: 2, Absent: 1}) {
		t.Errorf("positions = %+v, want the decoded counts", w.Positions)
	}
}

// A server with no record is never asked about its list, so a pinned-none
// server with an unreachable flag still reads unreachable.
func TestUnreachableWinsOverEveryOtherNoRecordReason(t *testing.T) {
	f := newFixture(t, recent)
	s := f.srv("a", newKey(t, 1), nil, nil, noRecord(), noList())
	s.Unreachable = true
	s.Tip = u32(0)
	s.RecordBelow, s.RecordAbove = true, true
	got := byLabel(t, evaluate(t, f.block(s)), "a")
	if got.Reason != state.ServerUnreachable || len(got.Warnings) != 0 {
		t.Errorf("got %s with warnings %v, want server_unreachable and no warning", got.Reason, got.Warnings)
	}
}

// The signed tip from a valid receipt is reported, so the state file can
// show it.
func TestSignedResultReportsTheReceipt(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(3, "a")
	got := byLabel(t, evaluate(t, f.block(f.srv("a", newKey(t, 1), L, full(L)))), "a")
	if !got.Signed || got.Receipt == nil || got.Receipt.TipHeight != coreTip {
		t.Fatalf("signed = %v, receipt = %+v, want a valid receipt with tip %d", got.Signed, got.Receipt, coreTip)
	}
	if got.Record == nil || got.Record.Commitment.N != 3 || got.Record.Event.ID == "" {
		t.Errorf("record = %+v, want the checked record", got.Record)
	}
	if got.Positions == nil || *got.Positions != (state.Positions{Full: 3}) {
		t.Errorf("positions = %+v, want 3 full", got.Positions)
	}
}

// An empty block is committed, not skipped. Its four-byte list checks out.
func TestEmptyBlockIsChecked(t *testing.T) {
	f := newFixture(t, recent)
	got := byLabel(t, evaluate(t, f.block(f.srv("a", newKey(t, 1), nil, []wire.Position{}))), "a")
	if got.State != state.Verified || !got.RootRecomputed {
		t.Errorf("empty block = %s/%s recomputed %v, want verified with a recomputed root", got.State, got.Reason, got.RootRecomputed)
	}
}
