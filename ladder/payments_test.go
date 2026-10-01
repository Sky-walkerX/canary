package ladder

import (
	"math"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/policy"
	"github.com/Sky-walkerX/canary/wire"
)

// paymentOutcome returns the server's outcome for its only declared payment.
func paymentOutcome(t *testing.T, r ServerResult) string {
	t.Helper()
	if len(r.Payments) != 1 {
		t.Fatalf("%s: payments = %+v, want one outcome", r.Label, r.Payments)
	}
	return r.Payments[0].Outcome
}

// A result from the window step stands whatever the payment step finds. The
// first reason in step order is the one recorded.
func TestPaymentStepKeepsAnEarlierAccusation(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(4, "a")
	f.payments = []Payment{{Entry: leaves(1, "paid")[0], Outputs: []Output{spent(5000)}}}
	res := evaluate(t, f.block(
		f.srv("w", newKey(t, 2), L, absentAt(full(L), 1)),
		f.srv("b", newKey(t, 3), L, full(L)),
	))
	w := byLabel(t, res, "w")
	if w.State != state.Compromised || w.Reason != state.AbsentInWindow {
		t.Errorf("w = %s/%s, want compromised/absent_in_window kept from the window step", w.State, w.Reason)
	}
	if !w.RootMatched {
		t.Fatal("test setup: w's root must match, or the payment step never reaches the record")
	}
	if got := paymentOutcome(t, w); got != PaymentWithheld {
		t.Errorf("w payment outcome = %s, want withheld", got)
	}
}

// A payment whose entry was absent where the rule forbids it is withheld,
// even when every output is spent. Pruning cannot excuse what the window
// rule already named.
func TestPaymentLeftOutWhereTheRuleForbidsItIsWithheld(t *testing.T) {
	cases := []struct {
		name   string
		height uint32
		opts   []opt
		want   state.Reason
	}{
		{"inside the window", recent, nil, state.AbsentInWindow},
		{"excused by a false chain claim", deep, []opt{recordHeight(deep - 50)}, state.FalseChainClaim},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.height)
			L := leaves(4, "a")
			f.payments = []Payment{{Entry: L[1], Outputs: []Output{spent(5000)}}}
			w := byLabel(t, evaluate(t, f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1), c.opts...))), "w")
			if w.Reason != c.want {
				t.Errorf("w = %s/%s, want %s", w.State, w.Reason, c.want)
			}
			if got := paymentOutcome(t, w); got != PaymentWithheld {
				t.Errorf("payment outcome = %s, want withheld: the list left it out where that is not permitted", got)
			}
		})
	}
}

// The dust test is "at or above" the threshold. An unspent output worth
// exactly the threshold is not dust, so pruning cannot explain it. The list
// carries no receipt, so the declared threshold is the one that applies.
func TestUnspentOutputAtTheDustThresholdIsNotDust(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(4, "a")
	f.payments = []Payment{{Entry: L[2], Outputs: []Output{unspent(1000)}}}
	w := byLabel(t, evaluate(t, f.block(f.srv("w", newKey(t, 2), L, hashAt(full(L), 2), noReceipt(),
		withPolicy(&policy.Policy{Network: regtest, PrunesSpent: true, DustThresholdSat: 1000})))), "w")
	if w.State != state.Compromised || w.Reason != state.ExpectedPaymentNotInList {
		t.Errorf("w = %s/%s, want compromised/expected_payment_not_in_list", w.State, w.Reason)
	}
	if got := paymentOutcome(t, w); got != PaymentWithheld {
		t.Errorf("payment outcome = %s, want withheld", got)
	}
}

// A list that carries the payment in full has shown it, even when a gap
// elsewhere left the root uncomputed.
func TestPaymentCarriedInFullIsFoundDespiteAnUnfilledGap(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(4, "a")
	f.payments = []Payment{{Entry: L[2], Outputs: []Output{unspent(5000)}}}
	w := byLabel(t, evaluate(t, f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 0)))), "w")
	if w.State != state.Unresolvable || w.Reason != state.GapUnfilled || w.RootRecomputed {
		t.Fatalf("test setup: w = %s/%s recomputed %v, want unresolvable/gap_unfilled with no root",
			w.State, w.Reason, w.RootRecomputed)
	}
	if got := paymentOutcome(t, w); got != PaymentFound {
		t.Errorf("payment outcome = %s, want found", got)
	}
}

// /info is unsigned, so a dust threshold declared there cannot excuse an entry
// held back from a list that came with a valid receipt. canary check asks for
// no threshold, and the receipt signs the threshold the server applied: 0. A
// withholder that declares a huge threshold is still named by the tripwire.
func TestReceiptDustThresholdOutranksTheDeclaredOne(t *testing.T) {
	huge := withPolicy(&policy.Policy{Network: regtest, PrunesSpent: true, DustThresholdSat: math.MaxUint64})
	cases := []struct {
		name   string
		height uint32
		served func(L []canonical.Leaf) []wire.Position
	}{
		{"the entry sent as a hash", recent, func(L []canonical.Leaf) []wire.Position { return hashAt(full(L), 2) }},
		{"the entry absent past the window", deep, func(L []canonical.Leaf) []wire.Position { return absentAt(full(L), 2) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.height)
			L := leaves(4, "a")
			f.payments = []Payment{{Entry: L[2], Outputs: []Output{unspent(10000)}}}
			w := byLabel(t, evaluate(t, f.block(f.srv("w", newKey(t, 2), L, c.served(L), huge))), "w")
			if !w.Signed || w.Receipt == nil || w.Receipt.DustSat != 0 {
				t.Fatalf("test setup: signed %v, receipt %+v, want a valid receipt for dust 0", w.Signed, w.Receipt)
			}
			if w.State != state.Compromised || w.Reason != state.ExpectedPaymentNotInList {
				t.Errorf("w = %s/%s, want compromised/expected_payment_not_in_list", w.State, w.Reason)
			}
			if got := paymentOutcome(t, w); got != PaymentWithheld {
				t.Errorf("payment outcome = %s, want withheld", got)
			}
		})
	}
}

// Without a receipt nothing signed says which threshold the server applied.
// Canary then falls back to the threshold the server declared, an unsigned
// claim, so that a server with a real dust filter is not accused.
func TestUnsignedListFallsBackToTheDeclaredDustThreshold(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(4, "a")
	f.payments = []Payment{{Entry: L[2], Outputs: []Output{unspent(300)}}}
	w := byLabel(t, evaluate(t, f.block(f.srv("w", newKey(t, 2), L, hashAt(full(L), 2), noReceipt(),
		withPolicy(&policy.Policy{Network: regtest, PrunesSpent: true, DustThresholdSat: 1000})))), "w")
	if w.State != state.Resolved || w.Reason != state.HashRetained {
		t.Errorf("w = %s/%s, want resolved/hash_retained", w.State, w.Reason)
	}
	if got := paymentOutcome(t, w); got != PaymentHashOnly {
		t.Errorf("payment outcome = %s, want hash_only", got)
	}
	if !w.Payments[0].DustExcused {
		t.Error("DustExcused = false: only the declared threshold excused an unspent output, and the result must say so")
	}
}

// DustExcused marks only the case where the declared threshold was the
// excuse: an unsigned list, and an output Core shows unspent below that
// threshold. Pruning explains a payment whose outputs are all spent, and a
// receipted list is judged by the threshold its receipt signs.
func TestDustExcusedOnlyWhenTheDeclaredThresholdExcuses(t *testing.T) {
	declared := withPolicy(&policy.Policy{Network: regtest, PrunesSpent: true, DustThresholdSat: 1000})
	cases := []struct {
		name    string
		outputs []Output
		opts    []opt
		outcome string
		excused bool
	}{
		{"unsigned, unspent below the threshold", []Output{unspent(300)}, []opt{noReceipt(), declared}, PaymentHashOnly, true},
		{"unsigned, every output spent", []Output{spent(300)}, []opt{noReceipt(), declared}, PaymentHashOnly, false},
		{"unsigned, unspent above the threshold", []Output{unspent(5000)}, []opt{noReceipt(), declared}, PaymentWithheld, false},
		{"unsigned, no threshold declared", []Output{spent(300)}, []opt{noReceipt(), prunes()}, PaymentHashOnly, false},
		{"receipted, unspent below the declared threshold", []Output{unspent(300)}, []opt{declared}, PaymentWithheld, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, recent)
			L := leaves(4, "a")
			f.payments = []Payment{{Entry: L[2], Outputs: c.outputs}}
			w := byLabel(t, evaluate(t, f.block(f.srv("w", newKey(t, 2), L, hashAt(full(L), 2), c.opts...))), "w")
			if got := paymentOutcome(t, w); got != c.outcome {
				t.Errorf("payment outcome = %s, want %s", got, c.outcome)
			}
			if got := w.Payments[0].DustExcused; got != c.excused {
				t.Errorf("DustExcused = %v, want %v", got, c.excused)
			}
		})
	}
}
