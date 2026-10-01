package ladder

import (
	"testing"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/wire"
)

// canary check writes one finding per accusation. A payment's result names
// the accusation it raised, so check does not rebuild the payment step.
func TestPaymentResultNamesTheAccusationItRaised(t *testing.T) {
	L := leaves(4, "a")
	outsider := leaves(1, "paid")[0]
	cases := []struct {
		name    string
		height  uint32
		payment Payment
		list    func() []wire.Position
		outcome string
		reason  state.Reason
	}{
		{"missing from the record", recent, Payment{Entry: outsider, Outputs: []Output{unspent(5000)}},
			func() []wire.Position { return full(L) }, PaymentWithheld, state.ExpectedPaymentNotInRecord},
		{"sent as a hash while unspent", recent, Payment{Entry: L[2], Outputs: []Output{unspent(5000)}},
			func() []wire.Position { return hashAt(full(L), 2) }, PaymentWithheld, state.ExpectedPaymentNotInList},
		{"absent inside the window", recent, Payment{Entry: L[1], Outputs: []Output{unspent(5000)}},
			func() []wire.Position { return absentAt(full(L), 1) }, PaymentWithheld, ""},
		{"sent as a hash once spent", recent, Payment{Entry: L[2], Outputs: []Output{spent(5000)}},
			func() []wire.Position { return hashAt(full(L), 2) }, PaymentHashOnly, ""},
		{"carried in full", recent, Payment{Entry: L[3], Outputs: []Output{unspent(5000)}},
			func() []wire.Position { return full(L) }, PaymentFound, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.height)
			f.payments = []Payment{c.payment}
			// A second full server proves the root, so the absent case fills.
			w := byLabel(t, evaluate(t, f.block(
				f.srv("w", newKey(t, 2), L, c.list()),
				f.srv("b", newKey(t, 3), L, full(L)),
			)), "w")
			if len(w.Payments) != 1 {
				t.Fatalf("payments = %+v, want one", w.Payments)
			}
			got := w.Payments[0]
			if got.Outcome != c.outcome || got.Reason != c.reason {
				t.Errorf("payment = %s/%q, want %s/%q", got.Outcome, got.Reason, c.outcome, c.reason)
			}
		})
	}
}
