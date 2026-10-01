package ladder

import (
	"crypto/sha256"
	"testing"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/wire"
)

// alter returns a copy of body with one byte flipped, as a proxy or anyone
// on the path between the server and Canary could.
func alter(body []byte, at int) []byte {
	out := append([]byte(nil), body...)
	out[at] ^= 0x01
	return out
}

// A receipt the pinned key signed, for bytes other than the ones received,
// shows that something between the server and Canary changed the list. The
// server's signature covers what it sent, not what arrived, so Canary judges
// nothing from those bytes. The list reads as not served, with no warning,
// because nothing shows the server did anything.
func TestListAlteredInTransitAccusesNobody(t *testing.T) {
	cases := []struct {
		name   string
		height uint32
		mangle func(t *testing.T, body []byte) []byte
	}{
		{"a byte of an entry flipped", recent, func(_ *testing.T, b []byte) []byte { return alter(b, len(b)-1) }},
		{"a position turned absent", recent, func(t *testing.T, b []byte) []byte {
			L := leaves(4, "a")
			return encode(t, absentAt(full(L), 1))
		}},
		{"a position cut off", deep, func(t *testing.T, b []byte) []byte {
			L := leaves(4, "a")
			return encode(t, full(L[:3]))
		}},
		{"bytes that do not decode", recent, func(_ *testing.T, b []byte) []byte { return append(le32(1), 0x07) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.height)
			L := leaves(4, "a")
			f.payments = []Payment{{Entry: L[1], Outputs: []Output{unspent(5000)}}}
			s := f.srv("a", newKey(t, 1), L, full(L))
			s.List.Body = c.mangle(t, s.List.Body)
			res := evaluate(t, f.block(s))
			a := byLabel(t, res, "a")
			if a.State != state.Unresolvable || a.Reason != state.ListNotServed {
				t.Errorf("a = %s/%s, want unresolvable/list_not_served", a.State, a.Reason)
			}
			if !a.ListAltered || a.Signed || a.ReceiptErr == nil {
				t.Errorf("altered %v, signed %v, receipt err %v: want an altered, unsigned list with the receipt's error", a.ListAltered, a.Signed, a.ReceiptErr)
			}
			if len(a.Warnings) != 0 || len(a.Gaps) != 0 || a.Positions != nil {
				t.Errorf("warnings %v, gaps %v, positions %v: an altered list must not be judged", a.Warnings, a.Gaps, a.Positions)
			}
			if got := paymentOutcome(t, a); got != PaymentUnresolvable {
				t.Errorf("payment outcome = %s, want unresolvable", got)
			}
			if res.State == state.Compromised {
				t.Errorf("block = %s/%s, want no accusation", res.State, res.Reason)
			}
		})
	}
}

// The same holds when the pinned key signed a receipt for another request: a
// receipt replayed from another block or network, or one for a filtered
// list. The bytes it covers are not this block's full list.
func TestReceiptForAnotherRequestAccusesNobody(t *testing.T) {
	cases := []struct {
		name string
		edit func(r *wire.Receipt)
	}{
		{"another block", func(r *wire.Receipt) { r.BlockHash = blockHash(recent - 1) }},
		{"another network", func(r *wire.Receipt) { r.Network = 0x0709110b }},
		{"a dust threshold", func(r *wire.Receipt) { r.DustSat = 546 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, recent)
			L := leaves(4, "a")
			k := newKey(t, 1)
			s := f.srv("a", k, L, absentAt(full(L), 1))
			r := wire.Receipt{
				Network: regtest, Resource: wire.ResourceTweakList, BlockHash: f.hash,
				TipHeight: coreTip, TipHash: f.chain[coreTip], BodySHA256: sha256.Sum256(s.List.Body),
			}
			c.edit(&r)
			r, err := wire.SignReceipt(r, k.sk)
			if err != nil {
				t.Fatal(err)
			}
			s.List.Receipt = wire.EncodeReceiptHeader(r)
			a := byLabel(t, evaluate(t, f.block(s)), "a")
			if a.State != state.Unresolvable || a.Reason != state.ListNotServed || !a.ListAltered {
				t.Errorf("a = %s/%s altered %v, want unresolvable/list_not_served, altered", a.State, a.Reason, a.ListAltered)
			}
		})
	}
}

// A receipt the pinned key did not sign proves nothing about who changed
// what, so the list stays unsigned and is judged on what Canary saw, as
// before. That is safe only because canary check reads a server over https,
// or plain http to this computer. Then nobody else could have stripped or
// swapped the receipt, and the bytes are the ones the server sent
// (TestCheckTakesHTTPSOrPlainHTTPToThisComputer).
func TestReceiptByAnotherKeyLeavesTheListUnsigned(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(4, "a")
	s := f.srv("w", newKey(t, 2), L, absentAt(full(L), 1))
	s.List.Receipt = signReceipt(t, newKey(t, 9), f.hash, coreTip, f.chain[coreTip], s.List.Body)
	w := byLabel(t, evaluate(t, f.block(s)), "w")
	if w.ListAltered || w.Signed || w.State != state.Compromised || w.Reason != state.AbsentInWindow {
		t.Errorf("w = %s/%s altered %v signed %v, want compromised/absent_in_window, unsigned, not altered",
			w.State, w.Reason, w.ListAltered, w.Signed)
	}
}
