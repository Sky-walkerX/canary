package ladder

import (
	"crypto/sha256"
	"fmt"
	"math"
	"testing"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/wire"
)

// The window boundary, measured from the signed values. The receipt's tip is
// 250, not Core's 300, so the test also shows that the signed tip decides:
// by Core's tip every one of these blocks would sit outside the window.
func TestRetentionBoundaryBySignedValues(t *testing.T) {
	const tip uint32 = 250
	cases := []struct {
		depth uint32
		want  state.Reason
	}{
		{143, state.AbsentInWindow},
		{144, state.GapUnfilled},
		{145, state.GapUnfilled},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("depth %d", c.depth), func(t *testing.T) {
			height := tip - c.depth
			inside := c.depth < wire.RetentionWindow
			if got := wire.InsideRetentionWindow(tip, height); got != inside {
				t.Fatalf("wire.InsideRetentionWindow(%d, %d) = %v, the test expects %v", tip, height, got, inside)
			}
			if wire.InsideRetentionWindow(coreTip, height) {
				t.Fatalf("test setup: height %d must sit outside the window by Core's tip", height)
			}

			f := newFixture(t, height)
			L := leaves(3, "a")
			w := byLabel(t, evaluate(t, f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1),
				signedTip(tip, f.chain[tip])))), "w")
			if w.Reason != c.want {
				t.Errorf("depth %d: %s/%s, want %s", c.depth, w.State, w.Reason, c.want)
			}
		})
	}
}

// Without a receipt there is no signed tip, so depth comes from Core's tip and
// Core's height for the block. Core may be a few blocks behind the server,
// and a server that far ahead may already have let the block leave the
// window. So an unsigned list is accused only below depth 144 - TipMargin by
// Core's tip. Nearer the edge the absence reads Can't be checked.
func TestRetentionBoundaryByCoreWithoutAReceipt(t *testing.T) {
	cases := []struct {
		depth uint32
		want  state.Reason
	}{
		{wire.RetentionWindow - TipMargin - 1, state.AbsentInWindow},
		{wire.RetentionWindow - TipMargin, state.TipUnconfirmed},
		{143, state.TipUnconfirmed},
		{144, state.GapUnfilled},
		{145, state.GapUnfilled},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("depth %d", c.depth), func(t *testing.T) {
			height := coreTip - c.depth
			if got, want := wire.InsideRetentionWindow(coreTip, height), c.depth < wire.RetentionWindow; got != want {
				t.Fatalf("wire.InsideRetentionWindow(%d, %d) = %v, want %v", coreTip, height, got, want)
			}
			f := newFixture(t, height)
			L := leaves(3, "a")
			w := byLabel(t, evaluate(t, f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1), noReceipt()))), "w")
			if w.Reason != c.want || w.Signed {
				t.Errorf("depth %d: %s/%s signed %v, want %s unsigned", c.depth, w.State, w.Reason, w.Signed, c.want)
			}
			if len(w.Warnings) != 0 {
				t.Errorf("depth %d: warnings %v, want none", c.depth, w.Warnings)
			}
		})
	}
}

// Each path reads the block height from its own source. A signed list takes it
// from the record, the same value canary verify reads. An unsigned list takes
// it from Core, because no signed tip exists to pair with the record's. In
// both rows the two heights disagree about the window, so a swap shows.
func TestRetentionReadsTheHeightFromTheRightSource(t *testing.T) {
	t.Run("unsigned list uses Core's height, not the record's", func(t *testing.T) {
		f := newFixture(t, recent)
		L := leaves(4, "a")
		if wire.InsideRetentionWindow(coreTip, deep) || !wire.InsideRetentionWindow(coreTip, recent) {
			t.Fatal("test setup: the record's height must sit outside the window and Core's inside")
		}
		res := evaluate(t, f.block(
			f.srv("w", newKey(t, 2), L, absentAt(full(L), 1), noReceipt(), recordHeight(deep)),
			f.srv("b", newKey(t, 3), L, full(L)),
		))
		w := byLabel(t, res, "w")
		if w.State != state.Compromised || w.Reason != state.AbsentInWindow || w.Signed {
			t.Errorf("w = %s/%s signed %v, want compromised/absent_in_window unsigned", w.State, w.Reason, w.Signed)
		}
		if res.State != state.Compromised || res.Reason != state.AbsentInWindow {
			t.Errorf("block = %s/%s, want compromised/absent_in_window", res.State, res.Reason)
		}
	})
	t.Run("signed list uses the record's height, not Core's", func(t *testing.T) {
		f := newFixture(t, deep)
		L := leaves(4, "a")
		if !wire.InsideRetentionWindow(coreTip, recent) || wire.InsideRetentionWindow(coreTip, deep) {
			t.Fatal("test setup: the record's height must sit inside the window and Core's outside")
		}
		res := evaluate(t, f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1), recordHeight(recent))))
		w := byLabel(t, res, "w")
		if w.State != state.Compromised || w.Reason != state.AbsentInWindow || !w.Signed {
			t.Errorf("w = %s/%s signed %v, want compromised/absent_in_window signed, the answer canary verify gives",
				w.State, w.Reason, w.Signed)
		}
	})
}

// A block above the server's own signed tip counts as inside. A server cannot
// escape the rule by understating its tip.
func TestBlockAboveTheSignedTipIsInside(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(3, "a")
	w := byLabel(t, evaluate(t, f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1),
		signedTip(recent-10, f.chain[recent-10])))), "w")
	if w.Reason != state.AbsentInWindow {
		t.Errorf("%s/%s, want absent_in_window", w.State, w.Reason)
	}
}

// Core is consulted only when the signed values put the block outside the
// window. A block inside needs no chain view at all.
func TestInsideTheWindowNeedsNoChainView(t *testing.T) {
	f := newFixture(t, recent)
	L := leaves(3, "a")
	b := f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1)))
	b.Core.Chain = nil
	if w := byLabel(t, evaluate(t, b), "w"); w.Reason != state.AbsentInWindow {
		t.Errorf("%s/%s, want absent_in_window", w.State, w.Reason)
	}
}

// Outside the window the signed tip must be checked, so a missing chain view
// is an error, not a guess.
func TestOutsideTheWindowWithoutAChainViewFails(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(3, "a")
	b := f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1)))
	b.Core.Chain = nil
	if _, err := Evaluate(b); err == nil {
		t.Error("Evaluate succeeded without a chain view it needed")
	}
}

// A chain error from Core stops the run: it is an operational failure, never
// a result about the server.
func TestChainErrorIsReturned(t *testing.T) {
	f := newFixture(t, deep)
	L := leaves(3, "a")
	b := f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1)))
	b.Core.Chain = failingChain{}
	if _, err := Evaluate(b); err == nil {
		t.Error("Evaluate hid a chain error")
	}
}

type failingChain struct{}

func (failingChain) ActiveHash(uint32) ([32]byte, bool, error) {
	return [32]byte{}, false, fmt.Errorf("core unreachable")
}

// A Core node behind the server is no reason to accuse it. Here Core's tip is
// 300 and the honest server signed its real tip, 320, a block Core has not
// seen yet. By that tip block 100 sits past the window, so the absence is
// permitted if the tip is real. Canary can't tell yet, so the block reads
// Can't be checked, never Data withheld.
func TestLaggingCoreAccusesNobody(t *testing.T) {
	const ahead = coreTip + 20
	f := newFixture(t, deep)
	if _, ok := f.chain[ahead]; ok {
		t.Fatal("test setup: Core must not have a block at the server's tip")
	}
	L := leaves(4, "a")
	res := evaluate(t, f.block(f.srv("honest", newKey(t, 1), L, absentAt(full(L), 1),
		signedTip(ahead, blockHash(ahead)))))
	h := byLabel(t, res, "honest")
	if h.State != state.Unresolvable || h.Reason != state.TipUnconfirmed {
		t.Errorf("honest = %s/%s, want unresolvable/tip_unconfirmed", h.State, h.Reason)
	}
	if res.State == state.Compromised {
		t.Errorf("block = %s/%s: a lagging Core made Canary accuse an honest server", res.State, res.Reason)
	}
	if len(h.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", h.Warnings)
	}
	if !h.TipUnconfirmed {
		t.Error("TipUnconfirmed = false, want true")
	}
}

// The signed tip is judged against Core only when the signed values put the
// block past the window. A tip Core holds a different block for is a false
// claim only when that height sits more than TipMargin blocks below Core's
// tip. A tip at or above Core's tip is never one, because Core may be behind.
func TestSignedTipAgainstCore(t *testing.T) {
	other := func(h uint32) [32]byte { return sha256.Sum256([]byte(fmt.Sprintf("fork block %d", h))) }
	cases := []struct {
		name    string
		tip     uint32
		tipHash func(f *fixture, h uint32) [32]byte
		advance uint32 // blocks Core gained since the run read its tip
		want    state.Reason
	}{
		{"on Core's chain", coreTip, func(f *fixture, h uint32) [32]byte { return f.chain[h] }, 0, state.GapUnfilled},
		{"one block above Core's tip", coreTip + 1, func(_ *fixture, h uint32) [32]byte { return blockHash(h) }, 0, state.TipUnconfirmed},
		{"twenty blocks above Core's tip", coreTip + 20, func(_ *fixture, h uint32) [32]byte { return blockHash(h) }, 0, state.TipUnconfirmed},
		{"above any height Core reads", 1 << 31, func(_ *fixture, h uint32) [32]byte { return other(h) }, 0, state.TipUnconfirmed},
		{"the largest height", math.MaxUint32, func(_ *fixture, h uint32) [32]byte { return other(h) }, 0, state.TipUnconfirmed},
		{"at Core's tip, another block", coreTip, func(_ *fixture, h uint32) [32]byte { return other(h) }, 0, state.TipUnconfirmed},
		{"TipMargin below Core's tip, another block", coreTip - TipMargin, func(_ *fixture, h uint32) [32]byte { return other(h) }, 0, state.TipUnconfirmed},
		{"more than TipMargin below Core's tip, another block", coreTip - TipMargin - 1, func(_ *fixture, h uint32) [32]byte { return other(h) }, 0, state.FalseChainClaim},
		{"Core reached the tip during the run, same block", coreTip + 5, func(_ *fixture, h uint32) [32]byte { return blockHash(h) }, 10, state.GapUnfilled},
		{"Core reached the tip during the run, another block", coreTip + 5, func(_ *fixture, h uint32) [32]byte { return other(h) }, 10, state.TipUnconfirmed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, deep)
			for h := coreTip + 1; h <= coreTip+c.advance; h++ {
				f.chain[h] = blockHash(h)
			}
			L := leaves(4, "a")
			w := byLabel(t, evaluate(t, f.block(f.srv("w", newKey(t, 2), L, absentAt(full(L), 1),
				signedTip(c.tip, c.tipHash(f, c.tip))))), "w")
			if w.Reason != c.want {
				t.Errorf("w = %s/%s, want %s", w.State, w.Reason, c.want)
			}
			if want := c.want == state.TipUnconfirmed; w.TipUnconfirmed != want {
				t.Errorf("TipUnconfirmed = %v, want %v", w.TipUnconfirmed, want)
			}
		})
	}
}

// TipUnconfirmed outlives a filled gap, so canary check can still say that an
// unconfirmed tip excused it. A full list never sets it, whatever its tip.
func TestTipUnconfirmedOutlivesAFilledGap(t *testing.T) {
	const ahead = coreTip + 20
	f := newFixture(t, deep)
	L := leaves(4, "a")
	res := evaluate(t, f.block(
		f.srv("w", newKey(t, 2), L, absentAt(full(L), 1), signedTip(ahead, blockHash(ahead))),
		f.srv("h", newKey(t, 1), L, full(L), signedTip(ahead, blockHash(ahead))),
	))
	w, h := byLabel(t, res, "w"), byLabel(t, res, "h")
	if w.State != state.Resolved || w.Reason != state.FilledFromServer || !w.TipUnconfirmed {
		t.Errorf("w = %s/%s TipUnconfirmed %v, want resolved/filled_from_server and true", w.State, w.Reason, w.TipUnconfirmed)
	}
	if h.TipUnconfirmed {
		t.Error("h: TipUnconfirmed = true for a full list")
	}
}

// A Core node behind the server is no reason to accuse a server that sends
// no receipts either. Without a signed tip, the tip the server's /info
// declares may excuse an absence, never convict: Core's tip is 300, the
// server declares 320, and blocks 160 and 170 sit inside the window by Core's
// tip but past it by the server's. A declared tip that puts the block inside
// the window, or one below Core's, changes nothing.
func TestLaggingCoreAccusesNobodyWithoutAReceipt(t *testing.T) {
	cases := []struct {
		name     string
		height   uint32
		declared *uint32
		want     state.Reason
	}{
		{"four blocks behind, at the edge", 160, u32(coreTip + 4), state.TipUnconfirmed},
		{"twenty blocks behind, at the edge", 160, u32(coreTip + 20), state.TipUnconfirmed},
		{"twenty blocks behind, past the margin", 170, u32(coreTip + 20), state.TipUnconfirmed},
		{"twenty blocks behind, inside by the server's own tip", 180, u32(coreTip + 20), state.AbsentInWindow},
		{"no declared tip", 170, nil, state.AbsentInWindow},
		{"a declared tip below Core's", 170, u32(coreTip - 50), state.AbsentInWindow},
		{"the largest declared tip", 170, u32(math.MaxUint32), state.TipUnconfirmed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !wire.InsideRetentionWindow(coreTip, c.height) {
				t.Fatalf("test setup: block %d must sit inside the window by Core's tip", c.height)
			}
			f := newFixture(t, c.height)
			L := leaves(4, "a")
			s := f.srv("w", newKey(t, 2), L, absentAt(full(L), 1), noReceipt())
			s.Tip = c.declared
			res := evaluate(t, f.block(s))
			w := byLabel(t, res, "w")
			if w.Reason != c.want || w.Signed {
				t.Errorf("w = %s/%s signed %v, want %s unsigned", w.State, w.Reason, w.Signed, c.want)
			}
			if c.want != state.AbsentInWindow && res.State == state.Compromised {
				t.Errorf("block = %s/%s: a lagging Core made Canary accuse a server", res.State, res.Reason)
			}
			if len(w.Warnings) != 0 {
				t.Errorf("warnings = %v, want none", w.Warnings)
			}
		})
	}
}

// The tripwire still reads such a block. A declared payment whose output Core
// shows unspent names the server, as it does for a signed tip above Core's.
func TestLaggingCoreWithoutAReceiptLeavesTheTripwire(t *testing.T) {
	f := newFixture(t, 170)
	L := leaves(4, "a")
	f.payments = []Payment{{Entry: L[1], Outputs: []Output{unspent(5000)}}}
	s := f.srv("w", newKey(t, 2), L, absentAt(full(L), 1), noReceipt())
	s.Tip = u32(coreTip + 20)
	w := byLabel(t, evaluate(t, f.block(s)), "w")
	if w.State != state.Compromised || w.Reason != state.ExpectedPaymentNotInList {
		t.Errorf("w = %s/%s, want compromised/expected_payment_not_in_list", w.State, w.Reason)
	}
}
