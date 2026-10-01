package ladder

import (
	"fmt"
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
// Core's height for the block. The same boundary holds.
func TestRetentionBoundaryByCoreWithoutAReceipt(t *testing.T) {
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
