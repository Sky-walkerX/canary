package ladder

import (
	"errors"
	"fmt"

	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/wire"
)

// window is what the retention rule said about a list's absent positions.
type window int

const (
	windowNone        window = iota // no absent position, so the rule never ran
	windowInside                    // inside the window: an omission
	windowFalseClaim                // excused by a signed chain claim Core contradicts
	windowConfirmed                 // outside, and Core confirms the server's claim
	windowUnconfirmed               // outside, by a signed tip Core cannot confirm yet
	windowOutside                   // outside by Core's own view, for an unsigned list
)

// eval carries one server through the steps.
type eval struct {
	in  Server
	res ServerResult

	// stopped is true when steps 1 to 4 fixed the result. Such a server
	// takes no part in filling and has no root.
	stopped bool

	// decoded is the list as read, of any length. positions is the same list
	// when its length equals the record's n, and nil otherwise.
	decoded   []wire.Position
	positions []wire.Position

	window window

	// Set by filling. vector is the leaf-hash vector the root was recomputed
	// over, when recomputed is true.
	recomputed bool
	matched    bool
	vector     [][32]byte
}

func (e *eval) stop(s state.StateCode, r state.Reason) {
	e.res.State, e.res.Reason = s, r
	e.stopped = true
}

func (e *eval) warn(r state.Reason) {
	e.res.Warnings = append(e.res.Warnings, r)
}

// Evaluate runs every step for every server, then combines the servers into
// the block's state. It returns an error only when the input is unusable or
// Core could not answer. Every judgement about a server is in the result.
func Evaluate(b Block) (BlockResult, error) {
	seen := make(map[string]bool, len(b.Servers))
	for _, s := range b.Servers {
		if seen[s.Label] {
			return BlockResult{}, fmt.Errorf("ladder: server labels: %q appears twice", s.Label)
		}
		seen[s.Label] = true
	}

	evals := make([]*eval, len(b.Servers))
	for i, s := range b.Servers {
		e, err := firstSteps(b, s)
		if err != nil {
			return BlockResult{}, err
		}
		evals[i] = e
	}

	// Steps 6 and 7. Every group fills its gaps before any root is
	// recomputed for a server with a gap.
	for _, g := range groupByRecord(b, evals) {
		g.fill()
	}
	for _, e := range evals {
		e.finishRoot()
	}
	passReasons(b, evals)
	for _, e := range evals {
		e.checkPayments(b)
	}
	disagreements := crossCheck(evals)

	out := BlockResult{Servers: make([]ServerResult, len(evals)), Disagreements: disagreements}
	for i, e := range evals {
		out.Servers[i] = e.res
	}
	out.State, out.Reason = Aggregate(out.Servers)
	return out, nil
}

// firstSteps runs steps 1 to 5 for one server.
func firstSteps(b Block, s Server) (*eval, error) {
	e := &eval{in: s, res: ServerResult{Label: s.Label}}
	r := &e.res

	// Step 1. Record.
	if s.Unreachable {
		e.stop(state.Unverified, state.ServerUnreachable)
		return e, nil
	}
	if s.Pubkey != nil && s.Record != nil {
		rec, err := CheckRecord(s.Record, *s.Pubkey, b.Hash, b.Core.Network)
		if err != nil {
			r.RecordErr = err
		} else {
			r.Record = rec
		}
	}
	if r.Record == nil {
		// A record the server signed for a higher block shows it indexed past
		// this one. That signature outranks the unsigned tip, so a low tip
		// never excuses a missing record between two signed ones.
		switch {
		case s.Pubkey != nil && s.RecordBelow && s.RecordAbove:
			e.stop(state.Unverified, state.NoRecordForBlock)
			e.warn(state.NoRecordForBlock)
		case s.Tip != nil && *s.Tip < b.Height && !s.RecordAbove:
			e.stop(state.Unverified, state.NotIndexedYet)
		default:
			e.stop(state.Unverified, state.NoRecords)
		}
		return e, nil
	}
	rec := r.Record.Commitment

	// A warning has no signed tip to measure from, so it uses Core's.
	insideByCore := wire.InsideRetentionWindow(b.Core.TipHeight, b.Height)

	// Step 2. List.
	if s.List == nil {
		e.stop(state.Unresolvable, state.ListNotServed)
		if insideByCore {
			e.warn(state.ListNotServed)
		}
		return e, nil
	}

	// Step 3. Receipt. A failure leaves the list unsigned, not rejected.
	if s.List.Receipt != "" {
		rc, err := wire.DecodeReceiptHeader(s.List.Receipt)
		if err == nil {
			req := wire.ReceiptRequest{Network: b.Core.Network, BlockHash: b.Hash, DustSat: DustSat}
			err = wire.VerifyReceipt(rc, *s.Pubkey, req, s.List.Body)
		}
		if err != nil {
			r.ReceiptErr = fmt.Errorf("ladder: receipt rejected: %w", err)
		} else {
			r.Signed, r.Receipt = true, &rc
		}
	}

	// Step 4. Decode. The server signed a receipted list's exact bytes, so
	// a receipted list that fails to decode contradicts its own record.
	decoded, err := wire.DecodeResponse(s.List.Body)
	if err != nil {
		r.ListErr = fmt.Errorf("ladder: list unreadable: %w", err)
		if r.Signed {
			e.stop(state.Compromised, state.ServedContradictsRecord)
		} else {
			e.stop(state.Unresolvable, state.ListUnreadable)
			if insideByCore {
				e.warn(state.ListUnreadable)
			}
		}
		return e, nil
	}
	e.decoded = decoded
	counts := countPositions(decoded)
	r.Positions = &counts
	// canary check asks for no dust threshold, so only pruning can explain a
	// hash. A server that declared none gets a warning, never an accusation,
	// because its policy is unsigned.
	if counts.Hash > 0 && s.Policy != nil && !s.Policy.PrunesSpent {
		e.warn(state.HashWithoutPolicy)
	}
	if uint64(len(decoded)) != uint64(rec.N) {
		r.ListErr = fmt.Errorf("ladder: list length: %d positions, the signed record says n=%d", len(decoded), rec.N)
		e.stop(state.Compromised, state.ServedContradictsRecord)
		return e, nil
	}
	e.positions = decoded

	// Step 5. Window. A result here stands whatever filling finds.
	if counts.Absent > 0 {
		w, err := retention(b, rec, r.Receipt)
		if err != nil {
			return nil, err
		}
		e.window = w
		switch w {
		case windowInside:
			r.State, r.Reason = state.Compromised, state.AbsentInWindow
		case windowFalseClaim:
			r.State, r.Reason = state.Compromised, state.FalseChainClaim
		}
	}
	return e, nil
}

func countPositions(ps []wire.Position) state.Positions {
	var c state.Positions
	for _, p := range ps {
		switch p.Kind {
		case wire.KindFull:
			c.Full++
		case wire.KindHash:
			c.Hash++
		case wire.KindAbsent:
			c.Absent++
		}
	}
	return c
}

// retention applies the retention rule to a list with absent positions.
//
// With a receipt, the depth comes from two values the server signed: the tip
// in the receipt and the height in the record. If they put the block inside
// the window, that settles it, whatever Core says. Only when they put it
// outside does Canary check the server's chain claim against Core.
//
// Without a receipt there is no signed tip. Depth then comes from Core's tip
// and Core's height for the block, and no chain claim exists to check.
func retention(b Block, rec feed.Commitment, rc *wire.Receipt) (window, error) {
	if rc == nil {
		if wire.InsideRetentionWindow(b.Core.TipHeight, b.Height) {
			return windowInside, nil
		}
		return windowOutside, nil
	}
	if wire.InsideRetentionWindow(rc.TipHeight, rec.BlockHeight) {
		return windowInside, nil
	}

	// A block hash has one height forever, so no reorg explains a record
	// that names another.
	if rec.BlockHeight != b.Height {
		return windowFalseClaim, nil
	}
	if b.Core.Chain == nil {
		return 0, errors.New("ladder: check the signed tip: no chain view to ask Core")
	}
	h, ok, err := b.Core.Chain.ActiveHash(rc.TipHeight)
	if err != nil {
		return 0, fmt.Errorf("ladder: check the signed tip: Core at height %d: %w", rc.TipHeight, err)
	}
	if ok && h == rc.TipHash {
		return windowConfirmed, nil
	}
	// Near Core's tip, a reorg or a node a block behind can explain a tip
	// Core does not know. Further off, nothing does.
	if distance(rc.TipHeight, b.Core.TipHeight) > TipMargin {
		return windowFalseClaim, nil
	}
	return windowUnconfirmed, nil
}

func distance(a, b uint32) int64 {
	d := int64(a) - int64(b)
	if d < 0 {
		return -d
	}
	return d
}

// finishRoot records step 7's result. A result from steps 4 or 5 stands.
func (e *eval) finishRoot() {
	if e.stopped {
		return
	}
	r := &e.res
	r.RootRecomputed, r.RootMatched = e.recomputed, e.matched
	for _, g := range r.Gaps {
		if g.Served != wire.KindFull && g.Entry != nil {
			r.Filled++
		}
	}
	if r.State == state.Compromised {
		return
	}
	switch {
	case e.matched:
		r.State, r.Reason = passState(r.Gaps)
	case e.recomputed:
		r.State, r.Reason = state.Compromised, state.ServedContradictsRecord
	case e.window == windowUnconfirmed:
		r.State, r.Reason = state.Unresolvable, state.TipUnconfirmed
	default:
		r.State, r.Reason = state.Unresolvable, state.GapUnfilled
	}
}

// passState names a matching root's state from how its gaps were closed. A
// list with any hash or filled position is never plain Checked. Its reason
// for Checked is set later, once every server's record is known.
func passState(gaps []Gap) (state.StateCode, state.Reason) {
	var fromServer, fromPayment, hashes bool
	for _, g := range gaps {
		switch g.Served {
		case wire.KindAbsent:
			if g.FoundBy == FoundByServer {
				fromServer = true
			} else {
				fromPayment = true
			}
		case wire.KindHash:
			hashes = true
		}
	}
	switch {
	case fromServer:
		return state.Resolved, state.FilledFromServer
	case fromPayment:
		return state.Resolved, state.FilledFromExpectedPayment
	case hashes:
		return state.Resolved, state.HashRetained
	}
	return state.Verified, ""
}

// passReasons picks the reason for each Checked server. Agreement with
// another server's record comes first, then a declared payment carried in
// full, then the server's own record alone.
func passReasons(b Block, evals []*eval) {
	for _, e := range evals {
		if e.res.State != state.Verified {
			continue
		}
		root := e.res.Record.Commitment.Root
		switch {
		case agrees(evals, e, root):
			e.res.Reason = state.RecordsAgree
		case carriesAnyPayment(e.decoded, b.Payments):
			e.res.Reason = state.ExpectedPayment
		default:
			e.res.Reason = state.OwnRecord
		}
	}
}

func agrees(evals []*eval, self *eval, root [32]byte) bool {
	for _, o := range evals {
		if o != self && o.res.Record != nil && o.res.Record.Commitment.Root == root {
			return true
		}
	}
	return false
}

func carriesAnyPayment(ps []wire.Position, pays []Payment) bool {
	for _, p := range pays {
		if carries(ps, p) {
			return true
		}
	}
	return false
}

// carries reports whether the list holds the payment's entry in full.
func carries(ps []wire.Position, p Payment) bool {
	for _, q := range ps {
		if q.Kind == wire.KindFull && q.Leaf == p.Entry {
			return true
		}
	}
	return false
}

// checkPayments runs step 9 and records each payment's outcome. A
// compromised result here replaces a pass from step 7.
func (e *eval) checkPayments(b Block) {
	var found state.Reason
	for _, p := range b.Payments {
		outcome, reason := e.payment(p)
		e.res.Payments = append(e.res.Payments, PaymentResult{TxID: p.Entry.TxID, Outcome: outcome, Reason: reason})
		if reason != "" && found == "" {
			found = reason
		}
	}
	if found != "" && e.res.State.Passed() {
		e.res.State, e.res.Reason = state.Compromised, found
	}
}

// payment says what the server did with one declared payment, and names the
// reason when that is an accusation.
func (e *eval) payment(p Payment) (string, state.Reason) {
	switch {
	case e.res.Reason == state.NotIndexedYet:
		return PaymentNotIndexedYet, ""
	case e.decoded == nil:
		return PaymentUnresolvable, ""
	case carries(e.decoded, p):
		return PaymentFound, ""
	case !e.matched:
		return PaymentUnresolvable, ""
	}

	// The root matched, so the vector is every entry the record commits to.
	// A record commits to every entry in the block, spent or not, so no
	// policy explains an entry missing from it.
	h := commit.LeafHash(p.Entry)
	at := -1
	for i, v := range e.vector {
		if v == h {
			at = i
			break
		}
	}
	if at < 0 {
		return PaymentWithheld, state.ExpectedPaymentNotInRecord
	}

	// The record holds the entry and the list did not carry it in full.
	if e.positions[at].Kind == wire.KindAbsent && (e.window == windowInside || e.window == windowFalseClaim) {
		return PaymentWithheld, "" // already named at step 5
	}
	if e.unspentAboveDust(p) {
		return PaymentWithheld, state.ExpectedPaymentNotInList
	}
	return PaymentHashOnly, ""
}

// unspentAboveDust reports whether Core shows one of the payment's taproot
// outputs unspent at or above the server's declared dust threshold. Then
// pruning cannot explain a list that holds back the entry.
func (e *eval) unspentAboveDust(p Payment) bool {
	var dust uint64
	if e.in.Policy != nil {
		dust = e.in.Policy.DustThresholdSat
	}
	for _, o := range p.Outputs {
		if o.Unspent && o.ValueSat >= dust {
			return true
		}
	}
	return false
}

// crossCheck runs step 8. It lists every pair of servers whose signed roots
// differ, and turns each such server's pass into Servers disagree. A
// compromised result is not replaced, because Data withheld outranks it.
func crossCheck(evals []*eval) []Disagreement {
	var out []Disagreement
	differs := make([]bool, len(evals))
	for i, a := range evals {
		if a.res.Record == nil {
			continue
		}
		for j := i + 1; j < len(evals); j++ {
			b := evals[j]
			if b.res.Record == nil || b.res.Record.Commitment.Root == a.res.Record.Commitment.Root {
				continue
			}
			out = append(out, Disagreement{First: a.res.Label, Second: b.res.Label})
			differs[i], differs[j] = true, true
		}
	}
	for i, e := range evals {
		if differs[i] && e.res.State.Passed() {
			e.res.State, e.res.Reason = state.Disputed, state.RecordsDiffer
		}
	}
	return out
}
