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
	windowUnconfirmed               // outside by a tip Core cannot confirm or refute: a signed one, or for an unsigned list, one Core may lag
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

	// Step 3. Receipt. A receipt that does not verify under the pin leaves
	// the list unsigned, not rejected. An unsigned list is judged on what
	// arrived. That is safe because canary check reads servers over https,
	// or plain http to this computer only, so nobody else can strip or swap
	// a receipt on the way.
	//
	// A receipt that does verify, but for other bytes or another request, is
	// different. The server signed what it sent, and this is not it. Someone
	// between the server and Canary changed the list, or the server sent the
	// wrong receipt. Judging those bytes would let a third party make Canary
	// accuse an honest server. So the list counts as not served, and nothing
	// names the server, not even a warning. A withholder gains nothing new by
	// sending such a pair: refusing the record already leaves no warning.
	if s.List.Receipt != "" {
		rc, err := wire.DecodeReceiptHeader(s.List.Receipt)
		if err == nil {
			req := wire.ReceiptRequest{Network: b.Core.Network, BlockHash: b.Hash, DustSat: DustSat}
			err = wire.VerifyReceipt(rc, *s.Pubkey, req, s.List.Body)
		}
		switch {
		case errors.Is(err, wire.ErrReceiptMismatch):
			r.ReceiptErr = fmt.Errorf("ladder: list altered: %w", err)
			r.ListAltered = true
			e.stop(state.Unresolvable, state.ListNotServed)
			return e, nil
		case err != nil:
			r.ReceiptErr = fmt.Errorf("ladder: receipt rejected: %w", err)
		default:
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
		w, err := retention(b, rec, r.Receipt, s.Tip)
		if err != nil {
			return nil, err
		}
		e.window = w
		r.TipUnconfirmed = w == windowUnconfirmed
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
// The check is one-sided. Core can contradict a claim only about a height it
// has reached. A signed tip above Core's tip may be a lie, or Core may be
// behind, and Canary can't tell the two apart. So it never accuses on such a
// tip: the gap reads Can't be checked unless something fills it. It accuses
// only when Core holds a different block at the signed height, more than
// TipMargin blocks below Core's tip, or when the record names a height that
// Core's block with that hash does not have. A lagging node therefore never
// makes Canary accuse an honest server.
//
// Without a receipt there is no signed tip. Depth then comes from Core's tip
// and Core's height for the block, and no chain claim exists to check. Core
// may still be behind the server, so an absence that Core's tip puts inside
// the window may be one the server's tip permits. Canary allows for that in
// two ways. It accuses only below depth 144 - TipMargin by Core's tip,
// enough for a node a few blocks behind. And it measures again from the tip
// the server's /info declared, when that tip is higher. That tip is
// unsigned, so it can excuse an absence and never convict. Either way an
// excused absence reads unconfirmed, as for a signed tip above Core's.
func retention(b Block, rec feed.Commitment, rc *wire.Receipt, declared *uint32) (window, error) {
	if rc == nil {
		if !wire.InsideRetentionWindow(b.Core.TipHeight, b.Height) {
			return windowOutside, nil
		}
		tip := int64(b.Core.TipHeight) + TipMargin
		if declared != nil {
			tip = max(tip, int64(*declared))
		}
		if tip-int64(b.Height) < wire.RetentionWindow {
			return windowInside, nil
		}
		return windowUnconfirmed, nil
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
	switch {
	case ok && h == rc.TipHash:
		return windowConfirmed, nil
	case !ok:
		// Core has no block at that height yet. It may be behind.
		return windowUnconfirmed, nil
	}
	// Core holds another block at the signed height. Near Core's tip a reorg
	// explains that. More than TipMargin blocks below it, nothing does. The
	// tip Core had when the run began is the measure, so a node that moved
	// on during the run never makes a claim look older than it is.
	if int64(b.Core.TipHeight)-int64(rc.TipHeight) > TipMargin {
		return windowFalseClaim, nil
	}
	return windowUnconfirmed, nil
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
		e.res.Payments = append(e.res.Payments, PaymentResult{
			TxID: p.Entry.TxID, Outcome: outcome, Reason: reason,
			DustExcused: outcome == PaymentHashOnly && e.unspentAbove(p, 0),
		})
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
// outputs unspent at or above the dust threshold the server applied. Then
// pruning cannot explain a list that holds back the entry.
func (e *eval) unspentAboveDust(p Payment) bool {
	return e.unspentAbove(p, e.dustThreshold())
}

// unspentAbove reports whether Core shows one of the payment's taproot
// outputs unspent at or above dust. With dust 0, any unspent output counts.
// A hash_only payment with one is excused by the declared threshold alone.
func (e *eval) unspentAbove(p Payment, dust uint64) bool {
	for _, o := range p.Outputs {
		if o.Unspent && o.ValueSat >= dust {
			return true
		}
	}
	return false
}

// dustThreshold is the dust threshold the server applied to its list. A valid
// receipt signs it, and canary check asks every server for DustSat, so a
// receipted list has that threshold whatever /info declares. /info is
// unsigned, and a withholder could declare a threshold that excuses any
// entry. Only a list with no valid receipt falls back to the declared
// threshold. That rests on an unsigned declaration, and it keeps a server
// with a real dust filter, and no receipts, from being accused.
func (e *eval) dustThreshold() uint64 {
	if e.res.Signed && e.res.Receipt != nil {
		return e.res.Receipt.DustSat
	}
	if e.in.Policy != nil {
		return e.in.Policy.DustThresholdSat
	}
	return 0
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
