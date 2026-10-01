package ladder

import (
	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/wire"
	"github.com/nbd-wtf/go-nostr"
)

// Where a recovered entry came from. The values match the evidence file's
// context.found_by.
const (
	FoundByServer  = "other_server"
	FoundByPayment = "expected_payment"
)

// What one server did with a declared payment. The values match the state
// file's expected_payments[].servers[].outcome.
const (
	PaymentFound         = "found"
	PaymentWithheld      = "withheld"
	PaymentHashOnly      = "hash_only"
	PaymentNotIndexedYet = "not_indexed_yet"
	PaymentUnresolvable  = "unresolvable"
)

// BlockResult is the ladder's answer for one block.
type BlockResult struct {
	// State and Reason are the block's, from the servers' results by the
	// formats' order of precedence. See Aggregate.
	State  state.StateCode
	Reason state.Reason

	// Servers holds one result per server, in input order.
	Servers []ServerResult

	// Disagreements lists every pair of servers that signed different roots
	// for this block hash. Each pair says one of the two lied, not which.
	Disagreements []Disagreement
}

// Disagreement names two servers that signed different roots for one block.
// First comes before Second in input order.
type Disagreement struct {
	First, Second string
}

// ServerResult is one server's result for one block.
type ServerResult struct {
	Label string

	// State and Reason are this server's result. A reason always belongs to
	// its state, as the formats pair them.
	State  state.StateCode
	Reason state.Reason

	// Warnings lists what the server did that an honest server would not,
	// where nothing it signed shows it. Each is at most once, in step order.
	// A warning never changes a state.
	Warnings []state.Reason

	// Record is the checked signed record. Nil when the server served none
	// that passed the checks. RecordErr says why a served record failed.
	Record    *Record
	RecordErr error

	// Signed is true when a valid receipt covered the list. Only then can a
	// finding about the list be proved to others. ReceiptErr says why a
	// receipt that came with the list failed.
	Signed     bool
	Receipt    *wire.Receipt
	ReceiptErr error

	// ListAltered is true when the pinned key signed the receipt, but for
	// other bytes or another request: another block, network or dust
	// threshold. Something between the server and Canary changed the list,
	// or the server sent the wrong receipt. Either way the bytes are not what
	// the server signed for this request, so Canary judged nothing from them
	// and the list reads as not served, with no warning.
	ListAltered bool

	// TipUnconfirmed is true when the retention rule found an absent
	// position past the window only by a tip Core could neither confirm nor
	// refute. For a receipted list that is the signed tip. It stays true when
	// another source filled the gap, so canary check can still say that the
	// tip excused it.
	TipUnconfirmed bool

	// ListErr says why the list could not be matched to the record: it
	// failed the reader rules, or its length differs from n.
	ListErr error

	// Positions counts what the decoded list carried. Nil when no list
	// decoded.
	Positions *state.Positions

	// Filled counts the hash and absent positions whose entry Canary
	// recovered.
	Filled int

	// RootRecomputed is true when Canary recomputed the root over all n
	// positions, after filling. RootMatched is true when it equalled the
	// signed root. Checked and Checked, gap filled need both.
	//
	// Once another list proves the root, an absent position no entry filled
	// takes the proven hash. A root recomputed that way can only name the
	// server. When it matches, RootRecomputed stays false, because the entry
	// was never recovered.
	RootRecomputed bool
	RootMatched    bool

	// Gaps lists, by position, every position the list did not carry in
	// full, and every position whose data differs from what the record
	// commits to.
	Gaps []Gap

	// Payments holds one outcome per declared payment, in input order.
	Payments []PaymentResult
}

// Record is a signed record that passed the checks: the raw event and what it
// commits to.
type Record struct {
	Event      nostr.Event
	Commitment feed.Commitment
}

// Gap is one position the server did not serve in full, or served with data
// its record does not hold.
type Gap struct {
	Position uint32

	// Served is what the list carried at this position.
	Served wire.PositionKind

	// Wrong is true when the list's data here differs from what the signed
	// root commits to. Canary knows this only once some server's list proved
	// the root.
	Wrong bool

	// Entry is the entry that belongs at this position, when Canary recovered
	// it. FoundBy says where it came from.
	Entry   *canonical.Leaf
	FoundBy string

	// Proof carries Entry to the server's signed root. It is set once Entry
	// is known and some list proved the root, and only where an evidence file
	// can use it: a wrong position, or an absent position inside the
	// retention window. An absence the rule permits gets no proof.
	Proof *commit.Proof
}

// PaymentResult is what one server did with one declared payment.
type PaymentResult struct {
	// TxID is the payment's txid, in internal byte order.
	TxID    [32]byte
	Outcome string

	// Reason is the accusation this payment raised in the payment step:
	// expected_payment_not_in_record or expected_payment_not_in_list. It is
	// empty for every other outcome, and for a withheld payment whose gap the
	// retention rule already named in the window step.
	Reason state.Reason

	// DustExcused is true when only the dust threshold the server's /info
	// declares excused holding the entry back. The list had no valid receipt,
	// and Core shows an output of the payment unspent below that threshold,
	// so pruning cannot explain it. /info is unsigned, so this never accuses.
	// canary check says so on the server's error line instead.
	DustExcused bool
}
