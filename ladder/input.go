package ladder

import (
	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/policy"
)

// DustSat is the dust threshold canary check asks every server for. It asks
// for none, because it checks the full list, not a wallet's filtered view.
// Every receipt must sign this value.
const DustSat uint64 = 0

// TipMargin is how many blocks a server's signed tip may sit from Core's tip
// and still pass as a reorg or a lagging node. A tip further off that Core
// cannot find is a false chain claim.
const TipMargin = 6

// Block is everything the ladder needs to judge one block. It names the block
// by hash, because the same height can name different blocks on two chains.
type Block struct {
	// Hash is the block hash in internal byte order. Canary got it from Core
	// for Height.
	Hash [32]byte

	// Height is Core's height for Hash.
	Height uint32

	// Core is what the user's own Bitcoin Core node says.
	Core Core

	// Servers lists every configured server, in --indexer order. The block's
	// reason quotes the first deciding server in this order.
	Servers []Server

	// Payments lists the declared payments Core places in this block. Leave
	// out a payment with no BIP-352 entry: there is nothing to check.
	Payments []Payment
}

// Core is what the user's Bitcoin Core node reports at the time of the run.
type Core struct {
	// Network is Core's P2P message-start magic. Records and receipts must
	// name the same network.
	Network canonical.Network

	// TipHeight is the height of Core's best block. It measures depth for an
	// unsigned list and for warnings.
	TipHeight uint32

	// Chain answers questions about Core's active chain. The ladder asks it
	// only when a server's signed values put an absent position outside the
	// retention window. It may be nil when no such position exists.
	Chain Chain
}

// Chain is the one question the ladder asks of Core's active chain.
type Chain interface {
	// ActiveHash returns the hash, in internal byte order, of the block at
	// height on Core's active chain. ok is false when the chain has no block
	// there, such as a height above Core's tip. err means Core could not
	// answer, which stops the run.
	ActiveHash(height uint32) (hash [32]byte, ok bool, err error)
}

// Server is what one server answered for the block.
type Server struct {
	// Label names the server. Labels are unique within one block.
	Label string

	// Pubkey is the pinned x-only key the server signs with. Nil means the
	// server was pinned as signing nothing, so its blocks read Not checked.
	// The ladder never learns a key from the server.
	Pubkey *[32]byte

	// Policy is what the server's /info declared. Nil when /info did not
	// answer. It is unsigned in v1, so it only ever raises a warning.
	Policy *policy.Policy

	// Tip is the server's best height as Canary last saw it, from a receipt
	// or from /info. Nil when unknown. A tip below the block means the
	// server has not indexed it yet, unless the server signed a record for a
	// higher block in this run. That signature outranks an unsigned tip.
	Tip *uint32

	// Unreachable is true when the record request got no answer, or an
	// internal or not_ready error. It is also true when canary check stopped
	// asking the server before it asked for this block's list, because the
	// server refused nothing. The ladder then reads nothing else.
	Unreachable bool

	// Record is the body of /commitment/{hash}, the signed Nostr event as
	// served. Nil when the server answered unknown_block.
	Record []byte

	// RecordBelow and RecordAbove say whether the server signed a valid
	// record for a lower block and for a higher block in this run. A server
	// that signed both but not this block gets a warning.
	RecordBelow bool
	RecordAbove bool

	// List is the /tweaks/{hash} response. Nil when the server served no
	// list.
	List *List
}

// List is one served tweak list and the receipt that came with it.
type List struct {
	// Body is the exact response body.
	Body []byte

	// Receipt is the X-Canary-Receipt header value as received. Empty when
	// the response carried none.
	Receipt string
}

// Payment is a transaction the user made and declared with --expect.
type Payment struct {
	// Entry is the payment's (txid, tweak), computed from Core's copy of the
	// block. The txid is in internal byte order.
	Entry canonical.Leaf

	// Outputs lists the payment's taproot outputs as Core sees them now. An
	// unspent output at or above the server's dust threshold means pruning
	// cannot explain a missing entry.
	Outputs []Output
}

// Output is one taproot output of a declared payment.
type Output struct {
	ValueSat uint64
	Unspent  bool
}
