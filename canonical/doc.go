// Package canonical computes a block's canonical set: every BIP-352 entry, a
// (txid, tweak) pair, in transaction order, with nothing filtered out.
//
// The set depends only on the block and the outputs its transactions spend.
// No chain state after the block, no thresholds and no configuration enter
// it. So every honest server gets the same list for the same block, whatever
// it chooses to serve. A server signs a root over this list, and Canary
// checks each tweak list it is served against that signed root.
//
// Who calls it: the reference indexer, when it builds a block's signed record,
// and internal/testvector, which replays the committed test vectors. The v1
// reference indexer reuses this package on purpose, so v1 does not test two
// independent implementations against each other. A later indexer keeps its
// own computation path, or a differential test between the two proves nothing.
//
// Where it sits in the flow: a block and its spent outputs go in, and entries
// come out. The commit package hashes the entries into a root, and the feed
// package carries that root in a signed Nostr event.
//
// A transaction is in the set when all four eligibility rules hold. The
// comments in this package cite them by number:
//
//  1. It has at least one BIP-341 taproot output, ignoring the optional
//     "unspent" clause.
//  2. At least one input is of a type BIP-352 uses for shared secret
//     derivation: P2TR, P2WPKH, P2SH-P2WPKH or P2PKH.
//  3. No input spends an output with SegWit version above 1.
//  4. (a) A_sum is not the point at infinity, and (b) input_hash is a valid
//     scalar.
//
// Byte order: Leaf.TxID is in internal order, the order every hash preimage
// uses. The go-bip352 library wants display order. The package converts
// between the two in one place, vin.go.
//
// The design doc's "Canonical tweak sets" section explains each rule.
package canonical
