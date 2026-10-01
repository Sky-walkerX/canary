// Package policy holds a server's declared index policy: the ways it may serve
// less than the canonical set.
//
// Every field only removes entries. Cut-through drops transactions whose
// taproot outputs are all spent, a dust threshold drops small ones, and a
// start height drops everything below it. No field can add an entry, which is
// why a served tweak list is always a subset of the canonical set.
//
// A policy explains a gap. It never proves anything. An entry carries no
// amount, so a client cannot check that a dust threshold really covers a gap,
// and no state Canary reports depends on the threshold. A declared policy
// routes effort, and it gives an auditor holding the block a statement to hold
// the server to.
//
// FromBlindBitInfo reads blindbit-oracle's GET /info, so the checker can run
// against an unmodified server today. That /info is unsigned and not per
// block, and the server can revise it at will, so v1 treats a contradiction
// with it as a warning, never an accusation. A signed, per-block policy event
// is a later protocol step. The v1 reference indexer serves its own /info,
// canary-info/1, described in the v1 formats doc.
//
// The design doc's "Policy declaration" section gives the reasons.
package policy
