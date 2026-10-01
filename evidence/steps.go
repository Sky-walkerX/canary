package evidence

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
	"github.com/Sky-walkerX/canary/wire"
)

// Steps 2 to 8. Each returns the sentence for its check and, on failure, an
// error that wraps the step's sentinel. Steps 1 to 5 need no receipt.

// recordSignature is step 2. feed.FromEvent recomputes the event id, checks
// the BIP-340 signature, the kind and every tag, and that the root tag equals
// the content.
func (v *verifier) recordSignature() (string, error) {
	c, err := feed.FromEvent(v.p.event)
	switch {
	case err == nil:
		v.record = c
		return wording.VerifyRecordSignatureOK, nil
	case errors.Is(err, feed.ErrBadSignature):
		return wording.VerifyRecordSignatureBad, fmt.Errorf("%w: %v", ErrBadSignature, err)
	default:
		return wording.VerifyRecordMalformed, fmt.Errorf("%w: signed record: %v", ErrMalformed, err)
	}
}

// signer is step 3.
func (v *verifier) signer() (string, error) {
	if v.record.Author != v.p.accused {
		return wording.VerifySignerBad, fmt.Errorf("%w: the record's pubkey %x is not the accused key %s",
			ErrSignerMismatch, v.record.Author, v.p.file.Accused)
	}
	return wording.VerifySignerOK, nil
}

// block is step 4. The record's signed values must name the block the file
// names.
func (v *verifier) block() (string, error) {
	f, c := v.p.file, v.record
	switch {
	case c.BlockHash != v.p.blockHash:
		return wording.VerifyBlockBad, fmt.Errorf("%w: the record's b tag names block %s, the file names %s",
			ErrBlockMismatch, core.DisplayHex(c.BlockHash), f.Block.Hash)
	case c.BlockHeight != f.Block.Height:
		return wording.VerifyBlockBad, fmt.Errorf("%w: the record's height is %d, the file says %d",
			ErrBlockMismatch, c.BlockHeight, f.Block.Height)
	case uint32(c.Network) != f.Network.Magic:
		return wording.VerifyBlockBad, fmt.Errorf("%w: the record's network is %d, the file says %d",
			ErrBlockMismatch, uint32(c.Network), f.Network.Magic)
	}
	return wording.VerifyBlockOK(c.BlockHeight, v.rep.Network.Name, uint32(c.Network)), nil
}

// inclusion is step 5. The proof must carry the entry to the root the server
// signed, for the record's network, block hash and n.
func (v *verifier) inclusion() (string, error) {
	pr, c := v.p.proof, v.record
	if pr.N != c.N {
		return wording.VerifyInclusionWrongSize(pr.N, c.N), fmt.Errorf("%w: the proof is for n=%d, the record signs n=%d",
			ErrProofInvalid, pr.N, c.N)
	}
	if !commit.VerifyProof(c.Network, c.BlockHash, c.Root, v.p.entry, pr) {
		return wording.VerifyInclusionBad(pr.Index, c.N), fmt.Errorf("%w: entry %d of %d does not prove into root %x",
			ErrProofInvalid, pr.Index, c.N, c.Root)
	}
	return wording.VerifyInclusionOK(pr.Index, c.N), nil
}

// receiptStep is step 6. The evidence file has no dust field, so this step
// checks the signature under the accused key and the network, block hash,
// resource and body digest itself, rather than calling wire.VerifyReceipt.
func (v *verifier) receiptStep() (string, error) {
	r, err := wire.DecodeReceiptHeader(*v.p.file.Receipt)
	if err != nil {
		return wording.VerifyReceiptMalformed, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := wire.VerifyReceiptSignature(r, v.p.accused); err != nil {
		return wording.VerifyReceiptWrongKey, fmt.Errorf("%w: %v", ErrReceiptInvalid, err)
	}
	// The tip is signed by the accused key, so the report can show it.
	v.receipt = r
	v.rep.ReceiptTip = &Tip{Height: r.TipHeight, Hash: core.DisplayHex(r.TipHash)}

	served := v.p.served
	switch {
	case r.Network != v.record.Network:
		return wording.VerifyReceiptOtherNetwork, fmt.Errorf("%w: the receipt's network is %d, the record's is %d",
			ErrReceiptInvalid, uint32(r.Network), uint32(v.record.Network))
	case r.BlockHash != v.record.BlockHash:
		return wording.VerifyReceiptOtherBlock, fmt.Errorf("%w: the receipt names block %s, the record names %s",
			ErrReceiptInvalid, core.DisplayHex(r.BlockHash), core.DisplayHex(v.record.BlockHash))
	case r.Resource != wire.ResourceTweakList:
		return wording.VerifyReceiptOtherResource, fmt.Errorf("%w: resource %#x, want the tweak list %#x",
			ErrReceiptInvalid, byte(r.Resource), byte(wire.ResourceTweakList))
	}
	if sum := sha256.Sum256(served); sum != r.BodySHA256 {
		return wording.VerifyReceiptOtherBody(len(served)), fmt.Errorf("%w: body_sha256 %x, the %d served bytes hash to %x",
			ErrReceiptInvalid, r.BodySHA256, len(served), sum)
	}
	return wording.VerifyReceiptOK(len(served)), nil
}

// servedList is step 7. The signed list must decode, have the record's n
// positions, and not carry the entry at the proof's position.
func (v *verifier) servedList() (string, error) {
	positions, err := wire.DecodeResponse(v.p.served)
	if err != nil {
		return wording.VerifyServedMalformed, fmt.Errorf("%w: served list: %v", ErrMalformed, err)
	}
	n, idx := v.record.N, v.p.proof.Index
	if uint64(len(positions)) != uint64(n) {
		got := uint32(len(positions)) // DecodeResponse reads a 4-byte count
		return wording.VerifyServedWrongSize(got, n), fmt.Errorf("%w: the served list has %d positions, the record signs n=%d",
			ErrBlockMismatch, got, n)
	}
	v.positions = positions

	pos := positions[idx] // idx < n, since step 5 proved it
	switch pos.Kind {
	case wire.KindAbsent:
		v.absent = true
		return wording.VerifyServedAbsent(n, idx), nil
	case wire.KindFull:
		if pos.Leaf == v.p.entry {
			return wording.VerifyServedEntry(idx), fmt.Errorf("%w: position %d carries the entry in full", ErrEntryServed, idx)
		}
		return wording.VerifyServedOtherEntry(n, idx), nil
	default: // wire.KindHash, the only other kind DecodeResponse returns
		if pos.Hash == commit.LeafHash(v.p.entry) {
			return wording.VerifyServedEntryHash(idx), fmt.Errorf("%w: position %d carries the entry's hash", ErrEntryServed, idx)
		}
		return wording.VerifyServedOtherHash(n, idx), nil
	}
}

// window is step 8. An absent position breaks the retention rule only while
// the block sat inside the window, measured from the receipt's signed tip and
// the record's signed height. Different data at a committed position is
// never permitted, so depth does not matter for it. This step never reads the
// tip hash. Signed values that put the block inside the window settle it.
func (v *verifier) window() (string, error) {
	idx := v.p.proof.Index
	if !v.absent {
		return wording.VerifyWindowNotNeeded(idx), nil
	}
	tip, height := v.receipt.TipHeight, v.record.BlockHeight
	depth := wire.BlockDepth(tip, height)
	if !wire.InsideRetentionWindow(tip, height) {
		return wording.VerifyWindowOutside(tip, depth, wire.RetentionWindow), fmt.Errorf("%w: signed tip %d, block height %d, depth %d",
			ErrNotInWindow, tip, height, depth)
	}
	if depth < 0 {
		return wording.VerifyWindowAboveTip(tip, wire.RetentionWindow), nil
	}
	return wording.VerifyWindowInside(tip, depth, wire.RetentionWindow), nil
}
