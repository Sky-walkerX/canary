package evidence

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/nbd-wtf/go-nostr"
)

// Input is what canary check holds when it has caught a server leaving out an
// entry it signed for.
type Input struct {
	// Record is the accused server's signed kind-1352 event for the block,
	// exactly as served. Its author is the accused key.
	Record nostr.Event

	// Leaves holds the record's entries in canonical order. Set one of
	// Leaves, LeafHashes or Proof.
	Leaves []canonical.Leaf

	// LeafHashes holds the record's entry hashes in canonical order, for a
	// caller that knows some entries only by hash. It needs Entry.
	LeafHashes [][32]byte

	// Proof is a Merkle proof of Entry at Index, for a caller that already
	// holds one, such as canary check after the ladder proved the root. It
	// needs Entry, and replaces Leaves and LeafHashes. Build copies it and
	// checks it against the signed root like any other proof.
	Proof *commit.Proof

	// Entry is the left-out entry. With Leaves, a zero Entry means
	// Leaves[Index]; any other value must equal it.
	Entry canonical.Leaf

	// Index is the entry's position in canonical order.
	Index uint32

	// Served is the exact body of the /tweaks response, and Receipt is its
	// X-Canary-Receipt value exactly as received. Set both or neither. A file
	// without them proves inclusion only.
	Served  []byte
	Receipt string

	// Context holds notes for people. Nothing checks them.
	Context *Context
}

// Build writes the evidence file for in and checks it the way canary verify
// would. It returns the file only if it checks out, with or without a
// receipt. Otherwise the error wraps the failing step's sentinel, so canary
// check never writes a file that accuses the wrong server or the wrong entry.
func Build(in Input) (File, error) {
	f, err := assemble(in)
	if err != nil {
		return File{}, err
	}
	b, err := f.Marshal()
	if err != nil {
		return File{}, err
	}
	if _, err := Verify(b); err != nil {
		return File{}, fmt.Errorf("evidence: build: the file does not check out: %w", err)
	}
	return f, nil
}

// assemble lays out the file for in without verifying the result. The
// record, the proof and the pairing of receipt and list are checked, because
// nothing useful can be built without them.
func assemble(in Input) (File, error) {
	c, err := feed.FromEvent(in.Record)
	if err != nil {
		return File{}, fmt.Errorf("evidence: build: the signed record does not verify: %w", err)
	}
	if (in.Served != nil) != (in.Receipt != "") {
		return File{}, errors.New("evidence: build: a receipt and the served bytes go together; set both or neither")
	}

	entry := in.Entry
	var proof commit.Proof
	sources := 0
	for _, set := range []bool{in.Leaves != nil, in.LeafHashes != nil, in.Proof != nil} {
		if set {
			sources++
		}
	}
	switch {
	case sources > 1:
		return File{}, errors.New("evidence: build: set one of Leaves, LeafHashes or Proof")
	case in.Proof != nil:
		if entry == (canonical.Leaf{}) {
			return File{}, errors.New("evidence: build: Proof needs the left-out entry in Entry")
		}
		if in.Proof.Index != in.Index {
			return File{}, fmt.Errorf("evidence: build: the proof is for index %d, not %d", in.Proof.Index, in.Index)
		}
		proof = commit.Proof{
			Index:    in.Proof.Index,
			N:        in.Proof.N,
			Siblings: append([][32]byte(nil), in.Proof.Siblings...),
		}
	case in.Leaves != nil:
		if int(in.Index) >= len(in.Leaves) {
			return File{}, fmt.Errorf("evidence: build: index %d is past the %d leaves", in.Index, len(in.Leaves))
		}
		if entry == (canonical.Leaf{}) {
			entry = in.Leaves[in.Index]
		} else if entry != in.Leaves[in.Index] {
			return File{}, fmt.Errorf("evidence: build: the entry is not the leaf at index %d", in.Index)
		}
		proof, err = commit.Prove(in.Leaves, in.Index)
	case in.LeafHashes != nil:
		if entry == (canonical.Leaf{}) {
			return File{}, errors.New("evidence: build: LeafHashes needs the left-out entry in Entry")
		}
		if int(in.Index) >= len(in.LeafHashes) {
			return File{}, fmt.Errorf("evidence: build: index %d is past the %d leaf hashes", in.Index, len(in.LeafHashes))
		}
		if commit.LeafHash(entry) != in.LeafHashes[in.Index] {
			return File{}, fmt.Errorf("evidence: build: the entry's hash is not the hash at index %d", in.Index)
		}
		proof, err = commit.ProveFromLeafHashes(in.LeafHashes, in.Index)
	default:
		return File{}, errors.New("evidence: build: no leaves or leaf hashes for the record")
	}
	if err != nil {
		return File{}, fmt.Errorf("evidence: build: prove entry %d: %w", in.Index, err)
	}
	if !commit.VerifyProof(c.Network, c.BlockHash, c.Root, entry, proof) {
		return File{}, errors.New("evidence: build: the leaves do not recompute the record's signed root")
	}

	siblings := make([]string, len(proof.Siblings))
	for i, s := range proof.Siblings {
		siblings[i] = hex.EncodeToString(s[:])
	}
	f := File{
		Format:          Format,
		Claim:           ClaimOmission,
		Accused:         hex.EncodeToString(c.Author[:]),
		Network:         Network{Name: core.NetworkName(c.Network), Magic: uint32(c.Network)},
		Block:           Block{Hash: core.DisplayHex(c.BlockHash), Height: c.BlockHeight},
		CommitmentEvent: fileEvent(in.Record),
		Missing:         Missing{TxID: core.DisplayHex(entry.TxID), Tweak: hex.EncodeToString(entry.Tweak[:])},
		Proof:           Proof{Index: proof.Index, N: proof.N, Siblings: siblings},
	}
	if in.Receipt != "" {
		receipt := in.Receipt
		served := base64.StdEncoding.EncodeToString(in.Served)
		f.Receipt, f.ServedBase64 = &receipt, &served
	}
	if in.Context != nil {
		ctx := *in.Context
		f.Context = &ctx
	}
	return f, nil
}
