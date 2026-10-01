package evidence

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// inputFromProof rebuilds the golden file's input the way canary check
// holds it: the record, the recovered entry and a proof, with no leaf list.
func inputFromProof(t *testing.T, g golden) (Input, *parsed) {
	t.Helper()
	p, _, err := read(g.bytes)
	if err != nil {
		t.Fatal(err)
	}
	served, err := base64.StdEncoding.DecodeString(*g.file.ServedBase64)
	if err != nil {
		t.Fatal(err)
	}
	proof := p.proof
	ctx := *g.file.Context
	return Input{
		Record:  p.event,
		Entry:   p.entry,
		Index:   p.proof.Index,
		Proof:   &proof,
		Served:  served,
		Receipt: *g.file.Receipt,
		Context: &ctx,
	}, p
}

func TestBuildFromAProofMatchesBuildFromLeaves(t *testing.T) {
	g := buildGolden(t)
	in, _ := inputFromProof(t, g)

	f, err := Build(in)
	if err != nil {
		t.Fatalf("Build from a proof: %v", err)
	}
	out, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, g.bytes) {
		t.Errorf("a file built from a proof differs from one built from leaves:\n%s\n%s", out, g.bytes)
	}
}

func TestBuildFromAProofRejectsWhatCannotHold(t *testing.T) {
	g := buildGolden(t)

	tests := []struct {
		name   string
		change func(in *Input)
	}{
		{"proof and leaves together", func(in *Input) { in.LeafHashes = [][32]byte{{1}} }},
		{"proof for another index", func(in *Input) { p := *in.Proof; p.Index++; in.Proof = &p }},
		{"no entry", func(in *Input) { in.Entry.TxID, in.Entry.Tweak = [32]byte{}, [33]byte{} }},
		{"a sibling flipped", func(in *Input) {
			p := *in.Proof
			p.Siblings = append([][32]byte(nil), p.Siblings...)
			p.Siblings[0][0] ^= 1
			in.Proof = &p
		}},
		{"another entry", func(in *Input) { in.Entry.Tweak[5] ^= 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, _ := inputFromProof(t, g)
			tt.change(&in)
			if _, err := Build(in); err == nil {
				t.Fatal("Build accepted an input that cannot check out")
			}
		})
	}
}

func TestBuildDoesNotKeepTheCallersProof(t *testing.T) {
	g := buildGolden(t)
	in, _ := inputFromProof(t, g)
	f, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Proof.Siblings[0][0] ^= 1
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(b); err != nil {
		t.Errorf("changing the caller's proof after Build changed the file: %v", err)
	}
}
