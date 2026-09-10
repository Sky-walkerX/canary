package testvector

import (
	"os"
	"path/filepath"
	"testing"
)

// Every committed vector must load and pass. This is the whole CI contract for
// §7: hermetic, no node, no network.
func TestAllCommittedVectorsPass(t *testing.T) {
	paths, err := filepath.Glob("../../testdata/vectors/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no vectors committed — the suite asserts nothing")
	}

	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			v, err := Load(p)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if v.Name == "" {
				t.Error("vector has no name")
			}
			if v.Rationale == "" {
				t.Error("vector has no rationale — a vector nobody can explain is a vector nobody can fix")
			}
			if err := v.Run(); err != nil {
				t.Errorf("run: %v", err)
			}
		})
	}
}

func TestVectorDetectsAWrongExpectedRoot(t *testing.T) {
	v, err := Load("../../testdata/vectors/empty-block.json")
	if err != nil {
		t.Fatal(err)
	}
	v.Expected.Root = "00" + v.Expected.Root[2:]
	if err := v.Run(); err == nil {
		t.Error("a corrupted expected root must fail the vector")
	}
}

func TestLoadRejectsMalformed(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmp, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(tmp); err == nil {
		t.Error("malformed vector must fail to load")
	}
}
