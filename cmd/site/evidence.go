package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// checkerView is what the checker area on the home page shows. The page
// script that runs the checker reads the data attributes it renders.
type checkerView struct {
	HasEvidence  bool
	RealName     string
	RealURL      string
	TamperedName string
	TamperedURL  string
	TamperNote   string
}

// The tampered copy flips one hex digit of one of these JSON values. Either
// change makes the inclusion step fail for a real reason: the proof no longer
// leads from the left-out entry to the signed root. A block with one entry
// has no sibling, so its copy changes the entry's txid instead.
const (
	tamperSibling = "proof.siblings[0]"
	tamperTxid    = "missing.txid"
)

// writeEvidence publishes the real evidence file unchanged, and a copy with
// one byte flipped. It records exactly which byte, so the page can say so.
func (s *site) writeEvidence() error {
	if s.cfg.Evidence == "" {
		return nil
	}
	real, err := os.ReadFile(s.cfg.Evidence)
	if err != nil {
		return fmt.Errorf("site: read evidence: %w", err)
	}
	tampered, offset, field, err := tamper(real)
	if err != nil {
		return fmt.Errorf("site: evidence %s: %w", s.cfg.Evidence, err)
	}
	name := filepath.Base(s.cfg.Evidence)
	tname := strings.TrimSuffix(name, ".json") + "-tampered.json"
	if err := s.write("evidence/"+name, real); err != nil {
		return err
	}
	if err := s.write("evidence/"+tname, tampered); err != nil {
		return err
	}
	s.checker = checkerView{
		HasEvidence:  true,
		RealName:     name,
		RealURL:      "/evidence/" + name,
		TamperedName: tname,
		TamperedURL:  "/evidence/" + tname,
		TamperNote:   wording.Site.TamperNote(offset+1, field, string(real[offset]), string(tampered[offset])),
	}
	return nil
}

// tamper returns a copy of an evidence file with one hex digit flipped, the
// offset of the byte it changed, and the JSON value that holds it. It changes
// the first proof sibling, or the left-out entry's txid when the proof has no
// sibling. XOR 1 on the value's first byte changes one hex digit, so exactly
// one byte of the file changes and the JSON stays valid.
func tamper(file []byte) ([]byte, int, string, error) {
	var ev struct {
		Format  string `json:"format"`
		Missing struct {
			Txid string `json:"txid"`
		} `json:"missing"`
		Proof struct {
			Siblings []string `json:"siblings"`
		} `json:"proof"`
	}
	if err := json.Unmarshal(file, &ev); err != nil {
		return nil, 0, "", fmt.Errorf("not JSON: %w", err)
	}
	if ev.Format != "canary-evidence/1" {
		return nil, 0, "", fmt.Errorf("format %q, want canary-evidence/1", ev.Format)
	}
	field, value := tamperTxid, ev.Missing.Txid
	if len(ev.Proof.Siblings) > 0 {
		field, value = tamperSibling, ev.Proof.Siblings[0]
	}
	if len(value) != 64 || flipHexDigit(value[1]) == value[1] {
		return nil, 0, "", fmt.Errorf("%s is missing or not 32 bytes of hex", field)
	}
	quoted := []byte(`"` + value + `"`)
	at := bytes.Index(file, quoted)
	if at < 0 || bytes.Index(file[at+1:], quoted) >= 0 {
		return nil, 0, "", fmt.Errorf("%s does not appear exactly once in the file", field)
	}
	// The low hex digit of the first byte sits after the quote and the high digit.
	offset := at + 2
	out := bytes.Clone(file)
	out[offset] = flipHexDigit(out[offset])
	return out, offset, field, nil
}

// flipHexDigit returns the hex digit for the value XOR 1, in the same case.
func flipHexDigit(c byte) byte {
	const lower, upper = "0123456789abcdef", "0123456789ABCDEF"
	if i := strings.IndexByte(lower, c); i >= 0 {
		return lower[i^1]
	}
	if i := strings.IndexByte(upper, c); i >= 0 {
		return upper[i^1]
	}
	return c
}
