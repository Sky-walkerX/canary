package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/ui"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// The checker writes the verifyReport partial by hand, and the dashboard
// renders it with html/template. These tests hold the two to the same bytes.
// Only the tests import internal/ui, so the module never links html/template.

// sameMarkup renders rep both ways and fails unless the bytes match. The
// dashboard renders the JSON canary verify --json prints.
func sameMarkup(t *testing.T, name string, rep evidence.VerifyReport) {
	t.Helper()
	j, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("%s: encode report: %v", name, err)
	}
	want, wantErr := ui.VerifyReportHTML(j)
	got, gotErr := renderReport(rep)
	if (wantErr == nil) != (gotErr == nil) {
		t.Fatalf("%s: dashboard error %v, checker error %v", name, wantErr, gotErr)
	}
	if got != string(want) {
		t.Fatalf("%s: markup differs from the dashboard's partial.\nchecker:\n%s\ndashboard:\n%s", name, got, want)
	}
}

// fileMarkup checks one evidence file both ways.
func fileMarkup(t *testing.T, name string, file []byte) evidence.VerifyReport {
	t.Helper()
	rep, _ := evidence.Verify(file)
	sameMarkup(t, name, rep)
	return rep
}

func TestMarkupMatchesTheDashboard(t *testing.T) {
	good := docExample(t, "## 6. The evidence file")
	if rep := fileMarkup(t, "doc example", good); rep.Code != evidence.CodeOK {
		t.Fatalf("doc example gives %s, want ok", rep.Code)
	}

	var f map[string]any
	if err := json.Unmarshal(good, &f); err != nil {
		t.Fatal(err)
	}
	f["receipt"], f["served_base64"] = nil, nil
	noReceipt, _ := json.Marshal(f)
	if rep := fileMarkup(t, "no receipt", noReceipt); rep.Code != evidence.CodeInclusionOnly {
		t.Fatalf("no receipt gives %s, want inclusion_only", rep.Code)
	}
	f["format"] = "canary-evidence/2"
	other, _ := json.Marshal(f)
	fileMarkup(t, "other format", other)
	fileMarkup(t, "empty", nil)
	fileMarkup(t, "not JSON", []byte("this is not JSON"))
}

// Every one-byte change to the doc example gives a real verify outcome: most
// files stop at reading, and the rest stop at the step whose bytes changed.
// Each one renders the same both ways.
func TestMarkupMatchesForEveryByteChange(t *testing.T) {
	good := docExample(t, "## 6. The evidence file")
	codes := map[string]int{}
	b := bytes.Clone(good)
	for i := range b {
		orig := b[i]
		// A hex digit becomes another hex digit; any other byte flips its low bit.
		switch {
		case orig == 'f':
			b[i] = '0'
		case orig >= '0' && orig <= '9' || orig >= 'a' && orig <= 'e':
			b[i] = orig + 1
			if orig == '9' {
				b[i] = 'a'
			}
		default:
			b[i] = orig ^ 1
		}
		rep := fileMarkup(t, "byte "+itoa(i), b)
		codes[rep.Code]++
		b[i] = orig
	}
	for _, code := range []string{
		evidence.CodeMalformed, evidence.CodeBadSignature, evidence.CodeSignerMismatch,
		evidence.CodeBlockMismatch, evidence.CodeProofInvalid, evidence.CodeReceiptInvalid,
	} {
		if codes[code] == 0 {
			t.Errorf("no one-byte change gave %s; outcomes: %v", code, codes)
		}
	}
}

// Every code, with every step's outcome and every fact present or absent,
// renders the same both ways. These reports are built by hand, so they reach
// the codes no one-byte change can.
func TestMarkupMatchesForEveryCode(t *testing.T) {
	yes, no := true, false
	codes := []struct{ result, code string }{
		{evidence.ResultChecksOut, evidence.CodeOK},
		{evidence.ResultChecksOut, evidence.CodeInclusionOnly},
		{evidence.ResultUnreadable, evidence.CodeMalformed},
		{evidence.ResultUnreadable, evidence.CodeUnsupportedFormat},
		{evidence.ResultDoesNotCheckOut, evidence.CodeBadSignature},
		{evidence.ResultDoesNotCheckOut, evidence.CodeSignerMismatch},
		{evidence.ResultDoesNotCheckOut, evidence.CodeBlockMismatch},
		{evidence.ResultDoesNotCheckOut, evidence.CodeProofInvalid},
		{evidence.ResultDoesNotCheckOut, evidence.CodeReceiptInvalid},
		{evidence.ResultDoesNotCheckOut, evidence.CodeEntryServed},
		{evidence.ResultDoesNotCheckOut, evidence.CodeNotInWindow},
	}
	for _, c := range codes {
		for failAt := -1; failAt < len(wording.VerifySteps); failAt++ {
			for facts := 0; facts < 1<<5; facts++ {
				rep := evidence.VerifyReport{
					Result:  c.result,
					Code:    c.code,
					Message: wording.VerifyCode(c.code),
				}
				for i, step := range wording.VerifySteps {
					ch := evidence.Check{Step: step, Text: "Text for " + step + "."}
					switch {
					case failAt < 0 || i < failAt:
						ch.OK = &yes
					case i == failAt:
						ch.OK = &no
					}
					rep.Checks = append(rep.Checks, ch)
				}
				if facts&1 != 0 {
					rep.Accused = &evidence.Accused{Pubkey: strings.Repeat("ab", 32), Npub: "npub1example"}
				}
				if facts&2 != 0 {
					rep.Block = &evidence.Block{Hash: strings.Repeat("cd", 32), Height: 205}
				}
				if facts&4 != 0 {
					rep.Network = &evidence.Network{Name: "regtest", Magic: 3669344250}
				}
				if facts&8 != 0 {
					rep.Missing = &evidence.ReportEntry{TxID: strings.Repeat("ef", 32), Tweak: strings.Repeat("02", 33), Index: 1}
				}
				if facts&16 != 0 {
					rep.ReceiptTip = &evidence.Tip{Height: 212, Hash: strings.Repeat("12", 32)}
				}
				sameMarkup(t, c.code+" fail at "+itoa(failAt)+" facts "+itoa(facts), rep)
			}
		}
	}
}

// Text a file's author could reach, and text that needs escaping, renders the
// same both ways: markup characters, a NUL, bytes that are not UTF-8,
// characters wider than one byte, and keys of every length around the cut.
func TestMarkupMatchesForAwkwardText(t *testing.T) {
	yes := true
	awkward := []string{
		"", "a", `<script>alert("x")</script>`, `&amp; ' " + < >`, "a\x00b", "\xff\xfe bad bytes \xc3",
		"Checks out. lower-case after the label", "Checks out: ünïcode after the label", "Checks out. \xff",
		"Does not check out. ", "Checks out", "€€€€€€€€€€€€€€€€€€", strings.Repeat("0123456789abcdef", 4) + "+",
	}
	for i, s := range awkward {
		for _, length := range []int{0, 1, 4, 15, 16, 17, 64} {
			key := s
			if len(key) < length {
				key += strings.Repeat("9", length-len(key))
			}
			rep := evidence.VerifyReport{
				Result:     evidence.ResultChecksOut,
				Code:       evidence.CodeOK,
				Message:    "Checks out. " + s,
				Accused:    &evidence.Accused{Pubkey: key, Npub: s},
				Network:    &evidence.Network{Name: s},
				Block:      &evidence.Block{Height: 7},
				Missing:    &evidence.ReportEntry{TxID: key, Index: 3},
				ReceiptTip: &evidence.Tip{Height: 9},
			}
			for _, step := range wording.VerifySteps {
				rep.Checks = append(rep.Checks, evidence.Check{Step: step, OK: &yes, Text: s})
			}
			sameMarkup(t, "awkward "+itoa(i)+" length "+itoa(length), rep)
			if s != "" {
				rep.Message = s
				sameMarkup(t, "awkward message "+itoa(i), rep)
			}
		}
	}
}

// A report the dashboard refuses, the checker refuses too, with no markup.
func TestMarkupRefusesTheSameReports(t *testing.T) {
	yes := true
	valid := func() evidence.VerifyReport {
		r := evidence.VerifyReport{Result: evidence.ResultChecksOut, Code: evidence.CodeOK, Message: "Checks out."}
		for _, step := range wording.VerifySteps {
			r.Checks = append(r.Checks, evidence.Check{Step: step, OK: &yes, Text: "x"})
		}
		return r
	}
	bad := map[string]func(*evidence.VerifyReport){
		"unknown result": func(r *evidence.VerifyReport) { r.Result = "fine" },
		"no checks":      func(r *evidence.VerifyReport) { r.Checks = nil },
		"seven checks":   func(r *evidence.VerifyReport) { r.Checks = r.Checks[:7] },
		"steps swapped":  func(r *evidence.VerifyReport) { r.Checks[0], r.Checks[1] = r.Checks[1], r.Checks[0] },
		"no message":     func(r *evidence.VerifyReport) { r.Message = "" },
	}
	for name, edit := range bad {
		r := valid()
		edit(&r)
		sameMarkup(t, name, r)
		if h, err := renderReport(r); err == nil || h != "" || !strings.HasPrefix(err.Error(), "verify-wasm: ") {
			t.Errorf("%s: renderReport = %q, %v; want no markup and a verify-wasm error", name, h, err)
		}
	}
}

// FuzzMarkupMatchesTheDashboard checks any file both ways. Its seeds run with
// every go test; go test -fuzz explores further.
func FuzzMarkupMatchesTheDashboard(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"format":"canary-evidence/1"}`))
	if doc, err := readDocExample("## 6. The evidence file"); err == nil {
		f.Add(doc)
	}
	f.Fuzz(func(t *testing.T, file []byte) {
		fileMarkup(t, "fuzz", file)
	})
}

func itoa(i int) string { return strconv.Itoa(i) }
