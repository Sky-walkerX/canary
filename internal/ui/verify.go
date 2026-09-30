package ui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// VerifyReport is the JSON object canary verify --json prints, as the v1
// formats document fixes it. The evidence package builds it; the dashboard
// only reads it, so this type mirrors the document rather than that package.
type VerifyReport struct {
	Result            string          `json:"result"`
	Code              string          `json:"code"`
	Message           string          `json:"message"`
	Format            *string         `json:"format"`
	Claim             *string         `json:"claim"`
	Accused           *ReportAccused  `json:"accused"`
	Network           *state.Network  `json:"network"`
	Block             *state.BlockRef `json:"block"`
	Missing           *ReportMissing  `json:"missing"`
	CommitmentEventID *string         `json:"commitment_event_id"`
	HasReceipt        bool            `json:"has_receipt"`
	ReceiptTip        *state.Tip      `json:"receipt_tip"`
	Checks            []ReportCheck   `json:"checks"`
}

// ReportAccused names the accused server's key.
type ReportAccused struct {
	Pubkey string `json:"pubkey"`
	Npub   string `json:"npub"`
}

// ReportMissing is the entry the file says was left out.
type ReportMissing struct {
	Txid  string `json:"txid"`
	Tweak string `json:"tweak"`
	Index uint32 `json:"index"`
}

// ReportCheck is one of the eight verify steps. OK is nil when the step did
// not run.
type ReportCheck struct {
	Step string `json:"step"`
	OK   *bool  `json:"ok"`
	Text string `json:"text"`
}

var reportResults = map[string]bool{"checks_out": true, "does_not_check_out": true, "unreadable": true}

// ParseVerifyReport decodes a VerifyReport and checks its shape: a known
// result, all eight steps in order, and no unknown fields.
func ParseVerifyReport(b []byte) (*VerifyReport, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r VerifyReport
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("ui: read verify report: %w", err)
	}
	if !reportResults[r.Result] {
		return nil, fmt.Errorf("ui: read verify report: unknown result %q", r.Result)
	}
	if len(r.Checks) != len(wording.VerifySteps) {
		return nil, fmt.Errorf("ui: read verify report: %d checks, want %d", len(r.Checks), len(wording.VerifySteps))
	}
	for i, c := range r.Checks {
		if c.Step != wording.VerifySteps[i] {
			return nil, fmt.Errorf("ui: read verify report: check %d is %q, want %q", i, c.Step, wording.VerifySteps[i])
		}
	}
	if r.Message == "" {
		return nil, errors.New("ui: read verify report: no message")
	}
	return &r, nil
}

type reportStep struct {
	Label  string
	Text   string
	Status string
	Word   string
	Glyph  string
	Tone   string
}

type reportView struct {
	Label           string
	Glyph           string
	Tone            string
	Message         string
	InclusionDetail []string
	NotHonest       string
	Steps           []reportStep
	Accused         *hashView
	Npub            string
	Block           string
	Missing         string
	ReceiptTip      string
}

// afterLabel drops a leading copy of label from message. The badge above the
// message already shows the label, so "Checks out. The server signed..."
// reads as "The server signed...". A message that does not start with the
// label comes back unchanged.
func afterLabel(message, label string) string {
	rest, ok := strings.CutPrefix(message, label)
	if !ok {
		return message
	}
	for _, sep := range []string{". ", ": "} {
		if r, ok := strings.CutPrefix(rest, sep); ok && r != "" {
			first, size := utf8.DecodeRuneInString(r)
			return string(unicode.ToUpper(first)) + r[size:]
		}
	}
	return message
}

func buildReport(r *VerifyReport) reportView {
	label := wording.VerifyResultLabel(r.Result, r.Code)
	v := reportView{
		Label:   label,
		Message: afterLabel(r.Message, label),
	}
	switch r.Result {
	case "checks_out":
		v.Tone = toneGood
		if r.Code == "inclusion_only" {
			v.InclusionDetail = wording.VerifyInclusionOnlyDetail[:]
		}
	case "does_not_check_out":
		v.Tone = toneBad
		v.NotHonest = wording.VerifyNotHonest
	default:
		v.Tone = toneNeutral
	}
	v.Glyph = toneGlyph(v.Tone)
	for _, c := range r.Checks {
		s := reportStep{Label: wording.VerifyStep(c.Step), Text: c.Text}
		switch {
		case c.OK == nil:
			s.Status, s.Word, s.Tone = "skip", wording.StepNotRun, toneNeutral
		case *c.OK:
			s.Status, s.Word, s.Tone = "pass", wording.StepPassed, toneGood
		default:
			s.Status, s.Word, s.Tone = "fail", wording.StepFailed, toneBad
		}
		s.Glyph = toneGlyph(s.Tone)
		v.Steps = append(v.Steps, s)
	}
	if r.Accused != nil {
		h := newHash(r.Accused.Pubkey, "Copy the accused server's public key")
		v.Accused = &h
		v.Npub = r.Accused.Npub
	}
	if r.Block != nil {
		v.Block = strconv.FormatUint(uint64(r.Block.Height), 10)
		if r.Network != nil {
			v.Block += " on " + r.Network.Name
		}
	}
	if r.Missing != nil {
		v.Missing = "Position " + strconv.FormatUint(uint64(r.Missing.Index), 10) + ", transaction " + wording.ShortHash(r.Missing.Txid, 8, 8)
	}
	if r.ReceiptTip != nil {
		v.ReceiptTip = strconv.FormatUint(uint64(r.ReceiptTip.Height), 10)
	}
	return v
}
