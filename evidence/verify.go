package evidence

import (
	"errors"
	"fmt"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
	"github.com/Sky-walkerX/canary/wire"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// Sentinel errors, one per report code. Callers match them with errors.Is.
var (
	// ErrMalformed means the file is not JSON, has an unknown or missing
	// field, holds a value of the wrong type or length, or carries bytes that
	// do not decode.
	ErrMalformed = errors.New("evidence: file malformed")

	// ErrUnsupportedFormat means the format is not canary-evidence/1, or the
	// claim is not omission.
	ErrUnsupportedFormat = errors.New("evidence: format not supported")

	// ErrBadSignature means the record's event id or signature is invalid.
	ErrBadSignature = errors.New("evidence: record signature invalid")

	// ErrSignerMismatch means a key other than the accused key signed the
	// record.
	ErrSignerMismatch = errors.New("evidence: record signed by another key")

	// ErrBlockMismatch means the record, the file or the served list disagree
	// about the block, its height, its network or its n.
	ErrBlockMismatch = errors.New("evidence: block mismatch")

	// ErrProofInvalid means the Merkle proof does not carry the entry to the
	// signed root.
	ErrProofInvalid = errors.New("evidence: proof invalid")

	// ErrReceiptInvalid means the receipt's signature, network, block hash,
	// resource or body digest does not match, or it signs a dust threshold
	// other than 0.
	ErrReceiptInvalid = errors.New("evidence: receipt invalid")

	// ErrEntryServed means the served list carries the entry, or its correct
	// hash, at the proof's position or at any other. The file's claim fails.
	ErrEntryServed = errors.New("evidence: entry served")

	// ErrNotInWindow means the position is absent, but the block sat at least
	// wire.RetentionWindow blocks below the signed tip, where absence is
	// permitted.
	ErrNotInWindow = errors.New("evidence: block outside the retention window")
)

// Result values of a VerifyReport.
const (
	ResultChecksOut       = "checks_out"
	ResultDoesNotCheckOut = "does_not_check_out"
	ResultUnreadable      = "unreadable"
)

// Code values of a VerifyReport.
const (
	CodeOK                = "ok"
	CodeInclusionOnly     = "inclusion_only"
	CodeMalformed         = "malformed"
	CodeUnsupportedFormat = "unsupported_format"
	CodeBadSignature      = "bad_signature"
	CodeSignerMismatch    = "signer_mismatch"
	CodeBlockMismatch     = "block_mismatch"
	CodeProofInvalid      = "proof_invalid"
	CodeReceiptInvalid    = "receipt_invalid"
	CodeEntryServed       = "entry_served"
	CodeNotInWindow       = "not_in_window"
)

var codes = []struct {
	err    error
	code   string
	result string
}{
	{ErrMalformed, CodeMalformed, ResultUnreadable},
	{ErrUnsupportedFormat, CodeUnsupportedFormat, ResultUnreadable},
	{ErrBadSignature, CodeBadSignature, ResultDoesNotCheckOut},
	{ErrSignerMismatch, CodeSignerMismatch, ResultDoesNotCheckOut},
	{ErrBlockMismatch, CodeBlockMismatch, ResultDoesNotCheckOut},
	{ErrProofInvalid, CodeProofInvalid, ResultDoesNotCheckOut},
	{ErrReceiptInvalid, CodeReceiptInvalid, ResultDoesNotCheckOut},
	{ErrEntryServed, CodeEntryServed, ResultDoesNotCheckOut},
	{ErrNotInWindow, CodeNotInWindow, ResultDoesNotCheckOut},
}

// VerifyReport is the one result canary verify --json, canary ui and the
// browser checker all show. The formats doc fixes its fields. A field is nil
// when verify stopped before it could read that value.
type VerifyReport struct {
	Result            string       `json:"result"`
	Code              string       `json:"code"`
	Message           string       `json:"message"`
	Format            *string      `json:"format"`
	Claim             *string      `json:"claim"`
	Accused           *Accused     `json:"accused"`
	Network           *Network     `json:"network"`
	Block             *Block       `json:"block"`
	Missing           *ReportEntry `json:"missing"`
	CommitmentEventID *string      `json:"commitment_event_id"`
	HasReceipt        bool         `json:"has_receipt"`
	ReceiptTip        *Tip         `json:"receipt_tip"`
	Checks            []Check      `json:"checks"`
}

// Accused names the accused server's key, as hex and as a bech32 npub for
// display.
type Accused struct {
	Pubkey string `json:"pubkey"`
	Npub   string `json:"npub"`
}

// ReportEntry is the entry the file says was left out, and its position.
type ReportEntry struct {
	TxID  string `json:"txid"`
	Tweak string `json:"tweak"`
	Index uint32 `json:"index"`
}

// Tip is the server's signed tip from the receipt, hash in display order. A
// reader with a node can check it.
type Tip struct {
	Height uint32 `json:"height"`
	Hash   string `json:"hash"`
}

// Check is one verify step. OK is nil when the step did not run.
type Check struct {
	Step string `json:"step"`
	OK   *bool  `json:"ok"`
	Text string `json:"text"`
}

// ExitCode is the exit status canary verify gives the report: 0 for Checks
// out, 4 for inclusion only, 1 for Does not check out, 3 for a file it
// cannot read.
func (r VerifyReport) ExitCode() int {
	switch {
	case r.Result == ResultChecksOut && r.Code == CodeInclusionOnly:
		return 4
	case r.Result == ResultChecksOut:
		return 0
	case r.Result == ResultDoesNotCheckOut:
		return 1
	}
	return 3
}

// verifier holds what the steps have read so far.
type verifier struct {
	in        []byte
	rep       VerifyReport
	p         *parsed
	record    feed.Commitment
	receipt   wire.Receipt
	positions []wire.Position
	absent    bool // the proof's position is marked absent in the served list
}

// Step indexes, in the order the formats doc lists them.
const (
	stepRead = iota
	stepRecordSignature
	stepSigner
	stepBlock
	stepInclusion
	stepReceipt
	stepServedList
	stepWindow
)

// Verify checks one evidence file and returns its report. It runs the eight
// steps of the formats doc in order and stops at the first failure. It opens
// no network connection, and it takes no result from the file: every outcome
// comes from recomputing the file's signatures, proof and served bytes.
//
// The error is nil when the file checks out, with or without a receipt, and
// otherwise wraps the sentinel for the failing step. A file without a receipt
// stops after step 5 with the code inclusion_only. It shows that the server
// signed for the entry, but not what the server sent.
func Verify(b []byte) (VerifyReport, error) {
	v := &verifier{in: b}
	v.rep.Checks = make([]Check, len(wording.VerifySteps))
	for i, s := range wording.VerifySteps {
		v.rep.Checks[i] = Check{Step: s}
	}

	steps := []func() (string, error){
		v.read, v.recordSignature, v.signer, v.block, v.inclusion, v.receiptStep, v.servedList, v.window,
	}
	for i, run := range steps {
		if i == stepReceipt && !v.rep.HasReceipt {
			for j := i; j < len(steps); j++ {
				v.rep.Checks[j].Text = wording.VerifyNotRunNoReceipt
			}
			v.finish(ResultChecksOut, CodeInclusionOnly)
			return v.rep, nil
		}
		text, err := run()
		ok := err == nil
		v.rep.Checks[i].OK = &ok
		v.rep.Checks[i].Text = text
		if err != nil {
			for j := i + 1; j < len(steps); j++ {
				v.rep.Checks[j].Text = wording.VerifyNotRunEarlier
			}
			for _, c := range codes {
				if errors.Is(err, c.err) {
					v.finish(c.result, c.code)
					return v.rep, err
				}
			}
			// Every step returns one of the sentinels, so this is a bug.
			v.finish(ResultUnreadable, CodeMalformed)
			return v.rep, fmt.Errorf("%w: step %s: %v", ErrMalformed, wording.VerifySteps[i], err)
		}
	}
	v.finish(ResultChecksOut, CodeOK)
	return v.rep, nil
}

func (v *verifier) finish(result, code string) {
	v.rep.Result, v.rep.Code, v.rep.Message = result, code, wording.VerifyCode(code)
}

// read is step 1. Once it passes, the report shows the file's own values.
// They are what the file claims, and the later steps say whether they hold.
func (v *verifier) read() (string, error) {
	p, h, err := read(v.in)
	v.rep.Format, v.rep.Claim = h.format, h.claim
	if err != nil {
		if errors.Is(err, ErrUnsupportedFormat) {
			return wording.VerifyReadUnsupported, err
		}
		return wording.VerifyReadMalformed, err
	}
	v.p = p
	f := p.file

	npub, err := nip19.EncodePublicKey(f.Accused)
	if err != nil {
		npub = ""
	}
	id := f.CommitmentEvent.ID
	v.rep.Accused = &Accused{Pubkey: f.Accused, Npub: npub}
	v.rep.Network = &Network{Name: core.NetworkName(canonical.Network(f.Network.Magic)), Magic: f.Network.Magic}
	v.rep.Block = &Block{Hash: f.Block.Hash, Height: f.Block.Height}
	v.rep.Missing = &ReportEntry{TxID: f.Missing.TxID, Tweak: f.Missing.Tweak, Index: f.Proof.Index}
	v.rep.CommitmentEventID = &id
	v.rep.HasReceipt = f.Receipt != nil
	return wording.VerifyReadOK(f.Format, f.Claim), nil
}
