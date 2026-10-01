package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
	"github.com/Sky-walkerX/canary/wire"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/nbd-wtf/go-nostr"
)

func stepIndex(t *testing.T, name string) int {
	t.Helper()
	for i, s := range wording.VerifySteps {
		if s == name {
			return i
		}
	}
	t.Fatalf("no step %q", name)
	return -1
}

// wantChecksOut asserts a full Checks out report and returns it.
func wantChecksOut(t *testing.T, b []byte) VerifyReport {
	t.Helper()
	rep, err := Verify(b)
	if err != nil {
		t.Fatalf("Verify: %v\nchecks: %+v", err, rep.Checks)
	}
	if rep.Result != ResultChecksOut || rep.Code != CodeOK {
		t.Fatalf("result %s/%s, want checks_out/ok", rep.Result, rep.Code)
	}
	if rep.Message != wording.VerifyCode(CodeOK) {
		t.Errorf("message %q", rep.Message)
	}
	if len(rep.Checks) != len(wording.VerifySteps) {
		t.Fatalf("%d checks, want %d", len(rep.Checks), len(wording.VerifySteps))
	}
	for i, c := range rep.Checks {
		if c.Step != wording.VerifySteps[i] || c.OK == nil || !*c.OK || c.Text == "" {
			t.Errorf("check %d = %s ok=%v %q, want a passed %s", i, c.Step, c.OK, c.Text, wording.VerifySteps[i])
		}
	}
	if rep.ExitCode() != 0 {
		t.Errorf("exit code %d, want 0", rep.ExitCode())
	}
	return rep
}

// The scenario's record carries a fixed created_at, so every build of it
// gives the same event id. With the clock's time instead, two builds a
// second boundary apart differ, and a test that compares them fails at
// random.
func TestScenarioRecordIsFixed(t *testing.T) {
	s := newScenario()
	a := s.event(t)
	if a.CreatedAt != scenarioCreatedAt {
		t.Errorf("created_at = %d, want the fixed %d", a.CreatedAt, scenarioCreatedAt)
	}
	if b := s.event(t); a.ID != b.ID {
		t.Errorf("two builds of the scenario's record have ids %s and %s", a.ID, b.ID)
	}
}

func TestScenarioChecksOut(t *testing.T) {
	s := newScenario()
	f := s.file(t)
	rep := wantChecksOut(t, marshal(t, f))

	pub := pubOf(t, s.recordKey)
	if rep.Accused == nil || rep.Accused.Pubkey != hex.EncodeToString(pub[:]) || !strings.HasPrefix(rep.Accused.Npub, "npub1") {
		t.Errorf("accused = %+v", rep.Accused)
	}
	if rep.Network == nil || rep.Network.Name != "regtest" || rep.Network.Magic != uint32(regtest) {
		t.Errorf("network = %+v", rep.Network)
	}
	if rep.Block == nil || rep.Block.Height != 205 || rep.Block.Hash != core.DisplayHex(s.blockHash) {
		t.Errorf("block = %+v", rep.Block)
	}
	if rep.Missing == nil || rep.Missing.Index != 1 || rep.Missing.TxID != core.DisplayHex(s.leaves[1].TxID) ||
		rep.Missing.Tweak != hex.EncodeToString(s.leaves[1].Tweak[:]) {
		t.Errorf("missing = %+v", rep.Missing)
	}
	if !rep.HasReceipt || rep.ReceiptTip == nil || rep.ReceiptTip.Height != 212 || rep.ReceiptTip.Hash != core.DisplayHex(s.receipt.TipHash) {
		t.Errorf("receipt: has=%v tip=%+v", rep.HasReceipt, rep.ReceiptTip)
	}
	if rep.Format == nil || *rep.Format != Format || rep.Claim == nil || *rep.Claim != ClaimOmission {
		t.Errorf("format/claim = %v/%v", rep.Format, rep.Claim)
	}
	if rep.CommitmentEventID == nil || *rep.CommitmentEventID != f.CommitmentEvent.ID {
		t.Errorf("commitment_event_id = %v", rep.CommitmentEventID)
	}
	want := []string{
		wording.VerifyReadOK(Format, ClaimOmission),
		wording.VerifyRecordSignatureOK,
		wording.VerifySignerOK,
		wording.VerifyBlockOK(205, "regtest", uint32(regtest)),
		wording.VerifyInclusionOK(1, 3),
		wording.VerifyReceiptOK(137),
		wording.VerifyServedAbsent(3, 1),
		wording.VerifyWindowInside(212, 7, wire.RetentionWindow),
	}
	for i, w := range want {
		if rep.Checks[i].Text != w {
			t.Errorf("check %s text %q, want %q", rep.Checks[i].Step, rep.Checks[i].Text, w)
		}
	}
}

func TestParseRoundTrip(t *testing.T) {
	s := newScenario()
	f := s.file(t)
	f.Context = &Context{ServerLabel: "withholder", FoundBy: "other_server", WrittenAt: "2026-10-03T08:32:11Z"}
	b := marshal(t, f)
	got, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	again := marshal(t, got)
	if !bytes.Equal(b, again) {
		t.Errorf("parse and marshal changed the file:\n%s\n%s", b, again)
	}
}

type failCase struct {
	name string
	file func(t *testing.T) []byte
	step string
	code string
	err  error
	text string // the failing check's text, when the case pins it
}

// fromScenario builds a failing file by changing the scenario before signing.
func fromScenario(fn func(s *scenario)) func(t *testing.T) []byte {
	return func(t *testing.T) []byte {
		s := newScenario()
		fn(s)
		return s.json(t)
	}
}

// fromFile builds a failing file by editing a valid one after signing.
func fromFile(fn func(t *testing.T, m map[string]any)) func(t *testing.T) []byte {
	return func(t *testing.T) []byte {
		return edit(t, newScenario().json(t), func(m map[string]any) { fn(t, m) })
	}
}

// fromBytes builds a failing file by rewriting a valid one's bytes.
func fromBytes(fn func(b []byte) []byte) func(t *testing.T) []byte {
	return func(t *testing.T) []byte { return fn(newScenario().json(t)) }
}

// fromParts builds a failing file by editing the typed file before encoding.
func fromParts(fn func(t *testing.T, f *File)) func(t *testing.T) []byte {
	return func(t *testing.T) []byte {
		f := newScenario().file(t)
		fn(t, &f)
		return marshal(t, f)
	}
}

func failCases() []failCase {
	otherHash := sha256.Sum256([]byte("another block"))
	signet := canonical.Network(chaincfg.SigNetParams.Net)
	return []failCase{
		// read
		{name: "not JSON", file: func(*testing.T) []byte { return []byte("this is not JSON") },
			step: "read", code: CodeMalformed, err: ErrMalformed, text: wording.VerifyReadMalformed},
		{name: "empty file", file: func(*testing.T) []byte { return nil },
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "a JSON array", file: func(*testing.T) []byte { return []byte("[]") },
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "a stored result field", file: fromFile(func(_ *testing.T, m map[string]any) { m["result"] = "checks_out" }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "unknown field in network", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "network")["verified"] = true }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "unknown field in block", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "block")["state"] = "compromised" }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "unknown field in commitment_event", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "commitment_event")["seen_on"] = "x" }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "unknown field in missing", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "missing")["index"] = 1 }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "unknown field in proof", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "proof")["root"] = "00" }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "unknown field in context", file: fromFile(func(_ *testing.T, m map[string]any) {
			m["context"] = map[string]any{"server_label": "x", "verdict": "guilty"}
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "context that is not an object", file: fromFile(func(_ *testing.T, m map[string]any) { m["context"] = "notes" }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "context note that is not a string", file: fromFile(func(_ *testing.T, m map[string]any) {
			m["context"] = map[string]any{"server_label": 7}
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "null context", file: fromFile(func(_ *testing.T, m map[string]any) { m["context"] = nil }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "newer format", file: fromFile(func(_ *testing.T, m map[string]any) { m["format"] = "canary-evidence/2" }),
			step: "read", code: CodeUnsupportedFormat, err: ErrUnsupportedFormat, text: wording.VerifyReadUnsupported},
		{name: "newer format with a field v1 lacks", file: fromFile(func(_ *testing.T, m map[string]any) {
			m["format"] = "canary-evidence/2"
			m["relay_proof"] = "abc"
		}), step: "read", code: CodeUnsupportedFormat, err: ErrUnsupportedFormat},
		{name: "another claim", file: fromFile(func(_ *testing.T, m map[string]any) { m["claim"] = "equivocation" }),
			step: "read", code: CodeUnsupportedFormat, err: ErrUnsupportedFormat},
		{name: "format that is not a string", file: fromFile(func(_ *testing.T, m map[string]any) { m["format"] = 1 }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "no format", file: fromFile(func(_ *testing.T, m map[string]any) { delete(m, "format") }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "malformed base64", file: fromFile(func(_ *testing.T, m map[string]any) { m["served_base64"] = "not*base64!" }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "base64 with a line break", file: fromFile(func(_ *testing.T, m map[string]any) {
			s := m["served_base64"].(string)
			m["served_base64"] = s[:8] + "\n" + s[8:]
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "base64 without padding", file: fromFile(func(_ *testing.T, m map[string]any) {
			m["served_base64"] = strings.TrimRight(m["served_base64"].(string), "=")
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "URL-safe base64", file: fromParts(func(t *testing.T, f *File) {
			s := base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb, 0xff}, 9))
			f.ServedBase64 = &s
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "receipt without the served list", file: fromFile(func(_ *testing.T, m map[string]any) { m["served_base64"] = nil }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "served list without a receipt", file: fromFile(func(_ *testing.T, m map[string]any) { m["receipt"] = nil }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "receipt that is not a string", file: fromFile(func(_ *testing.T, m map[string]any) { m["receipt"] = 12 }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "no receipt key", file: fromFile(func(_ *testing.T, m map[string]any) { delete(m, "receipt"); delete(m, "served_base64") }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "no proof", file: fromFile(func(_ *testing.T, m map[string]any) { delete(m, "proof") }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "null block", file: fromFile(func(_ *testing.T, m map[string]any) { m["block"] = nil }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "null tag value", file: fromFile(func(_ *testing.T, m map[string]any) {
			obj(m, "commitment_event")["tags"].([]any)[0].([]any)[1] = nil
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "height as a string", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "block")["height"] = "205" }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "negative height", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "block")["height"] = -1 }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "fractional index", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "proof")["index"] = 1.5 }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "uppercase accused", file: fromFile(func(_ *testing.T, m map[string]any) { m["accused"] = strings.ToUpper(m["accused"].(string)) }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "short accused", file: fromFile(func(_ *testing.T, m map[string]any) { m["accused"] = m["accused"].(string)[:62] }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "uppercase block hash", file: fromFile(func(_ *testing.T, m map[string]any) {
			obj(m, "block")["hash"] = strings.ToUpper(obj(m, "block")["hash"].(string))
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "short event id", file: fromFile(func(_ *testing.T, m map[string]any) {
			ev := obj(m, "commitment_event")
			ev["id"] = ev["id"].(string)[:63]
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "short signature", file: fromFile(func(_ *testing.T, m map[string]any) {
			ev := obj(m, "commitment_event")
			ev["sig"] = ev["sig"].(string)[:126]
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "short tweak", file: fromFile(func(_ *testing.T, m map[string]any) {
			obj(m, "missing")["tweak"] = obj(m, "missing")["tweak"].(string)[:64]
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "short sibling", file: fromFile(func(_ *testing.T, m map[string]any) {
			sib := obj(m, "proof")["siblings"].([]any)
			sib[0] = sib[0].(string)[:62]
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "null siblings", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "proof")["siblings"] = nil }),
			step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "duplicate key", file: fromBytes(func(b []byte) []byte {
			return append([]byte(`{"accused":"`+strings.Repeat("00", 32)+`",`), bytes.TrimPrefix(bytes.TrimSpace(b), []byte("{"))...)
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "key in another case", file: fromBytes(func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"accused"`), []byte(`"Accused"`), 1)
		}), step: "read", code: CodeMalformed, err: ErrMalformed},
		{name: "data after the object", file: fromBytes(func(b []byte) []byte { return append(b, []byte("{}")...) }),
			step: "read", code: CodeMalformed, err: ErrMalformed},

		// record_signature
		{name: "flipped event id", file: fromFile(func(_ *testing.T, m map[string]any) {
			ev := obj(m, "commitment_event")
			ev["id"] = flipHex(ev["id"].(string), 10)
		}), step: "record_signature", code: CodeBadSignature, err: ErrBadSignature, text: wording.VerifyRecordSignatureBad},
		{name: "flipped record signature", file: fromFile(func(_ *testing.T, m map[string]any) {
			ev := obj(m, "commitment_event")
			ev["sig"] = flipHex(ev["sig"].(string), 100)
		}), step: "record_signature", code: CodeBadSignature, err: ErrBadSignature},
		{name: "edited height tag", file: fromFile(func(_ *testing.T, m map[string]any) {
			obj(m, "commitment_event")["tags"].([]any)[1].([]any)[1] = "206"
			obj(m, "block")["height"] = 206
		}), step: "record_signature", code: CodeBadSignature, err: ErrBadSignature},
		{name: "edited created_at", file: fromFile(func(_ *testing.T, m map[string]any) {
			obj(m, "commitment_event")["created_at"] = 1
		}), step: "record_signature", code: CodeBadSignature, err: ErrBadSignature},
		{name: "wrong kind", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "commitment_event")["kind"] = 1 }),
			step: "record_signature", code: CodeMalformed, err: ErrMalformed, text: wording.VerifyRecordMalformed},
		{name: "signed record without an n tag", file: fromParts(func(t *testing.T, f *File) {
			f.CommitmentEvent = eventWith(t, testKey(1), func(ev *nostr.Event) {
				ev.Tags = append(ev.Tags[:2:2], ev.Tags[3:]...)
			})
		}), step: "record_signature", code: CodeMalformed, err: ErrMalformed},
		{name: "signed record whose root tag differs from its content", file: fromParts(func(t *testing.T, f *File) {
			f.CommitmentEvent = eventWith(t, testKey(1), func(ev *nostr.Event) {
				ev.Tags[5][1] = strings.Repeat("ab", 32)
			})
		}), step: "record_signature", code: CodeMalformed, err: ErrMalformed},

		// signer
		{name: "accused is another key", file: fromFile(func(t *testing.T, m map[string]any) {
			p := pubOf(t, testKey(2))
			m["accused"] = hex.EncodeToString(p[:])
		}), step: "signer", code: CodeSignerMismatch, err: ErrSignerMismatch, text: wording.VerifySignerBad},

		// block
		{name: "another block hash", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "block")["hash"] = core.DisplayHex(otherHash) }),
			step: "block", code: CodeBlockMismatch, err: ErrBlockMismatch, text: wording.VerifyBlockBad},
		{name: "another height", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "block")["height"] = 204 }),
			step: "block", code: CodeBlockMismatch, err: ErrBlockMismatch},
		{name: "another network", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "network")["magic"] = uint32(signet) }),
			step: "block", code: CodeBlockMismatch, err: ErrBlockMismatch},

		// inclusion
		{name: "flipped byte in a proof sibling", file: fromFile(func(_ *testing.T, m map[string]any) {
			sib := obj(m, "proof")["siblings"].([]any)
			sib[1] = flipHex(sib[1].(string), 40)
		}), step: "inclusion", code: CodeProofInvalid, err: ErrProofInvalid, text: wording.VerifyInclusionBad(1, 3)},
		{name: "proof for another size", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "proof")["n"] = 4 }),
			step: "inclusion", code: CodeProofInvalid, err: ErrProofInvalid, text: wording.VerifyInclusionWrongSize(4, 3)},
		{name: "proof for another position", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "proof")["index"] = 0 }),
			step: "inclusion", code: CodeProofInvalid, err: ErrProofInvalid},
		{name: "index past the end", file: fromFile(func(_ *testing.T, m map[string]any) { obj(m, "proof")["index"] = 3 }),
			step: "inclusion", code: CodeProofInvalid, err: ErrProofInvalid},
		{name: "another tweak", file: fromFile(func(_ *testing.T, m map[string]any) {
			obj(m, "missing")["tweak"] = flipHex(obj(m, "missing")["tweak"].(string), 30)
		}), step: "inclusion", code: CodeProofInvalid, err: ErrProofInvalid},
		{name: "another txid", file: fromFile(func(_ *testing.T, m map[string]any) {
			obj(m, "missing")["txid"] = flipHex(obj(m, "missing")["txid"].(string), 0)
		}), step: "inclusion", code: CodeProofInvalid, err: ErrProofInvalid},
		{name: "extra sibling", file: fromFile(func(_ *testing.T, m map[string]any) {
			p := obj(m, "proof")
			p["siblings"] = append(p["siblings"].([]any), strings.Repeat("00", 32))
		}), step: "inclusion", code: CodeProofInvalid, err: ErrProofInvalid},

		// receipt
		{name: "receipt from another key", file: fromScenario(func(s *scenario) { s.receiptKey = testKey(2) }),
			step: "receipt", code: CodeReceiptInvalid, err: ErrReceiptInvalid, text: wording.VerifyReceiptWrongKey},
		{name: "receipt for another block", file: fromScenario(func(s *scenario) { s.receipt.BlockHash = otherHash }),
			step: "receipt", code: CodeReceiptInvalid, err: ErrReceiptInvalid, text: wording.VerifyReceiptOtherBlock},
		{name: "receipt for another network", file: fromScenario(func(s *scenario) { s.receipt.Network = signet }),
			step: "receipt", code: CodeReceiptInvalid, err: ErrReceiptInvalid, text: wording.VerifyReceiptOtherNetwork},
		{name: "receipt for another resource", file: fromScenario(func(s *scenario) { s.receipt.Resource = 0x02 }),
			step: "receipt", code: CodeReceiptInvalid, err: ErrReceiptInvalid, text: wording.VerifyReceiptOtherResource},
		{name: "receipt for a dust-filtered list", file: fromScenario(func(s *scenario) { s.receipt.DustSat = 10000 }),
			step: "receipt", code: CodeReceiptInvalid, err: ErrReceiptInvalid, text: wording.VerifyReceiptDust(10000)},
		{name: "receipt over other bytes", file: fromScenario(func(s *scenario) {
			s.keepDigest = true
			s.receipt.BodySHA256 = sha256.Sum256([]byte("another list"))
		}), step: "receipt", code: CodeReceiptInvalid, err: ErrReceiptInvalid, text: wording.VerifyReceiptOtherBody(137)},
		{name: "served bytes edited after signing", file: fromFile(func(t *testing.T, m map[string]any) {
			b, _ := base64.StdEncoding.DecodeString(m["served_base64"].(string))
			b[5] ^= 0x01
			m["served_base64"] = base64.StdEncoding.EncodeToString(b)
		}), step: "receipt", code: CodeReceiptInvalid, err: ErrReceiptInvalid},
		{name: "flipped receipt signature", file: fromFile(func(_ *testing.T, m map[string]any) {
			m["receipt"] = flipHex(m["receipt"].(string), 300)
		}), step: "receipt", code: CodeReceiptInvalid, err: ErrReceiptInvalid, text: wording.VerifyReceiptWrongKey},
		{name: "flipped signed tip", file: fromFile(func(_ *testing.T, m map[string]any) {
			m["receipt"] = flipHex(m["receipt"].(string), 93) // tip_height, low byte
		}), step: "receipt", code: CodeReceiptInvalid, err: ErrReceiptInvalid},
		{name: "short receipt", file: fromFile(func(_ *testing.T, m map[string]any) { m["receipt"] = m["receipt"].(string)[:354] }),
			step: "receipt", code: CodeMalformed, err: ErrMalformed, text: wording.VerifyReceiptMalformed},
		{name: "receipt version 2", file: fromFile(func(_ *testing.T, m map[string]any) { m["receipt"] = "02" + m["receipt"].(string)[2:] }),
			step: "receipt", code: CodeMalformed, err: ErrMalformed},
		{name: "uppercase receipt", file: fromFile(func(_ *testing.T, m map[string]any) { m["receipt"] = strings.ToUpper(m["receipt"].(string)) }),
			step: "receipt", code: CodeMalformed, err: ErrMalformed},

		// served_list
		{name: "signed bytes that are not a list", file: fromScenario(func(s *scenario) { s.body = []byte{3, 0, 0, 0, 9} }),
			step: "served_list", code: CodeMalformed, err: ErrMalformed, text: wording.VerifyServedMalformed},
		{name: "signed list with bytes left over", file: fromScenario(func(s *scenario) {
			b, _ := wire.EncodeResponse(s.served)
			s.body = append(b, 0)
		}), step: "served_list", code: CodeMalformed, err: ErrMalformed},
		{name: "signed list shorter than n", file: fromScenario(func(s *scenario) { s.served = s.served[:2] }),
			step: "served_list", code: CodeBlockMismatch, err: ErrBlockMismatch, text: wording.VerifyServedWrongSize(2, 3)},
		{name: "signed list longer than n", file: fromScenario(func(s *scenario) {
			s.served = append(s.served, wire.Position{Kind: wire.KindAbsent})
		}), step: "served_list", code: CodeBlockMismatch, err: ErrBlockMismatch},
		{name: "position carries the entry", file: fromScenario(func(s *scenario) {
			s.served[1] = wire.Position{Kind: wire.KindFull, Leaf: s.leaves[1]}
		}), step: "served_list", code: CodeEntryServed, err: ErrEntryServed, text: wording.VerifyServedEntry(1)},
		{name: "position carries the entry's hash", file: fromScenario(func(s *scenario) {
			s.served[1] = wire.Position{Kind: wire.KindHash, Hash: commit.LeafHash(s.leaves[1])}
		}), step: "served_list", code: CodeEntryServed, err: ErrEntryServed, text: wording.VerifyServedEntryHash(1)},
		{name: "entry served at another position", file: fromScenario(func(s *scenario) {
			s.served = []wire.Position{
				{Kind: wire.KindFull, Leaf: s.leaves[0]},
				{Kind: wire.KindFull, Leaf: s.leaves[2]},
				{Kind: wire.KindFull, Leaf: s.leaves[1]},
			}
		}), step: "served_list", code: CodeEntryServed, err: ErrEntryServed, text: wording.VerifyServedEntryElsewhere(1, 2)},
		{name: "entry's hash served at another position", file: fromScenario(func(s *scenario) {
			s.served = []wire.Position{
				{Kind: wire.KindHash, Hash: commit.LeafHash(s.leaves[1])},
				{Kind: wire.KindAbsent},
				{Kind: wire.KindFull, Leaf: s.leaves[2]},
			}
		}), step: "served_list", code: CodeEntryServed, err: ErrEntryServed, text: wording.VerifyServedEntryElsewhere(1, 0)},

		// window
		{name: "block outside the window", file: fromScenario(func(s *scenario) { s.receipt.TipHeight = s.height + wire.RetentionWindow }),
			step: "window", code: CodeNotInWindow, err: ErrNotInWindow,
			text: wording.VerifyWindowOutside(205+wire.RetentionWindow, wire.RetentionWindow, wire.RetentionWindow)},
		{name: "block far outside the window", file: fromScenario(func(s *scenario) { s.receipt.TipHeight = 900 }),
			step: "window", code: CodeNotInWindow, err: ErrNotInWindow},
	}
}

// Each step fails on its own, with its own code, and stops verify there.
func TestEachStepFailsOnItsOwn(t *testing.T) {
	for _, tc := range failCases() {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.file(t)
			rep, err := Verify(b)
			if err == nil {
				t.Fatalf("Verify passed, want %s at step %s", tc.code, tc.step)
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("error %v, want %v", err, tc.err)
			}
			if !strings.HasPrefix(err.Error(), "evidence: ") {
				t.Errorf("error %q does not start with the package name", err)
			}
			if rep.Code != tc.code {
				t.Errorf("code %s, want %s (error %v)", rep.Code, tc.code, err)
			}
			wantResult, wantExit := ResultDoesNotCheckOut, 1
			if tc.code == CodeMalformed || tc.code == CodeUnsupportedFormat {
				wantResult, wantExit = ResultUnreadable, 3
			}
			if rep.Result != wantResult || rep.ExitCode() != wantExit {
				t.Errorf("result %s exit %d, want %s exit %d", rep.Result, rep.ExitCode(), wantResult, wantExit)
			}
			if rep.Message != wording.VerifyCode(tc.code) {
				t.Errorf("message %q, want %q", rep.Message, wording.VerifyCode(tc.code))
			}

			at := stepIndex(t, tc.step)
			if len(rep.Checks) != len(wording.VerifySteps) {
				t.Fatalf("%d checks, want all %d", len(rep.Checks), len(wording.VerifySteps))
			}
			for i, c := range rep.Checks {
				if c.Step != wording.VerifySteps[i] {
					t.Errorf("check %d is %s, want %s", i, c.Step, wording.VerifySteps[i])
				}
				switch {
				case i < at:
					if c.OK == nil || !*c.OK {
						t.Errorf("step %s did not pass before the failing step %s: %q", c.Step, tc.step, c.Text)
					}
				case i == at:
					if c.OK == nil || *c.OK {
						t.Errorf("step %s ok=%v, want false; text %q", c.Step, c.OK, c.Text)
					}
					if c.Text == "" || (tc.text != "" && c.Text != tc.text) {
						t.Errorf("failing text %q, want %q", c.Text, tc.text)
					}
				default:
					if c.OK != nil || c.Text != wording.VerifyNotRunEarlier {
						t.Errorf("step %s after the failure: ok=%v text %q", c.Step, c.OK, c.Text)
					}
				}
			}
		})
	}
}

// The report fills a field only once verify has read that value.
func TestReportFieldsAreNullBeforeTheyAreRead(t *testing.T) {
	rep, _ := Verify([]byte("{"))
	if rep.Format != nil || rep.Claim != nil || rep.Accused != nil || rep.Network != nil || rep.Block != nil ||
		rep.Missing != nil || rep.CommitmentEventID != nil || rep.HasReceipt || rep.ReceiptTip != nil {
		t.Errorf("a file that is not JSON filled fields: %+v", rep)
	}
	out, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"format":null`, `"accused":null`, `"receipt_tip":null`, `"has_receipt":false`} {
		if !bytes.Contains(out, []byte(k)) {
			t.Errorf("report JSON lacks %s: %s", k, out)
		}
	}

	newer := edit(t, newScenario().json(t), func(m map[string]any) { m["format"] = "canary-evidence/2" })
	rep, _ = Verify(newer)
	if rep.Format == nil || *rep.Format != "canary-evidence/2" {
		t.Errorf("format as read = %v, want canary-evidence/2", rep.Format)
	}
	if rep.Accused != nil || rep.Block != nil {
		t.Error("a newer format filled fields this reader cannot read")
	}

	// A forged receipt carries a tip nobody signed, so the report leaves it out.
	s := newScenario()
	s.receiptKey = testKey(2)
	rep, _ = Verify(s.json(t))
	if !rep.HasReceipt || rep.ReceiptTip != nil {
		t.Errorf("forged receipt: has=%v tip=%+v, want a receipt and no tip", rep.HasReceipt, rep.ReceiptTip)
	}
}

// Without a receipt a file proves inclusion only: the user can be sure, but
// cannot yet prove to others what the server sent.
func TestNoReceiptIsInclusionOnly(t *testing.T) {
	s := newScenario()
	s.noReceipt = true
	b := s.json(t)
	if !bytes.Contains(b, []byte(`"receipt": null`)) || !bytes.Contains(b, []byte(`"served_base64": null`)) {
		t.Fatalf("a file without a receipt must say null for both:\n%s", b)
	}

	rep, err := Verify(b)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Result != ResultChecksOut || rep.Code != CodeInclusionOnly {
		t.Fatalf("result %s/%s, want checks_out/inclusion_only", rep.Result, rep.Code)
	}
	if rep.Message != wording.VerifyInclusionOnly {
		t.Errorf("message %q, want %q", rep.Message, wording.VerifyInclusionOnly)
	}
	if rep.HasReceipt || rep.ReceiptTip != nil {
		t.Error("a file without a receipt reports one")
	}
	if rep.ExitCode() != 4 {
		t.Errorf("exit code %d, want 4", rep.ExitCode())
	}
	for i, c := range rep.Checks {
		if i < stepIndex(t, "receipt") {
			if c.OK == nil || !*c.OK {
				t.Errorf("step %s did not pass: %q", c.Step, c.Text)
			}
			continue
		}
		if c.OK != nil || c.Text != wording.VerifyNotRunNoReceipt {
			t.Errorf("step %s: ok=%v text %q, want not run for want of a receipt", c.Step, c.OK, c.Text)
		}
	}
}

// A file without a receipt still fails on steps 1 to 5.
func TestNoReceiptStillChecksInclusion(t *testing.T) {
	s := newScenario()
	s.noReceipt = true
	b := edit(t, s.json(t), func(m map[string]any) {
		sib := obj(m, "proof")["siblings"].([]any)
		sib[0] = flipHex(sib[0].(string), 3)
	})
	rep, err := Verify(b)
	if !errors.Is(err, ErrProofInvalid) || rep.Code != CodeProofInvalid {
		t.Fatalf("error %v code %s, want proof_invalid", err, rep.Code)
	}
	if c := rep.Checks[stepIndex(t, "window")]; c.OK != nil || c.Text != wording.VerifyNotRunEarlier {
		t.Errorf("window after a failure: %+v", c)
	}
}

func TestWindowBoundaries(t *testing.T) {
	tests := []struct {
		name string
		tip  uint32
		text string
		ok   bool
	}{
		{"the tip itself", 205, wording.VerifyWindowInside(205, 0, wire.RetentionWindow), true},
		{"the oldest block inside", 205 + wire.RetentionWindow - 1,
			wording.VerifyWindowInside(205+wire.RetentionWindow-1, wire.RetentionWindow-1, wire.RetentionWindow), true},
		{"the first block outside", 205 + wire.RetentionWindow, "", false},
		{"a tip below the block", 200, wording.VerifyWindowAboveTip(200, wire.RetentionWindow), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario()
			s.receipt.TipHeight = tt.tip
			rep, err := Verify(s.json(t))
			if tt.ok {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if got := rep.Checks[stepIndex(t, "window")].Text; got != tt.text {
					t.Errorf("window text %q, want %q", got, tt.text)
				}
				return
			}
			if !errors.Is(err, ErrNotInWindow) {
				t.Errorf("error %v, want ErrNotInWindow", err)
			}
		})
	}
}

// Different data at a committed position is never permitted, so the window
// does not matter for it.
func TestDifferentDataAtThePositionChecksOut(t *testing.T) {
	other := leafFor(9)
	tests := []struct {
		name   string
		pos    wire.Position
		served string
	}{
		{"another entry", wire.Position{Kind: wire.KindFull, Leaf: other}, wording.VerifyServedOtherEntry(3, 1)},
		{"another hash", wire.Position{Kind: wire.KindHash, Hash: commit.LeafHash(other)}, wording.VerifyServedOtherHash(3, 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario()
			s.served[1] = tt.pos
			s.receipt.TipHeight = 5000 // far outside the window
			rep := wantChecksOut(t, s.json(t))
			if got := rep.Checks[stepIndex(t, "served_list")].Text; got != tt.served {
				t.Errorf("served_list text %q, want %q", got, tt.served)
			}
			if got := rep.Checks[stepIndex(t, "window")].Text; got != wording.VerifyWindowNotNeeded(1) {
				t.Errorf("window text %q", got)
			}
		})
	}
}

// The result comes from recomputation only. Nothing the file says about
// itself, apart from the values verify checks, changes it.
func TestVerifyIgnoresTheFilesOwnWords(t *testing.T) {
	b := edit(t, newScenario().json(t), func(m map[string]any) {
		obj(m, "network")["name"] = "main"
		m["context"] = map[string]any{
			"server_label": "honest",
			"found_by":     "a hunch",
			"written_by":   "Does not check out",
			"written_at":   "never",
		}
	})
	rep := wantChecksOut(t, b)
	if rep.Network.Name != "regtest" {
		t.Errorf("network name %q, want regtest from the magic", rep.Network.Name)
	}
	out, _ := json.Marshal(rep)
	for _, s := range []string{"a hunch", "honest", "never"} {
		if bytes.Contains(out, []byte(s)) {
			t.Errorf("the report echoes the unchecked note %q", s)
		}
	}
}

func TestSingleEntryBlockHasNoSiblings(t *testing.T) {
	s := newScenario()
	s.leaves = s.leaves[:1]
	s.index = 0
	s.served = []wire.Position{{Kind: wire.KindAbsent}}
	b := s.json(t)
	if !bytes.Contains(b, []byte(`"siblings": []`)) {
		t.Errorf("a one-entry proof must write an empty sibling list:\n%s", b)
	}
	wantChecksOut(t, b)
}

func TestBuildRefusesWhatDoesNotCheckOut(t *testing.T) {
	s := newScenario()
	s.served[1] = wire.Position{Kind: wire.KindFull, Leaf: s.leaves[1]}
	if _, err := Build(s.input(t)); !errors.Is(err, ErrEntryServed) {
		t.Errorf("Build with the entry served: %v, want ErrEntryServed", err)
	}

	s = newScenario()
	s.receipt.TipHeight = 1000
	if _, err := Build(s.input(t)); !errors.Is(err, ErrNotInWindow) {
		t.Errorf("Build outside the window: %v, want ErrNotInWindow", err)
	}
}

func TestBuildFromLeafHashes(t *testing.T) {
	s := newScenario()
	in := s.input(t)
	hashes := make([][32]byte, len(s.leaves))
	for i, l := range s.leaves {
		hashes[i] = commit.LeafHash(l)
	}
	in.Leaves, in.LeafHashes, in.Entry = nil, hashes, s.leaves[1]
	f, err := Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	fromLeaves, err := Build(s.input(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(marshal(t, f), marshal(t, fromLeaves)) {
		t.Error("a file built from leaf hashes differs from one built from leaves")
	}
}

func TestBuildRejectsBadInput(t *testing.T) {
	s := newScenario()
	tests := []struct {
		name string
		edit func(in *Input)
	}{
		{"no leaves", func(in *Input) { in.Leaves = nil }},
		{"leaves and hashes", func(in *Input) { in.LeafHashes = make([][32]byte, 3) }},
		{"hashes without the entry", func(in *Input) { in.Leaves, in.LeafHashes = nil, make([][32]byte, 3) }},
		{"entry that is not at the index", func(in *Input) { in.Entry = s.leaves[0] }},
		{"index past the end", func(in *Input) { in.Index = 3 }},
		{"receipt without the served bytes", func(in *Input) { in.Served = nil }},
		{"served bytes without a receipt", func(in *Input) { in.Receipt = "" }},
		{"record that does not verify", func(in *Input) { in.Record.Content = strings.Repeat("00", 32) }},
		{"leaves that miss the signed root", func(in *Input) { in.Leaves = []canonical.Leaf{leafFor(0), leafFor(7), leafFor(2)} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := s.input(t)
			tt.edit(&in)
			if _, err := Build(in); err == nil {
				t.Error("Build accepted it")
			} else if !strings.HasPrefix(err.Error(), "evidence: ") {
				t.Errorf("error %q does not start with the package name", err)
			}
		})
	}
}

func TestFileName(t *testing.T) {
	s := newScenario()
	f := s.file(t)
	pub := pubOf(t, s.recordKey)
	want := "omission-regtest-205-" + core.DisplayHex(s.leaves[1].TxID)[:8] + "-" + hex.EncodeToString(pub[:4]) + ".json"
	if got := f.Name(); got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}
