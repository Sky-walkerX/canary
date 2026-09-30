//go:build uidev

package ui

// This file exists only in builds with the uidev tag. It holds the sample
// data the dev server renders, so the release binary cannot show sample data
// at all. Every page a uidev build renders carries the watermark below.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Sky-walkerX/canary/internal/state"
)

const watermark = "SAMPLE DATA — not a real run"

// SampleScenarios lists the scenarios WriteSample accepts.
var SampleScenarios = []string{"sample", "clear", "stale", "missing", "unreadable", "newer"}

// Keys and hashes from the examples in the v1 formats document. They come
// from an example key made for that document, not from a real run.
const (
	sampleHonestKey = "b3f217a31dbfb8ed4d37b47c28ba531a50bb64426ecf66496eaaeaf5a48b3724"
	sampleWithKey   = "b1070620799e7da6bbc296ec7ea6aacf7f027317af796abf35f0c9c83710270d"
	sampleTip       = "8f5bc4871669d86d1dc72d7961ce7573fb55ccdb59cc9bbd22521c155f1c31d2"
	sampleBlock205  = "cafb64b3cfa7d9c38917ab7fd88107ba27342cadee3dcf2f85138a8322dc09b8"
	sampleTxid      = "01982d712503c4e22cd00be57b905bacf4d8bff0533c23c276c8b738da217c16"
	sampleRoot205   = "46f2d74791bf0922bed8b430d36e6a36020eb00513470bbdad6ef4f0988b4130"
	sampleEvidence  = "omission-regtest-205-01982d71-b1070620.json"
)

// sampleEvidenceJSON is the complete evidence file from the formats document.
const sampleEvidenceJSON = `{
  "format": "canary-evidence/1",
  "claim": "omission",
  "accused": "b1070620799e7da6bbc296ec7ea6aacf7f027317af796abf35f0c9c83710270d",
  "network": { "name": "regtest", "magic": 3669344250 },
  "block": {
    "hash": "cafb64b3cfa7d9c38917ab7fd88107ba27342cadee3dcf2f85138a8322dc09b8",
    "height": 205
  },
  "commitment_event": {
    "kind": 1352,
    "id": "90d82e3fd8c4f1ea18c97c9a446672fcb3b81803c5a21675b2fdaa70a49086cc",
    "pubkey": "b1070620799e7da6bbc296ec7ea6aacf7f027317af796abf35f0c9c83710270d",
    "created_at": 1791016200,
    "tags": [
      ["b", "cafb64b3cfa7d9c38917ab7fd88107ba27342cadee3dcf2f85138a8322dc09b8"],
      ["height", "205"],
      ["n", "3"],
      ["network", "3669344250"],
      ["policy_ref", "0000000000000000000000000000000000000000000000000000000000000000"],
      ["root", "46f2d74791bf0922bed8b430d36e6a36020eb00513470bbdad6ef4f0988b4130"]
    ],
    "content": "46f2d74791bf0922bed8b430d36e6a36020eb00513470bbdad6ef4f0988b4130",
    "sig": "eb2d283de022dcc647d6fcf8e1526a661c7afc903d937caac1df78c857bb64c8044968919b7e5f2f33c96daaa7df36cb07b7d183028ef7fa3878c2e8c06fc3c6"
  },
  "receipt": "01fabfb5da01b809dc22838a13852fcf3deead2c3427ba0781d87fab1789c3d9a7cfb364fbca0000000000000000d4000000d2311c5f151c5222bd9bcc59dbcc55fb7375ce61792dc71d6dd8691687c45b8fa1b3b064b0286290f4b87ac6915a523301f0b4977ea3b04d3663df60bcc707c9b3f5f6f98dddbd7080322b8e42a6384d00841fba8e69dc37687cd492830379bfedd2111778f28cb1ea58c0b1ec183ce7e4c8aeb1e1d34eb03f090df07139ed0b",
  "served_base64": "AwAAAAF11Z42oeHMu9WkfxKbkjBHJoxYDWoJqdY8MIS9OXFmrgP5pb79DqHbuhXmzLo4P728dQoPY3aYoG+kfGgjBE4J6wMBP2kvgSMykXobx8r9AdXQKnvytMJbtPXXIRtnBhDA4LgDYlc6s+tuzMcwcWI8IR9Bs5K/Ke3Ln6vnqprd60u9ark=",
  "missing": {
    "txid": "01982d712503c4e22cd00be57b905bacf4d8bff0533c23c276c8b738da217c16",
    "tweak": "02b84222b639a797cbacb1a5c7c3dd9fe766f59f51e823bb85cd446cb454ee3cb0"
  },
  "proof": {
    "index": 1,
    "n": 3,
    "siblings": [
      "93625b68eed841902dd2a682a9babbaa5f9fc073efb7214a28ca1ff3d4ef15d5",
      "de81aca98a9968e424b988f581c6e1680bfbdde3533496786a1b3b008f87c2a9"
    ]
  },
  "context": {
    "server_label": "withholder",
    "server_url": "http://127.0.0.1:8082",
    "found_by": "other_server",
    "written_by": "canary 0.1.0+abc1234",
    "written_at": "2026-10-03T08:32:11Z"
  }
}
`

// sampleReportJSON is the VerifyReport the formats document gives for it.
const sampleReportJSON = `{
  "result": "checks_out",
  "code": "ok",
  "message": "Checks out. The server signed a record that includes this entry, then signed a list that left it out.",
  "format": "canary-evidence/1",
  "claim": "omission",
  "accused": {
    "pubkey": "b1070620799e7da6bbc296ec7ea6aacf7f027317af796abf35f0c9c83710270d",
    "npub": "npub1kyrsvgrene76dw7zjmk8af42ealsyuch4auk40e47ryusdcsyuxsden9fz"
  },
  "network": { "name": "regtest", "magic": 3669344250 },
  "block": { "hash": "cafb64b3cfa7d9c38917ab7fd88107ba27342cadee3dcf2f85138a8322dc09b8", "height": 205 },
  "missing": {
    "txid": "01982d712503c4e22cd00be57b905bacf4d8bff0533c23c276c8b738da217c16",
    "tweak": "02b84222b639a797cbacb1a5c7c3dd9fe766f59f51e823bb85cd446cb454ee3cb0",
    "index": 1
  },
  "commitment_event_id": "90d82e3fd8c4f1ea18c97c9a446672fcb3b81803c5a21675b2fdaa70a49086cc",
  "has_receipt": true,
  "receipt_tip": { "height": 212, "hash": "8f5bc4871669d86d1dc72d7961ce7573fb55ccdb59cc9bbd22521c155f1c31d2" },
  "checks": [
    { "step": "read", "ok": true, "text": "Format canary-evidence/1, claim omission." },
    { "step": "record_signature", "ok": true, "text": "The signed record's id and signature are valid." },
    { "step": "signer", "ok": true, "text": "The record is signed by the accused key." },
    { "step": "block", "ok": true, "text": "The record names block 205 on regtest, the block this file names." },
    { "step": "inclusion", "ok": true, "text": "Entry 1 of 3 proves into the signed root." },
    { "step": "receipt", "ok": true, "text": "The receipt is signed by the same key, names the same block and covers these 137 bytes." },
    { "step": "served_list", "ok": true, "text": "The served list has 3 positions, and position 1 is marked absent." },
    { "step": "window", "ok": true, "text": "The server's signed tip was 212, so the block was 7 blocks deep, inside the 144-block window." }
  ]
}
`

func fakeHex(parts ...any) string {
	sum := sha256.Sum256([]byte(fmt.Sprint(parts...)))
	return hex.EncodeToString(sum[:])
}

func ptr[T any](v T) *T { return &v }

func sampleBlockHash(h uint32) string {
	switch h {
	case 205:
		return sampleBlock205
	case 212:
		return sampleTip
	}
	return fakeHex("canary sample block ", h)
}

// WriteSample writes the named scenario into dir: a state file, and for the
// sample scenarios an evidence directory holding the example evidence file.
// It returns the state file's path. now sets the run time, so the status line
// reads a few minutes old.
func WriteSample(dir, scenario string, now time.Time) (string, error) {
	path := filepath.Join(dir, "state.json")
	evDir := filepath.Join(dir, "evidence")
	if err := os.MkdirAll(evDir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(evDir, sampleEvidence), []byte(sampleEvidenceJSON+"\n"), 0o644); err != nil {
		return "", err
	}
	os.Remove(path)
	switch scenario {
	case "missing":
		return path, nil
	case "unreadable":
		return path, os.WriteFile(path, []byte("{\"format\": \"canary-state/1\", \"generated_at\": "), 0o644)
	case "newer":
		return path, os.WriteFile(path, []byte(`{"format": "canary-state/2", "generated_at": "2026-10-03T08:32:11Z"}`), 0o644)
	case "sample":
		return path, state.Save(path, SampleState(now.Add(-6*time.Minute), evDir, false))
	case "stale":
		return path, state.Save(path, SampleState(now.Add(-5*time.Hour), evDir, false))
	case "clear":
		return path, state.Save(path, SampleState(now.Add(-6*time.Minute), evDir, true))
	}
	return "", fmt.Errorf("ui: unknown sample scenario %q", scenario)
}

// SampleVerify stands in for the evidence package in the dev server. It
// returns the formats document's report for the example evidence file.
func SampleVerify(file []byte) ([]byte, error) {
	if string(file) == sampleEvidenceJSON+"\n" || string(file) == sampleEvidenceJSON {
		return []byte(sampleReportJSON), nil
	}
	return nil, errors.New("ui: sample verify knows only the example evidence file")
}

type sampleResult struct {
	state  state.StateCode
	reason state.Reason
}

// SampleState builds a realistic regtest run over blocks 0 to 212 with three
// servers. With clear set, every block reads Checked and nothing is found.
func SampleState(generated time.Time, evidenceDir string, clear bool) *state.File {
	const tipHeight = 212
	f := &state.File{
		Format:      state.Format,
		GeneratedAt: state.Time{Time: generated.UTC().Truncate(time.Second)},
		Canary:      state.Build{Version: "0.1.0", Build: "abc1234"},
		Network:     state.Network{Name: "regtest", Magic: state.MagicRegtest},
		ChainTip:    state.ChainTip{Height: tipHeight, Hash: sampleTip, Source: "core"},
		Checked:     state.Range{From: 0, To: tipHeight},
		EvidenceDir: evidenceDir,
	}
	openPolicy := &state.Policy{PrunesSpent: false, DustThresholdSat: 0, DustConfigurable: false, Signed: false}
	f.Servers = []state.Server{
		{Label: "honest", URL: "http://127.0.0.1:8081", Pubkey: ptr(sampleHonestKey), PublishesRecords: true, SignsReceipts: true, Reachable: true,
			Tip: &state.ServerTip{Height: tipHeight, Hash: sampleTip, Signed: true}, Policy: openPolicy},
		{Label: "withholder", URL: "http://127.0.0.1:8082", Pubkey: ptr(sampleWithKey), PublishesRecords: true, SignsReceipts: true, Reachable: true,
			Tip: &state.ServerTip{Height: tipHeight, Hash: sampleTip, Signed: true}, Policy: openPolicy},
	}
	if !clear {
		f.Servers = append(f.Servers, state.Server{
			Label: "backup", URL: "http://127.0.0.1:8083", Pubkey: nil, PublishesRecords: false, SignsReceipts: false, Reachable: true,
			Tip:    &state.ServerTip{Height: 210, Hash: sampleBlockHash(210), Signed: false},
			Policy: &state.Policy{PrunesSpent: true, DustThresholdSat: 546, DustConfigurable: false, Signed: false},
		})
	}

	tip := &state.Tip{Height: tipHeight, Hash: sampleTip}
	signedRecord := func(label string, h uint32, st state.StateCode, reason state.Reason, n uint32, pos state.Positions, filled uint32) state.BlockServer {
		return state.BlockServer{
			Label: label, State: st, Reason: reason,
			RecordEventID: ptr(fakeHex("record ", label, h)),
			N:             ptr(n), Root: ptr(fakeHex("root ", h, n)),
			Positions: &pos, Filled: filled, Signed: true, Tip: tip,
		}
	}
	noRecord := func(label string, reason state.Reason) state.BlockServer {
		return state.BlockServer{Label: label, State: state.Unverified, Reason: reason}
	}
	entries := func(h uint32) uint32 {
		switch {
		case h == 198 || h == 205:
			return 3
		case h == 121:
			return 2
		case h%17 == 5:
			return 1
		}
		return 0
	}

	var results []sampleResult
	for h := uint32(0); h <= tipHeight; h++ {
		hash := sampleBlockHash(h)
		n := entries(h)
		full := state.Positions{Full: n}
		b := state.Block{Height: h, Hash: hash}
		var honest, with state.BlockServer
		switch {
		case clear:
			honest = signedRecord("honest", h, state.Verified, state.RecordsAgree, n, full, 0)
			with = signedRecord("withholder", h, state.Verified, state.RecordsAgree, n, full, 0)
			b.State, b.Reason = state.Verified, state.RecordsAgree
		case h < 10:
			honest = noRecord("honest", state.NoRecords)
			with = noRecord("withholder", state.NoRecords)
			b.State, b.Reason = state.Unverified, state.NoRecords
		case h < 20:
			honest = noRecord("honest", state.NoRecords)
			with = signedRecord("withholder", h, state.Verified, state.OwnRecord, n, full, 0)
			b.State, b.Reason = state.Verified, state.OwnRecord
		case h < 32:
			honest = noRecord("honest", state.NoRecords)
			with = signedRecord("withholder", h, state.Unresolvable, state.GapUnfilled, 1, state.Positions{Absent: 1}, 0)
			b.State, b.Reason = state.Unresolvable, state.GapUnfilled
		case h == 121:
			honest = noRecord("honest", state.ServerUnreachable)
			with = signedRecord("withholder", h, state.Resolved, state.HashRetained, n, state.Positions{Full: 1, Hash: 1}, 0)
			b.State, b.Reason = state.Resolved, state.HashRetained
		case h == 198:
			honest = signedRecord("honest", h, state.Disputed, state.RecordsDiffer, 3, state.Positions{Full: 3}, 0)
			with = signedRecord("withholder", h, state.Disputed, state.RecordsDiffer, 2, state.Positions{Full: 2}, 0)
			with.Root = ptr(fakeHex("smaller root ", h))
			b.State, b.Reason = state.Disputed, state.RecordsDiffer
		case h == 205:
			honest = signedRecord("honest", h, state.Verified, state.RecordsAgree, 3, full, 0)
			honest.RecordEventID = ptr("2133b0fe6c4355c08b3fe29a4e796f7610e4e4a432e9e0ff35eece87cc34df19")
			honest.Root = ptr(sampleRoot205)
			with = signedRecord("withholder", h, state.Compromised, state.AbsentInWindow, 3, state.Positions{Full: 2, Absent: 1}, 1)
			with.RecordEventID = ptr("90d82e3fd8c4f1ea18c97c9a446672fcb3b81803c5a21675b2fdaa70a49086cc")
			with.Root = ptr(sampleRoot205)
			b.State, b.Reason = state.Compromised, state.AbsentInWindow
		case h == 209:
			honest = signedRecord("honest", h, state.Verified, state.RecordsAgree, n, full, 0)
			with = signedRecord("withholder", h, state.Unresolvable, state.ListNotServed, n, full, 0)
			with.Positions, with.Signed, with.Tip = nil, false, nil
			b.State, b.Reason = state.Verified, state.RecordsAgree
		default:
			honest = signedRecord("honest", h, state.Verified, state.RecordsAgree, n, full, 0)
			with = signedRecord("withholder", h, state.Verified, state.RecordsAgree, n, full, 0)
			b.State, b.Reason = state.Verified, state.RecordsAgree
		}
		b.Servers = []state.BlockServer{honest, with}
		if !clear {
			b.Servers = append(b.Servers, noRecord("backup", state.NoRecords))
		}
		f.Blocks = append(f.Blocks, b)
		results = append(results, sampleResult{b.State, b.Reason})
	}

	// Merge consecutive heights with one state and reason into ranges.
	for i, r := range results {
		h := uint32(i)
		if n := len(f.Coverage); n > 0 && f.Coverage[n-1].State == r.state && f.Coverage[n-1].Reason == r.reason {
			f.Coverage[n-1].To = h
		} else {
			f.Coverage = append(f.Coverage, state.CoverageRange{From: h, To: h, State: r.state, Reason: r.reason})
		}
		switch r.state {
		case state.Verified:
			f.Counts.Verified++
		case state.Resolved:
			f.Counts.Resolved++
		case state.Unresolvable:
			f.Counts.Unresolvable++
		case state.Unverified:
			f.Counts.Unverified++
		case state.Disputed:
			f.Counts.Disputed++
		case state.Compromised:
			f.Counts.Compromised++
		}
	}
	if clear {
		return f
	}

	seen := state.Time{Time: f.GeneratedAt.Add(-2 * time.Hour)}
	pos1 := uint32(1)
	finding := func(kind string, reason state.Reason, keys []string, labels []string, h uint32, pos *uint32, txid *string) state.Finding {
		refs := make([]state.ServerRef, len(labels))
		for i := range labels {
			refs[i] = state.ServerRef{Label: labels[i], Pubkey: ptr(keys[i])}
		}
		hash := sampleBlockHash(h)
		return state.Finding{
			ID:   state.FindingID(kind, keys, hash, state.FindingSubject(kind, reason, pos, txid)),
			Kind: kind, Reason: reason, Servers: refs,
			Block:    state.BlockRef{Height: h, Hash: hash},
			Position: pos, Txid: txid,
			FirstSeen: seen, LastSeen: f.GeneratedAt,
		}
	}
	withheld := finding(state.KindWithheld, state.AbsentInWindow, []string{sampleWithKey}, []string{"withholder"}, 205, &pos1, ptr(sampleTxid))
	withheld.Evidence, withheld.Provable = ptr(sampleEvidence), true
	withheld.FirstSeen = f.GeneratedAt
	f.Findings = []state.Finding{
		withheld,
		finding(state.KindDisagree, state.RecordsDiffer, []string{sampleHonestKey, sampleWithKey}, []string{"honest", "withholder"}, 198, nil, nil),
		finding(state.KindWarning, state.HashWithoutPolicy, []string{sampleWithKey}, []string{"withholder"}, 121, nil, nil),
		finding(state.KindWarning, state.ListNotServed, []string{sampleWithKey}, []string{"withholder"}, 209, nil, nil),
	}
	f.ExpectedPayments = []state.Payment{{
		Txid:    sampleTxid,
		Block:   &state.BlockRef{Height: 205, Hash: sampleBlock205},
		Outcome: "withheld",
		Servers: []state.PaymentServer{{Label: "honest", Outcome: "found"}, {Label: "withholder", Outcome: "withheld"}, {Label: "backup", Outcome: "unresolvable"}},
	}}
	return f
}
