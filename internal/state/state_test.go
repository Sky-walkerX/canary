package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func readExample(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "example-state.json"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	return b
}

// TestParseFormatsDocExample parses the example from the formats document and
// checks every top-level field and a sample of nested ones by value.
func TestParseFormatsDocExample(t *testing.T) {
	f, err := Parse(readExample(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	str := func(s string) *string { return &s }
	u32 := func(v uint32) *uint32 { return &v }
	at := time.Date(2026, 10, 3, 8, 32, 11, 0, time.UTC)
	tip := "8f5bc4871669d86d1dc72d7961ce7573fb55ccdb59cc9bbd22521c155f1c31d2"
	blk := "cafb64b3cfa7d9c38917ab7fd88107ba27342cadee3dcf2f85138a8322dc09b8"
	txid := "01982d712503c4e22cd00be57b905bacf4d8bff0533c23c276c8b738da217c16"
	honestKey := "b3f217a31dbfb8ed4d37b47c28ba531a50bb64426ecf66496eaaeaf5a48b3724"
	withKey := "b1070620799e7da6bbc296ec7ea6aacf7f027317af796abf35f0c9c83710270d"
	root := "46f2d74791bf0922bed8b430d36e6a36020eb00513470bbdad6ef4f0988b4130"
	policy := &Policy{PrunesSpent: false, DustThresholdSat: 0, DustConfigurable: false, Signed: false}

	want := &File{
		Format:      "canary-state/1",
		GeneratedAt: Time{at},
		Canary:      Build{Version: "0.1.0", Build: "abc1234"},
		Network:     Network{Name: "regtest", Magic: 3669344250},
		ChainTip:    ChainTip{Height: 212, Hash: tip, Source: "core"},
		Checked:     Range{From: 0, To: 212},
		EvidenceDir: "/home/you/.canary/evidence",
		Servers: []Server{
			{Label: "honest", URL: "http://127.0.0.1:8081", Pubkey: str(honestKey), PublishesRecords: true, SignsReceipts: true, Reachable: true,
				Tip: &ServerTip{Height: 212, Hash: tip, Signed: true}, Policy: policy},
			{Label: "withholder", URL: "http://127.0.0.1:8082", Pubkey: str(withKey), PublishesRecords: true, SignsReceipts: true, Reachable: true,
				Tip: &ServerTip{Height: 212, Hash: tip, Signed: true}, Policy: policy},
		},
		Coverage: []CoverageRange{
			{From: 0, To: 204, State: Verified, Reason: RecordsAgree},
			{From: 205, To: 205, State: Compromised, Reason: AbsentInWindow},
			{From: 206, To: 212, State: Verified, Reason: RecordsAgree},
		},
		Counts: Counts{Verified: 212, Compromised: 1},
		Blocks: []Block{{
			Height: 205, Hash: blk, State: Compromised, Reason: AbsentInWindow,
			Servers: []BlockServer{
				{Label: "honest", State: Verified, Reason: RecordsAgree,
					RecordEventID: str("2133b0fe6c4355c08b3fe29a4e796f7610e4e4a432e9e0ff35eece87cc34df19"),
					N:             u32(3), Root: str(root), Positions: &Positions{Full: 3}, Filled: 0, Signed: true,
					Tip: &Tip{Height: 212, Hash: tip}},
				{Label: "withholder", State: Compromised, Reason: AbsentInWindow,
					RecordEventID: str("90d82e3fd8c4f1ea18c97c9a446672fcb3b81803c5a21675b2fdaa70a49086cc"),
					N:             u32(3), Root: str(root), Positions: &Positions{Full: 2, Absent: 1}, Filled: 1, Signed: true,
					Tip: &Tip{Height: 212, Hash: tip}},
			},
		}},
		Findings: []Finding{{
			ID: "827a8d3f502e", Kind: KindWithheld, Reason: AbsentInWindow,
			Servers:  []ServerRef{{Label: "withholder", Pubkey: str(withKey)}},
			Block:    BlockRef{Height: 205, Hash: blk},
			Position: u32(1), Txid: str(txid),
			Evidence: str("omission-regtest-205-01982d71-b1070620.json"),
			Provable: true, FirstSeen: Time{at}, LastSeen: Time{at},
		}},
		ExpectedPayments: []Payment{{
			Txid: txid, Block: &BlockRef{Height: 205, Hash: blk}, Outcome: "withheld",
			Servers: []PaymentServer{{Label: "honest", Outcome: "found"}, {Label: "withholder", Outcome: "withheld"}},
		}},
	}
	if !reflect.DeepEqual(f, want) {
		got, _ := json.MarshalIndent(f, "", " ")
		t.Fatalf("parsed example differs from the formats document.\ngot:\n%s", got)
	}
	if f.Canary.ID() != "0.1.0+abc1234" {
		t.Errorf("build id = %q, want 0.1.0+abc1234", f.Canary.ID())
	}
}

// TestMarshalRoundTripsExample checks that writing the parsed example gives
// back the same JSON value, field for field.
func TestMarshalRoundTripsExample(t *testing.T) {
	raw := readExample(t)
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	out, err := Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var a, b any
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("round trip changed the document:\n%s", out)
	}
}

// mutate returns the example with one JSON edit applied.
func mutate(t *testing.T, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(readExample(t), &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func first(m map[string]any, key string) map[string]any {
	return m[key].([]any)[0].(map[string]any)
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name  string
		input func(t *testing.T) []byte
		want  error
	}{
		{"empty file", func(*testing.T) []byte { return nil }, ErrUnreadable},
		{"not JSON", func(*testing.T) []byte { return []byte("canary") }, ErrUnreadable},
		{"truncated", func(t *testing.T) []byte { b := readExample(t); return b[:len(b)/2] }, ErrUnreadable},
		{"trailing data", func(t *testing.T) []byte { return append(readExample(t), []byte("{}")...) }, ErrUnreadable},
		{"no format", func(t *testing.T) []byte { return mutate(t, func(m map[string]any) { delete(m, "format") }) }, ErrUnreadable},
		{"evidence format", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) { m["format"] = "canary-evidence/1" })
		}, ErrUnreadable},
		{"version zero", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) { m["format"] = "canary-state/0" })
		}, ErrUnreadable},
		{"version with leading zero", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) { m["format"] = "canary-state/02" })
		}, ErrUnreadable},
		{"newer version", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) { m["format"] = "canary-state/2"; m["new_field"] = true })
		}, ErrNewerFormat},
		{"unknown top-level field", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) { m["result"] = "fine" })
		}, ErrUnreadable},
		{"unknown nested field", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) { first(m, "servers")["trusted"] = true })
		}, ErrUnreadable},
		{"unknown state", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) { first(m, "coverage")["state"] = "clean" })
		}, ErrUnreadable},
		{"reason from another state", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) { first(m, "coverage")["reason"] = "gap_unfilled" })
		}, ErrUnreadable},
		{"counts key missing", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) { delete(m["counts"].(map[string]any), "disputed") })
		}, ErrUnreadable},
		{"counts disagree with coverage", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) {
				c := m["counts"].(map[string]any)
				c["verified"] = 211.0
				c["unverified"] = 1.0
			})
		}, ErrUnreadable},
		{"uppercase hash", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) {
				ct := m["chain_tip"].(map[string]any)
				ct["hash"] = strings.ToUpper(ct["hash"].(string))
			})
		}, ErrUnreadable},
		{"evidence name with a directory", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) { first(m, "findings")["evidence"] = "../../etc/passwd.json" })
		}, ErrUnreadable},
		{"withheld finding with warning reason", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) { first(m, "findings")["reason"] = "hash_without_policy" })
		}, ErrUnreadable},
		{"duplicate server label", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) {
				s := m["servers"].([]any)
				s[1].(map[string]any)["label"] = "honest"
			})
		}, ErrUnreadable},
		{"bad time", func(t *testing.T) []byte {
			return mutate(t, func(m map[string]any) { m["generated_at"] = "yesterday" })
		}, ErrUnreadable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.input(t))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Parse error = %v, want %v", err, tt.want)
			}
			if !strings.HasPrefix(err.Error(), "state: ") {
				t.Errorf("error %q does not start with the package name", err)
			}
		})
	}
}

func TestNewerFormatErrorNamesTheFormat(t *testing.T) {
	_, err := Parse([]byte(`{"format":"canary-state/7","anything":1}`))
	var nf *NewerFormatError
	if !errors.As(err, &nf) {
		t.Fatalf("error %v is not a *NewerFormatError", err)
	}
	if nf.Found != "canary-state/7" {
		t.Errorf("Found = %q", nf.Found)
	}
	if errors.Is(err, ErrUnreadable) {
		t.Error("a newer format must not also read as unreadable")
	}
}

func TestLoadMissingAndUnreadable(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "none.json")); !errors.Is(err, ErrMissing) {
		t.Errorf("missing file: error = %v, want ErrMissing", err)
	}
	// A directory in place of the file cannot be read as one.
	if _, err := Load(dir); !errors.Is(err, ErrUnreadable) {
		t.Errorf("directory: error = %v, want ErrUnreadable", err)
	}
}

func TestSaveIsAtomicAndLoadable(t *testing.T) {
	f, err := Parse(readExample(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	if err := Save(path, f); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if !reflect.DeepEqual(got, f) {
		t.Fatal("loaded file differs from the saved one")
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary file left behind: %v", err)
	}

	// Overwrite with a changed file.
	f.GeneratedAt = Time{f.GeneratedAt.Add(time.Hour)}
	if err := Save(path, f); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	got, err = Load(path)
	if err != nil || !got.GeneratedAt.Equal(f.GeneratedAt.Time) {
		t.Fatalf("second Load = %v, %v", got, err)
	}
}

func TestSaveRefusesAnInvalidFile(t *testing.T) {
	f, err := Parse(readExample(t))
	if err != nil {
		t.Fatal(err)
	}
	f.Coverage[0].State = "clean"
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, f); err == nil {
		t.Fatal("Save accepted an unknown state")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("Save wrote a file it refused")
	}
}

func TestMarshalWritesEmptyArrays(t *testing.T) {
	f, err := Parse(readExample(t))
	if err != nil {
		t.Fatal(err)
	}
	f.Findings = nil
	f.ExpectedPayments = nil
	f.Blocks[0].Servers = nil
	b, err := Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"findings": []`, `"expected_payments": []`, `"servers": []`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("output lacks %s", want)
		}
	}
	if strings.Contains(string(b), "null,\n  \"") && strings.Contains(string(b), `"findings": null`) {
		t.Error("nil slice written as null")
	}
}

func TestTimeIsWrittenInUTCWholeSeconds(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+1800)
	b, err := json.Marshal(Time{time.Date(2026, 10, 3, 14, 2, 11, 999, ist)})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"2026-10-03T08:32:11Z"` {
		t.Errorf("time = %s", b)
	}
}

func TestETag(t *testing.T) {
	raw := readExample(t)
	want := func(b []byte, build string) string {
		s := sha256.Sum256(append(append(append([]byte{}, b...), 0), build...))
		return hex.EncodeToString(s[:16])
	}
	tests := []struct {
		name  string
		bytes []byte
		build string
	}{
		{"example", raw, "0.1.0+abc1234"},
		{"missing file is zero bytes", nil, "0.1.0+abc1234"},
		{"other build", raw, "0.1.1+def5678"},
	}
	seen := map[string]bool{}
	for _, tt := range tests {
		got := ETag(tt.bytes, tt.build)
		if got != want(tt.bytes, tt.build) {
			t.Errorf("%s: ETag = %s", tt.name, got)
		}
		if len(got) != 32 {
			t.Errorf("%s: ETag has %d characters, want 32", tt.name, len(got))
		}
		if seen[got] {
			t.Errorf("%s: ETag collides with an earlier case", tt.name)
		}
		seen[got] = true
	}
	// The separator byte keeps "state ‖ build" unambiguous.
	if ETag([]byte("ab"), "c") == ETag([]byte("a"), "bc") {
		t.Error("ETag does not separate the file from the build id")
	}
}

// TestFindingIDMatchesFormatsDoc recomputes the example id from the formats
// document: withheld|b1070620…270d|cafb64b3…09b8|pos:1 gives 827a8d3f502e.
func TestFindingIDMatchesFormatsDoc(t *testing.T) {
	pos := uint32(1)
	subject := FindingSubject(KindWithheld, AbsentInWindow, &pos, nil)
	if subject != "pos:1" {
		t.Fatalf("subject = %q", subject)
	}
	id := FindingID(KindWithheld,
		[]string{"b1070620799e7da6bbc296ec7ea6aacf7f027317af796abf35f0c9c83710270d"},
		"cafb64b3cfa7d9c38917ab7fd88107ba27342cadee3dcf2f85138a8322dc09b8", subject)
	if id != "827a8d3f502e" {
		t.Errorf("FindingID = %s, want 827a8d3f502e", id)
	}
}

func TestFindingSubject(t *testing.T) {
	pos := uint32(4)
	txid := strings.Repeat("ab", 32)
	tests := []struct {
		kind   string
		reason Reason
		pos    *uint32
		txid   *string
		want   string
	}{
		{KindWarning, ListNotServed, &pos, &txid, "reason:list_not_served"},
		{KindWithheld, AbsentInWindow, &pos, &txid, "pos:4"},
		{KindWithheld, ExpectedPaymentNotInRecord, nil, &txid, "txid:" + txid},
		{KindWithheld, ServedContradictsRecord, nil, nil, "-"},
		{KindDisagree, RecordsDiffer, nil, nil, "-"},
	}
	for _, tt := range tests {
		if got := FindingSubject(tt.kind, tt.reason, tt.pos, tt.txid); got != tt.want {
			t.Errorf("FindingSubject(%s, %s) = %q, want %q", tt.kind, tt.reason, got, tt.want)
		}
	}
	// Pubkey order must not change the id.
	a := FindingID(KindDisagree, []string{"bb", "aa"}, "h", "-")
	b := FindingID(KindDisagree, []string{"aa", "bb"}, "h", "-")
	if a != b {
		t.Error("FindingID depends on pubkey order")
	}
}

func TestEveryReasonHasOneState(t *testing.T) {
	for r, s := range reasonStates {
		if !s.Valid() {
			t.Errorf("reason %s maps to unknown state %s", r, s)
		}
	}
	if _, ok := StateOf(HashWithoutPolicy); ok {
		t.Error("hash_without_policy must have no state")
	}
	if len(reasonStates) != 20 {
		t.Errorf("formats document lists 20 state reasons, table has %d", len(reasonStates))
	}
}

func TestNetworkName(t *testing.T) {
	for magic, want := range map[uint32]string{3652501241: "main", 1087308554: "signet", 3669344250: "regtest", 1: "unknown"} {
		if got := NetworkName(magic); got != want {
			t.Errorf("NetworkName(%d) = %s, want %s", magic, got, want)
		}
	}
}
