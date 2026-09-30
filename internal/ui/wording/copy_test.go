package wording

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Sky-walkerX/canary/internal/state"
)

func TestSixStatesInOrder(t *testing.T) {
	want := []struct{ code, label string }{
		{"verified", "Checked"},
		{"resolved", "Checked, gap filled"},
		{"unresolvable", "Can't be checked"},
		{"unverified", "Not checked"},
		{"disputed", "Servers disagree"},
		{"compromised", "Data withheld"},
	}
	got := States()
	if len(got) != len(want) {
		t.Fatalf("States() has %d entries, want 6", len(got))
	}
	for i, w := range want {
		if got[i].Code != w.code || got[i].Label != w.label {
			t.Errorf("state %d = %s %q, want %s %q", i, got[i].Code, got[i].Label, w.code, w.label)
		}
		if got[i].Meaning == "" || got[i].Explain == "" {
			t.Errorf("state %s lacks a meaning or an explanation", w.code)
		}
		if string(state.States[i]) != w.code {
			t.Errorf("state package order differs at %d: %s", i, state.States[i])
		}
	}
	if u := State("clean"); u.Label == "Checked" || u.Code != "clean" {
		t.Errorf("unknown state got label %q", u.Label)
	}
}

// TestEveryReasonHasASentence covers every state reason in the state package
// and the warning-only reason.
func TestEveryReasonHasASentence(t *testing.T) {
	codes := []state.Reason{state.HashWithoutPolicy}
	for _, s := range []state.Reason{
		state.RecordsAgree, state.ExpectedPayment, state.OwnRecord,
		state.FilledFromServer, state.FilledFromExpectedPayment, state.HashRetained,
		state.GapUnfilled, state.TipUnconfirmed, state.ListNotServed, state.ListUnreadable,
		state.NoRecords, state.NoRecordForBlock, state.NotIndexedYet, state.ServerUnreachable,
		state.RecordsDiffer,
		state.AbsentInWindow, state.FalseChainClaim, state.ServedContradictsRecord,
		state.ExpectedPaymentNotInRecord, state.ExpectedPaymentNotInList,
	} {
		if _, ok := state.StateOf(s); !ok {
			t.Errorf("reason %s is not a state reason", s)
		}
		codes = append(codes, s)
	}
	for _, c := range codes {
		if _, ok := reasons[string(c)]; !ok {
			t.Errorf("reason %s has no sentence", c)
		}
	}
	if len(reasons) != len(codes) {
		t.Errorf("wording table explains %d reasons, formats document lists %d", len(reasons), len(codes))
	}
}

// allText collects every sentence the table can produce, with sample
// arguments for the functions.
func allText() []string {
	var out []string
	for _, s := range States() {
		out = append(out, s.Label, s.Meaning, s.Explain)
	}
	for _, r := range reasons {
		out = append(out, r)
	}
	kinds := map[string][]string{
		"withheld": {"absent_in_window", "false_chain_claim", "served_contradicts_record", "expected_payment_not_in_record", "expected_payment_not_in_list"},
		"disagree": {"records_differ"},
		"warning":  {"no_record_for_block", "list_not_served", "list_unreadable", "hash_without_policy"},
	}
	for kind, rs := range kinds {
		out = append(out, KindLabel(kind))
		for _, r := range rs {
			out = append(out, FindingSentence(kind, r, []string{"honest", "withholder"}),
				FindingDoesNotShow(kind, r),
				FindingStatusLine(kind, r, []string{"withholder"}, 205, strings.Repeat("ab", 32)))
			for _, p := range []bool{true, false} {
				for _, e := range []bool{true, false} {
					out = append(out, FindingShows(kind, r, p, e))
				}
			}
		}
		for _, p := range []bool{true, false} {
			for _, e := range []bool{true, false} {
				out = append(out, Provable(kind, p, e), ProvableShort(kind, p, e))
			}
		}
	}
	for _, m := range []Moment{NoCheckYet, PageNotFound, StateUnreadable("/tmp/state.json"), StateNotOpened("/tmp/state.json"),
		NewerFormat("canary-state/2"), BlockNotFound(0, 212), FindingNotFound("827a8d3f502e"), FindingNotFound(""),
		EvidenceNotFound("x.json"), EvidenceNotFound(""), ServerError("1a2b3c4d"), Stale("3 h")} {
		out = append(out, m.Title, m.Body, m.Action)
	}
	for _, v := range []Verdict{VerdictAllChecked(213), VerdictSomeChecked(200, 213), VerdictNoneChecked(213),
		VerdictDisputed(2), VerdictWithheldOne("withholder left out an entry it had signed for.", 205, "You can prove this to others."), VerdictWithheldMany(3),
		VerdictOpenFindings(VerdictAllChecked(220), 1), VerdictOpenFindings(VerdictSomeChecked(200, 213), 2)} {
		out = append(out, v.Headline, v.Lede)
	}
	out = append(out, LowerBound(1, false), LowerBound(24, true), NoFindings, BlockNotCovered, ServersNote, PaymentsNote, FindingsIntro,
		EvidenceNote, BlocksIntro(0, 212, 213), HeightNotFound("150", 1, 213), HeightNotFound("abc", 1, 213),
		UpdateNewResults, UpdateNewFindings(1), UpdateNewFindings(3), UpdateUpdated, UpdateLost("14:02"), UpdateBack,
		UpdateReload, UpdateDismiss, RegtestBadge, NetworkBadge("signet"), Framing, WarningSuffix, NoPubkey,
		PolicyText(true, 546, false), PolicyText(false, 0, false), TipText(212, true), TipText(210, false),
		VerifyChecksOut, VerifyInclusionOnly, VerifyInclusionOnlyDetail[0], VerifyInclusionOnlyDetail[1],
		VerifyDoesNotCheckOut("receipt"), VerifyCantRead("not JSON"), VerifyNotHonest, VerifyNotRunEarlier, VerifyNotRunNoReceipt,
		EvidenceStatusLine("x.json", true), EvidenceStatusLine("x.json", false))
	for code := range verifyCodes {
		out = append(out, VerifyCode(code))
	}
	for _, s := range VerifySteps {
		out = append(out, VerifyStep(s))
	}
	for code := range paymentOutcomes {
		l, s := PaymentOutcome(code)
		out = append(out, l, s)
	}
	return out
}

// TestHonestyRules keeps the words inside the claims Canary can make.
func TestHonestyRules(t *testing.T) {
	banned := []string{
		"trustless", "secure", "guarantee", "hidden payment", "protecting", "!", "§",
		"rung", "t_base", "relay", "—", "timestamp",
	}
	for _, s := range allText() {
		low := strings.ToLower(s)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("%q contains %q", s, b)
			}
		}
	}
}

// TestSentenceLength holds every sentence to 30 words at most.
func TestSentenceLength(t *testing.T) {
	split := regexp.MustCompile(`[.?]\s+`)
	for _, s := range allText() {
		for _, sentence := range split.Split(s, -1) {
			if n := len(strings.Fields(sentence)); n > 30 {
				t.Errorf("%d words: %q", n, sentence)
			}
		}
	}
}

func TestFormatsDocLines(t *testing.T) {
	tests := []struct{ got, want string }{
		{StatusLine("2026-10-03 08:32 UTC", "", 0, 212, "regtest", "0.1.0", "abc1234"),
			"Last check 2026-10-03 08:32 UTC · blocks 0–212 · regtest · canary 0.1.0 (abc1234)"},
		{StatusLine("2026-10-03 14:02 IST", "6 min ago", 0, 212, "regtest", "0.1.0", "abc1234"),
			"Last check 2026-10-03 14:02 IST (6 min ago) · blocks 0–212 · regtest · canary 0.1.0 (abc1234)"},
		{CountsLine(map[string]int{"verified": 212, "compromised": 1}), "212 Checked · 1 Data withheld"},
		{FindingStatusLine("withheld", "absent_in_window", []string{"withholder"}, 205,
			"01982d712503c4e22cd00be57b905bacf4d8bff0533c23c276c8b738da217c16"),
			"withholder left out an entry it had signed for: block 205, txid 01982d71…7c16."},
		{EvidenceStatusLine("omission-regtest-205-01982d71-b1070620.json", true),
			"Evidence: omission-regtest-205-01982d71-b1070620.json. You can prove this to others."},
		{VerifyCode("ok"), "Checks out. The server signed a record that includes this entry, then signed a list that left it out."},
		{VerifyInclusionOnly, "Inclusion only: you can be sure of this, you can't yet prove it to others."},
		{VerifyDoesNotCheckOut("receipt"), "Does not check out: receipt failed."},
		{VerifyNotRunEarlier, "Not run: an earlier step failed."},
		{VerifyNotRunNoReceipt, "Not run: this file has no receipt."},
		{UpdateLost("14:02"), "Can't reach Canary since 14:02."},
		{UpdateNewFindings(1), "New finding."},
		{UpdateNewFindings(2), "2 new findings."},
		{RegtestBadge, "regtest: a private test chain on this computer"},
		{LowerBound(12, false), "12 blocks couldn't be checked. A payment in them could be missing from what your wallet shows, so treat its balance as a lower bound."},
		{LowerBound(1, false), "1 block couldn't be checked. A payment in it could be missing from what your wallet shows, so treat its balance as a lower bound."},
		{LowerBound(24, true), "24 blocks are not Checked. A payment in them could be missing from what your wallet shows, so treat its balance as a lower bound."},
		{LowerBound(1, true), "1 block is not Checked. A payment in it could be missing from what your wallet shows, so treat its balance as a lower bound."},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("got  %q\nwant %q", tt.got, tt.want)
		}
	}
	if !strings.HasSuffix(FindingStatusLine("warning", "list_not_served", []string{"withholder"}, 209, ""), WarningSuffix) ||
		!strings.HasPrefix(FindingStatusLine("warning", "list_not_served", []string{"withholder"}, 209, ""), "Warning: ") {
		t.Error("a warning line must start with Warning: and end with Not an accusation.")
	}
}

func TestAge(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{-time.Minute, "just now"},
		{30 * time.Second, "just now"},
		{6 * time.Minute, "6 min ago"},
		{3*time.Hour + 5*time.Minute, "3 h ago"},
		{50 * time.Hour, "2 days ago"},
	}
	for _, tt := range tests {
		if got := Age(tt.d); got != tt.want {
			t.Errorf("Age(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

// TestKindLabelsReuseStateLabels keeps one word per idea: a withheld finding
// reads Data withheld and a disagreement reads Servers disagree.
func TestKindLabelsReuseStateLabels(t *testing.T) {
	if KindLabel("withheld") != State("compromised").Label || KindLabel("disagree") != State("disputed").Label {
		t.Error("finding kinds must reuse the state labels")
	}
}

// TestAbsentInWindowClaimsASignedTipOnlyWithAReceipt keeps the knowing versus
// proving line. A list with no receipt has no signed tip, so only a provable
// finding may say the block sat below a signed tip.
func TestAbsentInWindowClaimsASignedTipOnlyWithAReceipt(t *testing.T) {
	if strings.Contains(Reason("absent_in_window"), "signed tip") {
		t.Errorf("the reason sentence claims a signed tip, which a list without a receipt lacks: %q", Reason("absent_in_window"))
	}
	if s := FindingShows("withheld", "absent_in_window", true, true); !strings.Contains(s, "signed tip") {
		t.Errorf("a provable finding should name the signed tip: %q", s)
	}
	for _, e := range []bool{true, false} {
		s := FindingShows("withheld", "absent_in_window", false, e)
		if strings.Contains(s, "signed tip") {
			t.Errorf("hasEvidence=%v: a finding with no receipt claims a signed tip: %q", e, s)
		}
		if strings.Contains(s, "signed a list") || strings.Contains(s, "served and signed") {
			t.Errorf("hasEvidence=%v: a finding with no receipt claims a signed list: %q", e, s)
		}
	}
	noReceipt := FindingShows("withheld", "absent_in_window", false, true)
	for _, want := range []string{"unsigned list", "your own node's tip"} {
		if !strings.Contains(noReceipt, want) {
			t.Errorf("the no-receipt wording lacks %q: %q", want, noReceipt)
		}
	}
}

func TestVerdictOpenFindings(t *testing.T) {
	v := VerdictOpenFindings(VerdictAllChecked(220), 1)
	if v.Headline != "All 220 blocks checked. 1 finding from an earlier run is still open." {
		t.Errorf("headline = %q", v.Headline)
	}
	if !strings.HasPrefix(v.Lede, VerdictAllChecked(220).Lede) || !strings.Contains(v.Lede, "does not clear a finding") {
		t.Errorf("lede = %q", v.Lede)
	}
	if v := VerdictOpenFindings(VerdictSomeChecked(200, 213), 2); v.Headline != "200 of 213 blocks checked. 2 findings from an earlier run are still open." {
		t.Errorf("headline = %q", v.Headline)
	}
}

// TestNotFoundPagesEchoOnlyWhatTheCallerPasses keeps arbitrary address text
// off the page: the handler passes "" for anything that is not an id or name.
func TestNotFoundPagesEchoOnlyWhatTheCallerPasses(t *testing.T) {
	if b := FindingNotFound("").Body; strings.Contains(b, "with id") {
		t.Errorf("FindingNotFound(\"\") = %q", b)
	}
	if b := EvidenceNotFound("").Body; strings.Contains(b, "named") {
		t.Errorf("EvidenceNotFound(\"\") = %q", b)
	}
	if b := FindingNotFound("827a8d3f502e").Body; !strings.Contains(b, "827a8d3f502e") {
		t.Errorf("FindingNotFound lost the id: %q", b)
	}
}
