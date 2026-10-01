package wording

import (
	"regexp"
	"strings"
	"testing"
)

// cliText collects every sentence the command-line tool can print from this
// table, with sample arguments for the functions.
func cliText() []string {
	out := []string{
		CLIUsage, CLIHelpHint, CLINoCommand, CLIUnknownCommand("chek"), CLIFlagError("flag provided but not defined: -x"),
		CLIUnexpectedArgument("extra"), CLICommandHelpHint("check"), CLIDetails("core: GET /chaininfo.json: refused"),
		VersionLine("0.1.0", "abc1234"),
		CheckUsage, VerifyUsage, StatusUsage, UIUsage,
		CheckNoIndexer, CheckBadIndexer("http://x"), CheckBadLabel("Honest"), CheckDuplicateLabel("honest"),
		CheckBadPubkeyFlag("honest"), CheckBadPubkey("honest"), CheckPubkeyUnknownLabel("other"),
		CheckDuplicatePubkey("honest"), CheckMissingPin("honest"), CheckNoCore, CheckBadCore("x"),
		CheckBadHeight("--from", "x"), CheckRangeBackwards(9, 3), CheckRangeAboveTip(300, 212),
		CheckBadExpect("x"), CheckDuplicateExpect(strings.Repeat("ab", 32)),
		CheckExpectNotInBlock(strings.Repeat("ab", 32), strings.Repeat("cd", 32)),
		CheckExpectBlockUnknown(strings.Repeat("cd", 32)),
		CheckExpectNotChecked(strings.Repeat("ab", 32), strings.Repeat("cd", 32), 0, 100),
		ServerInfoFailed, ServerRecordUnanswered(3), ServerRecordRefused(3), ServerRecordRejected(3),
		ServerListUnanswered(3), ServerNotAsked(3), ServerReceiptRejected(3), ServerListRejected(3),
		CheckServerLastError("honest", ServerListUnanswered(3)), CheckInterrupted,
		CheckExpectNotFound(strings.Repeat("ab", 32)), CheckNoHome("state file"), CheckPaymentEntry(strings.Repeat("ab", 32)),
		CheckStateUnreadable("/s.json"), CheckStateNewer("/s.json", "canary-state/2"),
		CheckStateOtherNetwork("/s.json", "main", "regtest"),
		CheckCoreUnreachable("http://127.0.0.1:18443/rest"), CheckCoreSyncing, CheckCoreChain("testnet4"), CheckCoreChain("signet"),
		CheckServerUnusable("honest", "http://127.0.0.1:8081"), CheckWriteState("/s.json"),
		CheckWriteEvidence("/e/x.json"), CheckStarting(0, 212, 2), CheckDroppedFinding("827a8d3f502e", strings.Repeat("cd", 32)),
		CheckSaved("/s.json"),
		StatusMissing("/s.json"), StatusUnreadable("/s.json"), StatusNewer("/s.json", "canary-state/2"),
		VerifyNoFile, VerifyReasonMissing, VerifyReasonNotOpened, VerifyReasonTooLarge(16 << 20), VerifyReasonMalformed, VerifyReasonUnsupported,
		VerifyChecksOutDetail, VerifySubject("b1070620…270d", 205, "regtest", 1, "01982d71…7c16"),
		UIServing("http://127.0.0.1:7352/"), UINotLoopback("0.0.0.0:7352"), UICantListen("127.0.0.1:7352"),
		UIBadAddr("nonsense"), CLIFlagsHeading,
	}
	for _, ok := range []*bool{nil, ptr(true), ptr(false)} {
		out = append(out, VerifyCheckLine(ok, "receipt", "The receipt is signed by the same key."))
	}
	for _, list := range [][]FlagHelp{CheckFlags, VerifyFlags, StatusFlags, UIFlags} {
		for _, f := range list {
			out = append(out, f.Text)
		}
	}
	return out
}

func ptr(b bool) *bool { return &b }

// The command-line words keep to the same limits as every other screen.
func TestCLIWordsFollowTheHonestyRules(t *testing.T) {
	banned := []string{
		"trustless", "secure", "guarantee", "hidden payment", "protecting", "!", "§",
		"rung", "t_base", "relay", "—", "timestamp",
	}
	split := regexp.MustCompile(`[.?]\s+`)
	for _, s := range cliText() {
		if strings.TrimSpace(s) == "" {
			t.Error("an empty string in the command-line wording")
		}
		low := strings.ToLower(s)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("%q contains %q", s, b)
			}
		}
		for _, sentence := range split.Split(s, -1) {
			if n := len(strings.Fields(sentence)); n > 30 {
				t.Errorf("%d words: %q", n, sentence)
			}
		}
	}
}

// The usage texts list every flag the formats doc gives each command, and no
// other.
func TestFlagHelpMatchesTheFormatsDoc(t *testing.T) {
	names := func(fs []FlagHelp) string {
		var out []string
		for _, f := range fs {
			out = append(out, f.Name)
		}
		return strings.Join(out, " ")
	}
	tests := []struct {
		got, want string
	}{
		{names(CheckFlags), "indexer pubkey core-rest from to expect state evidence-dir"},
		{names(VerifyFlags), "json"},
		{names(StatusFlags), "json state"},
		{names(UIFlags), "addr state"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("flags %q, want %q", tt.got, tt.want)
		}
	}
}

func TestCLILines(t *testing.T) {
	tests := []struct{ got, want string }{
		{VerifyCheckLine(ptr(true), "read", "Format canary-evidence/1, claim omission."),
			"  Read the file: Passed. Format canary-evidence/1, claim omission."},
		{VerifyCheckLine(ptr(false), "receipt", "The receipt is not signed by the accused key."),
			"  Receipt: Failed. The receipt is not signed by the accused key."},
		{VerifyCheckLine(nil, "window", VerifyNotRunEarlier), "  Retention window: Not run: an earlier step failed."},
		{VerifyCantRead(VerifyReasonMissing), "Can't read this file: there is no file at this path."},
		{VersionLine("0.1.0", "abc1234"), "canary 0.1.0 (abc1234)"},
		{CLIDetails("x: y"), "  Details: x: y"},
		{CheckRangeBackwards(9, 3), "--from 9 is above --to 3."},
		{CheckCoreChain("testnet4"), `Bitcoin Core reports chain "testnet4". canary check v1 runs on regtest and main only.`},
		// Every signet reports the chain name "signet", and a custom signet's
		// magic comes from its challenge. So the name cannot say which magic
		// to check against, and v1 refuses until a flag can name it.
		{CheckCoreChain("signet"), `Bitcoin Core reports chain "signet". canary check v1 runs on regtest and main only. ` +
			"Every signet reports that same name, so Canary can't tell which signet Core is on. " +
			"Signet needs a flag that names the network, which is planned after v1."},
		// not_found, bad_block_hash and unsupported_parameter are v1 error
		// codes. A v1 server never gives them to Canary's well-formed requests.
		{ServerRecordRefused(3), "It answered the request for block 3's record with an error a v1 server never gives Canary."},
		{Reason("server_unreachable"), "The server did not answer, said it was not ready, " +
			"or refused the request with an error a v1 server never gives Canary."},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("got  %q\nwant %q", tt.got, tt.want)
		}
	}
}
