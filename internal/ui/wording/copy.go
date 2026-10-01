// Package wording is Canary's one wording table. canary status, canary ui and
// the browser checker take every state label, reason sentence and message from
// here, so the three never drift apart.
//
// The package has no dependencies beyond the standard library, so the wasm
// checker can import it without pulling in the dashboard.
//
// Rules the words follow. Checked means the tweak list was checked, never the
// payments. Servers disagree names two servers and accuses neither. Can't be
// checked is neither a pass nor an accusation. Knowing is not proving: a
// finding says whether others can check it. Canary looks for entries a server
// left out, never for entries it faked.
package wording

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// StateText is the on-screen wording for one of the six coverage states.
type StateText struct {
	// Code is the stable state code from the state file. It is never shown.
	Code string
	// Label is the word every screen prints.
	Label string
	// Meaning is one line that says what the label means.
	Meaning string
	// Explain answers "What does this mean?" in a short paragraph.
	Explain string
}

var stateOrder = []string{"verified", "resolved", "unresolvable", "unverified", "disputed", "compromised"}

var states = map[string]StateText{
	"verified": {
		Code:    "verified",
		Label:   "Checked",
		Meaning: "The tweak list matched the record its server signed.",
		Explain: "Canary recomputed the root over every position in the tweak list, and it matched the server's signed record. " +
			"No position needed filling. This checks the tweak list only. It never checks the payment outputs a wallet matches against, " +
			"so a server could still hide a payment there, and Canary v1 would not see it.",
	},
	"resolved": {
		Code:    "resolved",
		Label:   "Checked, gap filled",
		Meaning: "The tweak list matched its signed record once Canary filled the gaps.",
		Explain: "Some positions arrived only as hashes, or were empty and Canary found the entry elsewhere. " +
			"Canary filled every position first, then recomputed the root, and it matched. " +
			"An entry sent only as a hash is a known limit. Canary can't tell a server that pruned it from one that hid it.",
	},
	"unresolvable": {
		Code:    "unresolvable",
		Label:   "Can't be checked",
		Meaning: "Canary could not recompute the root for this block.",
		Explain: "Something the root needs was missing. An entry nobody could supply ends here, and so does a list the server signed for but did not serve. " +
			"This is neither a pass nor an accusation. A payment in this block could be missing, and Canary would not know.",
	},
	"unverified": {
		Code:    "unverified",
		Label:   "Not checked",
		Meaning: "There was no signed record to check against.",
		Explain: "No server gave Canary a signed record it could use for this block. " +
			"The server may sign nothing, may not have reached the block yet, or may not have answered. " +
			"The data may still be fine. Canary checked nothing about it.",
	},
	"disputed": {
		Code:    "disputed",
		Label:   "Servers disagree",
		Meaning: "Two servers signed different records for this block.",
		Explain: "Two servers each signed a record for the same block hash, and the records differ. At least one of them is wrong. " +
			"Canary can't tell which, so it names both servers and accuses neither.",
	},
	"compromised": {
		Code:    "compromised",
		Label:   "Data withheld",
		Meaning: "A named server left out an entry it had signed for, or the entry for a payment you declared.",
		Explain: "One server signed a record that includes an entry, then served a list that left it out. " +
			"Or its record or list left out the entry for a payment you declared. Canary names that one server. " +
			"Whether you can prove it to others depends on the evidence, and each finding says which.",
	},
}

// States returns the six states in the order every screen lists them.
func States() []StateText {
	out := make([]StateText, len(stateOrder))
	for i, c := range stateOrder {
		out[i] = states[c]
	}
	return out
}

// State returns the wording for a state code. An unknown code gets a neutral
// label that says so, never one of the six.
func State(code string) StateText {
	if s, ok := states[code]; ok {
		return s
	}
	return StateText{
		Code:    code,
		Label:   "Unknown state",
		Meaning: "This build of Canary does not know the state " + strconv.Quote(code) + ".",
	}
}

// Labels returns the six on-screen labels in display order.
func Labels() []string {
	out := make([]string, len(stateOrder))
	for i, c := range stateOrder {
		out[i] = states[c].Label
	}
	return out
}

// reasons explains every reason code, including the warning-only one.
var reasons = map[string]string{
	"records_agree":    "Two or more servers signed the same root, and a served list matched it.",
	"expected_payment": "One server's list matched its signed record and carried a payment you declared.",
	"own_record": "One server's list matched the record it signed. Nothing tested whether that record is complete. " +
		"A second server or a declared payment would.",

	"filled_from_server":           "Another server supplied the missing entry, and it proved into this server's signed root.",
	"filled_from_expected_payment": "Canary computed the missing entry from a payment you declared, and it proved into the signed root.",
	"hash_retained":                "The server sent some entries only as hashes. The root matched, but Canary can't tell pruning from hiding here.",

	"gap_unfilled": "The server left an entry out of a block past the 144-block window. Your node confirmed its chain, and nobody supplied the entry.",
	"tip_unconfirmed": "The server left an entry out and signed a tip that puts the block past the window. " +
		"Your node can't confirm that tip yet, and nobody supplied the entry.",
	"list_not_served": "The server signed a record for this block but did not serve its tweak list.",
	"list_unreadable": "The server sent a tweak list without a valid receipt, and Canary could not read it.",

	"no_records":          "The server signed no record for this block. It may sign nothing, or may have started indexing above this block.",
	"no_record_for_block": "The server signed records for blocks on both sides of this one, but not for this one.",
	"not_indexed_yet":     "The server has not reached this block yet.",
	"server_unreachable": "The server did not answer, said it was not ready, " +
		"or refused the request with an error a v1 server never gives Canary.",

	"records_differ": "Two servers signed different roots for this block hash.",

	"absent_in_window":  "The server left out an entry it had signed for, while the block sat inside the 144-block window.",
	"false_chain_claim": "The server left out an entry and excused it with a block height or tip that your node contradicts.",
	"served_contradicts_record": "The list the server served contradicts its own signed record. " +
		"Its length or root differs, or bytes it signed fail to decode.",
	"expected_payment_not_in_record": "The server's signed record leaves out the entry for a payment you declared.",
	"expected_payment_not_in_list": "The server's list does not carry a payment you declared in full. " +
		"Your node shows the payment's output unspent, so pruning can't explain it.",

	"hash_without_policy": "The server declares that it prunes nothing, yet it sent some entries only as hashes. " +
		"Its policy is unsigned, so this is a warning, not an accusation.",
}

// Reason returns the plain sentence for a reason code.
func Reason(code string) string {
	if s, ok := reasons[code]; ok {
		return s
	}
	return "This build of Canary does not know the reason " + strconv.Quote(code) + "."
}

// ReasonCodes returns every reason code the table explains.
func ReasonCodes() []string {
	out := make([]string, 0, len(reasons))
	for c := range reasons {
		out = append(out, c)
	}
	return out
}

// WarningSuffix ends every warning line. A warning is never an accusation.
const WarningSuffix = "Not an accusation."

// WarningLabel names the warning kind of finding.
const WarningLabel = "Warning"

// KindLabel returns the label for a finding kind. A withheld finding reads as
// Data withheld and a disagreement as Servers disagree, the same words the
// block states use.
func KindLabel(kind string) string {
	switch kind {
	case "withheld":
		return states["compromised"].Label
	case "disagree":
		return states["disputed"].Label
	case "warning":
		return WarningLabel
	}
	return "Unknown finding"
}

func serverName(names []string, i int) string {
	if i < len(names) && names[i] != "" {
		return names[i]
	}
	return "A server"
}

// FindingSentence returns the sentence for a finding, as canary status prints
// it. servers holds the labels of the servers it names: one, or two for a
// disagreement. The sentence opens with the bare label, as the formats
// document pins for the terminal. Screens use FindingHeadline instead.
func FindingSentence(kind, reason string, servers []string) string {
	return findingSentence(kind, reason, serverName(servers, 0), serverName(servers, 1))
}

// FindingHeadline returns the headline a screen shows for a finding. A label
// is a name the user chose, often lower case, so the headline introduces it:
// "Server withholder left out an entry it had signed for."
func FindingHeadline(kind, reason string, servers []string) string {
	first, second := "A server", "a server"
	if len(servers) > 0 && servers[0] != "" {
		first = "Server " + servers[0]
	}
	if len(servers) > 1 && servers[1] != "" {
		second = "server " + servers[1]
		if kind == "disagree" && servers[0] != "" {
			first, second = "Servers "+servers[0], servers[1]
		}
	}
	return findingSentence(kind, reason, first, second)
}

// findingSentence builds a finding's sentence from the phrases that name its
// first and second server.
func findingSentence(kind, reason, s, second string) string {
	switch kind {
	case "withheld":
		switch reason {
		case "absent_in_window":
			return s + " left out an entry it had signed for."
		case "false_chain_claim":
			return s + " left out an entry and excused it with a chain claim your node contradicts."
		case "served_contradicts_record":
			return s + " served a list that contradicts its own signed record."
		case "expected_payment_not_in_record":
			return s + " left your declared payment out of its signed record."
		case "expected_payment_not_in_list":
			return s + " left your declared payment out of its tweak list."
		}
		return s + " withheld data it had signed for."
	case "disagree":
		return s + " and " + second + " signed different records for the same block."
	case "warning":
		switch reason {
		case "no_record_for_block":
			return s + " signed records around this block, but not for it."
		case "list_not_served":
			return s + " signed a record for this block, then did not serve its list."
		case "list_unreadable":
			return s + " sent an unsigned list for this block that Canary could not read."
		case "hash_without_policy":
			return s + " sent entries as hashes although it declares that it prunes nothing."
		}
		return s + " did something an honest server would not."
	}
	return s + " is named in a finding this build of Canary does not know."
}

// FindingShows says what a finding establishes. provable and hasEvidence are
// the finding's own facts, as Provable takes them. A list that arrived without
// a receipt has no signed tip, so the wording never claims one for it.
func FindingShows(kind, reason string, provable, hasEvidence bool) string {
	switch kind {
	case "withheld":
		switch reason {
		case "absent_in_window":
			const record = "The server signed a record for this block that includes the entry. "
			switch {
			case provable:
				return record + "Then it served and signed a list that marked the entry's position empty, " +
					"while the block sat less than 144 blocks below its signed tip."
			case hasEvidence:
				return record + "Then it served an unsigned list that marked the entry's position empty. " +
					"The list had no receipt, so Canary measured depth from your own node's tip, and the block sat inside the 144-block window."
			}
			return record + "Then it served a list that marked the entry's position empty, while the block sat inside the 144-block window."
		case "false_chain_claim":
			return "The server left the position empty and signed a block height or tip that your Bitcoin Core node contradicts."
		case "served_contradicts_record":
			return "The server signed a record for this block, then served a list for the same block that does not match it."
		case "expected_payment_not_in_record":
			return "Your node shows your payment in this block, and the server's signed record has no entry for it. " +
				"A record commits to every entry in the block, spent or not, so no policy explains the gap."
		case "expected_payment_not_in_list":
			return "The server's record includes your payment's entry, but its list does not carry it in full. " +
				"Your node shows one of the payment's outputs unspent, so pruning can't explain the gap."
		}
	case "disagree":
		return "Both servers signed a record for the same block hash, and the records differ. At least one of them is wrong."
	case "warning":
		switch reason {
		case "no_record_for_block":
			return "The server signed records for a lower and a higher block in this run, but not for this one."
		case "list_not_served":
			return "The server signed a record for this block, then answered the request for its list with an error, inside the 144-block window."
		case "list_unreadable":
			return "The server sent a list for this block with no valid receipt, and the list failed Canary's reader rules."
		case "hash_without_policy":
			return "The server's /info declares that it prunes nothing, yet its list sent at least one entry only as a hash."
		}
	}
	return Reason(reason)
}

// FindingDoesNotShow says what a finding leaves open.
func FindingDoesNotShow(kind, reason string) string {
	switch kind {
	case "withheld":
		switch reason {
		case "absent_in_window":
			return "It does not show whether the entry paid you, or what the server did in other blocks. " +
				"It says nothing about payment outputs, which Canary v1 does not check."
		case "false_chain_claim":
			return "Checking the chain claim needs a node, and v1's evidence format has no claim for it. So nobody else can confirm this from Canary's files."
		case "served_contradicts_record":
			return "v1's evidence format covers only an entry left out of a list, so this finding has no evidence file."
		case "expected_payment_not_in_record":
			return "A stranger would need the block to check this, and v1's evidence format has no claim for it."
		case "expected_payment_not_in_list":
			return "The evidence format can't show that an output is unspent, so nobody else can confirm this from Canary's files."
		}
		return "It says nothing about payment outputs, which Canary v1 does not check."
	case "disagree":
		return "It does not say which server is wrong. Canary accuses neither."
	case "warning":
		return "Nothing the server signed shows this, so it is not an accusation. No block's state changes because of it."
	}
	return ""
}

// Provable answers "Can you prove it to others?" for a finding.
func Provable(kind string, provable, hasEvidence bool) string {
	switch {
	case kind == "withheld" && provable:
		return "Yes. The evidence file carries the server's signed receipt, so anyone can check it offline with canary verify."
	case kind == "withheld" && hasEvidence:
		return "Not yet. The evidence file has no receipt, so it shows only that the server signed for the entry. Your own check saw the entry left out."
	case kind == "withheld":
		return "No. You know this from your own check, but Canary has no file that shows it to others."
	case kind == "disagree":
		return "No. Canary v1 writes no evidence file for a disagreement."
	case kind == "warning":
		return "No. Nothing the server signed shows this."
	}
	return "No."
}

// ProvableShort is the one-line version for lists.
func ProvableShort(kind string, provable, hasEvidence bool) string {
	switch {
	case kind == "withheld" && provable:
		return "You can prove this to others."
	case kind == "withheld" && hasEvidence:
		return "Inclusion only. You can be sure of this, you can't yet prove it to others."
	case kind == "withheld":
		return "You know this. You can't prove it to others."
	case kind == "warning":
		return WarningSuffix
	}
	return "Not provable to others."
}

// Moment is the wording for one situation the dashboard can be in: a title,
// what it means, and what to do.
type Moment struct {
	Title  string
	Body   string
	Action string
}

// Verdict is the overview's headline and the sentence under it.
type Verdict struct {
	Headline string
	Lede     string
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// blocks returns "1 block" or "N blocks".
func blocks(n int) string {
	return strconv.Itoa(n) + " " + plural(n, "block", "blocks")
}

// VerdictAllChecked is the verdict when every block passed.
func VerdictAllChecked(total int) Verdict {
	head := "All " + blocks(total) + " checked."
	if total == 1 {
		head = "The 1 block was checked."
	}
	return Verdict{
		Headline: head,
		Lede:     "Each tweak list matched the record its server signed. That covers tweak lists, not the payment outputs a wallet matches against.",
	}
}

// VerdictSomeChecked is the verdict when some blocks passed and the rest
// could not be checked, with nothing found against any server.
func VerdictSomeChecked(passed, total int) Verdict {
	return Verdict{
		Headline: strconv.Itoa(passed) + " of " + blocks(total) + " checked.",
		Lede:     "This run found no withheld entries in the blocks it could check.",
	}
}

// VerdictNoneChecked is the verdict when no block could be checked.
func VerdictNoneChecked(total int) Verdict {
	head := "None of the " + blocks(total) + " could be checked."
	if total == 1 {
		head = "The 1 block could not be checked."
	}
	return Verdict{
		Headline: head,
		Lede:     "No block had a signed record and a list Canary could check against it.",
	}
}

// VerdictDisputed is the verdict when servers disagree and nobody is accused.
func VerdictDisputed(n int) Verdict {
	return Verdict{
		Headline: "Servers disagree about " + blocks(n) + ".",
		Lede:     "Two servers signed different records for the same block. Canary can't tell which one is wrong.",
	}
}

// VerdictWithheldOne is the verdict for one withheld finding in one block.
// sentence is FindingHeadline for it.
func VerdictWithheldOne(sentence string, height uint32, provableShort string) Verdict {
	return Verdict{
		Headline: sentence,
		Lede:     "Block " + strconv.FormatUint(uint64(height), 10) + ". " + provableShort,
	}
}

// VerdictWithheldMany is the verdict when data was withheld in several blocks.
func VerdictWithheldMany(n int) Verdict {
	return Verdict{
		Headline: "Data withheld in " + blocks(n) + ".",
		Lede:     "Each finding names the server and what it left out.",
	}
}

// VerdictOpenFindings extends a verdict whose blocks show no problem when n
// findings from earlier runs still name a server. A later run never clears a
// finding, so the headline says it is still open.
func VerdictOpenFindings(v Verdict, n int) Verdict {
	v.Headline += " " + strconv.Itoa(n) + " " + plural(n, "finding", "findings") +
		" from an earlier run " + plural(n, "is", "are") + " still open."
	v.Lede += " A later run does not clear a finding, so " + plural(n, "it stays", "they stay") + " in the findings list."
	return v
}

// LowerBound is the sentence shown whenever any block is not Checked. n is
// the number of such blocks. problems is true when some of them read Data
// withheld or Servers disagree, which Canary did check. The sentence says a
// payment could be missing, never that one is: Can't be checked and Not
// checked accuse nobody.
func LowerBound(n int, problems bool) string {
	it := plural(n, "it", "them")
	tail := " A payment in " + it + " could be missing from what your wallet shows, so treat its balance as a lower bound."
	if problems {
		return blocks(n) + " " + plural(n, "is", "are") + " not Checked." + tail
	}
	return blocks(n) + " couldn't be checked." + tail
}

// Section notes on the dashboard.
const (
	ServersNote = "You pinned each server's key with --pubkey, and Canary never learns a key from the server itself. " +
		"A signed tip came from a valid receipt. Policies and unsigned tips come from the server's /info, which nothing signs."
	PaymentsNote = "Canary computed each payment's entry from your node and looked for it in every server's record and list. " +
		"It checks the entry only, not the payment's outputs."
	FindingsIntro = "A finding is a fact about a server and a block. Data withheld names one server. " +
		"Servers disagree names two and accuses neither. A warning names a server but proves nothing."
	EvidenceNote = "Anyone can check this file offline. canary verify recomputes every step and trusts nothing the file says about itself."
)

// BlocksIntro opens the blocks page.
func BlocksIntro(from, to uint32, total int) string {
	return fmt.Sprintf("Blocks %d to %d, %s in all. Each row is a run of blocks that share a state and a reason.", from, to, blocks(total))
}

// HeightNotFound explains a failed height lookup on the blocks page.
func HeightNotFound(query string, detailed, total int) string {
	if _, err := strconv.ParseUint(strings.TrimSpace(query), 10, 32); err != nil {
		return "Enter a block height as a whole number, such as 205."
	}
	return fmt.Sprintf("No block at height %s in these results. Canary keeps detail for %d of the %s.", strings.TrimSpace(query), detailed, blocks(total))
}

// NoFindings is shown when the findings list is empty.
const NoFindings = "No findings. No server was caught leaving out an entry it had signed for."

// Full-page and error moments.
var (
	NoCheckYet = Moment{
		Title:  "No check yet",
		Body:   "Canary has no results to show. Run a check, then reload this page.",
		Action: "Run this in a terminal. Replace URL, label and HEX with each server's address, a short name, and its public key.",
	}
	PageNotFound = Moment{
		Title:  "Page not found",
		Body:   "Canary has no page at this address.",
		Action: "Go to the overview.",
	}
)

// StateUnreadable is the page for a state file Canary opened but cannot
// parse. Moving it aside is the fix, and it costs the findings the file holds.
func StateUnreadable(path string) Moment {
	return Moment{
		Title: "Canary can't read its state file",
		Body:  "The file at " + path + " is not a canary-state/1 file Canary can read. It may be damaged, or another program may have written it.",
		Action: "canary check won't overwrite a file it can't read, so move the file aside, then run canary check again. " +
			"The command below keeps it as " + path + ".bad. " +
			"Findings in that file won't carry into the new run, so the dashboard stops showing them.",
	}
}

// StateNotOpened is the page for a state file the system would not let
// Canary read, such as one without read permission. Moving it aside is the
// wrong fix, so the page does not suggest it.
func StateNotOpened(path string) Moment {
	return Moment{
		Title:  "Canary can't open its state file",
		Body:   "The system would not let Canary read the file at " + path + ". The technical details give the reason.",
		Action: "Fix the file's permissions or the path, then reload this page. Keep the file where it is, because it holds your findings.",
	}
}

// NewerFormat is the page for a state file from a later Canary.
func NewerFormat(found string) Moment {
	return Moment{
		Title:  "This state file is newer than this Canary",
		Body:   "The file says " + found + ". This build of Canary reads canary-state/1.",
		Action: "Update Canary, then reload this page. An older canary check won't overwrite the file either.",
	}
}

// BlockNotFound is the page for a block hash the results do not hold.
func BlockNotFound(from, to uint32) Moment {
	return Moment{
		Title: "Block not in these results",
		Body: fmt.Sprintf("The last check covered blocks %d to %d and has no block with this hash. "+
			"A block from another chain, or one mined after the check, won't appear.", from, to),
		Action: "See all blocks.",
	}
}

// FindingNotFound is the page for a finding id the results do not hold. The
// caller passes "" for anything that is not a finding id, so the page never
// echoes arbitrary text from the address.
func FindingNotFound(id string) Moment {
	first := "Canary has no finding at this address."
	if id != "" {
		first = "Canary has no finding with id " + id + "."
	}
	return Moment{
		Title: "Finding not found",
		Body: first + " It drops a finding only when your node no longer knows its block, " +
			"as after a regtest chain is wiped.",
		Action: "See all findings.",
	}
}

// EvidenceNotFound is the page for an evidence file Canary can't serve. The
// caller passes "" for anything that is not a plain evidence file name, so
// the page never echoes arbitrary text from the address.
func EvidenceNotFound(name string) Moment {
	first := "Canary lists no evidence file at this address"
	if name != "" {
		first = "Canary lists no evidence file named " + name
	}
	return Moment{
		Title:  "Evidence file not found",
		Body:   first + ", or the file is no longer in the evidence directory.",
		Action: "Check the evidence directory, or run canary check again.",
	}
}

// BlockNotCovered follows a finding's block height when the results hold no
// detail for that block, so the dashboard has no page for it. A finding
// carried forward from an earlier run can name such a block.
const BlockNotCovered = "Not in these results, so it has no block page."

// ServerError is the page for a failure inside canary ui. id matches the
// line canary ui logs to its terminal.
func ServerError(id string) Moment {
	return Moment{
		Title:  "Canary failed to show this page",
		Body:   "Something went wrong inside canary ui. Error id " + id + " marks the full error in the terminal where canary ui runs.",
		Action: "Reload the page. If it fails again, report the error id and the terminal output.",
	}
}

// Stale is the banner shown when the results are older than the dashboard's
// limit. age is a Duration string such as "3 h".
func Stale(age string) Moment {
	return Moment{
		Title:  "These results are " + age + " old",
		Body:   "Blocks mined since the last check are not in them.",
		Action: "Run canary check again to include them.",
	}
}

// Update-bar messages. The page polls /state.etag and shows one of these in a
// status bar that stays until the reader acts on it.
const (
	UpdateNewResults = "New results."
	UpdateNewFinding = "New finding."
	UpdateUpdated    = "Canary was updated."
	UpdateBack       = "Canary is reachable again."
	UpdateReload     = "Reload"
	UpdateDismiss    = "Dismiss"
)

// Patterns the page script fills in. {n} is a count and {time} is the local
// time as HH:MM.
const (
	UpdateNewFindingsPattern = "{n} new findings."
	UpdateLostPattern        = "Can't reach Canary since {time}."
)

// UpdateNewFindings is the bar text when n findings arrived.
func UpdateNewFindings(n int) string {
	if n == 1 {
		return UpdateNewFinding
	}
	return strings.Replace(UpdateNewFindingsPattern, "{n}", strconv.Itoa(n), 1)
}

// UpdateLost is the bar text when the page cannot reach canary ui. since is
// the local time as HH:MM.
func UpdateLost(since string) string {
	return strings.Replace(UpdateLostPattern, "{time}", since, 1)
}

// Labels for the theme button, which cycles automatic, light and dark.
const (
	ThemeAuto  = "Theme: automatic"
	ThemeLight = "Theme: light"
	ThemeDark  = "Theme: dark"
)

// Framing is the one-line claim the dashboard footer carries.
const Framing = "Canary holds tweak servers to what they signed. It does not remove the need to trust one."

// RegtestBadge is the network notice shown on regtest.
const RegtestBadge = "regtest: a private test chain on this computer"

// RecordedRegtestBadge is the network notice on a recorded run's pages. The
// reader's computer never ran that chain, so it names no computer.
const RecordedRegtestBadge = "regtest: a private test chain, not a public network"

// Labels for the dashboard's links. A recorded run's pages sit inside the
// public site, whose own links are already called Main.
const (
	DashboardNavLabel = "Main"
	RecordedNavLabel  = "Recorded dashboard"
)

// RecordedNetworkBadge returns the network notice for a recorded run's pages.
func RecordedNetworkBadge(name string) string {
	if name == "regtest" {
		return RecordedRegtestBadge
	}
	return NetworkBadge(name)
}

// NetworkBadge returns the network notice for the header.
func NetworkBadge(name string) string {
	switch name {
	case "regtest":
		return RegtestBadge
	case "":
		return ""
	}
	return name + ": Canary v1 is tested on regtest only"
}

// StatusTimeLayout formats the time in the status line.
const StatusTimeLayout = "2006-01-02 15:04 MST"

// StatusLine is the one-line summary of a run. canary status passes the time
// in UTC and no age. The dashboard passes local time and an age such as
// "6 min ago".
func StatusLine(when, age string, from, to uint32, network, version, build string) string {
	t := when
	if age != "" {
		t += " (" + age + ")"
	}
	return fmt.Sprintf("Last check %s · blocks %d–%d · %s · canary %s (%s)", t, from, to, network, version, build)
}

// Duration returns a short, rounded duration: "45 min", "3 h", "2 days".
func Duration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under 1 min"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " min"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + " h"
	}
	n := int(d / (24 * time.Hour))
	return strconv.Itoa(n) + " days"
}

// Age returns a relative age for the status line: "6 min ago". A time in the
// future, from clock skew, reads as "just now".
func Age(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	return Duration(d) + " ago"
}

// CountsLine returns the counts summary, "212 Checked · 1 Data withheld",
// listing only states with at least one block, in display order.
func CountsLine(counts map[string]int) string {
	var parts []string
	for _, c := range stateOrder {
		if n := counts[c]; n > 0 {
			parts = append(parts, strconv.Itoa(n)+" "+states[c].Label)
		}
	}
	if len(parts) == 0 {
		return "No blocks checked"
	}
	return strings.Join(parts, " · ")
}

// ShortHash returns the first head and last tail characters of a hex value
// joined by an ellipsis. It returns short values unchanged.
func ShortHash(h string, head, tail int) string {
	if len(h) <= head+tail+1 {
		return h
	}
	return h[:head] + "…" + h[len(h)-tail:]
}

// FindingStatusLine is the finding line canary status prints, for example
// "withholder left out an entry it had signed for: block 205, txid 01982d71…7c16."
func FindingStatusLine(kind, reason string, servers []string, height uint32, txid string) string {
	s := strings.TrimSuffix(FindingSentence(kind, reason, servers), ".")
	line := fmt.Sprintf("%s: block %d", s, height)
	if txid != "" {
		line += ", txid " + ShortHash(txid, 8, 4)
	}
	line += "."
	if kind == "warning" {
		line = WarningLabel + ": " + line + " " + WarningSuffix
	}
	return line
}

// EvidenceStatusLine is the evidence line under a finding in canary status.
func EvidenceStatusLine(name string, provable bool) string {
	if provable {
		return "Evidence: " + name + ". You can prove this to others."
	}
	return "Evidence: " + name + ". Inclusion only. You can't yet prove this to others."
}

// Declared-payment outcomes.
var paymentOutcomes = map[string][2]string{
	"found":           {"Found", "The server's list carries the entry in full."},
	"withheld":        {"Withheld", "The server left the entry out where pruning can't explain it."},
	"hash_only":       {"Hash only", "The record includes the entry, but the list sent only its hash. Pruning may explain that, so Canary does not accuse."},
	"not_indexed_yet": {"Not indexed yet", "The server has not reached this block yet."},
	"unresolvable":    {"Couldn't check", "Canary could not check this server's list for the block."},
	"not_eligible":    {"No entry", "The transaction has no silent-payments entry, so there is nothing to check."},
	"pending":         {"Pending", "The payment is unconfirmed, or a server has not reached its block yet."},
}

// PaymentOutcome returns the label and sentence for a declared-payment
// outcome.
func PaymentOutcome(code string) (label, sentence string) {
	if o, ok := paymentOutcomes[code]; ok {
		return o[0], o[1]
	}
	return code, "This build of Canary does not know this outcome."
}

// PolicyNotDeclared describes the policy of a server whose /info answered as
// canary-info/1 with no policy in it.
const PolicyNotDeclared = "Not declared"

// PolicyUnknown describes the policy of a server whose /info gave no
// canary-info/1 answer. The server may still have served valid records and
// lists, so its policy is unknown, not absent.
const PolicyUnknown = "Unknown: its /info did not answer"

// PolicyText describes a server's declared policy. v1 policies come from the
// unsigned /info, so the text says so.
func PolicyText(prunesSpent bool, dustSat uint64, signed bool) string {
	var b strings.Builder
	if prunesSpent {
		b.WriteString("Prunes spent entries")
	} else {
		b.WriteString("Prunes nothing")
	}
	if dustSat == 0 {
		b.WriteString(", no dust filter")
	} else {
		fmt.Fprintf(&b, ", drops outputs under %d sat", dustSat)
	}
	if signed {
		b.WriteString(", signed")
	} else {
		b.WriteString(", unsigned")
	}
	return b.String()
}

// NoPubkey describes a server pinned as none.
const NoPubkey = "None. It signs nothing, so its blocks read Not checked."

// TipText describes a server's tip: signed when it came from a valid
// receipt, unsigned when it came from /info.
func TipText(height uint32, signed bool) string {
	if signed {
		return fmt.Sprintf("%d, signed", height)
	}
	return fmt.Sprintf("%d, unsigned", height)
}

// YesNo returns "Yes" or "No".
func YesNo(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
}

// Verify report wording. The evidence package builds the report; these are
// the words it and every screen use.

// VerifyResultLabel returns the short label for a report's result and code.
func VerifyResultLabel(result, code string) string {
	switch {
	case result == "checks_out" && code == "inclusion_only":
		return "Checks out, inclusion only"
	case result == "checks_out":
		return "Checks out"
	case result == "does_not_check_out":
		return "Does not check out"
	case result == "unreadable":
		return "Can't read this file"
	}
	return "Unknown result"
}

// Verify headlines, the first line canary verify prints.
const (
	VerifyChecksOut     = "Checks out."
	VerifyInclusionOnly = "Inclusion only: you can be sure of this, you can't yet prove it to others."
)

// VerifyInclusionOnlyDetail holds the two lines printed under
// VerifyInclusionOnly.
var VerifyInclusionOnlyDetail = [2]string{
	"The server signed a record that includes this entry. This file has no receipt, so it cannot show what the server sent.",
	"If your own canary check wrote this file, it saw the entry left out. Anyone else sees only that the entry was signed for.",
}

// VerifyDoesNotCheckOut is the headline for a failed step.
func VerifyDoesNotCheckOut(step string) string {
	return "Does not check out: " + step + " failed."
}

// VerifyCantRead is the headline for a file verify cannot read.
func VerifyCantRead(reason string) string {
	return "Can't read this file: " + strings.TrimSuffix(reason, ".") + "."
}

// VerifyNotHonest follows a Does not check out result.
const VerifyNotHonest = "This says the file's claim fails. It does not say the accused server is honest."

// Texts for a step that did not run.
const (
	VerifyNotRunEarlier   = "Not run: an earlier step failed."
	VerifyNotRunNoReceipt = "Not run: this file has no receipt."
)

var verifyCodes = map[string]string{
	"ok":                 "Checks out. The server signed a record that includes this entry, then signed a list that left it out.",
	"inclusion_only":     VerifyInclusionOnly,
	"malformed":          "The file is not valid canary-evidence/1. It has bad JSON, an unknown field, or a value of the wrong type or length.",
	"unsupported_format": "The file is not canary-evidence/1 with the omission claim, so this build can't check it.",
	"bad_signature":      "The signed record's id or signature is invalid.",
	"signer_mismatch":    "A key other than the accused server's signed the record.",
	"block_mismatch":     "The record, the file and the served list disagree about the block, its height, its network or its size.",
	"proof_invalid":      "The Merkle proof does not carry the entry to the signed root.",
	"receipt_invalid":    "The receipt's signature, network, block, resource or body digest does not match.",
	"entry_served":       "The served list carries the entry, or its correct hash, at that position.",
	"not_in_window":      "The position is empty, but the block sat 144 or more blocks below the signed tip, where that is allowed.",
}

// VerifyCode returns the plain sentence for a report code.
func VerifyCode(code string) string {
	if s, ok := verifyCodes[code]; ok {
		return s
	}
	return "This build of Canary does not know the code " + strconv.Quote(code) + "."
}

var verifySteps = map[string]string{
	"read":             "Read the file",
	"record_signature": "Record signature",
	"signer":           "Signer",
	"block":            "Block",
	"inclusion":        "Inclusion",
	"receipt":          "Receipt",
	"served_list":      "Served list",
	"window":           "Retention window",
}

// VerifySteps lists the eight step names in order.
var VerifySteps = []string{"read", "record_signature", "signer", "block", "inclusion", "receipt", "served_list", "window"}

// Words for a step's outcome, shown next to its glyph.
const (
	StepPassed = "Passed"
	StepFailed = "Failed"
	StepNotRun = "Not run"
)

// VerifyStep returns the label for a step name.
func VerifyStep(step string) string {
	if s, ok := verifySteps[step]; ok {
		return s
	}
	return step
}

// Check texts for the verify report, one sentence per step. The evidence
// package picks the text for each step it runs. A passing step's text matches
// the report example in the v1 formats doc. Nothing here echoes a value the
// file's author chose, apart from numbers and names verify has already checked.

// VerifyReadOK is the read step's text when the file parses.
func VerifyReadOK(format, claim string) string {
	return "Format " + format + ", claim " + claim + "."
}

// Texts for the read and record_signature steps.
const (
	VerifyReadMalformed = "The file is not valid canary-evidence/1. " +
		"It has bad JSON, an unknown or missing field, or a value of the wrong type or length."
	VerifyReadUnsupported    = "The file does not name canary-evidence/1 with the omission claim, so this build can't check it."
	VerifyRecordSignatureOK  = "The signed record's id and signature are valid."
	VerifyRecordSignatureBad = "The signed record's id or signature is invalid."
	VerifyRecordMalformed    = "The signed record is not a kind-1352 record with every tag, or its root tag differs from its content."
	VerifySignerOK           = "The record is signed by the accused key."
	VerifySignerBad          = "A key other than the accused key signed the record."
	VerifyBlockBad           = "The record names a different block, height or network than this file does."
)

// networkWords names a network for a sentence. An unknown magic prints as its
// decimal value, since "on unknown" reads as a typo.
func networkWords(name string, magic uint32) string {
	if name == "" || name == "unknown" {
		return "network " + strconv.FormatUint(uint64(magic), 10)
	}
	return name
}

// VerifyBlockOK is the block step's text when the record and the file agree.
func VerifyBlockOK(height uint32, network string, magic uint32) string {
	return fmt.Sprintf("The record names block %d on %s, the block this file names.", height, networkWords(network, magic))
}

// VerifyInclusionOK is the inclusion step's text when the proof holds.
func VerifyInclusionOK(index, n uint32) string {
	return fmt.Sprintf("Entry %d of %d proves into the signed root.", index, n)
}

// VerifyInclusionBad is the inclusion step's text when the proof fails.
func VerifyInclusionBad(index, n uint32) string {
	return fmt.Sprintf("Entry %d of %d does not prove into the signed root.", index, n)
}

// VerifyInclusionWrongSize is the inclusion step's text when the proof is for
// a different number of entries than the record signs for.
func VerifyInclusionWrongSize(proofN, n uint32) string {
	return fmt.Sprintf("The proof is for %d %s, but the record signs for %d.", proofN, plural(int(proofN), "entry", "entries"), n)
}

func byteCount(n int) string {
	return strconv.Itoa(n) + " " + plural(n, "byte", "bytes")
}

// VerifyReceiptOK is the receipt step's text when every receipt check passes.
func VerifyReceiptOK(size int) string {
	return "The receipt is signed by the same key, names the same block and covers these " + byteCount(size) + "."
}

// Texts for a receipt that fails.
const (
	VerifyReceiptMalformed     = "The receipt is not 178 bytes of lowercase hex with version 1."
	VerifyReceiptWrongKey      = "The receipt is not signed by the accused key."
	VerifyReceiptOtherNetwork  = "The receipt names a different network than the record."
	VerifyReceiptOtherBlock    = "The receipt names a different block than the record."
	VerifyReceiptOtherResource = "The receipt covers something other than a tweak list."
)

// VerifyReceiptOtherBody is the receipt step's text when the receipt signs
// different bytes than the file carries.
func VerifyReceiptOtherBody(size int) string {
	return "The receipt does not cover these " + byteCount(size) + "."
}

func positions(n uint32) string {
	return fmt.Sprintf("%d %s", n, plural(int(n), "position", "positions"))
}

// VerifyServedAbsent is the served_list step's text when the position is
// marked absent.
func VerifyServedAbsent(n, index uint32) string {
	return fmt.Sprintf("The served list has %s, and position %d is marked absent.", positions(n), index)
}

// VerifyServedOtherEntry is the served_list step's text when the position
// holds a different entry.
func VerifyServedOtherEntry(n, index uint32) string {
	return fmt.Sprintf("The served list has %s, and position %d holds a different entry.", positions(n), index)
}

// VerifyServedOtherHash is the served_list step's text when the position holds
// a hash other than the entry's hash.
func VerifyServedOtherHash(n, index uint32) string {
	return fmt.Sprintf("The served list has %s, and position %d holds a hash other than this entry's hash.", positions(n), index)
}

// VerifyServedMalformed is the served_list step's text when the served bytes
// fail the tweak list's reader rules.
const VerifyServedMalformed = "The served bytes do not decode as a tweak list."

// VerifyServedWrongSize is the served_list step's text when the list's length
// differs from the record's n.
func VerifyServedWrongSize(got, n uint32) string {
	return fmt.Sprintf("The served list has %s, but the record signs for %d.", positions(got), n)
}

// VerifyServedEntry is the served_list step's text when the position carries
// the entry itself.
func VerifyServedEntry(index uint32) string {
	return fmt.Sprintf("Position %d of the served list carries the entry.", index)
}

// VerifyServedEntryHash is the served_list step's text when the position
// carries the entry's correct hash.
func VerifyServedEntryHash(index uint32) string {
	return fmt.Sprintf("Position %d of the served list carries the entry's hash.", index)
}

func depthWords(depth int64) string {
	return fmt.Sprintf("%d %s", depth, plural(int(depth), "block", "blocks"))
}

// VerifyWindowInside is the window step's text when the block sat inside the
// retention window. window is the protocol's window, passed in so this table
// holds no second copy of it.
func VerifyWindowInside(tip uint32, depth int64, window int) string {
	return fmt.Sprintf("The server's signed tip was %d, so the block was %s deep, inside the %d-block window.", tip, depthWords(depth), window)
}

// VerifyWindowAboveTip is the window step's text when the server signed a tip
// below the block. That counts as inside, so a server cannot escape the rule
// by understating its tip.
func VerifyWindowAboveTip(tip uint32, window int) string {
	return fmt.Sprintf("The server's signed tip was %d, below the block, which counts as inside the %d-block window.", tip, window)
}

// VerifyWindowOutside is the window step's text when the block sat outside the
// retention window, where an absent position is allowed.
func VerifyWindowOutside(tip uint32, depth int64, window int) string {
	return fmt.Sprintf("The server's signed tip was %d, so the block was %s deep, outside the %d-block window, where an absent position is allowed.",
		tip, depthWords(depth), window)
}

// VerifyWindowNotNeeded is the window step's text when the position holds
// different data. That is never allowed at a committed position, at any depth.
func VerifyWindowNotNeeded(index uint32) string {
	return fmt.Sprintf("Position %d holds different data, which is never allowed at a committed position, so depth does not matter.", index)
}

// Command-line wording. canary check, verify, status and ui print every line
// from here. A Go error's own text appears only after CLIDetails, the way the
// dashboard keeps it behind "Technical details".

// CLIUsage is what canary help prints.
const CLIUsage = `Usage: canary <command> [flags]

Canary holds tweak servers to what they signed. It does not remove the need to trust one.

Commands:
  check    Check a range of blocks against each server, then write the state file and evidence files.
  verify   Check one evidence file offline.
  status   Print a summary of the state file.
  ui       Serve the dashboard for the state file on this computer.

Run canary <command> --help for a command's flags.`

// CLIHelpHint follows a top-level usage error.
const CLIHelpHint = "Run canary help for the commands."

// CLINoCommand is the usage error for a bare canary.
const CLINoCommand = "Give a command: check, verify, status or ui."

// CLIUnknownCommand is the usage error for a command canary does not have.
func CLIUnknownCommand(name string) string {
	return "There is no command " + strconv.Quote(name) + ". The commands are check, verify, status and ui."
}

// CLICommandHelpHint follows a usage error in one command.
func CLICommandHelpHint(command string) string {
	return "Run canary " + command + " --help for the flags."
}

// CLIFlagError wraps the flag parser's own message.
func CLIFlagError(detail string) string {
	return "Can't read the flags: " + strings.TrimSuffix(detail, ".") + "."
}

// CLIUnexpectedArgument is the usage error for a stray argument.
func CLIUnexpectedArgument(arg string) string {
	return "Unexpected argument " + strconv.Quote(arg) + "."
}

// CLIDetails introduces a Go error's own text under a plain sentence.
func CLIDetails(detail string) string {
	return "  Details: " + detail
}

// VersionLine is what canary --version prints.
func VersionLine(version, build string) string {
	return "canary " + version + " (" + build + ")"
}

// CLIFlagsHeading heads the flag list in a command's help.
const CLIFlagsHeading = "Flags:"

// FlagHelp is one flag in a command's usage text.
type FlagHelp struct {
	Name string // without dashes
	Arg  string // the value's placeholder, empty for a switch
	Text string
}

// Usage lines, one per command.
const (
	CheckUsage  = "Usage: canary check --indexer URL=label --pubkey label=HEX --core-rest URL [flags]"
	VerifyUsage = "Usage: canary verify FILE [--json]"
	StatusUsage = "Usage: canary status [--json] [--state PATH]"
	UIUsage     = "Usage: canary ui [--addr 127.0.0.1:7352] [--state PATH]"
)

// Flags for each command, in the order the formats doc lists them.
var (
	CheckFlags = []FlagHelp{
		{"indexer", "URL=label", "A server to check. Repeat it for each server. A label is up to 32 lowercase letters, digits and -."},
		{"pubkey", "label=HEX", "Pins a server's 32-byte public key, one per server. Give label=none for a server that signs nothing. Canary never learns a key from a server."},
		{"core-rest", "URL", "Bitcoin Core's REST address, for example http://127.0.0.1:18443/rest. Core must run with -rest=1."},
		{"from", "H", "First height to check. Default 0."},
		{"to", "H", "Last height to check. Default Core's tip."},
		{"expect", "TXID[@BLOCKHASH]", "A payment you made and expect each server to report, in display order. Repeatable. A bare TXID needs Core's -txindex=1."},
		{"state", "PATH", "State file. Default ~/.canary/state.json."},
		{"evidence-dir", "DIR", "Where evidence files go. Default ~/.canary/evidence."},
	}
	VerifyFlags = []FlagHelp{
		{"json", "", "Print the VerifyReport as JSON."},
	}
	StatusFlags = []FlagHelp{
		{"json", "", "Print the state file itself."},
		{"state", "PATH", "State file. Default ~/.canary/state.json."},
	}
	UIFlags = []FlagHelp{
		{"addr", "HOST:PORT", "Listen address. It must be a loopback address. Default 127.0.0.1:7352."},
		{"state", "PATH", "State file to read. Default ~/.canary/state.json."},
	}
)

// Usage errors from canary check.
const (
	CheckNoIndexer = "Give at least one server with --indexer URL=label."
	CheckNoCore    = "Give Bitcoin Core's REST address with --core-rest, for example http://127.0.0.1:18443/rest."
)

// CheckBadIndexer is the usage error for an --indexer value that is not
// URL=label.
func CheckBadIndexer(v string) string {
	return "--indexer " + strconv.Quote(v) + " is not URL=label with an http or https URL."
}

// CheckBadLabel is the usage error for a label outside the allowed set.
func CheckBadLabel(label string) string {
	return "Label " + strconv.Quote(label) + " must be 1 to 32 lowercase letters, digits or -."
}

// CheckDuplicateLabel is the usage error for two servers with one label.
func CheckDuplicateLabel(label string) string {
	return "Label " + label + " names two servers. Each --indexer needs its own label."
}

// CheckBadPubkeyFlag is the usage error for a --pubkey value that is not
// label=HEX.
func CheckBadPubkeyFlag(v string) string {
	return "--pubkey " + strconv.Quote(v) + " is not label=HEX or label=none."
}

// CheckBadPubkey is the usage error for a pin that is not a public key.
func CheckBadPubkey(label string) string {
	return "The --pubkey for " + label + " is not a 32-byte public key written as 64 lowercase hex characters."
}

// CheckPubkeyUnknownLabel is the usage error for a pin no server uses.
func CheckPubkeyUnknownLabel(label string) string {
	return "--pubkey names " + label + ", but no --indexer has that label."
}

// CheckDuplicatePubkey is the usage error for a server pinned twice.
func CheckDuplicatePubkey(label string) string {
	return "Server " + label + " has two --pubkey pins. Give it one."
}

// CheckMissingPin is the usage error for a server with no pinned key.
func CheckMissingPin(label string) string {
	return "Server " + label + " has no pinned key. Add --pubkey " + label + "=HEX, or " + label +
		"=none for a server that signs nothing. Canary never learns a key from a server."
}

// CheckBadCore is the usage error for a --core-rest value that is not a URL.
func CheckBadCore(v string) string {
	return "--core-rest " + strconv.Quote(v) + " is not a URL like http://127.0.0.1:18443/rest."
}

// CheckBadHeight is the usage error for a --from or --to that is not a
// height.
func CheckBadHeight(flag, v string) string {
	return flag + " " + strconv.Quote(v) + " is not a block height. Give a whole number."
}

// CheckRangeBackwards is the usage error for --from above --to.
func CheckRangeBackwards(from, to uint32) string {
	return fmt.Sprintf("--from %d is above --to %d.", from, to)
}

// CheckRangeAboveTip is the usage error for a --to above Core's tip.
func CheckRangeAboveTip(to, tip uint32) string {
	return fmt.Sprintf("--to %d is above Bitcoin Core's tip at height %d.", to, tip)
}

// CheckBadExpect is the usage error for an --expect value that does not
// parse.
func CheckBadExpect(v string) string {
	return "--expect " + strconv.Quote(v) + " is not TXID or TXID@BLOCKHASH, each 64 lowercase hex characters in display order."
}

// CheckDuplicateExpect is the usage error for a payment declared twice.
func CheckDuplicateExpect(txid string) string {
	return "--expect " + txid + " is given twice."
}

// CheckExpectNotInBlock is the usage error for a declared payment that is not
// in the block named.
func CheckExpectNotInBlock(txid, block string) string {
	return "Transaction " + txid + " is not in block " + block + "."
}

// CheckExpectBlockUnknown is the usage error for an --expect block that Core
// does not have.
func CheckExpectBlockUnknown(block string) string {
	return "Bitcoin Core has no block " + block + "."
}

// CheckExpectNotChecked is the usage error for a declared payment whose
// block is not among the blocks this run checks: it is outside the range, or
// it left Core's active chain.
func CheckExpectNotChecked(txid, block string, from, to uint32) string {
	return fmt.Sprintf("Payment %s is in block %s, which this run does not check. "+
		"The run checks heights %d–%d on Bitcoin Core's active chain.", txid, block, from, to)
}

// CheckExpectNotFound is the error for a bare --expect TXID that Core cannot
// find. It names both fixes.
func CheckExpectNotFound(txid string) string {
	return "Bitcoin Core can't find transaction " + txid + ". Run Core with -txindex=1, or name the block with --expect " +
		txid + "@BLOCKHASH."
}

// CheckPaymentEntry is the error when Canary cannot compute a declared
// payment's entry from Core's copy of its block.
func CheckPaymentEntry(txid string) string {
	return "Can't compute the entry for payment " + txid + " from Bitcoin Core's copy of its block."
}

// CheckNoHome is the usage error when the default path needs a home
// directory Canary cannot find.
func CheckNoHome(what string) string {
	return "Can't find your home directory for the default " + what + ". Give the path with its flag."
}

// Refusals to overwrite the state file, exit code 3.

// CheckStateUnreadable refuses a state file Canary cannot read.
func CheckStateUnreadable(path string) string {
	return "Won't overwrite the state file at " + path + ": Canary can't read it, and it may hold findings. " +
		"Move it aside, or give another --state path."
}

// CheckStateNewer refuses a state file from a later Canary.
func CheckStateNewer(path, found string) string {
	return "Won't overwrite the state file at " + path + ": it is " + found + ", newer than this Canary reads. " +
		"Update Canary, or give another --state path."
}

// CheckStateOtherNetwork refuses a state file for another network.
func CheckStateOtherNetwork(path, fileNetwork, coreNetwork string) string {
	return "Won't overwrite the state file at " + path + ": it holds results for " + fileNetwork +
		", and Bitcoin Core is on " + coreNetwork + ". Use a separate --state path for each network."
}

// Operational failures, exit code 5.

// CheckCoreUnreachable is the error when Core's REST interface does not
// answer.
func CheckCoreUnreachable(url string) string {
	return "Can't read Bitcoin Core's REST interface at " + url + ". Check that Core is running with -rest=1."
}

// CheckCoreSyncing is the error while Core is in its initial sync.
const CheckCoreSyncing = "Bitcoin Core is still in its initial sync, so honest tips would look false. " +
	"Run canary check again when the sync finishes."

// CheckCoreChain is the error for a chain canary check cannot name. Every
// signet reports the name "signet", and a custom signet's network magic comes
// from its challenge, so the name cannot say which magic to check against.
func CheckCoreChain(chain string) string {
	msg := "Bitcoin Core reports chain " + strconv.Quote(chain) + ". canary check v1 runs on regtest and main only."
	if chain == "signet" {
		msg += " Every signet reports that same name, so Canary can't tell which signet Core is on." +
			" Signet needs a flag that names the network, which is planned after v1."
	}
	return msg
}

// CheckServerUnusable is the error for a server that proves nothing in the
// run: an answer outside the v1 API, no canary-info/1 /info, and no record
// that verified under its pin. That is usually a wrong --indexer URL, and
// sometimes a wrong pin.
func CheckServerUnusable(label, url string) string {
	return "Server " + label + " at " + url + " answered in a way Canary can't use, " +
		"and none of its records verified under its pin. Check its --indexer URL and --pubkey."
}

// CheckServerUnusablePinnedNone is CheckServerUnusable for a server pinned as
// none. Canary asks such a server for no record, so only its /info could show
// that the URL reaches a v1 server, and it did not.
func CheckServerUnusablePinnedNone(label, url string) string {
	return "Server " + label + " at " + url + " did not answer /info as canary-info/1. " +
		"It is pinned as none, so nothing else shows that the URL reaches a v1 server. Check its --indexer URL."
}

// CheckWriteState is the error when the state file cannot be written.
func CheckWriteState(path string) string {
	return "Can't write the state file at " + path + "."
}

// CheckInterrupted is the error when the run is interrupted, as by Ctrl-C.
// A cut-off request says nothing about a server, so nothing is saved.
const CheckInterrupted = "Stopped before the run finished, so the state file was not changed. " +
	"Evidence files written so far stay on disk."

// CheckWriteEvidence is the error when an evidence file cannot be written.
func CheckWriteEvidence(path string) string {
	return "Can't write the evidence file " + path + "."
}

// Progress and notices from canary check.

// CheckStarting opens a run.
func CheckStarting(from, to uint32, servers int) string {
	return fmt.Sprintf("Checking blocks %d–%d against %s.", from, to, plural(servers, "1 server", strconv.Itoa(servers)+" servers"))
}

// CheckDroppedFinding reports a finding dropped because Core no longer knows
// its block.
func CheckDroppedFinding(id, blockHash string) string {
	return "Dropped finding " + id + ": Bitcoin Core no longer knows block " + blockHash + ". Its evidence file stays on disk."
}

// CheckSaved closes a run.
func CheckSaved(path string) string {
	return "Results saved to " + path + "."
}

// A server's last error, as the state file records it. Each is a plain
// sentence. The Go error's own text goes to the terminal after
// CheckServerLastError and CLIDetails, never into the state file.

// ServerInfoFailed is a server's error when /info did not answer, or
// answered internal or not_ready. The run goes on. The state file then has no
// policy for the server, and the dashboard shows it as PolicyUnknown.
const ServerInfoFailed = "Its /info did not answer, so its policy is unknown."

// ServerInfoUnusable is a server's error when /info answered with something
// other than canary-info/1. The run goes on only when one of the server's
// records verified under its pin. The state file then has no policy for the
// server, and the dashboard shows it as PolicyUnknown.
const ServerInfoUnusable = "Its /info did not answer as canary-info/1, so its policy is unknown."

// ServerRecordUnanswered is a server's error when a record request failed.
func ServerRecordUnanswered(height uint32) string {
	return fmt.Sprintf("It did not answer for block %d's record.", height)
}

// ServerRecordRefused is a server's error when it answered a record request
// with an error outside the v1 API, and the run went on. Canary records the
// block like an outage.
func ServerRecordRefused(height uint32) string {
	return fmt.Sprintf("It answered the request for block %d's record with an error a v1 server never gives Canary.", height)
}

// ServerRecordRejected is a server's error when a record failed the checks.
func ServerRecordRejected(height uint32) string {
	return fmt.Sprintf("Its record for block %d failed Canary's checks.", height)
}

// ServerRecordTooLarge is a server's error when its record verified under its
// pin but claims more entries than the block can hold. BIP-352 gives at most
// one entry per transaction and none for the coinbase. txs is the block's
// transaction count, coinbase included, as Core reports it.
func ServerRecordTooLarge(height, n uint32, txs int) string {
	entries := plural(int(n), "1 entry", strconv.FormatUint(uint64(n), 10)+" entries")
	others := "only " + plural(txs-1, "1 transaction", strconv.Itoa(txs-1)+" transactions")
	if txs <= 1 {
		others = "no transactions"
	}
	return fmt.Sprintf("Its record for block %d claims %s, but the block has %s besides the coinbase. "+
		"Canary counts it as no record.", height, entries, others)
}

// ServerListUnanswered is a server's error when a list request failed.
func ServerListUnanswered(height uint32) string {
	return fmt.Sprintf("It served no list for block %d.", height)
}

// ServerNotAsked is a server's error when canary check stopped sending it
// requests. The blocks it was not asked about read Not checked.
func ServerNotAsked(streak int) string {
	return fmt.Sprintf("Canary stopped asking it after %d requests in a row got no answer.", streak)
}

// ServerReceiptRejected is a server's error when a receipt failed the checks.
func ServerReceiptRejected(height uint32) string {
	return fmt.Sprintf("The receipt for block %d's list failed Canary's checks.", height)
}

// ServerListRejected is a server's error when a list could not be matched to
// its record.
func ServerListRejected(height uint32) string {
	return fmt.Sprintf("Its list for block %d does not match its record.", height)
}

// CheckServerLastError introduces a server's last error on the terminal,
// where CLIDetails follows it with the Go error's own text.
func CheckServerLastError(label, sentence string) string {
	return "Last error from " + label + ": " + sentence
}

// CheckServerInfoError introduces a server's /info error on the terminal,
// when a later error replaced it as the server's last error. It comes before
// CheckServerLastError, so the reader still learns the policy is unknown.
func CheckServerInfoError(label, sentence string) string {
	return "Error from " + label + ": " + sentence
}

// canary status failures, exit code 3.

// StatusMissing is the error when there is no state file.
func StatusMissing(path string) string {
	return "No state file at " + path + ". Run canary check first."
}

// StatusUnreadable is the error for a state file Canary cannot read.
func StatusUnreadable(path string) string {
	return "Can't read the state file at " + path + ". It is not a canary-state/1 file this Canary can read."
}

// StatusNewer is the error for a state file from a later Canary.
func StatusNewer(path, found string) string {
	return "The state file at " + path + " is " + found + ", newer than this Canary reads. Update Canary to read it."
}

// Reasons canary verify gives after "Can't read this file:".
const (
	VerifyReasonMissing     = "there is no file at this path"
	VerifyReasonNotOpened   = "the system would not let Canary open it"
	VerifyReasonMalformed   = "it is not valid canary-evidence/1"
	VerifyReasonUnsupported = "it is not canary-evidence/1 with the omission claim"
)

// VerifyNoFile is the usage error for canary verify with no file.
const VerifyNoFile = "Give one evidence file to check."

// VerifyReasonTooLarge is the reason for a file over canary verify's size
// limit.
func VerifyReasonTooLarge(limit int) string {
	return fmt.Sprintf("it is larger than %d MiB, far more than any block's evidence", limit>>20)
}

// VerifyChecksOutDetail follows the Checks out headline.
const VerifyChecksOutDetail = "The server signed a record that includes this entry, then signed a list that left it out."

// VerifySubject names what a file that checks out is about. key and txid are
// shortened hex.
func VerifySubject(key string, height uint32, network string, index uint32, txid string) string {
	return fmt.Sprintf("Accused key %s. Block %d on %s, position %d, txid %s.", key, height, network, index, txid)
}

// VerifyCheckLine prints one verify step. ok is nil when the step did not
// run; its text then already says so.
func VerifyCheckLine(ok *bool, step, text string) string {
	label := "  " + VerifyStep(step) + ": "
	switch {
	case ok == nil:
		return label + text
	case *ok:
		return label + StepPassed + ". " + text
	}
	return label + StepFailed + ". " + text
}

// canary ui lines.

// UIServing tells the user where the dashboard is.
func UIServing(url string) string {
	return "Serving the dashboard at " + url + ". Press Ctrl-C to stop."
}

// UINotLoopback is the usage error for a listen address off this computer.
func UINotLoopback(addr string) string {
	return "--addr " + addr + " is not a loopback address. canary ui serves this computer only, for example on 127.0.0.1:7352."
}

// UIBadAddr is the usage error for a listen address that is not host:port.
func UIBadAddr(addr string) string {
	return "--addr " + strconv.Quote(addr) + " is not HOST:PORT, for example 127.0.0.1:7352."
}

// UICantListen is the error when the listen address cannot be bound.
func UICantListen(addr string) string {
	return "Can't listen on " + addr + "."
}

// Public site wording. cmd/site renders the public site from these, with the
// same partials as the dashboard, so the two speak with one voice.

// SitePage is the title and description one site page carries in its head,
// for the browser tab, search results and link previews.
type SitePage struct {
	Title       string
	Description string
}

// SiteItem is one labelled line: a claim and its limit, or a kind of proof
// and what it covers.
type SiteItem struct {
	Label string
	Text  string
}

// SiteText holds every word the public site shows, apart from the pages it
// renders from the docs.
type SiteText struct {
	Home, HowItWorks, FAQ, Glossary, Runs, NotFound SitePage

	// Header and footer.
	NavLabel, NavHowItWorks, NavFAQ, NavGlossary, NavRuns string
	SkipLink                                              string
	FooterSource, FooterLicense, FooterNoRequests         string

	// The home page opens with the claim, the problem in one line, and the
	// conditions the claim needs.
	Claim, Lede, Conditions string

	// The evidence checker. Its script fills the result area.
	// CheckerInBrowser and CheckerPrivacy describe that script, so the page
	// renders them hidden and the script reveals them when it runs.
	// CheckerPending shows only when the site was built without the checker
	// module. With the module, CheckerWaiting holds the pending line until
	// the script mounts, so it must stay true if the script never runs. The
	// Example variants replace their namesakes when the sample is
	// the formats document's example, not a file from the recorded run.
	CheckerTitle, CheckerIntro, CheckerInBrowser     string
	CheckerChoose, CheckerTryReal, CheckerTryExample string
	CheckerTryTampered, CheckerSourceExample         string
	CheckerPending, CheckerNoScript, CheckerWaiting  string
	CheckerDownloadReal, CheckerDownloadExample      string
	CheckerDownloadTampered                          string
	CheckerStepsIntro, CheckerPrivacy                string

	ProblemTitle string
	Problem      []string
	Quote        string

	HowTitle, HowIntro string
	HowSteps           []string
	StatesIntro        string
	HowLink            string
	LowerBound         string

	ProvesTitle, ProvesIntro string
	Proves                   []SiteItem

	LimitsTitle, LimitsIntro        string
	LimitsClaimHead, LimitsStopHead string
	Limits                          []SiteItem
	LimitsLink                      string

	RunTitle, RunIntro, RunNeeds, RunAfter       string
	RunIntroNoEvidence, RunAfterNoEvidence       string
	RunFilePlaceholder, RunPlaceholderNote       string
	RunCloneLabel, RunBuildLabel, RunVerifyLabel string

	// The runs index. RunsEmpty, RunsAboutEmpty and RunsAction show only
	// while no run is recorded.
	RunsEmpty, RunsAboutEmpty, RunsAction string
	RunsAbout, RunsOpen, RunsStateHash    string

	// A recorded run's pages. Each one shows the dashboard as canary ui
	// showed it, under a banner that says it is a recording.
	RecordedFilesLink, RecordedSource, RecordedCrumbs  string
	RecordedFilesTitle, RecordedFetched, RecordedClone string
	RecordedRendered                                   string
	RecordedFileHead, RecordedAboutHead                string
	RecordedSizeHead, RecordedHashHead                 string
	RecordedHashLabel, RecordedNoAccusation            string
	CheckerSeeRun                                      string

	NotFoundBody, NotFoundHome string

	OnThisPage, DocSource string

	// DocTable names a table in a page built from the docs. See TableLabel.
	DocTable string

	Diagram SiteDiagramText
}

// SiteDiagramText is the site's own wording in its drawings of the docs'
// diagrams. The labels a drawing shares with its Mermaid source stay in the
// drawing, where a test holds them to the docs.
type SiteDiagramText struct {
	// The parts, and what flows between them.
	ToEachIndexer, CoreAlsoSends, Writes, FilesGoTo, PassesOn, Publishes string

	// The checks, and where each answer leads.
	IfNo, IfYes, IfNoOmission, IfNoNoOmission, GoOn, Or string
}

// Site is the public site's wording.
var Site = SiteText{
	Home: SitePage{
		Title:       "Canary: hold tweak servers to what they signed",
		Description: "Canary checks a silent-payments server's tweak list against the record the same server signed, and names the server when they differ.",
	},
	HowItWorks: SitePage{
		Title:       "How Canary works",
		Description: "What a tweak server signs and serves, the checks Canary runs on one block, a worked example, the six states and the limits.",
	},
	FAQ: SitePage{
		Title:       "Questions and answers",
		Description: "Plain answers to the questions reviewers ask about Canary: prior art, collusion, proof, and what version 1 does not cover.",
	},
	Glossary: SitePage{
		Title:       "Glossary",
		Description: "Every term Canary's docs and screens use, from canonical set to tweak list, with the name the design uses for it.",
	},
	Runs: SitePage{
		Title:       "Recorded runs",
		Description: "Real runs of canary check on regtest, each shown as the dashboard stood after the run, with the SHA-256 of every file.",
	},
	NotFound: SitePage{
		Title:       "Page not found",
		Description: "This site has no page at this address.",
	},

	NavLabel:         "Main",
	NavHowItWorks:    "How it works",
	NavFAQ:           "FAQ",
	NavGlossary:      "Glossary",
	NavRuns:          "Recorded runs",
	SkipLink:         "Skip to content",
	FooterSource:     "Source code",
	FooterLicense:    "MIT License",
	FooterNoRequests: "This site makes no outside requests.",

	Claim: "Canary names the silent-payments server that leaves out an entry it signed for.",
	Lede: "A light wallet can't tell \"nobody paid you\" from \"the server left your payment out.\" " +
		"Canary checks the tweak list a server sends against the record the same server signed for that block. " +
		"When they differ, it names the server and the block.",
	Conditions: "It makes a server accountable. It does not remove the need to trust one. " +
		"The claim needs at least one honest server that publishes signed records, and a path to those records that nobody censors. " +
		"Version 1 is built and tested on regtest only.",

	CheckerTitle: "Check an evidence file",
	CheckerIntro: "An evidence file holds a server's signed record, the exact bytes it served and its signature over them. " +
		"canary verify checks it with no network, and trusts nothing the file says about itself.",
	CheckerInBrowser:     "This page runs the same check in your browser.",
	CheckerChoose:        "Choose an evidence file",
	CheckerTryReal:       "Try the real evidence file",
	CheckerTryExample:    "Try the example file",
	CheckerTryTampered:   "Try a tampered copy",
	CheckerSourceExample: "The sample is an example file from the formats document, not from a recorded run.",
	CheckerPending: "This build of the site has no checker, so this page can't check files. " +
		"Download a file and run canary verify on it in a terminal.",
	CheckerNoScript:         "Without JavaScript, download a file and run canary verify on it in a terminal.",
	CheckerWaiting:          "The checker needs JavaScript. Until it starts, download a file and run canary verify on it in a terminal.",
	CheckerDownloadReal:     "Download the real file",
	CheckerDownloadExample:  "Download the example file",
	CheckerDownloadTampered: "Download the tampered copy",
	CheckerStepsIntro:       "The check runs these eight steps in order, and stops at the first that fails.",
	CheckerPrivacy:          "The file stays in your browser.",

	ProblemTitle: "The problem",
	Problem: []string{
		"A silent-payments light wallet asks a server for the tweaks it scans with, because it lacks the data to compute them. " +
			"If the server leaves out the tweak for your payment, the wallet shows the balance it would show if nobody had paid you. There is no error.",
		"A server can't tell which transactions pay you without your scan key. So hiding one payment takes outside knowledge of it, and the sender always has that knowledge.",
	},
	Quote: "The exchange that pays you can also run the server that tells you whether you were paid.",

	HowTitle: "How it works",
	HowIntro: "Honest servers filter differently, so comparing what two servers send raises false alarms. " +
		"Canary asks each server to sign for the complete list, then lets it serve less.",
	HowSteps: []string{
		"When a server indexes a block, it signs a record: the entry count and a Merkle root over every eligible transaction.",
		"It serves a tweak list with exactly that many positions. Each carries the entry, its hash or nothing, and a receipt signs the exact bytes.",
		"Canary fills every gap it can from another server or a payment you declared. Only then does it recompute the root and compare it with the signed one.",
		"An entry sent as nothing while the block is less than 144 blocks deep is an omission. " +
			"Canary names the server and, when it can recover the entry, writes an evidence file.",
	},
	StatesIntro: "Every block ends in one of six states, shown as a symbol, a word and a colour together.",
	HowLink:     "Follow one block through every check",
	LowerBound:  "A balance computed over blocks you could not check is a lower bound, not a balance.",

	ProvesTitle: "What it proves, and what it does not",
	ProvesIntro: "Canary separates knowing from proving to others. You know whatever your own check saw. " +
		"Someone else can confirm a finding only from signed data they check themselves.",
	Proves: []SiteItem{
		{Label: "Others can check it", Text: "A server signed for an entry, then sent nothing for it inside the 144-block window and signed a receipt for what it sent. " +
			"canary verify checks the evidence file offline."},
		{Label: "Others see inclusion only", Text: "The same omission without a receipt. The file shows that the server signed for the entry, not what it sent."},
		{Label: "Only you know it", Text: "A false chain claim, a declared payment left out, or a list of the wrong length. Version 1 has no evidence format for these."},
		{Label: "Two servers, nobody accused", Text: "Servers disagree means two servers signed different roots for the same block. At least one is wrong, and Canary does not say which."},
		{Label: "No accusation", Text: "Can't be checked is neither a pass nor an accusation. A warning names a server that did something odd, and proves nothing."},
	},

	LimitsTitle:     "Limits of version 1",
	LimitsIntro:     "Each claim stops somewhere, and the limit belongs next to it.",
	LimitsClaimHead: "What Canary says",
	LimitsStopHead:  "Where it stops",
	Limits: []SiteItem{
		{Label: "A block reads Checked", Text: "Canary checked the tweak list, not the output data a wallet matches against. " +
			"A server can send the right tweak and hide the output, and the block still reads Checked. Output keys in the entry are planned for version 2."},
		{Label: "A server that serves less than it signed for gets named", Text: "Not when it sends the entry's hash under a declared pruning policy. The block then reads Checked, gap filled."},
		{Label: "Omission is detected", Text: "Only when you run canary check. Version 1 has no wallet in the loop, so nothing stops a wallet from using a block Canary flagged."},
		{Label: "Detection works", Text: "Version 1 is built and tested on regtest only, against its own reference indexer, which shares the checker's canonical package. No deployed server speaks this protocol yet."},
		{Label: "Several servers catch a lying one", Text: "If every server colludes, only a tripwire helps, and only for payments you know exist."},
		{Label: "Records are public", Text: "Version 1 fetches each server's records from that server over HTTP, and publishes them nowhere else yet."},
		{Label: "A lying server gets caught", Text: "Canary looks for entries left out, never for fake ones. Adding fake entries is a different attack."},
	},
	LimitsLink: "Every limit, with the reasoning",

	RunTitle: "Run it yourself",
	RunIntro: "Build Canary once with a network. Then turn the network off and check the evidence file in the repository. " +
		"canary verify opens no connection.",
	RunNeeds: "You need git and Go.",
	RunAfter: "For the real file, canary verify prints \"Checks out.\" For a tampered copy, it names the step that failed.",
	RunIntroNoEvidence: "Build Canary once with a network. Then turn the network off and check the example file from above, or one your own canary check wrote. " +
		"canary verify opens no connection.",
	RunAfterNoEvidence: "For a file that checks out, canary verify prints \"Checks out.\" For one that does not, it names the step that failed.",
	RunFilePlaceholder: "FILE",
	RunPlaceholderNote: "FILE stands for the path to an evidence file. The recorded run's file is not published yet.",
	RunCloneLabel:      "Copy the clone command",
	RunBuildLabel:      "Copy the build command",
	RunVerifyLabel:     "Copy the verify command",

	RunsEmpty: "No recorded run is published yet.",
	RunsAboutEmpty: "A recorded run is one real canary check on regtest, against two reference indexers, one of them told to withhold an entry. " +
		"Its page will show the results as they were, with the time of the run and the SHA-256 of its state file. It is a recording, not a live view.",
	RunsAction: "Until then, run it yourself",
	RunsAbout: "Each run here is one real canary check against Bitcoin Core on regtest, with reference indexers we ran ourselves. " +
		"Its pages show the dashboard as it stood after the run, rendered from the state files the run wrote. They are a recording, not a live view.",
	RunsOpen:      "Open the recording",
	RunsStateHash: "State file SHA-256",

	RecordedFilesLink:  "Files and hashes",
	RecordedSource:     "Rendered from",
	RecordedCrumbs:     "Where this page sits",
	RecordedFilesTitle: "This recording",
	RecordedRendered:   "These pages render the state files it wrote, with the dashboard's own templates and words.",
	RecordedFetched: "canary check fetched each server's signed records from that server over HTTP. " +
		"This run published them nowhere else.",
	RecordedClone:        "The same files are in the repository. In a clone, this command prints the SHA-256 of each state file:",
	RecordedFileHead:     "File",
	RecordedAboutHead:    "What it holds",
	RecordedSizeHead:     "Bytes",
	RecordedHashHead:     "SHA-256",
	RecordedHashLabel:    "Copy the command that hashes the state files",
	RecordedNoAccusation: "Can't be checked is neither a pass nor an accusation.",
	CheckerSeeRun:        "See the recorded run",

	NotFoundBody: "This site has no page at this address. The link may be old, or mistyped.",
	NotFoundHome: "Go to the home page",

	OnThisPage: "On this page",
	DocSource:  "This page is built from a file in the repository",

	DocTable: "Table",

	Diagram: SiteDiagramText{
		ToEachIndexer:  "to each indexer",
		CoreAlsoSends:  "Bitcoin Core also sends it",
		Writes:         "writes",
		FilesGoTo:      "the state file to the first, an evidence file to the second",
		PassesOn:       "passes them on",
		Publishes:      "publishes its signed records",
		IfNo:           "If no",
		IfYes:          "If yes",
		IfNoOmission:   "If no, with an omission noted",
		IfNoNoOmission: "If no, with no omission noted",
		GoOn:           "Either way, go on.",
		Or:             "or",
	},
}

// TableLabel names a doc table for screen readers, after the heading above
// it when there is one.
func (s SiteText) TableLabel(heading string) string {
	if heading == "" {
		return s.DocTable
	}
	return s.DocTable + ": " + heading
}

// TamperNote says exactly which byte the tampered copy changes, and which
// verify step that byte breaks. offset counts from 1, the way cmp reports a
// difference. field names the JSON value that holds the byte, and step is the
// step name the evidence package reports.
func (s SiteText) TamperNote(offset int, field, from, to, step string) string {
	return fmt.Sprintf("The tampered copy changes one byte of the original. Byte %d, inside %s, reads %q where the original has %q. "+
		"That one change makes the %s step fail.", offset, field, to, from, VerifyStep(step))
}

// CheckerSourceRun says where a sample from a recorded run comes from: the
// network, the day of the run, and the Bitcoin Core release it ran against,
// when the run's output names one.
func (s SiteText) CheckerSourceRun(network, date, core string) string {
	out := "The sample comes from our recorded " + network + " run on " + date
	if core != "" {
		out += ", against Bitcoin Core " + core
	}
	return out + "."
}

// RecordedBanner is the notice at the top of every recorded page. It can't
// be dismissed, so no page of a recording reads as live.
func (s SiteText) RecordedBanner(network, date string) (lead, body string) {
	return "Recorded run, not live.", "The dashboard as it stood after our " + network + " run on " + date + "."
}

// RecordedRunTitle names one recorded run.
func (s SiteText) RecordedRunTitle(date string) string { return "Run of " + date }

// RecordedTitle is a recorded page's title. part names a later check in the
// same run, such as "Act 5", or is empty.
func (s SiteText) RecordedTitle(page, date, part string) string {
	t := "Recorded: " + page + " · " + s.RecordedRunTitle(date)
	if part != "" {
		t += " · " + part
	}
	return t
}

// RecordedDescription describes a recorded page for search results and
// link previews.
func (s SiteText) RecordedDescription(network, date, counts string) string {
	return "Canary's dashboard as it stood after our " + network + " run on " + date + ": " + counts + "."
}

// RecordedRanWith says how a run was made. script is the command that made
// it, and core the Bitcoin Core release; either is empty when the run's
// output does not show it.
func (s SiteText) RecordedRanWith(script, network, date, core string) string {
	out := "We ran "
	if script != "" {
		out += script + " "
	}
	out += "on " + date
	if core != "" {
		out += ", against Bitcoin Core " + core + " on " + network
	} else {
		out += ", on " + network
	}
	return out + "."
}

// recordedFiles says what each file a run writes holds, by its name.
var recordedFiles = map[string]string{
	"state.json":              "The state file canary check wrote. These pages render it.",
	"check.txt":               "What canary check printed.",
	"verify.txt":              "What canary verify printed for the evidence file. It opens no connection.",
	"status.txt":              "What canary status printed.",
	"run.txt":                 "The network, transactions, servers and public keys of the run.",
	"demo-regtest-output.txt": "Everything the demo script printed, step by step.",
}

// RecordedFileAbout says what one file of a recorded run holds. name is the
// file's base name. It returns "" for a file it does not know.
func (s SiteText) RecordedFileAbout(name string) string {
	if about, ok := recordedFiles[name]; ok {
		return about
	}
	if server, ok := strings.CutSuffix(name, ".log"); ok {
		return "The log of the " + server + " indexer."
	}
	return ""
}

// RecordedEvidenceAbout says what the evidence file in a run's list holds.
func (s SiteText) RecordedEvidenceAbout(id string) string {
	return "The evidence file for finding " + id + ". Its page shows Canary's check of it."
}

// RecordedPartIntro says what a later check in the same run covered, such as
// act 5's single block.
func (s SiteText) RecordedPartIntro(label string, from, to uint32, servers []string) string {
	what := "block " + strconv.FormatUint(uint64(from), 10)
	if from != to {
		what = fmt.Sprintf("blocks %d to %d", from, to)
	}
	who := "only " + strings.Join(servers, "") + " pinned"
	if len(servers) != 1 {
		who = strconv.Itoa(len(servers)) + " servers pinned"
	}
	return label + " ran canary check again on " + what + " alone, with " + who + "."
}

// RecordedDepth says how deep one block sat below a server's signed tip.
func (s SiteText) RecordedDepth(server string, tip, height uint32) string {
	return fmt.Sprintf("Server %s's signed tip was %d, so block %d sat %d blocks deep.", server, tip, height, tip-height)
}

// RecordedOpenPart links a later check's own pages.
func (s SiteText) RecordedOpenPart(label string) string { return "Open " + label + "'s dashboard" }

// RecordedRange names what a run's check covered, on the runs index.
func (s SiteText) RecordedRange(label string, from, to uint32, servers int) string {
	r := fmt.Sprintf("Blocks %d to %d", from, to)
	if from == to {
		r = "Block " + strconv.FormatUint(uint64(from), 10)
	}
	if label != "" {
		r = label + ", " + strings.ToLower(r[:1]) + r[1:]
	}
	return r + ", " + strconv.Itoa(servers) + " " + plural(servers, "server", "servers")
}

// CheckerSourceRecorded says where a sample from the recorded run comes from.
// date is the day of the run.
func (s SiteText) CheckerSourceRecorded(date string) string {
	return "The sample comes from the recorded run on " + date + "."
}

// CheckerText is the browser checker's own words: the lines checker.js shows
// while it loads, runs and reports. cmd/site writes them into the page as one
// JSON block, keyed by these tags, and checker.js reads them from there.
// checker.js keeps the same words as fallbacks for a page with no block, and
// a test in internal/ui holds the two to each other.
//
// checker.js fills the slots in braces: {size}, {name}, {revision} and {go}.
type CheckerText struct {
	LoadingStart    string `json:"loadingStart"`
	Loading         string `json:"loading"`
	Starting        string `json:"starting"`
	Failed          string `json:"failed"`
	NoWasm          string `json:"noWasm"`
	Retry           string `json:"retry"`
	Choose          string `json:"choose"`
	Details         string `json:"details"`
	Command         string `json:"command"`
	Checking        string `json:"checking"`
	Internal        string `json:"internal"`
	Source          string `json:"source"`
	SourcePaste     string `json:"sourcePaste"`
	SourceDrop      string `json:"sourceDrop"`
	PasteOpen       string `json:"pasteOpen"`
	PasteLabel      string `json:"pasteLabel"`
	PasteButton     string `json:"pasteButton"`
	PasteEmpty      string `json:"pasteEmpty"`
	Build           string `json:"build"`
	BuildModified   string `json:"buildModified"`
	BuildNoRevision string `json:"buildNoRevision"`
	TooLarge        string `json:"tooLarge"`
	NotOpened       string `json:"notOpened"`
}

// Checker is the browser checker's wording. TooLarge and NotOpened are the
// lines canary verify prints. The module sends its own copies once it loads,
// with its own size limit, and those replace these.
var Checker = CheckerText{
	LoadingStart: "Loading the checker.",
	Loading:      "Loading the checker, a {size} download.",
	Starting:     "Starting the checker.",
	Failed: "The checker failed to load, so this page can't check files. " +
		"Try again, or download the file and run this in a terminal:",
	NoWasm: "This browser can't run WebAssembly, so the checker can't run in this page. " +
		"Download the file and run this in a terminal:",
	Retry:    "Try loading again",
	Choose:   Site.CheckerChoose,
	Details:  "Technical details",
	Command:  "canary verify " + Site.RunFilePlaceholder,
	Checking: "Checking the file in this browser.",
	Internal: "The checker stopped with an internal error and did not check this file. " +
		"Run this in a terminal instead:",
	Source:          "File: {name}",
	SourcePaste:     "Pasted text",
	SourceDrop:      "Dropped text",
	PasteOpen:       "Paste the file's text instead",
	PasteLabel:      "Text of an evidence file",
	PasteButton:     "Check the pasted text",
	PasteEmpty:      "Paste the text of an evidence file first.",
	Build:           "Built from commit {revision} with {go}.",
	BuildModified:   "Built from commit {revision} plus uncommitted changes, with {go}.",
	BuildNoRevision: "Built with {go}.",
	TooLarge:        VerifyCantRead(VerifyReasonTooLarge(16 << 20)),
	NotOpened:       VerifyCantRead(VerifyReasonNotOpened),
}

// CheckerBuildLine names the build of the checker module: its commit, cut to
// seven characters, and its Go release, such as "Go 1.26.4". It fills the
// same template checker.js fills from the module's own report.
func CheckerBuildLine(revision, goRelease string, modified bool) string {
	if len(revision) > 7 {
		revision = revision[:7]
	}
	line := Checker.Build
	switch {
	case revision == "":
		line = Checker.BuildNoRevision
	case modified:
		line = Checker.BuildModified
	}
	return strings.NewReplacer("{revision}", revision, "{go}", goRelease).Replace(line)
}
