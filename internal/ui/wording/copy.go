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
	"server_unreachable":  "The server did not answer, or said it was not ready.",

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

// FindingSentence returns the headline for a finding. servers holds the
// labels of the servers it names: one, or two for a disagreement.
func FindingSentence(kind, reason string, servers []string) string {
	s := serverName(servers, 0)
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
		return s + " and " + serverName(servers, 1) + " signed different records for the same block."
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
	return Verdict{
		Headline: "None of the " + blocks(total) + " could be checked.",
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
// sentence is FindingSentence for it.
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

// Framing is the one-line claim the dashboard footer carries.
const Framing = "Canary holds tweak servers to what they signed. It does not remove the need to trust one."

// RegtestBadge is the network notice shown on regtest.
const RegtestBadge = "regtest: a private test chain on this computer"

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
