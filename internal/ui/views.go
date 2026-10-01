package ui

import (
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// page is what every template receives.
type page struct {
	Title  string
	Nav    string
	Chrome chrome
	Main   any
}

// chrome is the header, footer and update-bar data every page shares.
type chrome struct {
	HasState      bool
	FindingsCount int
	NetworkBadge  string
	StatusLine    string
	Stale         *wording.Moment

	// The values the update bar compares against /state.etag.
	ETag     string
	Build    string
	Findings int

	UIVersion    string
	UIBuild      string
	ReleaseNotes string
	Framing      string
	Watermark    string
	Sprite       template.HTML
	Bar          barText
}

// barText carries the update bar's words to the page script, so the script
// holds no wording of its own.
type barText struct {
	NewResults, NewFinding, NewFindings, Updated, Lost, Back, Reload, Dismiss string
}

var updateBar = barText{
	NewResults:  wording.UpdateNewResults,
	NewFinding:  wording.UpdateNewFinding,
	NewFindings: wording.UpdateNewFindingsPattern,
	Updated:     wording.UpdateUpdated,
	Lost:        wording.UpdateLostPattern,
	Back:        wording.UpdateBack,
	Reload:      wording.UpdateReload,
	Dismiss:     wording.UpdateDismiss,
}

const timeLayout = wording.StatusTimeLayout

func (h *handler) page(r *http.Request, s snapshot, title, nav string) page {
	etag := s.etag
	if etag == "" {
		etag = state.ETag(nil, h.buildID)
	}
	c := chrome{
		ETag:         etag,
		Build:        h.buildID,
		UIVersion:    h.opts.Version,
		UIBuild:      h.opts.Build,
		ReleaseNotes: h.opts.ReleaseNotesURL,
		Framing:      wording.Framing,
		Watermark:    watermark,
		Sprite:       sprite,
		Bar:          updateBar,
	}
	if f := s.file; f != nil && s.err == nil {
		c.HasState = true
		c.FindingsCount = len(f.Findings)
		c.Findings = len(f.Findings)
		c.NetworkBadge = wording.NetworkBadge(f.Network.Name)
		gen := f.GeneratedAt.Time
		age := h.opts.Now().Sub(gen)
		c.StatusLine = wording.StatusLine(gen.In(h.opts.Location).Format(timeLayout), wording.Age(age),
			f.Checked.From, f.Checked.To, f.Network.Name, f.Canary.Version, f.Canary.Build)
		if age > h.opts.StaleAfter {
			m := wording.Stale(wording.Duration(age))
			c.Stale = &m
		}
	}
	return page{Title: title + " · Canary", Nav: nav, Chrome: c}
}

// errorView is the error panel: a title, what it means, what to do, and the
// raw error behind a disclosure.
type errorView struct {
	Moment       wording.Moment
	Tech         string
	Command      string
	CommandLabel string
	HomeLink     bool
	BackLink     string
	BackText     string
}

// copyData is what a copy button copies and its accessible name.
type copyData struct {
	Value string
	Label string
}

var funcs = template.FuncMap{
	"copyOf": func(value, label string) copyData { return copyData{Value: value, Label: label} },
	"themeLabel": func(mode string) string {
		switch mode {
		case "light":
			return wording.ThemeLight
		case "dark":
			return wording.ThemeDark
		}
		return wording.ThemeAuto
	},
}

// hashView renders a hex value in groups of four.
type hashView struct {
	Full      string
	Groups    []string
	Head      []string
	Tail      []string
	Short     bool
	CopyLabel string
}

func newHash(full, copyLabel string) hashView {
	v := hashView{Full: full, CopyLabel: copyLabel}
	for i := 0; i < len(full); i += 4 {
		v.Groups = append(v.Groups, full[i:min(i+4, len(full))])
	}
	if n := len(full); n > 16 {
		v.Short = true
		v.Head = []string{full[0:4], full[4:8]}
		v.Tail = []string{full[n-8 : n-4], full[n-4:]}
	}
	return v
}

func optHash(s *string, copyLabel string) *hashView {
	if s == nil {
		return nil
	}
	v := newHash(*s, copyLabel)
	return &v
}

type blockLink struct {
	Height uint32
	Hash   string
}

type countRow struct {
	State wording.StateText
	Count uint32
	Zero  bool
}

type findingRow struct {
	ID        string
	Kind      string
	KindLabel string
	// Glyph is the state glyph for the kind. It is empty for a warning,
	// which shows the info icon instead: a warning proves no problem.
	Glyph    string
	Sentence string
	Block    blockLink
	// BlockKnown is true when the results hold detail for the finding's
	// block, so it has a block page. A finding carried forward from an
	// earlier run can name a block outside them. Its height then shows as
	// plain text, followed by BlockNote.
	BlockKnown bool
	BlockNote  string
	Provable   string
	Evidence   string
	FirstSeen  string
	LastSeen   string
}

type serverRow struct {
	Label     string
	URL       string
	Pubkey    *hashView
	NoPubkey  string
	Records   string
	Receipts  string
	Reachable string
	Tip       string
	Policy    string
	Error     string
}

// A payment outcome or a verify result is not a block state, so it never
// wears a state's label or glyph. Its tone has its own glyphs, none of them
// one of the six state symbols: a tick for good, a cross for bad, a dash
// for neither.
type paymentRow struct {
	Txid        hashView
	Block       *blockLink
	Outcome     string
	OutcomeText string
	Glyph       string
	Tone        string
	Servers     []paymentServerRow
}

type paymentServerRow struct {
	Label   string
	Outcome string
	Text    string
	Glyph   string
	Tone    string
}

type overviewView struct {
	Verdict wording.Verdict
	// VerdictState is the state the verdict's badge shows, or nil when the
	// headline names no single state.
	VerdictState  *wording.StateText
	LowerBound    string
	Strip         stripView
	Counts        []countRow
	Findings      []findingRow
	MoreFindings  bool
	TotalFindings int
	NoFindings    string
	Servers       []serverRow
	ServersNote   string
	Payments      []paymentRow
	PaymentsNote  string
}

// overviewFindings is how many findings the overview lists before linking to
// the findings page.
const overviewFindings = 5

func fmtTime(t time.Time, loc *time.Location) string { return t.In(loc).Format(timeLayout) }

func kindOrder(kind string) int {
	switch kind {
	case state.KindWithheld:
		return 0
	case state.KindDisagree:
		return 1
	}
	return 2
}

func findingGlyph(kind string) string {
	switch kind {
	case state.KindWithheld:
		return string(state.Compromised)
	case state.KindDisagree:
		return string(state.Disputed)
	}
	return ""
}

func labels(refs []state.ServerRef) []string {
	out := make([]string, len(refs))
	for i, s := range refs {
		out[i] = s.Label
	}
	return out
}

// knownBlocks returns the hashes of the blocks the results hold detail for,
// the blocks that have a block page.
func knownBlocks(f *state.File) map[string]bool {
	out := make(map[string]bool, len(f.Blocks))
	for _, b := range f.Blocks {
		out[b.Hash] = true
	}
	return out
}

func newFindingRow(x state.Finding, loc *time.Location, known map[string]bool) findingRow {
	ev := ""
	if x.Evidence != nil {
		ev = *x.Evidence
	}
	row := findingRow{
		ID:         x.ID,
		Kind:       x.Kind,
		KindLabel:  wording.KindLabel(x.Kind),
		Glyph:      findingGlyph(x.Kind),
		Sentence:   wording.FindingHeadline(x.Kind, string(x.Reason), labels(x.Servers)),
		Block:      blockLink{Height: x.Block.Height, Hash: x.Block.Hash},
		BlockKnown: known[x.Block.Hash],
		Provable:   wording.ProvableShort(x.Kind, x.Provable, x.Evidence != nil),
		Evidence:   ev,
		FirstSeen:  fmtTime(x.FirstSeen.Time, loc),
		LastSeen:   fmtTime(x.LastSeen.Time, loc),
	}
	if !row.BlockKnown {
		row.BlockNote = wording.BlockNotCovered
	}
	return row
}

// sortedFindings lists withheld findings first, then disagreements, then
// warnings, and the highest block first within each kind.
func sortedFindings(f *state.File, loc *time.Location, keep func(state.Finding) bool) []findingRow {
	known := knownBlocks(f)
	var sel []state.Finding
	for _, x := range f.Findings {
		if keep == nil || keep(x) {
			sel = append(sel, x)
		}
	}
	sort.SliceStable(sel, func(i, j int) bool {
		a, b := sel[i], sel[j]
		if kindOrder(a.Kind) != kindOrder(b.Kind) {
			return kindOrder(a.Kind) < kindOrder(b.Kind)
		}
		return a.Block.Height > b.Block.Height
	})
	rows := make([]findingRow, len(sel))
	for i, x := range sel {
		rows[i] = newFindingRow(x, loc, known)
	}
	return rows
}

func buildCounts(c state.Counts) []countRow {
	rows := make([]countRow, len(state.States))
	for i, s := range state.States {
		n := c.Get(s)
		rows[i] = countRow{State: wording.State(string(s)), Count: n, Zero: n == 0}
	}
	return rows
}

// lowerBound returns the lower-bound sentence, or "" when every block passed.
func lowerBound(c state.Counts) string {
	n := c.NotPassed()
	if n == 0 {
		return ""
	}
	return wording.LowerBound(n, c.Disputed+c.Compromised > 0)
}

// badgeFor returns the wording for a state, for the verdict's badge.
func badgeFor(s state.StateCode) *wording.StateText {
	t := wording.State(string(s))
	return &t
}

// buildVerdict returns the overview's verdict and the state its badge shows.
// The badge is nil when the headline names no single state, as in "200 of
// 213 blocks checked.", so a state glyph never sits beside other words.
func buildVerdict(f *state.File) (wording.Verdict, *wording.StateText) {
	c := f.Counts
	total := f.Checked.Len()
	passed := int(c.Verified + c.Resolved)
	switch {
	case c.Compromised > 0:
		if c.Compromised == 1 {
			// Blocks are keyed by hash, so match the finding to the block by
			// hash. A finding carried forward for another block at the same
			// height, from before a reorg, is not this block's finding.
			var hash string
			for _, b := range f.Blocks {
				if b.State == state.Compromised {
					hash = b.Hash
				}
			}
			var one []state.Finding
			for _, x := range f.Findings {
				if x.Kind == state.KindWithheld && hash != "" && x.Block.Hash == hash {
					one = append(one, x)
				}
			}
			if len(one) == 1 {
				x := one[0]
				return wording.VerdictWithheldOne(
					wording.FindingHeadline(x.Kind, string(x.Reason), labels(x.Servers)),
					x.Block.Height,
					wording.ProvableShort(x.Kind, x.Provable, x.Evidence != nil),
				), badgeFor(state.Compromised)
			}
		}
		return wording.VerdictWithheldMany(int(c.Compromised)), badgeFor(state.Compromised)
	case c.Disputed > 0:
		return wording.VerdictDisputed(int(c.Disputed)), badgeFor(state.Disputed)
	}

	// No block in this run reads Data withheld or Servers disagree.
	var v wording.Verdict
	var badge *wording.StateText
	switch {
	case passed == total:
		v = wording.VerdictAllChecked(total)
		badge = badgeFor(state.Verified)
		if c.Verified == 0 {
			badge = badgeFor(state.Resolved)
		}
	case passed > 0:
		v = wording.VerdictSomeChecked(passed, total)
	default:
		v = wording.VerdictNoneChecked(total)
	}

	// A later run never clears a finding, so withheld and disagree findings
	// from earlier runs can still stand. The headline names them, and the
	// badge shows the kind of the most serious one.
	withheld, disagree := 0, 0
	for _, x := range f.Findings {
		switch x.Kind {
		case state.KindWithheld:
			withheld++
		case state.KindDisagree:
			disagree++
		}
	}
	if n := withheld + disagree; n > 0 {
		v = wording.VerdictOpenFindings(v, n)
		badge = badgeFor(state.Disputed)
		if withheld > 0 {
			badge = badgeFor(state.Compromised)
		}
	}
	return v, badge
}

func buildServers(f *state.File) []serverRow {
	rows := make([]serverRow, len(f.Servers))
	for i, s := range f.Servers {
		row := serverRow{
			Label:     s.Label,
			URL:       s.URL,
			Pubkey:    optHash(s.Pubkey, "Copy "+s.Label+"'s public key"),
			Records:   wording.YesNo(s.PublishesRecords),
			Receipts:  wording.YesNo(s.SignsReceipts),
			Reachable: wording.YesNo(s.Reachable),
		}
		if s.Pubkey == nil {
			row.NoPubkey = wording.NoPubkey
		}
		if s.Tip != nil {
			row.Tip = wording.TipText(s.Tip.Height, s.Tip.Signed)
		}
		if s.Policy != nil {
			row.Policy = wording.PolicyText(s.Policy.PrunesSpent, s.Policy.DustThresholdSat, s.Policy.Signed)
		}
		if s.Error != nil {
			row.Error = *s.Error
		}
		rows[i] = row
	}
	return rows
}

// Tones for results that are not block states.
const (
	toneGood    = "good"
	toneBad     = "bad"
	toneNeutral = "neutral"
)

// toneGlyph returns the glyph for a tone. The tone glyphs are their own
// shapes, never one of the six state symbols, so a payment outcome such as
// Pending can't be read as the Not checked state.
func toneGlyph(tone string) string {
	switch tone {
	case toneGood:
		return "tone-good"
	case toneBad:
		return "tone-bad"
	}
	return "tone-neutral"
}

func paymentTone(outcome string) string {
	switch outcome {
	case "found":
		return toneGood
	case "withheld":
		return toneBad
	}
	return toneNeutral
}

func buildPayments(ps []state.Payment, keep func(state.Payment) bool) []paymentRow {
	var rows []paymentRow
	for _, p := range ps {
		if keep != nil && !keep(p) {
			continue
		}
		label, text := wording.PaymentOutcome(p.Outcome)
		row := paymentRow{
			Txid:        newHash(p.Txid, "Copy the transaction id"),
			Outcome:     label,
			OutcomeText: text,
			Tone:        paymentTone(p.Outcome),
		}
		row.Glyph = toneGlyph(row.Tone)
		if p.Block != nil {
			row.Block = &blockLink{Height: p.Block.Height, Hash: p.Block.Hash}
		}
		for _, s := range p.Servers {
			l, t := wording.PaymentOutcome(s.Outcome)
			tone := paymentTone(s.Outcome)
			row.Servers = append(row.Servers, paymentServerRow{Label: s.Label, Outcome: l, Text: t, Glyph: toneGlyph(tone), Tone: tone})
		}
		rows = append(rows, row)
	}
	return rows
}

func buildOverview(f *state.File, loc *time.Location) overviewView {
	v, badge := buildVerdict(f)
	rows := sortedFindings(f, loc, nil)
	ov := overviewView{
		Verdict:       v,
		VerdictState:  badge,
		LowerBound:    lowerBound(f.Counts),
		Strip:         buildStrip("strip", f),
		Counts:        buildCounts(f.Counts),
		Findings:      rows,
		TotalFindings: len(rows),
		NoFindings:    wording.NoFindings,
		Servers:       buildServers(f),
		ServersNote:   wording.ServersNote,
		Payments:      buildPayments(f.ExpectedPayments, nil),
		PaymentsNote:  wording.PaymentsNote,
	}
	if len(rows) > overviewFindings {
		ov.Findings = rows[:overviewFindings]
		ov.MoreFindings = true
	}
	return ov
}

type rangeRow struct {
	Heights string
	Count   int
	State   wording.StateText
	Reason  string
	Links   []blockLink
	Gap     bool
}

type blocksView struct {
	Intro      string
	Strip      stripView
	Ranges     []rangeRow
	From, To   uint32
	Total      int
	Detailed   int
	LowerBound string
	Query      string
	QueryMiss  bool
	QueryError string
}

// heights returns "205" or "0–204".
func heights(from, to uint32) string {
	if from == to {
		return strconv.FormatUint(uint64(from), 10)
	}
	return strconv.FormatUint(uint64(from), 10) + "–" + strconv.FormatUint(uint64(to), 10)
}

// maxRangeLinks is how many blocks of one range the table links one by one.
// Longer ranges link their first and last block.
const maxRangeLinks = 12

func buildBlocks(f *state.File) blocksView {
	byHeight := map[uint32]string{}
	for _, b := range f.Blocks {
		byHeight[b.Height] = b.Hash
	}
	v := blocksView{
		Intro:      wording.BlocksIntro(f.Checked.From, f.Checked.To, f.Checked.Len()),
		Strip:      buildStrip("strip", f),
		From:       f.Checked.From,
		To:         f.Checked.To,
		Total:      f.Checked.Len(),
		Detailed:   len(f.Blocks),
		LowerBound: lowerBound(f.Counts),
	}
	for _, c := range f.Coverage {
		row := rangeRow{
			Heights: heights(c.From, c.To),
			Count:   c.Len(),
			State:   wording.State(string(c.State)),
			Reason:  wording.Reason(string(c.Reason)),
		}
		add := func(h uint32) {
			if hash, ok := byHeight[h]; ok {
				row.Links = append(row.Links, blockLink{Height: h, Hash: hash})
			}
		}
		if c.Len() <= maxRangeLinks {
			for h := c.From; ; h++ {
				add(h)
				if h == c.To {
					break
				}
			}
		} else {
			add(c.From)
			add(c.To)
			row.Gap = len(row.Links) == 2
		}
		v.Ranges = append(v.Ranges, row)
	}
	return v
}

type blockServerRow struct {
	Label     string
	State     wording.StateText
	Reason    string
	Record    *hashView
	N         string
	Root      *hashView
	Positions string
	Filled    string
	Signed    string
	Tip       string
}

type blockView struct {
	Height   uint32
	Hash     hashView
	State    wording.StateText
	Reason   string
	Servers  []blockServerRow
	Findings []findingRow
	Payments []paymentRow
	Prev     *blockLink
	Next     *blockLink
}

func positionsText(p *state.Positions) string {
	if p == nil {
		return "No list"
	}
	return strconv.FormatUint(uint64(p.Full), 10) + " full, " +
		strconv.FormatUint(uint64(p.Hash), 10) + " hash only, " +
		strconv.FormatUint(uint64(p.Absent), 10) + " absent"
}

func buildBlock(f *state.File, i int, loc *time.Location) blockView {
	b := f.Blocks[i]
	v := blockView{
		Height: b.Height,
		Hash:   newHash(b.Hash, "Copy the block hash"),
		State:  wording.State(string(b.State)),
		Reason: wording.Reason(string(b.Reason)),
	}
	for _, s := range b.Servers {
		row := blockServerRow{
			Label:     s.Label,
			State:     wording.State(string(s.State)),
			Reason:    wording.Reason(string(s.Reason)),
			Record:    optHash(s.RecordEventID, "Copy "+s.Label+"'s record id"),
			Root:      optHash(s.Root, "Copy "+s.Label+"'s signed root"),
			Positions: positionsText(s.Positions),
			Filled:    strconv.FormatUint(uint64(s.Filled), 10),
			Signed:    wording.YesNo(s.Signed),
			Tip:       "None",
			N:         "None",
		}
		if s.N != nil {
			row.N = strconv.FormatUint(uint64(*s.N), 10)
		}
		if s.Tip != nil {
			row.Tip = strconv.FormatUint(uint64(s.Tip.Height), 10)
		}
		v.Servers = append(v.Servers, row)
	}
	v.Findings = sortedFindings(f, loc, func(x state.Finding) bool { return x.Block.Hash == b.Hash })
	v.Payments = buildPayments(f.ExpectedPayments, func(p state.Payment) bool { return p.Block != nil && p.Block.Hash == b.Hash })
	for _, o := range f.Blocks {
		if o.Height+1 == b.Height {
			v.Prev = &blockLink{Height: o.Height, Hash: o.Hash}
		}
		if o.Height == b.Height+1 {
			v.Next = &blockLink{Height: o.Height, Hash: o.Hash}
		}
	}
	return v
}

type findingGroup struct {
	Kind  string
	Title string
	Rows  []findingRow
}

type findingsView struct {
	Intro      string
	Groups     []findingGroup
	Empty      string
	LowerBound string
}

func buildFindings(f *state.File, loc *time.Location) findingsView {
	v := findingsView{Intro: wording.FindingsIntro, Empty: wording.NoFindings, LowerBound: lowerBound(f.Counts)}
	for _, kind := range []string{state.KindWithheld, state.KindDisagree, state.KindWarning} {
		rows := sortedFindings(f, loc, func(x state.Finding) bool { return x.Kind == kind })
		if len(rows) == 0 {
			continue
		}
		title := wording.KindLabel(kind)
		if kind == state.KindWarning {
			title = "Warnings"
		}
		v.Groups = append(v.Groups, findingGroup{Kind: kind, Title: title, Rows: rows})
	}
	return v
}

type serverRefView struct {
	Label  string
	Pubkey *hashView
}

type evidenceView struct {
	Name          string
	Path          string
	VerifyCommand string
	Note          string
}

type findingView struct {
	Row          findingRow
	Servers      []serverRefView
	BlockHash    hashView
	Position     string
	Txid         *hashView
	WhatHappened string
	Shows        string
	DoesNotShow  string
	Provable     string
	IsProvable   bool
	Evidence     *evidenceView
	Report       *reportView
	ReportErr    *errorView
}

func buildFinding(f *state.File, i int, loc *time.Location) findingView {
	x := f.Findings[i]
	v := findingView{
		Row:          newFindingRow(x, loc, knownBlocks(f)),
		BlockHash:    newHash(x.Block.Hash, "Copy the block hash"),
		Txid:         optHash(x.Txid, "Copy the transaction id"),
		WhatHappened: wording.Reason(string(x.Reason)),
		Shows:        wording.FindingShows(x.Kind, string(x.Reason), x.Provable, x.Evidence != nil),
		DoesNotShow:  wording.FindingDoesNotShow(x.Kind, string(x.Reason)),
		Provable:     wording.Provable(x.Kind, x.Provable, x.Evidence != nil),
		IsProvable:   x.Provable,
	}
	for _, s := range x.Servers {
		v.Servers = append(v.Servers, serverRefView{Label: s.Label, Pubkey: optHash(s.Pubkey, "Copy "+s.Label+"'s public key")})
	}
	if x.Position != nil {
		v.Position = strconv.FormatUint(uint64(*x.Position), 10)
	}
	if x.Evidence != nil {
		v.Evidence = &evidenceView{Name: *x.Evidence, Note: wording.EvidenceNote}
	}
	return v
}
