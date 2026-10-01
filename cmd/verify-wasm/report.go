package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Sky-walkerX/canary/evidence"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// This file writes out the dashboard's verifyReport partial by hand. The
// dashboard renders that partial with html/template, and the checker can't
// link it: text/template keeps every exported method of every type the
// program can reach, which nearly doubles the module. report_test.go holds
// this markup to the partial's, byte for byte, so the two can't drift.

// Tones and their glyphs, as internal/ui names them.
const (
	toneGood    = "good"
	toneBad     = "bad"
	toneNeutral = "neutral"
)

func toneGlyph(tone string) string {
	switch tone {
	case toneGood:
		return "tone-good"
	case toneBad:
		return "tone-bad"
	}
	return "tone-neutral"
}

// escaper escapes text the way html/template does in text and in quoted
// attribute values. Each character it replaces is one byte, so working on
// bytes gives the same result as html/template's rune loop, invalid UTF-8
// included.
var escaper = strings.NewReplacer(
	"\x00", "�",
	`"`, "&#34;",
	"&", "&amp;",
	"'", "&#39;",
	"+", "&#43;",
	"<", "&lt;",
	">", "&gt;",
)

// markup is a builder for the report's markup. Every value that came from the
// file goes through text; the rest is fixed markup.
type markup struct{ strings.Builder }

func (b *markup) raw(s string)  { b.WriteString(s) }
func (b *markup) text(s string) { escaper.WriteString(&b.Builder, s) }

// glyph is the "glyph" partial. The name is one of toneGlyph's results.
func (b *markup) glyph(name string) {
	b.raw(`<svg class="glyph" aria-hidden="true" focusable="false"><use href="#g-`)
	b.text(name)
	b.raw(`"></use></svg>`)
}

// hashShort is the "hashShort" partial: a hex value in groups of four, cut to
// its first and last eight characters when longer than sixteen.
func (b *markup) hashShort(full string) {
	if n := len(full); n > 16 {
		b.raw(`<span class="hash" title="`)
		b.text(full)
		b.raw(`">`)
		for _, g := range []string{full[0:4], full[4:8]} {
			b.raw("<span>")
			b.text(g)
			b.raw("</span>")
		}
		b.raw(`<span class="hash-ell">…</span>`)
		for _, g := range []string{full[n-8 : n-4], full[n-4:]} {
			b.raw("<span>")
			b.text(g)
			b.raw("</span>")
		}
		b.raw("</span>")
		return
	}
	b.raw(`<span class="hash">`)
	for i := 0; i < len(full); i += 4 {
		b.raw("<span>")
		b.text(full[i:min(i+4, len(full))])
		b.raw("</span>")
	}
	b.raw("</span>")
}

// fact is one row of the facts list, left out when its value is empty.
func (b *markup) fact(term, value string, code bool) {
	if value == "" {
		return
	}
	b.raw("<div><dt>" + term + "</dt><dd>")
	if code {
		b.raw(`<code class="mono wrap-anywhere">`)
	}
	b.text(value)
	if code {
		b.raw("</code>")
	}
	b.raw("</dd></div>")
}

// checkShape applies the dashboard's checks on a report before it renders
// one: a known result, the eight steps in order, and a message.
func checkShape(r evidence.VerifyReport) error {
	switch r.Result {
	case evidence.ResultChecksOut, evidence.ResultDoesNotCheckOut, evidence.ResultUnreadable:
	default:
		return fmt.Errorf("verify-wasm: render report: unknown result %q", r.Result)
	}
	if len(r.Checks) != len(wording.VerifySteps) {
		return fmt.Errorf("verify-wasm: render report: %d checks, want %d", len(r.Checks), len(wording.VerifySteps))
	}
	for i, c := range r.Checks {
		if c.Step != wording.VerifySteps[i] {
			return fmt.Errorf("verify-wasm: render report: check %d is %q, want %q", i, c.Step, wording.VerifySteps[i])
		}
	}
	if r.Message == "" {
		return errors.New("verify-wasm: render report: no message")
	}
	return nil
}

// afterLabel drops a leading copy of label from message, as the dashboard
// does: the badge above the message already shows the label.
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

// reportHTML renders one report as the dashboard's verifyReport partial. A
// report the dashboard would refuse renders nothing and returns the reason.
func reportHTML(r evidence.VerifyReport) (string, error) {
	if err := checkShape(r); err != nil {
		return "", err
	}
	label := wording.VerifyResultLabel(r.Result, r.Code)
	tone := toneNeutral
	var inclusion []string
	var notHonest string
	switch r.Result {
	case evidence.ResultChecksOut:
		tone = toneGood
		if r.Code == evidence.CodeInclusionOnly {
			inclusion = wording.VerifyInclusionOnlyDetail[:]
		}
	case evidence.ResultDoesNotCheckOut:
		tone = toneBad
		notHonest = wording.VerifyNotHonest
	}

	var b markup
	b.raw("<div class=\"report\">\n")
	b.raw(`<p class="report-result"><span class="badge badge-large tone-` + tone + `">`)
	b.glyph(toneGlyph(tone))
	b.raw("<span>")
	b.text(label)
	b.raw("</span></span></p>\n")
	b.raw(`<p class="report-message">`)
	b.text(afterLabel(r.Message, label))
	b.raw("</p>\n")
	for _, d := range inclusion {
		b.raw(`<p class="report-detail">`)
		b.text(d)
		b.raw("</p>")
	}
	b.raw("\n")
	if notHonest != "" {
		b.raw(`<p class="report-detail">`)
		b.text(notHonest)
		b.raw("</p>")
	}
	b.raw("\n")

	b.raw("<ol class=\"report-steps\">\n")
	for _, c := range r.Checks {
		status, word, stepTone := "skip", wording.StepNotRun, toneNeutral
		switch {
		case c.OK == nil:
		case *c.OK:
			status, word, stepTone = "pass", wording.StepPassed, toneGood
		default:
			status, word, stepTone = "fail", wording.StepFailed, toneBad
		}
		b.raw(`<li class="step step-` + status + "\">\n")
		b.raw(`<span class="step-status tone-` + stepTone + `">`)
		b.glyph(toneGlyph(stepTone))
		b.raw("<span>")
		b.text(word)
		b.raw("</span></span>\n")
		b.raw(`<span class="step-name">`)
		b.text(wording.VerifyStep(c.Step))
		b.raw("</span>\n")
		b.raw(`<span class="step-text">`)
		b.text(c.Text)
		b.raw("</span>\n</li>")
	}
	b.raw("\n</ol>\n")

	var block, missing, tip string
	if r.Block != nil {
		block = strconv.FormatUint(uint64(r.Block.Height), 10)
		if r.Network != nil {
			block += " on " + r.Network.Name
		}
	}
	if r.Missing != nil {
		missing = "Position " + strconv.FormatUint(uint64(r.Missing.Index), 10) + ", transaction " + wording.ShortHash(r.Missing.TxID, 8, 8)
	}
	if r.ReceiptTip != nil {
		tip = strconv.FormatUint(uint64(r.ReceiptTip.Height), 10)
	}
	if r.Accused != nil || block != "" || missing != "" || tip != "" {
		b.raw("<dl class=\"facts facts-compact\">\n")
		if r.Accused != nil {
			b.raw("<div><dt>Accused key</dt><dd>")
			b.hashShort(r.Accused.Pubkey)
			b.raw("</dd></div>")
		}
		b.raw("\n")
		if r.Accused != nil {
			b.fact("As npub", r.Accused.Npub, true)
		}
		b.raw("\n")
		b.fact("Block", block, false)
		b.raw("\n")
		b.fact("Left-out entry", missing, false)
		b.raw("\n")
		b.fact("Signed tip", tip, false)
		b.raw("\n</dl>")
	}
	b.raw("\n</div>")
	return b.String(), nil
}
