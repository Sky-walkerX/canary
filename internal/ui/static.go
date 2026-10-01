package ui

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// This file renders a state file as static pages, for a recorded run on the
// public site. The pages use the dashboard's own templates, view models and
// words, so a recording shows exactly what canary ui showed. What needs a
// running server stays out: the update check, the stale notice, ages such as
// "6 min ago", and the height lookup on the blocks page.

// StaticOptions configures RenderStatic.
type StaticOptions struct {
	// State is the state file, format canary-state/1. Required.
	State []byte

	// Base is the address the pages live under. It starts and ends with a
	// slash, as in "/runs/2026-10-01/". The overview sits at Base itself.
	Base string

	// EvidenceURL returns the address of an evidence file a finding names.
	// It is required when a finding names one, because the finding page
	// links the file.
	EvidenceURL func(name string) string

	// VerifyCommand returns the canary verify command the finding page shows
	// for an evidence file. Nil shows "canary verify NAME".
	VerifyCommand func(name string) string

	// Evidence returns the bytes of an evidence file a finding names, and
	// Verify checks them as Options.Verify does. With both set, each
	// finding page carries Canary's check of its file. A file that can't be
	// read stops the render, so a recording never shows a broken report.
	Evidence func(name string) ([]byte, error)
	Verify   func(evidenceFile []byte) ([]byte, error)

	// Location sets the time zone of every time the pages show. Nil means
	// UTC, the zone canary status prints.
	Location *time.Location
}

// StaticPage is one recorded page.
type StaticPage struct {
	// Path is the page's address below Base: "" for the overview, then
	// "blocks/", "blocks/HASH/", "findings/" and "findings/ID/".
	Path string
	// Title is the page's name in the dashboard, such as "Block 351".
	Title string
	// Nav is the dashboard's links, with this page's marked.
	Nav template.HTML
	// Content is the page's main content.
	Content template.HTML
}

// StaticRun is one state file rendered as recorded pages.
type StaticRun struct {
	// File is the parsed state file.
	File *state.File
	// StatusLine is the run's one-line summary, with the time in Location
	// and no age, as canary status prints it.
	StatusLine string
	// NetworkBadge names the network for a reader who never ran the chain.
	NetworkBadge string
	// Pages lists the overview, the blocks page, one page per block with
	// detail, the findings page and one page per finding.
	Pages []StaticPage
}

// RenderStatic renders a state file as the dashboard's pages, with every
// link pointed below Base.
func RenderStatic(o StaticOptions) (*StaticRun, error) {
	if !strings.HasPrefix(o.Base, "/") || !strings.HasSuffix(o.Base, "/") {
		return nil, fmt.Errorf("ui: render recording: base %q must start and end with a slash", o.Base)
	}
	f, err := state.Parse(o.State)
	if err != nil {
		return nil, fmt.Errorf("ui: render recording: %w", err)
	}
	loc := o.Location
	if loc == nil {
		loc = time.UTC
	}
	for _, x := range f.Findings {
		if x.Evidence != nil && o.EvidenceURL == nil {
			return nil, fmt.Errorf("ui: render recording: finding %s names evidence %s, and no EvidenceURL links it", x.ID, *x.Evidence)
		}
	}

	fm := maps.Clone(funcs)
	fm["link"] = staticLink(o.Base, o.EvidenceURL)
	set := mustParsePages(fm)

	run := &StaticRun{
		File: f,
		StatusLine: wording.StatusLine(fmtTime(f.GeneratedAt.Time, loc), "",
			f.Checked.From, f.Checked.To, f.Network.Name, f.Canary.Version, f.Canary.Build),
		NetworkBadge: wording.RecordedNetworkBadge(f.Network.Name),
	}
	add := func(path, title, nav, tmpl string, main any) error {
		pg := page{Title: title, Nav: nav, Main: main, Chrome: chrome{
			HasState:      true,
			FindingsCount: len(f.Findings),
			NavLabel:      wording.RecordedNavLabel,
		}}
		var content, links bytes.Buffer
		if err := set[tmpl].ExecuteTemplate(&content, "content", pg); err != nil {
			return fmt.Errorf("ui: render recording: %s: %w", title, err)
		}
		if err := set[tmpl].ExecuteTemplate(&links, "dashNav", pg); err != nil {
			return fmt.Errorf("ui: render recording: %s links: %w", title, err)
		}
		run.Pages = append(run.Pages, StaticPage{
			Path: path, Title: title,
			Nav: template.HTML(links.String()), Content: template.HTML(content.String()),
		})
		return nil
	}

	if err := add("", "Overview", "overview", "overview", buildOverview(f, loc)); err != nil {
		return nil, err
	}
	bv := buildBlocks(f)
	bv.Recorded = true
	if err := add("blocks/", "Blocks", "blocks", "blocks", bv); err != nil {
		return nil, err
	}
	for i, b := range f.Blocks {
		if !pathSafe(b.Hash) {
			return nil, fmt.Errorf("ui: render recording: block hash %q", b.Hash)
		}
		title := "Block " + strconv.FormatUint(uint64(b.Height), 10)
		if err := add("blocks/"+b.Hash+"/", title, "blocks", "block", buildBlock(f, i, loc)); err != nil {
			return nil, err
		}
	}
	if err := add("findings/", "Findings", "findings", "findings", buildFindings(f, loc)); err != nil {
		return nil, err
	}
	for i, x := range f.Findings {
		if !pathSafe(x.ID) {
			return nil, fmt.Errorf("ui: render recording: finding id %q", x.ID)
		}
		v := buildFinding(f, i, loc)
		if ev := v.Evidence; ev != nil {
			ev.Path = ev.Name
			ev.VerifyCommand = "canary verify " + shellQuote(ev.Name)
			if o.VerifyCommand != nil {
				ev.VerifyCommand = o.VerifyCommand(ev.Name)
			}
			if o.Evidence != nil && o.Verify != nil {
				rep, err := staticReport(o, ev.Name)
				if err != nil {
					return nil, fmt.Errorf("ui: render recording: finding %s: %w", x.ID, err)
				}
				v.Report = rep
			}
		}
		if err := add("findings/"+x.ID+"/", "Finding "+x.ID, "findings", "finding", v); err != nil {
			return nil, err
		}
	}
	return run, nil
}

// staticReport checks one evidence file for a finding page.
func staticReport(o StaticOptions, name string) (*reportView, error) {
	b, err := o.Evidence(name)
	if err != nil {
		return nil, fmt.Errorf("read evidence %s: %w", name, err)
	}
	if len(b) > maxEvidenceBytes {
		return nil, fmt.Errorf("evidence %s: larger than %d bytes", name, maxEvidenceBytes)
	}
	out, err := o.Verify(b)
	if err != nil {
		return nil, fmt.Errorf("check evidence %s: %w", name, err)
	}
	rep, err := ParseVerifyReport(out)
	if err != nil {
		return nil, fmt.Errorf("read the report on evidence %s: %w", name, err)
	}
	v := buildReport(rep)
	return &v, nil
}

// staticLink returns the link function for a recording under base. It maps
// the dashboard's addresses to directory-style ones below base, and an
// evidence file's address to the one evidenceURL gives.
func staticLink(base string, evidenceURL func(string) string) func(string) (string, error) {
	return func(p string) (string, error) {
		target, frag, hasFrag := strings.Cut(p, "#")
		var out string
		switch {
		case strings.HasPrefix(target, "/evidence/"):
			if evidenceURL == nil {
				return "", errors.New("ui: recording links an evidence file, and no EvidenceURL links it")
			}
			out = evidenceURL(strings.TrimPrefix(target, "/evidence/"))
		case target == "/":
			out = base
		case strings.HasPrefix(target, "/"):
			out = base + strings.Trim(target, "/") + "/"
		default:
			return "", fmt.Errorf("ui: recording links %q, which is not a dashboard address", p)
		}
		if hasFrag {
			out += "#" + frag
		}
		return out, nil
	}
}

// pathSafe reports whether s can be one segment of a page's address: a
// non-empty run of lower-case hex digits, as block hashes and finding ids
// are.
func pathSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
