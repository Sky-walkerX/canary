---
name: Canary, Safety Lamp
description: The design system for Canary's local dashboard and, later, its public site.
colors:
  limestone: "#F5F3EC"
  limestone-surface: "#ECE9DF"
  coal: "#17160F"
  coal-muted: "#5A5648"
  rule: "#D6D1C2"
  rule-strong: "#8F8A78"
  canary: "#F4E13A"
  canary-text: "#5E5700"
  state-verified: "#1E6B35"
  state-resolved: "#0B6663"
  state-unresolvable: "#5A4A91"
  state-unverified: "#625D4F"
  state-disputed: "#9A4600"
  state-compromised: "#B3261E"
  dark-bg: "#121210"
  dark-surface: "#1C1B17"
  dark-ink: "#EDEAE0"
  dark-ink-muted: "#A8A392"
  dark-rule: "#34322A"
  dark-rule-strong: "#6B675A"
  dark-state-verified: "#6DC98A"
  dark-state-resolved: "#4FC6C0"
  dark-state-unresolvable: "#ADA0EA"
  dark-state-unverified: "#A7A290"
  dark-state-disputed: "#F09A52"
  dark-state-compromised: "#FF8272"
typography:
  verdict:
    fontFamily: "Atkinson Hyperlegible Next"
    fontSize: "2.125rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  h1:
    fontFamily: "Atkinson Hyperlegible Next"
    fontSize: "1.75rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.015em"
  h2:
    fontFamily: "Atkinson Hyperlegible Next"
    fontSize: "1.4375rem"
    fontWeight: 700
    lineHeight: 1.2
  h3:
    fontFamily: "Atkinson Hyperlegible Next"
    fontSize: "1.1875rem"
    fontWeight: 700
    lineHeight: 1.2
  body:
    fontFamily: "Atkinson Hyperlegible Next"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.5
  small:
    fontFamily: "Atkinson Hyperlegible Next"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
  data:
    fontFamily: "Atkinson Hyperlegible Mono"
    fontSize: "0.9375em"
    fontWeight: 400
rounded:
  s: "2px"
  m: "4px"
spacing:
  "1": "4px"
  "2": "8px"
  "3": "12px"
  "4": "16px"
  "5": "24px"
  "6": "32px"
  "7": "48px"
  "8": "64px"
components:
  button:
    textColor: "{colors.coal}"
    rounded: "{rounded.m}"
    padding: "6px 12px"
    height: "36px"
  network-badge:
    backgroundColor: "{colors.canary}"
    textColor: "{colors.coal}"
    rounded: "{rounded.s}"
    padding: "4px 8px"
  update-bar:
    backgroundColor: "{colors.canary}"
    textColor: "{colors.coal}"
  command:
    backgroundColor: "{colors.limestone-surface}"
    rounded: "{rounded.m}"
    padding: "12px 16px"
---

# Canary, Safety Lamp

The tokens live in `assets/tokens.css`. The component styles live in `assets/ui.css`.
The words live in `wording/copy.go`. This file records the rules those three follow.

## Overview

Canary is a tool people operate: they run `canary check`, then read what it found. The
dashboard leads with coverage, not alarms. Every block reads as one of six states, and
the page says plainly what was checked, what could not be, and which server left what
out. The look borrows from a mine's lamp room: coal ink on limestone, 1px rules, flat
surfaces, and one bright yellow that belongs to Canary itself.

## Colors

- **Coal on limestone** in light mode, limestone-tinted ink on `#121210` in dark mode.
  Dark mode follows the system; a reader's choice sets `data-theme` on `<html>`.
- **Canary yellow is Canary's own voice, never a state.** It fills the network badge,
  the skip link, the update bar, the focus halo and text selection. In dark mode it also
  draws the wordmark's perch line. Text in the yellow family uses `canary-text`.
- **Six state colours**, each at 4.5:1 or more against both surfaces in both themes.
  `contrast_test.go` recomputes this from `tokens.css`.
- **Tones** reuse three state colours for results that are not block states: payment
  outcomes and verify results (`tone-good`, `tone-bad`, `tone-neutral`). A tone never
  wears a state's label or glyph. Its glyphs are a tick, a cross and a dash, none of
  them one of the six state symbols.

## Typography

One family carries everything: Atkinson Hyperlegible Next for words, Atkinson
Hyperlegible Mono for data (hashes, heights, URLs, commands). Both are self-hosted
WOFF2, Latin subset, with the OFL text beside them. The scale is fixed rem, about 1.2
between steps. Body text stays under 60ch, about 75 characters a line. Numbers in
tables and counts use tabular figures.

## Layout

A single column up to 72rem, with a 16px gutter below 768px and 32px above. The header
reflows in three steps (one row at 1040px and up, two rows, then three at under 640px).
Tables scroll inside their own bordered container, never the page, so nothing scrolls
sideways at 360px. Under 720px the row tables (servers, payments, ranges) stack each
row into labelled lines, and the per-server table on a block page becomes one list per
server, so no column hides off the right edge. Sections sit 48px apart, with more
space above a heading than below.

## Elevation & Depth

None. Surfaces are flat and separated by 1px rules. The only shadow is the focus halo.

## Shapes

Corners are 2px (badges, focus) or 4px (buttons, panels, tables, commands). Nothing is
fully rounded: no pills.

## Components

- **State badge.** Glyph, word and colour, always all three, from `wording.State`.
  Round glyphs mean no proven problem; angular ones mean a problem.
- **Verdict.** The overview's headline is the h1, with no glyph of its own. A state
  badge follows it only when the headline names one state, so a mixed result such as
  "200 of 213 blocks checked." gets none.
- **Coverage strip.** An inline SVG with percentage x positions and pixel heights, so
  the hatch keeps a 4px gap at any width. Each state is drawn in its glyph's grammar,
  and problem ranges get a marker above. It is `role="img"` with a one-sentence summary;
  the range table is the accessible interface.
- **Hash.** Mono, grouped in fours by CSS margins so a manual copy carries no spaces.
  Lists show the first and last 8 characters; detail pages show the full value with a
  labelled copy button.
- **Error panel.** Title, what it means, what to do, and raw errors behind "Technical
  details".
- **Verify report.** The eight steps as an ordered list, each with a tone glyph and a
  word (Passed, Failed, Not run).
- **Update bar.** A fixed, non-modal `role="status"` bar in canary yellow. It stays until
  the reader reloads or dismisses it.
- **Focus.** A 2px ink ring with a canary halo on every focusable element.

## Do's and Don'ts

- Do take every state label, reason and message from `wording/copy.go`.
- Do state the limit next to the claim: Checked covers the tweak list, not payments.
- Don't use canary yellow for a state, or a state colour without its glyph and word.
- Don't add gradients, glass, shadows for depth, emoji, pills, stat tiles, eyebrow
  labels above headings, or Unicode arrows standing in for icons.
- Don't load anything from another origin. The CSP allows only `'self'`.
