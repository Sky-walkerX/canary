---
name: Canary, Instrument
description: The design system for Canary's local dashboard and its public site.
colors:
  brand:
    canary: "#FFC174"
    on-canary: "#2A1700"
    canary-text-light: "#8A4B00"
    canary-text-dark: "#FFC174"
  ground:
    bg-light: "#F6F6F8"
    surface-light: "#FFFFFF"
    surface-low-light: "#EFEFF2"
    surface-high-light: "#E7E7EC"
    surface-highest-light: "#DEDEE5"
    surface-bright-light: "#C4C4CD"
    bg-dark: "#0E0F12"
    surface-dark: "#131418"
    surface-low-dark: "#08090B"
    surface-high-dark: "#18191F"
    surface-highest-dark: "#22232A"
    surface-bright-dark: "#383944"
  ink:
    ink-light: "#12131A"
    ink-muted-light: "#5A5F6B"
    ink-dark: "#EDEDF0"
    ink-muted-dark: "#9496A1"
  rule:
    rule-light: "#DADAE1"
    rule-strong-light: "#8B8F99"
    rule-dark: "#2B2C36"
    rule-strong-dark: "#5E606E"
  states:
    verified-dark: "#09B788"
    resolved-dark: "#06B6D4"
    unresolvable-dark: "#F59E0B"
    unverified-dark: "#94A3B8"
    disputed-dark: "#F97316"
    compromised-dark: "#F43F5E"
    verified-light: "#067A57"
    resolved-light: "#0B6E86"
    unresolvable-light: "#9A5B00"
    unverified-light: "#5A6472"
    disputed-light: "#B4500A"
    compromised-light: "#B3243E"
typography:
  display:
    fontFamily: "Geist"
    fontSize: "2.5rem"
    fontWeight: 600
    lineHeight: 1.1
    letterSpacing: "-0.03em"
  h1:
    fontFamily: "Geist"
    fontSize: "1.75rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  h2:
    fontFamily: "Geist"
    fontSize: "1.4375rem"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "-0.015em"
  h3:
    fontFamily: "Geist"
    fontSize: "1.1875rem"
    fontWeight: 500
    lineHeight: 1.3
  body:
    fontFamily: "Geist"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.5
  small:
    fontFamily: "Geist"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
  data:
    fontFamily: "JetBrains Mono"
    fontSize: "0.8125rem"
    fontWeight: 400
    lineHeight: 1.4
  label:
    fontFamily: "JetBrains Mono"
    fontSize: "0.6875rem"
    fontWeight: 500
    lineHeight: 1.2
    letterSpacing: "0.04em"
rounded:
  s: "2px"
  m: "4px"
  l: "8px"
  xl: "12px"
  full: "9999px"
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
    textColor: "{colors.brand.canary-text-dark}"
    rounded: "{rounded.m}"
    padding: "6px 12px"
    height: "36px"
  primary-button:
    backgroundColor: "{colors.brand.canary}"
    textColor: "{colors.brand.on-canary}"
    rounded: "{rounded.m}"
    padding: "8px 14px"
    height: "38px"
  network-badge:
    backgroundColor: "{colors.brand.canary}"
    textColor: "{colors.brand.on-canary}"
    rounded: "{rounded.s}"
    padding: "3px 8px"
  update-bar:
    backgroundColor: "{colors.brand.canary}"
    textColor: "{colors.brand.on-canary}"
  command:
    backgroundColor: "{colors.ground.surface-low-dark}"
    rounded: "{rounded.m}"
    padding: "12px 16px"
---

# Canary, Instrument

The tokens live in `assets/tokens.css`. The component styles live in `assets/ui.css`.
The words live in `wording/copy.go`. This file records the rules those three follow.

## Overview

Canary is a tool people operate: they run `canary check`, then read what it found. The
dashboard is an instrument panel. It leads with coverage, not alarms. Every block reads as
one of six states, and the page says plainly what was checked, what could not be, and
which server left what out. Surfaces are quiet and dark by default, rules are 1px, nothing
decorates, and every hex, height, count and command is set in mono so a reader can compare
two runs by eye.

## Colors

- **Each surface follows its own mock.** The dashboard mock is cool: `#0E0F12` ground,
  `#131418` panels, `#08090B` insets, neutral grey ink `#EDEDF0`. The client mock is warm
  and one step lighter: `#121318` ground, `#1A1B21` panels, `#0D0E13` insets, and warm
  ink. Measured from the mock's own render, its body text is `#D8C3AD`; the site uses
  `#E6DFD2` for ink and `#B7A78F` for secondary text, so a heading keeps a step above the
  body and both clear 4.5:1 on the lighter panels. The site re-declares these neutrals
  inside `body.site` in `cmd/site/assets/site.css`, one block per dark route, and
  `cmd/site/contrast_test.go` holds them to the same floor as the dashboard's.
- **Dark first.** `#0E0F12` ground, `#131418` panels, `#08090B` insets. The light theme is
  the same family inverted: `#F6F6F8` ground, white panels, `#EFEFF2` insets. Dark is the
  default look; a reader's choice sets `data-theme` on `<html>`, and the system preference
  is honoured when they have not chosen.
- **Canary amber is Canary's own voice, never a state.** It fills the network badge,
  buttons, links, the focus ring, the skip link, the update bar and text selection. Text
  that must read as canary amber uses `canary-text`.
- **Six state colours**, from the taxonomy table below, each at 4.5:1 or more against both
  surfaces in both themes. `contrast_test.go` recomputes this from `tokens.css`.
- **Tones** reuse three state colours for results that are not block states: payment
  outcomes and verify results (`tone-good`, `tone-bad`, `tone-neutral`). A tone never
  wears a state's label or glyph. Its glyphs are a tick, a cross and a dash, none of them
  one of the six state symbols.

### The six states

| Code | Label | Token | Dark | Light |
|---|---|---|---|---|
| `verified` | Checked | `--state-verified` | `#09B788` | `#067A57` |
| `resolved` | Checked, gap filled | `--state-resolved` | `#06B6D4` | `#0B6E86` |
| `unresolvable` | Can't be checked | `--state-unresolvable` | `#F59E0B` | `#9A5B00` |
| `unverified` | Not checked | `--state-unverified` | `#94A3B8` | `#5A6472` |
| `disputed` | Servers disagree | `--state-disputed` | `#F97316` | `#B4500A` |
| `compromised` | Data withheld | `--state-compromised` | `#F43F5E` | `#B3243E` |

## Typography

Two families, each self-hosted WOFF2, Latin subset, with the OFL text beside it. **Geist**
carries words, at 300 to 600. **JetBrains Mono** carries data: hashes, heights, URLs,
public keys, counts, commands and every state label. The scale is fixed rem, about 1.2
between steps, with one 2.5rem display step for a page's verdict. Body text stays under
60ch, about 75 characters a line. Numbers in tables and counts use tabular figures.

## Layout

- **Dashboard.** A fixed 16rem rail on 1024px and up, holding the wordmark, the nav, the
  network badge and the run's own version and build; the theme toggle sits at its foot. A
  sticky 56px status bar crosses the content column. Under 1024px the rail becomes a
  header and the nav a row. The content column is capped at 72rem.
- A single column of content, 16px gutter below 768px and 32px above. Sections sit 48px
  apart, with more space above a heading than below.
- Tables scroll inside their own bordered container, never the page, so nothing scrolls
  sideways at 360px. Under 720px the row tables (servers, payments, ranges) stack each row
  into labelled lines, and the per-server table on a block page becomes one list per
  server, so no column hides off the right edge.

## Elevation & Depth

One shadow exists, `--shadow-chrome`, and only sticky chrome lifts off the page. Everything
else is flat and separated by 1px rules. There is no glass, no blur, no gradient, and no
glow.

## Shapes

Corners are 2px (badges, rules, focus), 8px (buttons, commands, panels, tables, cards),
12px (a panel's own foot) or 16px (the checker console). Nothing else is rounded. `--radius-full` is
reserved for the 2px status dots and beacons.

## Components

- **State badge.** Glyph, word and colour, always all three, from `wording.State`. Round
  glyphs mean no proven problem; angular ones mean a problem. Mono, uppercase, 2px corner.
- **Verdict.** The overview's headline is the h1, with no glyph of its own. A state
  badge follows it only when the headline names one state, so a mixed result such as
  "200 of 213 blocks checked." gets none.
- **Coverage strip.** An inline SVG with percentage x positions and pixel heights, so
  the hatch keeps a 4px gap at any width. Each state is drawn in its glyph's grammar,
  and problem ranges get a marker above. It is `role="img"` with a one-sentence summary;
  the range table is the accessible interface. A thin per-block ribbon MAY sit under it as
  decoration, `aria-hidden`, with a hover read-out; the strip and the range table stay.
- **Blocks by state.** Six tiles, in the order of the taxonomy, each with its count, its
  label and its meaning. Zero counts stay visible. The reasons for a state sit behind a
  disclosure that opens and closes with a button and keeps `aria-expanded` honest.
- **Hash.** Mono, grouped in fours by CSS margins so a manual copy carries no spaces.
  Lists show the first and last 8 characters; detail pages show the full value with a
  labelled copy button.
- **Error panel.** Title, what it means, what to do, and raw errors behind "Technical
  details".
- **Verify report.** The eight steps as an ordered list, each with a tone glyph and a
  word (Passed, Failed, Not run).
- **Checker console** (the client's one interactive part). A bordered 16px panel on the
  inset surface, opening with a label row: the title as an amber mono eyebrow over a
  hairline, the privacy note in muted mono beside it. Under it sit the drop target, the
  verdict banner and the eight steps. Amber is a label colour here, not a fill.
- **Buttons** are a filled surface with ink text and a hairline, never amber. Amber fills
  only the network badge, the update bar, the one primary action on a form, and the
  drawing's `canary check` box.
- **Update bar.** A fixed, non-modal `role="status"` bar in canary amber. It stays until
  the reader reloads or dismisses it.
- **Focus.** A 2px amber ring with a 2px offset on every focusable element.
- **Favicon.** The wordmark's first letter, a C, on its perch in canary amber, on the dark
  ground. `favicon.go` draws it from one set of numbers, as the SVG and as the PNG
  fallbacks, and a test keeps `assets/favicon.svg` equal to it. There is no bird.
- **Icons.** The sprite in `assets/glyphs.svg`, inlined by the `icon` partial, or one inline
  SVG. Never an icon font: the pages load nothing from another origin.
- **Finding headlines.** A server label is a name the user chose, often lower case, so a
  heading introduces it: "Server withholder left out an entry it had signed for."
  `canary status` keeps the bare label, as the formats document pins.

## The public site

`cmd/site` renders the public site to `site/dist` with this design system. It takes the
partials from `Partials()`, the files from `Assets()` and every word from
`wording.Site`, and adds its own stylesheet, `cmd/site/assets/site.css`, for layouts the
dashboard has no use for.

- **Header.** Sticky, 1px rule below, the wordmark and the brand beside it, the nav, and the
  theme toggle. A page that shows a run carries that run's status line in the page head,
  which is where the surface design puts it for recorded runs. The home and doc pages carry
  no status line yet; adding one there needs a wording-table sentence and a data source, so
  it is a decision to take with the developer, not a restyle.
- **Bands.** Each home-page section opens with a mono eyebrow label in canary amber, a rule,
  and one sentence on the right; the body sits under it. No eyebrow label stands above a
  heading anywhere else.
- **The checker console** carries the amber status banner and the eight steps.
- **Drawings.** The docs' Mermaid diagrams become HTML drawings in
  `cmd/site/templates/diagrams.html`: boxes with 1px rules, dashed for what comes after v1,
  and `canary check` in canary amber, because it is Canary. The decision chart is a
  numbered list whose exits are state badges. A test fails when a diagram in the docs gains
  a label its drawing lacks.
- **Doc tables.** A table cell holding exactly a state label shows the state badge.
- **No outside requests.** Pages load only their own files, under the CSP in
  `site/_headers`: no inline styles or scripts, and no link out except the repository.

## Do's and Don'ts

- Do take every state label, reason and message from `wording/copy.go`.
- Do state the limit next to the claim: Checked covers the tweak list, not payments.
- Do set data in mono and keep it tabular.
- Don't use canary amber for a state, or a state colour without its glyph and word.
- Don't add gradients, glass, blur, glows, shadows for depth, emoji, decorative pill shapes,
  stat tiles with invented numbers, or Unicode arrows standing in for icons.
- Don't load anything from another origin, including a font or an icon font. The CSP allows
  only `'self'`.
- Don't copy a number or a claim out of a design mock. Every count, hash, height and
  sentence on a rendered page comes from the run, the evidence file or the wording table.
