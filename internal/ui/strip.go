package ui

import (
	"math"
	"strconv"
	"strings"

	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// The coverage strip is an inline SVG drawn from the state file's run-length
// ranges. It has no viewBox: every x position and width is a percentage of
// the drawn width, while heights, strokes and the hatch pattern stay in real
// pixels. So the hatch keeps its spacing at any width, and a narrow screen
// never squeezes it into a smear.
//
// Each state is drawn in the grammar of its glyph. Checked is a solid band,
// Checked with a gap filled is a band inside a ring, Can't be checked is a
// hatch with a dotted edge, Not checked is hollow, Servers disagree is half
// filled, and Data withheld is solid with a triangle marker above it.
//
// The strip is a picture. The range table under it is the interface for
// anyone who cannot see it.

// Strip geometry in pixels.
const (
	stripHeight   = 76
	markerY       = 2
	markerSize    = 14
	bandY         = 22
	bandHeight    = 32
	axisY         = 58
	labelBaseline = 72

	// hatchPeriod is the distance between hatch lines, and hatchStroke is
	// each line's width. The clear gap between lines is their difference,
	// which must stay at 3px or more.
	hatchPeriod = 6
	hatchStroke = 2

	maxMarkers = 64
	maxLabels  = 4
	// minLabelGap keeps two axis labels at least this far apart, as a
	// percentage of the width.
	minLabelGap = 8.0
)

type stripView struct {
	ID       string
	Summary  string
	Segments []stripSegment
	Markers  []stripMarker
	Labels   []stripLabel

	Height, MarkerY, MarkerSize, MarkerOffset                         int
	BandY, BandHeight, BandMid, BandInnerY, BandInnerHeight, BandHalf int
	AxisY, LabelTickEnd, LabelBaseline                                int
	HatchPeriod, HatchStroke                                          int
}

type stripSegment struct {
	X, W  string
	State string
	Title string
}

type stripMarker struct {
	X     string
	State string
}

type stripLabel struct {
	X      string
	Text   string
	Anchor string
}

func pct(v float64) string {
	return strconv.FormatFloat(math.Round(v*10000)/10000, 'f', -1, 64)
}

func problem(s state.StateCode) bool {
	return s == state.Compromised || s == state.Disputed || s == state.Unresolvable
}

func buildStrip(id string, f *state.File) stripView {
	v := stripView{
		ID:              id,
		Height:          stripHeight,
		MarkerY:         markerY,
		MarkerSize:      markerSize,
		MarkerOffset:    -markerSize / 2,
		BandY:           bandY,
		BandHeight:      bandHeight,
		BandMid:         bandY + bandHeight/2,
		BandInnerY:      bandY + 5,
		BandInnerHeight: bandHeight - 10,
		BandHalf:        bandHeight / 2,
		AxisY:           axisY,
		LabelTickEnd:    axisY + 4,
		LabelBaseline:   labelBaseline,
		HatchPeriod:     hatchPeriod,
		HatchStroke:     hatchStroke,
	}
	from := f.Checked.From
	n := float64(f.Checked.Len())
	at := func(h float64) float64 { return (h - float64(from)) * 100 / n }

	type spot struct {
		x    float64
		text string
	}
	var spots []spot
	for _, c := range f.Coverage {
		x := at(float64(c.From))
		w := float64(c.Len()) * 100 / n
		label := wording.State(string(c.State)).Label
		v.Segments = append(v.Segments, stripSegment{
			X: pct(x), W: pct(w), State: string(c.State),
			Title: "Blocks " + heights(c.From, c.To) + ": " + label,
		})
		if problem(c.State) && len(v.Markers) < maxMarkers {
			v.Markers = append(v.Markers, stripMarker{X: pct(x + w/2), State: string(c.State)})
		}
		if c.State == state.Compromised || c.State == state.Disputed {
			spots = append(spots, spot{x: x + w/2, text: heights(c.From, c.To)})
		}
	}

	// Axis labels: the first and last height, then up to four problem
	// ranges that do not crowd another label.
	v.Labels = []stripLabel{
		{X: "0", Text: strconv.FormatUint(uint64(f.Checked.From), 10), Anchor: "start"},
	}
	if f.Checked.To != f.Checked.From {
		v.Labels = append(v.Labels, stripLabel{X: "100", Text: strconv.FormatUint(uint64(f.Checked.To), 10), Anchor: "end"})
	}
	taken := []float64{0, 100}
	for _, s := range spots {
		if len(v.Labels) >= 2+maxLabels {
			break
		}
		clear := true
		for _, t := range taken {
			if math.Abs(t-s.x) < minLabelGap {
				clear = false
				break
			}
		}
		if clear {
			taken = append(taken, s.x)
			v.Labels = append(v.Labels, stripLabel{X: pct(s.x), Text: s.text, Anchor: "middle"})
		}
	}
	v.Summary = stripSummary(f)
	return v
}

// stripSummary is the strip's one-sentence text alternative.
func stripSummary(f *state.File) string {
	var parts []string
	for _, s := range state.States {
		if n := f.Counts.Get(s); n > 0 {
			parts = append(parts, strconv.FormatUint(uint64(n), 10)+" "+wording.State(string(s)).Label)
		}
	}
	return "Coverage of blocks " + strconv.FormatUint(uint64(f.Checked.From), 10) + " to " +
		strconv.FormatUint(uint64(f.Checked.To), 10) + ": " + strings.Join(parts, "; ") + "."
}
