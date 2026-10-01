package ui

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
)

// The favicon comes from the wordmark: a C, the name's first letter, sitting
// on the perch line that runs on past it. It is drawn on a 32-unit grid. The
// SVG and the PNG fallbacks both come from the numbers below, and a test keeps
// assets/favicon.svg equal to FaviconSVG.
const (
	favGrid   = 32.0
	favRadius = 4.0 // corner radius of the coal square

	// The C: an arc with its opening facing right.
	favCX, favCY = 15.0, 13.5
	favR         = 7.5  // radius to the middle of the stroke
	favStroke    = 4.5  // stroke width
	favOpenDeg   = 42.0 // half the opening, in degrees from the right

	// The perch: a line with round ends, running past the letter.
	favPerchY     = 26.5
	favPerchX0    = 4.5
	favPerchX1    = 27.5
	favPerchWidth = 2.5
)

var (
	favCoal      = color.NRGBA{0x17, 0x16, 0x0F, 0xff}
	favLimestone = color.NRGBA{0xF5, 0xF3, 0xEC, 0xff}
	favCanary    = color.NRGBA{0xF4, 0xE1, 0x3A, 0xff}
)

func favHex(c color.NRGBA) string { return fmt.Sprintf("#%02X%02X%02X", c.R, c.G, c.B) }

// favArcEnds returns the C's two ends: upper right, then lower right.
func favArcEnds() (x, y0, y1 float64) {
	a := favOpenDeg * math.Pi / 180
	return favCX + favR*math.Cos(a), favCY - favR*math.Sin(a), favCY + favR*math.Sin(a)
}

// FaviconSVG returns the favicon as an SVG document.
func FaviconSVG() []byte {
	x, y0, y1 := favArcEnds()
	var b bytes.Buffer
	fmt.Fprintf(&b, "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 %g %g\">\n", favGrid, favGrid)
	fmt.Fprintf(&b, "  <rect width=\"%g\" height=\"%g\" rx=\"%g\" fill=\"%s\"/>\n", favGrid, favGrid, favRadius, favHex(favCoal))
	fmt.Fprintf(&b, "  <path d=\"M%.2f %.2fA%g %g 0 1 0 %.2f %.2f\" fill=\"none\" stroke=\"%s\" stroke-width=\"%g\"/>\n",
		x, y0, favR, favR, x, y1, favHex(favLimestone), favStroke)
	fmt.Fprintf(&b, "  <path d=\"M%g %gH%g\" stroke=\"%s\" stroke-width=\"%g\" stroke-linecap=\"round\"/>\n",
		favPerchX0, favPerchY, favPerchX1, favHex(favCanary), favPerchWidth)
	b.WriteString("</svg>\n")
	return b.Bytes()
}

// FaviconPNG returns the favicon as a size by size PNG, for browsers and
// devices that take no SVG icon. fullBleed fills the corners, for an Apple
// touch icon, which the device masks with its own rounding.
func FaviconPNG(size int, fullBleed bool) []byte {
	const ss = 8 // samples per pixel along each axis
	scale := favGrid / float64(size)
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) * scale
					y := (float64(py) + (float64(sy)+0.5)/ss) * scale
					c, ok := favSample(x, y, fullBleed)
					if !ok {
						continue
					}
					r += float64(c.R)
					g += float64(c.G)
					b += float64(c.B)
					a++
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{
				R: uint8(math.Round(r / a)),
				G: uint8(math.Round(g / a)),
				B: uint8(math.Round(b / a)),
				A: uint8(math.Round(255 * a / (ss * ss))),
			})
		}
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		// Encoding an in-memory NRGBA image cannot fail.
		panic(err)
	}
	return out.Bytes()
}

// favSample returns the colour at one point of the 32-unit grid, and false
// outside the icon.
func favSample(x, y float64, fullBleed bool) (color.NRGBA, bool) {
	if !fullBleed && !inRoundedSquare(x, y) {
		return color.NRGBA{}, false
	}
	// The perch paints over the letter, as it does in the SVG.
	if dist := segmentDist(x, y, favPerchX0, favPerchY, favPerchX1, favPerchY); dist <= favPerchWidth/2 {
		return favCanary, true
	}
	dx, dy := x-favCX, y-favCY
	d := math.Hypot(dx, dy)
	angle := math.Abs(math.Atan2(-dy, dx)) * 180 / math.Pi
	if math.Abs(d-favR) <= favStroke/2 && angle >= favOpenDeg {
		return favLimestone, true
	}
	return favCoal, true
}

func inRoundedSquare(x, y float64) bool {
	if x < 0 || y < 0 || x > favGrid || y > favGrid {
		return false
	}
	cx := math.Min(math.Max(x, favRadius), favGrid-favRadius)
	cy := math.Min(math.Max(y, favRadius), favGrid-favRadius)
	return math.Hypot(x-cx, y-cy) <= favRadius
}

func segmentDist(x, y, x0, y0, x1, y1 float64) float64 {
	vx, vy := x1-x0, y1-y0
	t := ((x-x0)*vx + (y-y0)*vy) / (vx*vx + vy*vy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(x-(x0+t*vx), y-(y0+t*vy))
}
