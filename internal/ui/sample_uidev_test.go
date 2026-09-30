//go:build uidev

package ui

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sky-walkerX/canary/internal/state"
)

// TestSampleScenariosCarryTheWatermark serves every scenario and checks that
// every page says it shows sample data.
func TestSampleScenariosCarryTheWatermark(t *testing.T) {
	for _, sc := range SampleScenarios {
		t.Run(sc, func(t *testing.T) {
			dir := t.TempDir()
			path, err := WriteSample(dir, sc, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			h, err := New(Options{StatePath: path, Verify: SampleVerify})
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{"/", "/blocks", "/findings", "/nope"} {
				req := httptest.NewRequest(http.MethodGet, p, nil)
				req.Host = "localhost"
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if !strings.Contains(rec.Body.String(), watermark) {
					t.Errorf("%s %s: no watermark", sc, p)
				}
			}
		})
	}
}

func TestSampleStateIsValid(t *testing.T) {
	for _, clear := range []bool{false, true} {
		f := SampleState(time.Now(), filepath.Join(t.TempDir(), "evidence"), clear)
		if err := f.Validate(); err != nil {
			t.Fatalf("clear=%v: %v", clear, err)
		}
		if f.Checked.Len() != len(f.Blocks) {
			t.Errorf("clear=%v: %d blocks for %d heights", clear, len(f.Blocks), f.Checked.Len())
		}
		if !clear && f.Findings[0].ID != "827a8d3f502e" {
			t.Errorf("withheld finding id = %s, want the formats document's 827a8d3f502e", f.Findings[0].ID)
		}
		if clear && f.Counts.NotPassed() != 0 {
			t.Error("the clear scenario has blocks that did not pass")
		}
	}
	_ = state.Format
}
