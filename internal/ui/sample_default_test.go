//go:build !uidev

package ui

import (
	"net/http"
	"strings"
	"testing"
)

// TestNoSampleDataInDefaultBuild renders every page of a default build and
// checks that none carries the sample-data watermark. Sample data exists only
// behind the uidev build tag.
func TestNoSampleDataInDefaultBuild(t *testing.T) {
	if watermark != "" {
		t.Fatalf("the default build has a watermark: %q", watermark)
	}
	routes := []string{"/", "/blocks", "/blocks/" + exampleBlock, "/findings", "/findings/" + exampleFinding, "/nope", "/state.etag"}
	for _, raw := range [][]byte{exampleState(t), nil, []byte("broken"), []byte(`{"format":"canary-state/2"}`)} {
		fx := newFixture(t, raw, nil)
		for _, p := range routes {
			rec := fx.do(http.MethodGet, p)
			body := rec.Body.String()
			for _, banned := range []string{"SAMPLE DATA", "not a real run", `class="watermark"`} {
				if strings.Contains(body, banned) {
					t.Errorf("GET %s contains %q in a default build", p, banned)
				}
			}
		}
	}
}
