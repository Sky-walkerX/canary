package indexer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sky-walkerX/canary/wire"
)

// wantError checks one error response against the formats doc: the status,
// the code, the exact JSON shape, and no receipt.
func wantError(t *testing.T, resp *http.Response, body []byte, status int, code string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Errorf("status %d, want %d; body %s", resp.StatusCode, status, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q, want application/json", ct)
	}
	if resp.Header.Get(wire.ReceiptHeader) != "" {
		t.Error("an error response carries a receipt; it must carry none")
	}
	var e struct {
		Error struct {
			Code    string  `json:"code"`
			Message string  `json:"message"`
			ErrorID *string `json:"error_id"`
		} `json:"error"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		t.Fatalf("error body %s does not match the error shape: %v", body, err)
	}
	if e.Error.Code != code {
		t.Errorf("code %q, want %q", e.Error.Code, code)
	}
	if e.Error.Message == "" {
		t.Error("error message is empty")
	}
	if code != "internal" && e.Error.ErrorID != nil {
		t.Errorf("error_id = %q, want null outside internal errors", *e.Error.ErrorID)
	}
	if !bytes.Contains(body, []byte(`"error_id":null`)) && code != "internal" {
		t.Errorf("error_id must be present as null: %s", body)
	}
}

func TestErrorResponses(t *testing.T) {
	f := newFixture(t)
	s := startServer(t, f.rest, 1)
	s.sync(t)

	unknown := strings.Repeat("ab", 32)
	cases := []struct {
		name, method, path string
		status             int
		code               string
	}{
		{"unknown block, record", "GET", "/commitment/" + unknown, 404, "unknown_block"},
		{"unknown block, list", "GET", "/tweaks/" + unknown, 404, "unknown_block"},
		{"uppercase hash", "GET", "/commitment/" + strings.ToUpper(f.hash()), 400, "bad_block_hash"},
		{"short hash", "GET", "/tweaks/" + f.hash()[:63], 400, "bad_block_hash"},
		{"long hash", "GET", "/tweaks/" + f.hash() + "0", 400, "bad_block_hash"},
		{"not hex", "GET", "/tweaks/" + strings.Repeat("zz", 32), 400, "bad_block_hash"},
		{"empty hash", "GET", "/commitment/", 400, "bad_block_hash"},
		{"height, not hash", "GET", "/tweaks/2", 400, "bad_block_hash"},
		{"dust threshold", "GET", "/tweaks/" + f.hash() + "?dust_sat=546", 400, "unsupported_parameter"},
		{"dust not a number", "GET", "/tweaks/" + f.hash() + "?dust_sat=abc", 400, "unsupported_parameter"},
		{"dust negative", "GET", "/tweaks/" + f.hash() + "?dust_sat=-1", 400, "unsupported_parameter"},
		{"dust twice", "GET", "/tweaks/" + f.hash() + "?dust_sat=0&dust_sat=0", 400, "unsupported_parameter"},
		{"dust empty", "GET", "/tweaks/" + f.hash() + "?dust_sat=", 400, "unsupported_parameter"},
		{"bad query", "GET", "/tweaks/" + f.hash() + "?dust_sat=%zz", 400, "unsupported_parameter"},
		{"other path", "GET", "/blocks", 404, "not_found"},
		{"root", "GET", "/", 404, "not_found"},
		{"extra segment", "GET", "/commitment/" + f.hash() + "/raw", 404, "not_found"},
		{"height route", "GET", "/tweaks/height/2", 404, "not_found"},
		{"post info", "POST", "/info", 405, "method_not_allowed"},
		{"put list", "PUT", "/tweaks/" + f.hash(), 405, "method_not_allowed"},
		{"delete record", "DELETE", "/commitment/" + f.hash(), 405, "method_not_allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := s.do(t, tc.method, tc.path)
			wantError(t, resp, body, tc.status, tc.code)
			if tc.status == 405 && resp.Header.Get("Allow") != "GET, HEAD" {
				t.Errorf("Allow = %q, want \"GET, HEAD\"", resp.Header.Get("Allow"))
			}
		})
	}
}

func TestExplicitZeroDustIsTheDefault(t *testing.T) {
	f := newFixture(t)
	s := startServer(t, f.rest, 1)
	s.sync(t)

	_, plain := s.get(t, "/tweaks/"+f.hash())
	resp, zero := s.get(t, "/tweaks/"+f.hash()+"?dust_sat=0")
	if resp.StatusCode != http.StatusOK || !bytes.Equal(plain, zero) {
		t.Errorf("dust_sat=0: status %d, body differs from the default: %v", resp.StatusCode, !bytes.Equal(plain, zero))
	}
	if got := resp.Header.Get("Content-Type"); got != "application/vnd.canary.tweaks.v1" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store: the receipt carries the current tip", got)
	}
}

func TestHeadReturnsHeadersOnly(t *testing.T) {
	f := newFixture(t)
	s := startServer(t, f.rest, 1)
	s.sync(t)

	_, full := s.get(t, "/tweaks/"+f.hash())
	resp, body := s.do(t, http.MethodHead, "/tweaks/"+f.hash())
	if resp.StatusCode != http.StatusOK || len(body) != 0 {
		t.Errorf("HEAD: status %d, %d body bytes, want 200 and none", resp.StatusCode, len(body))
	}
	if resp.ContentLength != int64(len(full)) {
		t.Errorf("HEAD Content-Length %d, want %d", resp.ContentLength, len(full))
	}
	if resp.Header.Get(wire.ReceiptHeader) == "" {
		t.Error("HEAD carries no receipt header")
	}
	for _, path := range []string{"/info", "/commitment/" + f.hash()} {
		resp, body := s.do(t, http.MethodHead, path)
		if resp.StatusCode != http.StatusOK || len(body) != 0 {
			t.Errorf("HEAD %s: status %d, %d body bytes", path, resp.StatusCode, len(body))
		}
	}
}

// Until the first sync reaches Core's tip, every route answers not_ready.
func TestNotReadyBeforeFirstSync(t *testing.T) {
	f := newFixture(t)
	s := startServer(t, f.rest, 1)

	for _, path := range []string{"/info", "/commitment/" + f.hash(), "/tweaks/" + f.hash()} {
		resp, body := s.get(t, path)
		wantError(t, resp, body, http.StatusServiceUnavailable, "not_ready")
	}
	s.sync(t)
	if resp, _ := s.get(t, "/info"); resp.StatusCode != http.StatusOK {
		t.Errorf("after the first sync, /info status %d, want 200", resp.StatusCode)
	}
}

func TestSyncFailsWhileCoreIsUnreachable(t *testing.T) {
	dead := httptest.NewServer(nil)
	url := dead.URL + "/rest"
	dead.Close()

	s := startServer(t, url, 1)
	if err := s.idx.Sync(context.Background()); err == nil {
		t.Fatal("sync against an unreachable Core succeeded")
	}
	resp, body := s.get(t, "/info")
	wantError(t, resp, body, http.StatusServiceUnavailable, "not_ready")
}
