package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/policy"
)

// Response size limits. They stop a server from streaming without end. A
// list's limit comes from its record, in listLimit. maxListBody caps it
// anyway: 64 MiB holds a million full entries, far past any block.
//
// maxRecordBody is 4 KiB. An honest record is about 700 bytes, because every
// field it carries has a bounded length. A server can still sign extra tags
// into its own record, and the record verifies. canary check keeps each
// valid record until the run ends, so this limit is also the most one
// server's record costs the run per block: a few times an honest record.
const (
	maxInfoBody   = 1 << 20
	maxRecordBody = 4 << 10
	maxListBody   = 64 << 20
)

// listLimit is the most bytes a list of n positions can take: the 4-byte
// count, then n positions of at most 1 + 32 + 33 bytes each. A longer answer
// cannot be a list of n positions. Reading no more keeps the decoder from
// building millions of positions for a record that names a few, because each
// 1-byte absent position becomes about 98 bytes in memory.
func listLimit(n uint32) int64 {
	return min(4+66*int64(n), maxListBody)
}

// maxDownStreak is how many requests in a row may fail to get any answer
// before canary check stops asking that server. Its remaining blocks read as
// unreachable, so one dead server cannot hold the run for a timeout per block.
// The list pass starts a new count.
const maxDownStreak = 3

// answer sorts one response into what canary check does with it.
type answer int

const (
	// answerOK is a 200 with a body.
	answerOK answer = iota
	// answerNone is 404 unknown_block: the server has nothing for this hash.
	answerNone
	// answerDown is no answer, a 5xx such as internal or not_ready, or a
	// body over the limit. It carries no signature, so it proves nothing.
	answerDown
	// answerUnusable is an answer a v1 server never gives Canary, such as
	// bad_block_hash or not_found. canary check records it like an outage,
	// as the server refusing one block or its /info. It stops the run only
	// for a server that proves nothing in the run: none of its records
	// verified and its /info was not canary-info/1. That points to a wrong
	// URL or a bug.
	answerUnusable
	// answerSkipped means Canary did not send the request, because the
	// server's last requests got no answer. The server refused nothing.
	answerSkipped
	// answerStopped means the run was interrupted. It says nothing about the
	// server, so canary check stops without saving anything.
	answerStopped
)

// response is one indexer response, sorted.
type response struct {
	kind   answer
	body   []byte
	header http.Header
	err    error // what went wrong, for the server's error field
}

// indexerClient reads one server's v1 HTTP API.
type indexerClient struct {
	base   string
	hc     *http.Client
	streak int // requests in a row with no answer at all
}

// get fetches one path and sorts the response. A request cut short by an
// interrupted run is answerStopped, never answerDown, so an interrupt is never
// held against the server.
func (x *indexerClient) get(ctx context.Context, path string, limit int64) response {
	if err := ctx.Err(); err != nil {
		return response{kind: answerStopped, err: fmt.Errorf("canary: GET %s: %w", path, err)}
	}
	if x.streak >= maxDownStreak {
		return response{kind: answerSkipped, err: fmt.Errorf("canary: GET %s: not sent after %d requests in a row got no answer", path, maxDownStreak)}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, x.base+path, nil)
	if err != nil {
		return response{kind: answerUnusable, err: fmt.Errorf("canary: GET %s: %w", path, err)}
	}
	resp, err := x.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return response{kind: answerStopped, err: fmt.Errorf("canary: GET %s: %w", path, err)}
		}
		x.streak++
		return response{kind: answerDown, err: fmt.Errorf("canary: GET %s: %w", path, err)}
	}
	defer resp.Body.Close()
	x.streak = 0

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	switch {
	case err != nil && ctx.Err() != nil:
		return response{kind: answerStopped, err: fmt.Errorf("canary: GET %s: read body: %w", path, err)}
	case err != nil:
		return response{kind: answerDown, err: fmt.Errorf("canary: GET %s: read body: %w", path, err)}
	case int64(len(body)) > limit:
		return response{kind: answerDown, err: fmt.Errorf("canary: GET %s: the response is longer than %d bytes", path, limit)}
	}

	code := errorCode(body)
	switch {
	case resp.StatusCode == http.StatusOK:
		return response{kind: answerOK, body: body, header: resp.Header}
	case resp.StatusCode == http.StatusNotFound && code == "unknown_block":
		return response{kind: answerNone, err: fmt.Errorf("canary: GET %s: unknown_block", path)}
	case resp.StatusCode >= 500:
		return response{kind: answerDown, err: fmt.Errorf("canary: GET %s: status %d %s", path, resp.StatusCode, code)}
	}
	return response{kind: answerUnusable, err: fmt.Errorf("canary: GET %s: status %d %s", path, resp.StatusCode, code)}
}

// errorCode reads the code from the v1 error shape, or "" for any other
// body.
func errorCode(body []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	return e.Error.Code
}

// newPass starts a new count of requests with no answer. canary check calls
// it before the list pass, so a server that went quiet while Canary read
// records is asked for its lists, in case it came back.
func (x *indexerClient) newPass() { x.streak = 0 }

// commitment fetches /commitment/{blockhash}. The URL carries the hash in
// display order.
func (x *indexerClient) commitment(ctx context.Context, hash [32]byte) response {
	return x.get(ctx, "/commitment/"+core.DisplayHex(hash), maxRecordBody)
}

// tweaks fetches /tweaks/{blockhash} for a block whose valid record names n
// entries. canary check always asks for no dust threshold, because it checks
// the full list, not a wallet's filtered view. A body longer than any list of
// n positions is over the limit, so it counts as no answer.
func (x *indexerClient) tweaks(ctx context.Context, hash [32]byte, n uint32) response {
	return x.get(ctx, "/tweaks/"+core.DisplayHex(hash)+"?dust_sat=0", listLimit(n))
}

// serverInfo is what canary check reads from /info. The server signs none of
// it, so it serves display and routing only, never evidence.
type serverInfo struct {
	tipHeight uint32
	tipHash   string         // display order
	policy    *policy.Policy // nil when the server declared none
}

// errInfoFormat means /info is not canary-info/1.
var errInfoFormat = errors.New("canary: /info: not canary-info/1")

// info fetches /info. The info is nil when the server gave no usable answer,
// and the response then says why.
func (x *indexerClient) info(ctx context.Context) (*serverInfo, response) {
	r := x.get(ctx, "/info", maxInfoBody)
	if r.kind != answerOK {
		if r.kind == answerNone {
			r.kind = answerUnusable
		}
		return nil, r
	}
	var raw struct {
		Format *string `json:"format"`
		Tip    *struct {
			Height *uint32 `json:"height"`
			Hash   *string `json:"hash"`
		} `json:"tip"`
		StartHeight uint32 `json:"start_height"`
		Policy      *struct {
			PrunesSpent      *bool   `json:"prunes_spent"`
			DustThresholdSat *uint64 `json:"dust_threshold_sat"`
			DustConfigurable *bool   `json:"dust_configurable"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(r.body, &raw); err != nil {
		return nil, response{kind: answerUnusable, err: fmt.Errorf("%w: %v", errInfoFormat, err)}
	}
	if raw.Format == nil || *raw.Format != "canary-info/1" || raw.Tip == nil || raw.Tip.Height == nil || raw.Tip.Hash == nil {
		return nil, response{kind: answerUnusable, err: errInfoFormat}
	}
	if _, err := core.ParseDisplayHash(*raw.Tip.Hash); err != nil {
		return nil, response{kind: answerUnusable, err: fmt.Errorf("%w: tip hash: %v", errInfoFormat, err)}
	}
	info := &serverInfo{tipHeight: *raw.Tip.Height, tipHash: *raw.Tip.Hash}
	if p := raw.Policy; p != nil && p.PrunesSpent != nil && p.DustThresholdSat != nil && p.DustConfigurable != nil {
		info.policy = &policy.Policy{
			StartHeight:      raw.StartHeight,
			PrunesSpent:      *p.PrunesSpent,
			DustThresholdSat: *p.DustThresholdSat,
			DustConfigurable: *p.DustConfigurable,
		}
	}
	return info, r
}
