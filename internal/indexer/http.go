package indexer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/wire"
)

// Content types and cache rules from the v1 formats doc.
const (
	contentJSON   = "application/json"
	contentTweaks = "application/vnd.canary.tweaks.v1"

	// A record never changes, because the server signs each block once.
	cacheRecord = "public, max-age=31536000, immutable"
	// A list's receipt carries the current tip, so nothing may cache it.
	cacheNone = "no-store"
)

// Info is the body of GET /info. The server signs none of it, so a client
// uses it for display and routing, never as evidence.
type Info struct {
	Format          string      `json:"format"`
	Software        Software    `json:"software"`
	Network         InfoNetwork `json:"network"`
	PubKey          string      `json:"pubkey"`
	Tip             InfoTip     `json:"tip"`
	StartHeight     uint32      `json:"start_height"`
	RetentionWindow int         `json:"retention_window"`
	Policy          InfoPolicy  `json:"policy"`
	RecordKind      int         `json:"record_kind"`
	SignsReceipts   bool        `json:"signs_receipts"`
}

// InfoNetwork names the network by its name and its magic, in decimal.
type InfoNetwork struct {
	Name  string `json:"name"`
	Magic uint32 `json:"magic"`
}

// InfoTip is the server's best block. Hash is in display order.
type InfoTip struct {
	Height uint32 `json:"height"`
	Hash   string `json:"hash"`
}

// InfoPolicy is what the server says it subtracts. v1 does not sign it.
type InfoPolicy struct {
	PrunesSpent      bool   `json:"prunes_spent"`
	DustThresholdSat uint64 `json:"dust_threshold_sat"`
	DustConfigurable bool   `json:"dust_configurable"`
}

// Handler serves GET and HEAD on /info, /commitment/{blockhash} and
// /tweaks/{blockhash}. Every error is JSON in one shape and carries no
// receipt.
func (x *Indexer) Handler() http.Handler {
	return http.HandlerFunc(x.serveHTTP)
}

type route int

const (
	routeInfo route = iota + 1
	routeCommitment
	routeTweaks
)

func (x *Indexer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	rt, segment, ok := matchRoute(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found",
			"No such route. This server serves /info, /commitment/{blockhash} and /tweaks/{blockhash}.", "")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET and HEAD are allowed.", "")
		return
	}

	var blockHash [32]byte
	if rt != routeInfo {
		h, err := core.ParseDisplayHash(segment)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_block_hash",
				"The block hash must be 64 lowercase hex characters, in display order.", "")
			return
		}
		blockHash = h
	}
	if rt == routeTweaks {
		if code, msg := checkDustParam(r.URL.RawQuery); code != "" {
			writeError(w, http.StatusBadRequest, code, msg, "")
			return
		}
	}

	x.mu.RLock()
	ready := x.ready
	x.mu.RUnlock()
	if !ready {
		writeError(w, http.StatusServiceUnavailable, "not_ready",
			"The server has not finished its first sync with Bitcoin Core.", "")
		return
	}

	switch rt {
	case routeInfo:
		x.serveInfo(w)
	case routeCommitment:
		x.serveCommitment(w, blockHash)
	case routeTweaks:
		x.serveTweaks(w, blockHash)
	}
}

// matchRoute splits a path into a route and its block-hash segment. A path
// with more segments than the route takes is no route at all.
func matchRoute(path string) (route, string, bool) {
	if path == "/info" {
		return routeInfo, "", true
	}
	for prefix, rt := range map[string]route{"/commitment/": routeCommitment, "/tweaks/": routeTweaks} {
		if seg, ok := strings.CutPrefix(path, prefix); ok {
			if strings.Contains(seg, "/") {
				return 0, "", false
			}
			return rt, seg, true
		}
	}
	return 0, "", false
}

// checkDustParam accepts no dust_sat, or dust_sat=0 once. The reference
// indexer applies no dust threshold, and /info says so.
func checkDustParam(rawQuery string) (code, message string) {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "unsupported_parameter", "The query string does not parse."
	}
	vals, ok := q["dust_sat"]
	if !ok {
		return "", ""
	}
	if len(vals) != 1 {
		return "unsupported_parameter", "Give dust_sat at most once."
	}
	n, err := strconv.ParseUint(vals[0], 10, 64)
	if err != nil {
		return "unsupported_parameter", "dust_sat must be a whole number of satoshis."
	}
	if n != 0 {
		return "unsupported_parameter", "This server applies no dust threshold, so it accepts only dust_sat=0."
	}
	return "", ""
}

func (x *Indexer) serveInfo(w http.ResponseWriter) {
	x.mu.RLock()
	height, tip, _ := x.tipLocked()
	net := x.net
	x.mu.RUnlock()

	// Nothing here mentions the withholding switch. Canary has to catch the
	// server without the server confessing.
	info := Info{
		Format:          "canary-info/1",
		Software:        x.software,
		Network:         InfoNetwork{Name: core.NetworkName(net), Magic: uint32(net)},
		PubKey:          x.pubkeyHex(),
		Tip:             InfoTip{Height: height, Hash: core.DisplayHex(tip)},
		StartHeight:     0,
		RetentionWindow: wire.RetentionWindow,
		Policy:          InfoPolicy{},
		RecordKind:      feed.KindCommitment,
		SignsReceipts:   true,
	}
	body, err := json.Marshal(info)
	if err != nil {
		x.internalError(w, "/info", err)
		return
	}
	write(w, contentJSON, cacheNone, append(body, '\n'))
}

func (x *Indexer) serveCommitment(w http.ResponseWriter, blockHash [32]byte) {
	x.mu.RLock()
	rec, ok := x.blocks[blockHash]
	x.mu.RUnlock()
	if !ok {
		writeUnknownBlock(w)
		return
	}
	write(w, contentJSON, cacheRecord, rec.event)
}

func (x *Indexer) serveTweaks(w http.ResponseWriter, blockHash [32]byte) {
	x.mu.RLock()
	rec, ok := x.blocks[blockHash]
	tipHeight, tipHash, _ := x.tipLocked()
	net := x.net
	x.mu.RUnlock()
	if !ok {
		writeUnknownBlock(w)
		return
	}

	positions := make([]wire.Position, len(rec.leaves))
	for i, leaf := range rec.leaves {
		if x.withhold != nil && leaf.TxID == *x.withhold {
			// The demo's attack: leave the entry out of what is served. The
			// signed record still includes it, and the receipt below signs
			// this list with the gap.
			positions[i] = wire.Position{Kind: wire.KindAbsent}
			continue
		}
		positions[i] = wire.Position{Kind: wire.KindFull, Leaf: leaf}
	}
	body, err := wire.EncodeResponse(positions)
	if err != nil {
		x.internalError(w, "/tweaks", err)
		return
	}

	receipt, err := wire.SignReceipt(wire.Receipt{
		Network:    net,
		Resource:   wire.ResourceTweakList,
		BlockHash:  blockHash,
		DustSat:    0,
		TipHeight:  tipHeight,
		TipHash:    tipHash,
		BodySHA256: sha256.Sum256(body),
	}, x.key)
	if err != nil {
		x.internalError(w, "/tweaks", err)
		return
	}
	w.Header().Set(wire.ReceiptHeader, wire.EncodeReceiptHeader(receipt))
	write(w, contentTweaks, cacheNone, body)
}

// internalError logs err under a fresh id and answers 500 with that id, so
// the id in the response names the line in the log.
func (x *Indexer) internalError(w http.ResponseWriter, where string, err error) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	x.log.Printf("error_id=%s %s: %v", id, where, err)
	writeError(w, http.StatusInternalServerError, "internal", "The server failed. The error_id names the line in its log.", id)
}

func writeUnknownBlock(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "unknown_block", "No block with this hash in this server's index.", "")
}

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string  `json:"code"`
	Message string  `json:"message"`
	ErrorID *string `json:"error_id"`
}

// writeError writes the one error shape. An empty errorID is JSON null.
func writeError(w http.ResponseWriter, status int, code, message, errorID string) {
	e := errorBody{Error: errorDetail{Code: code, Message: message}}
	if errorID != "" {
		e.Error.ErrorID = &errorID
	}
	body, err := json.Marshal(e)
	if err != nil {
		// errorBody holds only strings, so this cannot fail.
		body = []byte(fmt.Sprintf(`{"error":{"code":"internal","message":%q,"error_id":null}}`, err.Error()))
	}
	h := w.Header()
	h.Set("Content-Type", contentJSON)
	h.Set("Cache-Control", cacheNone)
	h.Set("Content-Length", strconv.Itoa(len(body)+1))
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

// write sends a 200 with an explicit length, so HEAD reports the size too.
func write(w http.ResponseWriter, contentType, cacheControl string, body []byte) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Cache-Control", cacheControl)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
