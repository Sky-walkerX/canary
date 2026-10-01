package coretest

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// Serve starts an HTTP server for c and returns its REST base URL, the value
// a user passes as --core-rest, for example http://127.0.0.1:54321/rest. The
// server stops when the test ends.
func Serve(t testing.TB, c *Chain) string {
	t.Helper()
	srv := httptest.NewServer(c)
	t.Cleanup(srv.Close)
	return srv.URL + "/rest"
}

// ServeHTTP answers the REST routes Canary reads, in the formats Bitcoin Core
// v30 writes them (src/rest.cpp):
//
//	/rest/chaininfo.json
//	/rest/blockhashbyheight/<height>.<bin|hex|json>
//	/rest/block/<hash>.<bin|hex>
//	/rest/spenttxouts/<hash>.<bin|hex>
//	/rest/tx/<txid>.<bin|hex|json>
//	/rest/getutxos/<txid>-<n>/....json
//
// Binary bodies match Core byte for byte. The chaininfo JSON carries the
// fields Canary reads plus a few others, in Core's order. Errors use Core's
// plain-text messages, each ending in CRLF.
func (c *Chain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		restError(w, http.StatusMethodNotAllowed, "only GET is supported here")
		return
	}
	p := r.URL.Path
	switch {
	case p == "/rest/chaininfo.json":
		c.serveChainInfo(w)
	case strings.HasPrefix(p, "/rest/blockhashbyheight/"):
		c.serveBlockHash(w, strings.TrimPrefix(p, "/rest/blockhashbyheight/"))
	case strings.HasPrefix(p, "/rest/block/notxdetails/"):
		restError(w, http.StatusNotFound, "coretest does not serve /rest/block/notxdetails")
	case strings.HasPrefix(p, "/rest/block/"):
		c.serveBlock(w, strings.TrimPrefix(p, "/rest/block/"))
	case strings.HasPrefix(p, "/rest/spenttxouts/"):
		c.serveSpent(w, strings.TrimPrefix(p, "/rest/spenttxouts/"))
	case strings.HasPrefix(p, "/rest/tx/"):
		c.serveTx(w, strings.TrimPrefix(p, "/rest/tx/"))
	case strings.HasPrefix(p, "/rest/getutxos/"):
		c.serveUTXOs(w, strings.TrimPrefix(p, "/rest/getutxos/"))
	default:
		http.NotFound(w, r)
	}
}

func (c *Chain) serveChainInfo(w http.ResponseWriter) {
	c.mu.Lock()
	tip := c.blocks[c.active[len(c.active)-1]]
	ibd := c.ibd
	c.mu.Unlock()

	// A struct keeps Core's field order, which a map would not.
	body, _ := json.Marshal(struct {
		Chain                string   `json:"chain"`
		Blocks               uint32   `json:"blocks"`
		Headers              uint32   `json:"headers"`
		BestBlockHash        string   `json:"bestblockhash"`
		Bits                 string   `json:"bits"`
		Time                 int64    `json:"time"`
		MedianTime           int64    `json:"mediantime"`
		VerificationProgress int      `json:"verificationprogress"`
		InitialBlockDownload bool     `json:"initialblockdownload"`
		Pruned               bool     `json:"pruned"`
		Warnings             []string `json:"warnings"`
	}{
		Chain:                "regtest",
		Blocks:               tip.height,
		Headers:              tip.height,
		BestBlockHash:        tip.msg.BlockHash().String(),
		Bits:                 "207fffff",
		Time:                 tip.msg.Header.Timestamp.Unix(),
		MedianTime:           tip.msg.Header.Timestamp.Unix(),
		VerificationProgress: 1,
		InitialBlockDownload: ibd,
		Warnings:             []string{},
	})
	reply(w, "application/json", append(body, '\n'))
}

func (c *Chain) serveBlockHash(w http.ResponseWriter, part string) {
	param, ext := splitFormat(part)
	height, err := strconv.ParseInt(param, 10, 32)
	if err != nil || height < 0 {
		restError(w, http.StatusBadRequest, "Invalid height: "+param)
		return
	}
	c.mu.Lock()
	var hash chainhash.Hash
	found := int(height) < len(c.active)
	if found {
		hash = c.active[height]
	}
	c.mu.Unlock()
	if !found {
		restError(w, http.StatusNotFound, "Block height out of range")
		return
	}

	switch ext {
	case "bin":
		// Core serializes a uint256 as its 32 bytes in internal order.
		reply(w, "application/octet-stream", hash[:])
	case "hex":
		reply(w, "text/plain", []byte(hash.String()+"\n"))
	case "json":
		body, _ := json.Marshal(map[string]string{"blockhash": hash.String()})
		reply(w, "application/json", append(body, '\n'))
	default:
		restError(w, http.StatusNotFound, "output format not found (available: json, bin, hex)")
	}
}

func (c *Chain) lookup(w http.ResponseWriter, param string) (*block, bool) {
	raw, err := hex.DecodeString(param)
	if err != nil || len(raw) != 32 {
		restError(w, http.StatusBadRequest, "Invalid hash: "+param)
		return nil, false
	}
	var hash chainhash.Hash
	for i := 0; i < 32; i++ {
		hash[i] = raw[31-i] // the path is display order
	}
	c.mu.Lock()
	b, ok := c.blocks[hash]
	c.mu.Unlock()
	if !ok {
		restError(w, http.StatusNotFound, param+" not found")
		return nil, false
	}
	return b, true
}

func (c *Chain) serveBlock(w http.ResponseWriter, part string) {
	param, ext := splitFormat(part)
	b, ok := c.lookup(w, param)
	if !ok {
		return
	}
	var buf bytes.Buffer
	if err := b.msg.Serialize(&buf); err != nil {
		restError(w, http.StatusInternalServerError, err.Error())
		return
	}
	switch ext {
	case "bin":
		reply(w, "application/octet-stream", buf.Bytes())
	case "hex":
		reply(w, "text/plain", []byte(hex.EncodeToString(buf.Bytes())+"\n"))
	default:
		restError(w, http.StatusNotFound, "output format not found (available: bin, hex)")
	}
}

func (c *Chain) serveSpent(w http.ResponseWriter, part string) {
	param, ext := splitFormat(part)
	b, ok := c.lookup(w, param)
	if !ok {
		return
	}
	body := encodeSpent(b.spent)
	switch ext {
	case "bin":
		reply(w, "application/octet-stream", body)
	case "hex":
		reply(w, "text/plain", []byte(hex.EncodeToString(body)+"\n"))
	default:
		restError(w, http.StatusNotFound, "output format not found (available: bin, hex)")
	}
}

// encodeSpent writes what Core's SerializeBlockUndo writes: a compact-size
// count of transactions, then per transaction a compact-size count of spent
// outputs followed by each output as an int64 value and a length-prefixed
// script. The coinbase's count is 0. This is written out by hand, apart from
// core.DecodeSpentOutputs, so a test that pairs them checks one against the
// other.
func encodeSpent(spent [][]*wire.TxOut) []byte {
	var b []byte
	b = appendCompactSize(b, uint64(len(spent)))
	for _, list := range spent {
		b = appendCompactSize(b, uint64(len(list)))
		for _, out := range list {
			b = binary.LittleEndian.AppendUint64(b, uint64(out.Value))
			b = appendCompactSize(b, uint64(len(out.PkScript)))
			b = append(b, out.PkScript...)
		}
	}
	return b
}

func appendCompactSize(b []byte, n uint64) []byte {
	switch {
	case n < 0xfd:
		return append(b, byte(n))
	case n <= 0xffff:
		return binary.LittleEndian.AppendUint16(append(b, 0xfd), uint16(n))
	case n <= 0xffffffff:
		return binary.LittleEndian.AppendUint32(append(b, 0xfe), uint32(n))
	default:
		return binary.LittleEndian.AppendUint64(append(b, 0xff), n)
	}
}

// splitFormat splits "<param>.<ext>" at the last dot, as Core's
// ParseDataFormat does.
func splitFormat(part string) (param, ext string) {
	i := strings.LastIndexByte(part, '.')
	if i < 0 {
		return part, ""
	}
	return part[:i], part[i+1:]
}

func reply(w http.ResponseWriter, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// restError writes an error the way Core's RESTERR does: plain text, ending
// in CRLF.
func restError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(message + "\r\n"))
}
