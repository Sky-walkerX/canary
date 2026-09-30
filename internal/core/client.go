// Package core reads a Bitcoin Core node over its unauthenticated REST
// interface. Core must run with -rest=1. The client needs no RPC credentials.
//
// It reads four things: the chain tip, the block hash at a height, a raw
// block, and the outputs a block's inputs spend. The last comes from
// /rest/spenttxouts, added in Core v30, so the client needs Core v30 or
// later. Together they give the canonical package everything it needs to
// compute a block's entries.
//
// Hashes cross this package in internal order. The package converts to and
// from display order in one place, ParseDisplayHash and DisplayHex.
package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// ErrNotFound means Core answered 404. It has no block at that height on its
// active chain, or no block or undo data for that hash.
var ErrNotFound = errors.New("core: not found")

// Response size limits. Core is the user's own node, so these only stop a
// wrong URL from streaming without end.
const (
	maxInfoSize  = 1 << 20
	maxHashSize  = 32
	maxBlockSize = 16 << 20
	maxSpentSize = 64 << 20
)

// Client reads one Core node's REST interface.
type Client struct {
	base string // ends in /rest, with no trailing slash
	hc   *http.Client
}

// New returns a client for the REST base URL, for example
// http://127.0.0.1:18443/rest. A nil hc gets a client with a 30-second
// timeout.
func New(baseURL string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("core: REST URL: want a URL like http://127.0.0.1:18443/rest, got %q", baseURL)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), hc: hc}, nil
}

// ChainInfo is the part of Core's getblockchaininfo that Canary reads.
type ChainInfo struct {
	// Chain is Core's name for its network: "main", "test", "testnet4",
	// "signet" or "regtest". NetworkFromChain turns it into a magic.
	Chain string

	// Height is the height of Core's best block.
	Height uint32

	// BestHash is the hash of that block, in internal order.
	BestHash chainhash.Hash

	// InitialBlockDownload is true while Core is still catching up.
	InitialBlockDownload bool
}

// ChainInfo reads /rest/chaininfo.json.
func (c *Client) ChainInfo(ctx context.Context) (ChainInfo, error) {
	body, err := c.get(ctx, "/chaininfo.json", maxInfoSize)
	if err != nil {
		return ChainInfo{}, err
	}
	var raw struct {
		Chain                *string `json:"chain"`
		Blocks               *int64  `json:"blocks"`
		BestBlockHash        *string `json:"bestblockhash"`
		InitialBlockDownload *bool   `json:"initialblockdownload"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return ChainInfo{}, fmt.Errorf("core: chain info: %w", err)
	}
	if raw.Chain == nil || raw.Blocks == nil || raw.BestBlockHash == nil || raw.InitialBlockDownload == nil {
		return ChainInfo{}, errors.New("core: chain info: chain, blocks, bestblockhash or initialblockdownload is missing")
	}
	if *raw.Blocks < 0 || *raw.Blocks > math.MaxUint32 {
		return ChainInfo{}, fmt.Errorf("core: chain info: height %d is out of range", *raw.Blocks)
	}
	best, err := ParseDisplayHash(*raw.BestBlockHash)
	if err != nil {
		return ChainInfo{}, fmt.Errorf("core: chain info: bestblockhash: %w", err)
	}
	return ChainInfo{
		Chain:                *raw.Chain,
		Height:               uint32(*raw.Blocks),
		BestHash:             best,
		InitialBlockDownload: *raw.InitialBlockDownload,
	}, nil
}

// BlockHash returns the hash of the block at height on Core's active chain.
// A height above Core's tip fails with ErrNotFound.
func (c *Client) BlockHash(ctx context.Context, height uint32) (chainhash.Hash, error) {
	body, err := c.get(ctx, "/blockhashbyheight/"+strconv.FormatUint(uint64(height), 10)+".bin", maxHashSize)
	if err != nil {
		return chainhash.Hash{}, err
	}
	if len(body) != 32 {
		return chainhash.Hash{}, fmt.Errorf("core: block hash at height %d: %d bytes, want 32", height, len(body))
	}
	// The binary form is the 32 bytes in internal order, so no reversal.
	var h chainhash.Hash
	copy(h[:], body)
	return h, nil
}

// Block returns the block with hash, with its witness data. It checks that
// the block Core sent hashes to the hash asked for.
func (c *Client) Block(ctx context.Context, hash chainhash.Hash) (*wire.MsgBlock, error) {
	body, err := c.get(ctx, "/block/"+DisplayHex(hash)+".bin", maxBlockSize)
	if err != nil {
		return nil, err
	}
	var blk wire.MsgBlock
	if err := blk.Deserialize(bytes.NewReader(body)); err != nil {
		return nil, fmt.Errorf("core: block %s: %w", DisplayHex(hash), err)
	}
	if got := blk.BlockHash(); got != hash {
		return nil, fmt.Errorf("core: block %s: Core sent block %s instead", DisplayHex(hash), DisplayHex(got))
	}
	return &blk, nil
}

// SpentOutputs returns the outputs spent by the block with hash, one list per
// transaction, as DecodeSpentOutputs describes.
func (c *Client) SpentOutputs(ctx context.Context, hash chainhash.Hash) ([][]*wire.TxOut, error) {
	body, err := c.get(ctx, "/spenttxouts/"+DisplayHex(hash)+".bin", maxSpentSize)
	if err != nil {
		return nil, err
	}
	return DecodeSpentOutputs(body)
}

// Prevouts fetches the outputs blk spends and pairs them with its inputs.
// The result is the canonical.PrevoutSource for blk.
func (c *Client) Prevouts(ctx context.Context, blk *wire.MsgBlock) (*BlockPrevouts, error) {
	spent, err := c.SpentOutputs(ctx, blk.BlockHash())
	if err != nil {
		return nil, err
	}
	return NewBlockPrevouts(blk, spent)
}

// get fetches one REST path and returns the body of a 200 response. A 404
// wraps ErrNotFound. Any other status is an error that quotes Core's
// message.
func (c *Client) get(ctx context.Context, path string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, fmt.Errorf("core: GET %s: %w", path, err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("core: GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("core: GET %s: read body: %w", path, err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%w: GET %s: %s", ErrNotFound, path, quote(body))
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("core: GET %s: status %d: %s", path, resp.StatusCode, quote(body))
	case int64(len(body)) > limit:
		return nil, fmt.Errorf("core: GET %s: response is longer than %d bytes", path, limit)
	}
	return body, nil
}

// quote trims Core's plain-text error message and caps its length.
func quote(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	if s == "" {
		return "no message"
	}
	return strconv.Quote(s)
}
