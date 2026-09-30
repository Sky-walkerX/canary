// Package indexer is Canary's v1 reference index server. It reads blocks from
// a Bitcoin Core node, computes each block's entries, signs one record per
// block, and serves the HTTP API in the v1 formats doc: /info,
// /commitment/{blockhash} and /tweaks/{blockhash}.
//
// For each block it computes the canonical set, commits to it with a Merkle
// root, and signs that root into a kind-1352 Nostr event with the server's
// key. It stores the signed event and the entries in memory, keyed by block
// hash, and never signs a block twice. Each tweak list it serves carries a
// receipt signed by the same key, including the server's current tip.
//
// The v1 indexer reuses the canonical package, the same code Canary uses to
// check it. That is a deliberate v1 shortcut: it saves building a separate
// indexer, but it means v1 does not test two independent implementations
// against each other. When the indexer's results match Canary's, that tests
// the protocol, not the entry computation.
//
// Config.WithholdTxID makes the server misbehave on purpose, for the demo. It
// still signs an honest record for every block, then leaves that one entry
// out of every list it serves. /info does not reveal it. Canary has to catch
// the server from its own signatures.
package indexer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
	"github.com/Sky-walkerX/canary/internal/core"
	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// Software names the server program in /info.
type Software struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Build   string `json:"build"`
}

// Config sets up an Indexer.
type Config struct {
	// Core reads the Bitcoin Core node the server indexes.
	Core *core.Client

	// Key is the server's secret key. It signs every record and every
	// receipt, so a client pins one pubkey for both.
	Key [32]byte

	// WithholdTxID, when set, names one transaction by its txid in internal
	// order. The server marks that entry absent in every list it serves,
	// while its signed record still includes it. It exists for the demo.
	WithholdTxID *[32]byte

	// Software fills the software object in /info.
	Software Software

	// Logger receives sync progress and internal errors. Nil logs to stderr.
	Logger *log.Logger
}

// record is everything the server keeps about one indexed block.
type record struct {
	height uint32
	prev   [32]byte // the parent block's hash, internal order
	leaves []canonical.Leaf
	event  []byte // the signed kind-1352 event, exactly as served
}

// Indexer indexes one Core node and serves the v1 HTTP API.
type Indexer struct {
	core     *core.Client
	key      [32]byte
	pubkey   [32]byte
	withhold *[32]byte
	software Software
	log      *log.Logger

	syncMu  sync.Mutex // one Sync at a time
	lastErr string     // the last sync error logged, guarded by syncMu

	mu     sync.RWMutex
	ready  bool                 // the first sync reached Core's tip
	net    canonical.Network    // set by the first successful chain read
	active [][32]byte           // active[h] is the block at height h on the chain the server follows
	blocks map[[32]byte]*record // every block ever indexed, keyed by hash in internal order
}

// New checks cfg and returns an Indexer that has indexed nothing yet. Every
// route answers not_ready until the first Sync reaches Core's tip.
func New(cfg Config) (*Indexer, error) {
	if cfg.Core == nil {
		return nil, errors.New("indexer: config: no Core client")
	}
	pub, err := PublicKey(cfg.Key)
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stderr, "canary-indexer: ", log.LstdFlags)
	}
	var withhold *[32]byte
	if cfg.WithholdTxID != nil {
		id := *cfg.WithholdTxID
		withhold = &id
	}
	return &Indexer{
		core:     cfg.Core,
		key:      cfg.Key,
		pubkey:   pub,
		withhold: withhold,
		software: cfg.Software,
		log:      logger,
		blocks:   make(map[[32]byte]*record),
	}, nil
}

// PublicKey returns the 32-byte x-only public key for a secret key. It
// rejects a zero key and a key not below the curve order.
func PublicKey(sk [32]byte) ([32]byte, error) {
	var out [32]byte
	var d btcec.ModNScalar
	if overflow := d.SetBytes(&sk); overflow != 0 || d.IsZero() {
		return out, errors.New("indexer: secret key: zero or not below the curve order")
	}
	priv := btcec.PrivKeyFromScalar(&d)
	defer priv.Zero()
	copy(out[:], schnorr.SerializePubKey(priv.PubKey()))
	return out, nil
}

// PubKey returns the server's x-only public key, the one clients pin.
func (x *Indexer) PubKey() [32]byte { return x.pubkey }

// Tip returns the height and hash of the last block the server indexed on
// the chain it follows. ok is false before anything is indexed.
func (x *Indexer) Tip() (height uint32, hash [32]byte, ok bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.tipLocked()
}

func (x *Indexer) tipLocked() (uint32, [32]byte, bool) {
	if len(x.active) == 0 {
		return 0, [32]byte{}, false
	}
	h := len(x.active) - 1
	return uint32(h), x.active[h], true
}

// Run syncs with Core every poll until ctx ends. A failed sync is logged and
// retried on the next tick. The log repeats an error only when it changes.
func (x *Indexer) Run(ctx context.Context, poll time.Duration) {
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		if err := x.Sync(ctx); err != nil && ctx.Err() == nil {
			x.syncMu.Lock()
			if msg := err.Error(); msg != x.lastErr {
				x.log.Printf("sync failed, retrying every %s: %v", poll, err)
				x.lastErr = msg
			}
			x.syncMu.Unlock()
		} else if err == nil {
			x.syncMu.Lock()
			if x.lastErr != "" {
				x.log.Printf("sync recovered")
				x.lastErr = ""
			}
			x.syncMu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// errChainMoved means Core's chain changed while a sync was reading it. The
// next sync starts again from the fork point.
var errChainMoved = errors.New("indexer: sync: Core's chain changed during the sync")

// Sync indexes every block from the server's tip to Core's tip. If Core's
// chain has reorganized, it first steps back to the last block both agree
// on. Blocks that leave the active chain keep their records, served by hash,
// because a block hash names one block at one height forever.
//
// A block that fails stops the sync there. The server never skips a block,
// because a missing record would read as a gap it chose.
func (x *Indexer) Sync(ctx context.Context) error {
	x.syncMu.Lock()
	defer x.syncMu.Unlock()

	info, err := x.core.ChainInfo(ctx)
	if err != nil {
		return err
	}
	net, err := core.NetworkFromChain(info.Chain)
	if err != nil {
		return err
	}

	x.mu.Lock()
	if x.net != 0 && x.net != net {
		x.mu.Unlock()
		return fmt.Errorf("indexer: sync: Core is on %s, but this server signed records for %s; restart it against the node it started with",
			core.NetworkName(net), core.NetworkName(x.net))
	}
	x.net = net
	active := append([][32]byte(nil), x.active...)
	x.mu.Unlock()

	start, err := x.forkPoint(ctx, active, info.Height)
	if err != nil {
		return err
	}
	if start < len(active) {
		x.log.Printf("Core's chain changed: %d blocks from height %d left the chain this server follows; their records stay served by hash", len(active)-start, start)
		x.mu.Lock()
		x.active = x.active[:start]
		x.mu.Unlock()
	}

	first := -1
	for h := uint32(start); h <= info.Height; h++ {
		if err := x.indexHeight(ctx, net, h); err != nil {
			x.logProgress(first, int(h)-1)
			return err
		}
		if first < 0 {
			first = int(h)
		}
	}
	x.logProgress(first, int(info.Height))

	x.mu.Lock()
	x.ready = true
	x.mu.Unlock()
	return nil
}

func (x *Indexer) logProgress(first, last int) {
	if first < 0 || last < first {
		return
	}
	_, tip, _ := x.Tip()
	if first == last {
		x.log.Printf("indexed height %d, tip %s", last, core.DisplayHex(tip))
		return
	}
	x.log.Printf("indexed heights %d to %d, tip %s", first, last, core.DisplayHex(tip))
}

// forkPoint returns the first height to index: one above the highest block
// on which the server's chain and Core's chain agree.
func (x *Indexer) forkPoint(ctx context.Context, active [][32]byte, coreHeight uint32) (int, error) {
	h := len(active) - 1
	for ; h >= 0; h-- {
		if uint32(h) > coreHeight {
			continue
		}
		hash, err := x.core.BlockHash(ctx, uint32(h))
		if err != nil {
			return 0, err
		}
		if [32]byte(hash) == active[h] {
			break
		}
	}
	return h + 1, nil
}

// indexHeight indexes the block at height h on Core's chain and makes it the
// server's tip. A block indexed before, for example on both sides of a
// reorg, keeps its first record.
func (x *Indexer) indexHeight(ctx context.Context, net canonical.Network, h uint32) error {
	hash, err := x.core.BlockHash(ctx, h)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return fmt.Errorf("%w: height %d is gone: %v", errChainMoved, h, err)
		}
		return err
	}
	blockHash := [32]byte(hash)

	x.mu.RLock()
	rec, seen := x.blocks[blockHash]
	var parent [32]byte
	if h > 0 && int(h) <= len(x.active) {
		parent = x.active[h-1]
	}
	x.mu.RUnlock()

	if !seen {
		rec, err = x.buildRecord(ctx, net, h, hash, parent)
		if err != nil {
			return err
		}
	} else if rec.height != h {
		return fmt.Errorf("indexer: index height %d: block %s was indexed at height %d", h, core.DisplayHex(blockHash), rec.height)
	} else if h > 0 && rec.prev != parent {
		return fmt.Errorf("%w: block %d does not build on the server's block %d", errChainMoved, h, h-1)
	}

	x.mu.Lock()
	defer x.mu.Unlock()
	if len(x.active) != int(h) {
		return fmt.Errorf("%w: expected to extend height %d, the server's chain has %d blocks", errChainMoved, h, len(x.active))
	}
	if !seen {
		x.blocks[blockHash] = rec
	}
	x.active = append(x.active, blockHash)
	return nil
}

// buildRecord computes the block's entries and signs its record.
func (x *Indexer) buildRecord(ctx context.Context, net canonical.Network, h uint32, hash chainhash.Hash, parent [32]byte) (*record, error) {
	blk, err := x.core.Block(ctx, hash)
	if err != nil {
		return nil, err
	}
	if h > 0 && [32]byte(blk.Header.PrevBlock) != parent {
		return nil, fmt.Errorf("%w: block %d does not build on the server's block %d", errChainMoved, h, h-1)
	}
	pv, err := x.core.Prevouts(ctx, blk)
	if err != nil {
		return nil, err
	}
	leaves, err := canonical.Set(net, blk, pv)
	if err != nil {
		return nil, fmt.Errorf("indexer: entries for block %d %s: %w", h, core.DisplayHex(hash), err)
	}

	c := feed.Commitment{
		Network:     net,
		BlockHash:   hash,
		BlockHeight: h,
		N:           uint32(len(leaves)),
		Root:        commit.Root(net, hash, leaves),
		// PolicyRef stays zero: v1 publishes no signed policy declaration.
		Author: x.pubkey,
	}
	ev, err := c.ToEvent(x.key)
	if err != nil {
		return nil, fmt.Errorf("indexer: sign record for block %d: %w", h, err)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("indexer: encode record for block %d: %w", h, err)
	}
	return &record{height: h, prev: blk.Header.PrevBlock, leaves: leaves, event: raw}, nil
}

// pubkeyHex is the server's pubkey as /info prints it.
func (x *Indexer) pubkeyHex() string { return hex.EncodeToString(x.pubkey[:]) }
