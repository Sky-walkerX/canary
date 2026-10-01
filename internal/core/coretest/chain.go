// Package coretest builds a synthetic regtest chain and serves it over HTTP
// the way Bitcoin Core's REST interface does. Tests use it so that nothing
// needs a running node.
//
// The chain keeps a real UTXO set. Every coinbase pays four funding outputs,
// two P2WPKH and two P2TR, each to a fresh key. A test builds a transaction
// that spends funding outputs of the kinds it names, then mines it. The chain
// records the output each input spent, which is exactly what Core's
// /rest/spenttxouts reports.
//
// The blocks are well-formed: headers link, and each merkle root is correct.
// They carry no proof of work and no witness commitment, and signatures are
// dummy bytes, because nothing in Canary checks any of these. The BIP-352
// input keys are real, so the tweaks are the ones a real node would yield.
package coretest

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// InputKind names the kind of funding output a transaction spends.
type InputKind int

const (
	// P2WPKH is a version 0 witness key-hash output. Its spend carries a
	// dummy signature and the compressed public key.
	P2WPKH InputKind = iota + 1

	// P2TR is a taproot output, spent on the key path with a dummy 64-byte
	// signature.
	P2TR
)

// fundingValue is what each coinbase funding output pays, in satoshis.
const fundingValue = 1_250_000_000

// fee is what each built transaction leaves for the miner, in satoshis.
const fee = 1_000

type keyInfo struct {
	key  *btcec.PrivateKey
	kind InputKind
}

type funding struct {
	op   wire.OutPoint
	kind InputKind
	key  *btcec.PrivateKey
}

type block struct {
	msg    *wire.MsgBlock
	height uint32
	spent  [][]*wire.TxOut // per transaction, per input
}

// Chain is a synthetic regtest chain. Its methods are safe for concurrent use,
// so a test can mine while an indexer reads it over HTTP.
type Chain struct {
	t  testing.TB
	mu sync.Mutex

	active []chainhash.Hash          // active[h] is the block at height h
	blocks map[chainhash.Hash]*block // every block ever mined, like Core's block index

	utxos    map[wire.OutPoint]*wire.TxOut
	funding  []funding // coinbase funding outputs of the active chain, oldest first
	reserved map[wire.OutPoint]bool
	keyring  map[string]keyInfo // scriptPubKey to the key that controls it

	nextKey uint64
	nonce   uint32 // never reset, so a block mined after Reorg gets a new hash
	ibd     bool
	txindex bool // Core's -txindex, for /rest/tx; off by default, as in Core
}

// NewChain returns a chain holding one block, at height 0, whose coinbase
// funds the first spends.
func NewChain(t testing.TB) *Chain {
	c := &Chain{
		t:        t,
		blocks:   make(map[chainhash.Hash]*block),
		utxos:    make(map[wire.OutPoint]*wire.TxOut),
		reserved: make(map[wire.OutPoint]bool),
		keyring:  make(map[string]keyInfo),
	}
	c.Mine()
	return c
}

// Tip returns the height and hash of the active chain's last block.
func (c *Chain) Tip() (uint32, chainhash.Hash) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := len(c.active) - 1
	return uint32(h), c.active[h]
}

// Block returns the active chain's block at height.
func (c *Chain) Block(height uint32) *wire.MsgBlock {
	c.mu.Lock()
	defer c.mu.Unlock()
	if int(height) >= len(c.active) {
		c.t.Fatalf("coretest: block: height %d is above the tip %d", height, len(c.active)-1)
	}
	return c.blocks[c.active[height]].msg
}

// SpentOutputs returns, for the block with hash, the output each input of
// each transaction spent. The coinbase's list is empty.
func (c *Chain) SpentOutputs(hash chainhash.Hash) [][]*wire.TxOut {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.blocks[hash]
	if !ok {
		c.t.Fatalf("coretest: spent outputs: no block %s", hash)
	}
	return b.spent
}

// SetInitialBlockDownload sets the initialblockdownload flag that
// /rest/chaininfo.json reports.
func (c *Chain) SetInitialBlockDownload(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ibd = on
}

// MineEmpty mines n blocks that hold only a coinbase.
func (c *Chain) MineEmpty(n int) []*wire.MsgBlock {
	out := make([]*wire.MsgBlock, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, c.Mine())
	}
	return out
}

// Mine mines one block holding a coinbase and then txs, in that order. Every
// input must spend an output that is unspent at that point in the block.
func (c *Chain) Mine(txs ...*wire.MsgTx) *wire.MsgBlock {
	c.mu.Lock()
	defer c.mu.Unlock()

	height := uint32(len(c.active))
	var prev chainhash.Hash
	if height > 0 {
		prev = c.active[height-1]
	}

	msg := &wire.MsgBlock{}
	all := append([]*wire.MsgTx{c.coinbase(height)}, txs...)
	for _, tx := range all {
		if err := msg.AddTransaction(tx); err != nil {
			c.t.Fatalf("coretest: mine: %v", err)
		}
	}
	msg.Header = wire.BlockHeader{
		Version:    0x20000000,
		PrevBlock:  prev,
		MerkleRoot: merkleRoot(all),
		Timestamp:  time.Unix(1_700_000_000+int64(height)*600, 0),
		Bits:       0x207fffff,
		Nonce:      c.nonce,
	}

	spent, err := c.connect(msg)
	if err != nil {
		c.t.Fatalf("coretest: mine: %v", err)
	}
	hash := msg.BlockHash()
	c.blocks[hash] = &block{msg: msg, height: height, spent: spent}
	c.active = append(c.active, hash)
	return msg
}

// Reorg removes the last depth blocks from the active chain. The server keeps
// serving them by hash, as Core keeps a stale block and its undo data. The
// next Mine builds on the new tip, with a block hash the removed block did not
// have.
func (c *Chain) Reorg(depth int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if depth < 1 || depth >= len(c.active) {
		c.t.Fatalf("coretest: reorg: depth %d, the chain has %d blocks and must keep one", depth, len(c.active))
	}
	c.active = c.active[:len(c.active)-depth]

	// Rebuild the UTXO set and the funding list by replaying the chain.
	c.utxos = make(map[wire.OutPoint]*wire.TxOut)
	c.funding = nil
	c.reserved = make(map[wire.OutPoint]bool)
	for _, h := range c.active {
		if _, err := c.connect(c.blocks[h].msg); err != nil {
			c.t.Fatalf("coretest: reorg: replay %s: %v", h, err)
		}
	}
}

// Reconnect puts a block that Reorg removed back on top of the active chain,
// as Core's reconsiderblock does. The block must build on the current tip.
func (c *Chain) Reconnect(hash chainhash.Hash) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.blocks[hash]
	if !ok {
		c.t.Fatalf("coretest: reconnect: no block %s", hash)
	}
	if b.msg.Header.PrevBlock != c.active[len(c.active)-1] || b.height != uint32(len(c.active)) {
		c.t.Fatalf("coretest: reconnect: block %s does not build on the tip", hash)
	}
	if _, err := c.connect(b.msg); err != nil {
		c.t.Fatalf("coretest: reconnect: %v", err)
	}
	c.active = append(c.active, hash)
}

// PayToTaproot builds a transaction that spends one unspent funding output of
// each kind in inputs, in that order, and pays a single P2TR output. BIP-352
// counts it: it pays taproot and spends eligible inputs. The transaction is
// not mined until a test passes it to Mine.
func (c *Chain) PayToTaproot(inputs ...InputKind) *wire.MsgTx {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pay(P2TR, inputs)
}

// PayToWitnessKeyHash builds the same kind of transaction as PayToTaproot,
// but pays a single P2WPKH output. BIP-352 skips it, because it pays no
// taproot output.
func (c *Chain) PayToWitnessKeyHash(inputs ...InputKind) *wire.MsgTx {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pay(P2WPKH, inputs)
}

func (c *Chain) pay(outKind InputKind, inputs []InputKind) *wire.MsgTx {
	if len(inputs) == 0 {
		c.t.Fatalf("coretest: pay: a transaction needs at least one input")
	}
	tx := wire.NewMsgTx(2)
	var total int64
	for _, kind := range inputs {
		f := c.takeFunding(kind)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: f.op,
			Witness:          witnessFor(f.kind, f.key),
			Sequence:         0xfffffffd,
		})
		total += c.utxos[f.op].Value
	}
	tx.AddTxOut(wire.NewTxOut(total-fee, scriptFor(outKind, c.newKey())))
	return tx
}

// takeFunding reserves the oldest unspent funding output of kind.
func (c *Chain) takeFunding(kind InputKind) funding {
	for _, f := range c.funding {
		if f.kind != kind || c.reserved[f.op] {
			continue
		}
		if _, unspent := c.utxos[f.op]; !unspent {
			continue
		}
		c.reserved[f.op] = true
		return f
	}
	c.t.Fatalf("coretest: pay: no unspent funding output of kind %d; mine more blocks first", kind)
	return funding{}
}

// connect applies msg to the UTXO set in transaction order, so a transaction
// may spend an output created earlier in the same block. It returns the
// output each input spent.
func (c *Chain) connect(msg *wire.MsgBlock) ([][]*wire.TxOut, error) {
	spent := make([][]*wire.TxOut, len(msg.Transactions))
	for i, tx := range msg.Transactions {
		txid := tx.TxHash()
		if i > 0 {
			for _, in := range tx.TxIn {
				out, ok := c.utxos[in.PreviousOutPoint]
				if !ok {
					return nil, errMissing(in.PreviousOutPoint)
				}
				spent[i] = append(spent[i], out)
				delete(c.utxos, in.PreviousOutPoint)
				delete(c.reserved, in.PreviousOutPoint)
			}
		}
		for vout, out := range tx.TxOut {
			op := wire.OutPoint{Hash: txid, Index: uint32(vout)}
			c.utxos[op] = out
			if ki, ok := c.keyring[string(out.PkScript)]; ok && i == 0 {
				c.funding = append(c.funding, funding{op: op, kind: ki.kind, key: ki.key})
			}
		}
	}
	return spent, nil
}

type errMissing wire.OutPoint

func (e errMissing) Error() string {
	return "input spends " + wire.OutPoint(e).String() + ", which is not unspent"
}

// coinbase builds a coinbase that pays four funding outputs to fresh keys.
// Its script holds the height and a nonce that no other block reuses.
func (c *Chain) coinbase(height uint32) *wire.MsgTx {
	c.nonce++
	sig := []byte{0x04}
	sig = binary.LittleEndian.AppendUint32(sig, height)
	sig = append(sig, 0x04)
	sig = binary.LittleEndian.AppendUint32(sig, c.nonce)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: wire.MaxPrevOutIndex},
		SignatureScript:  sig,
		Sequence:         wire.MaxTxInSequenceNum,
	})
	for _, kind := range []InputKind{P2WPKH, P2TR, P2WPKH, P2TR} {
		key := c.newKey()
		script := scriptFor(kind, key)
		c.keyring[string(script)] = keyInfo{key: key, kind: kind}
		tx.AddTxOut(wire.NewTxOut(fundingValue, script))
	}
	return tx
}

// newKey derives a fresh key from a counter, so every run builds the same
// chain.
func (c *Chain) newKey() *btcec.PrivateKey {
	c.nextKey++
	seed := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("canary/coretest/key"), c.nextKey))
	key, _ := btcec.PrivKeyFromBytes(seed[:])
	return key
}

func scriptFor(kind InputKind, key *btcec.PrivateKey) []byte {
	switch kind {
	case P2WPKH:
		return append([]byte{0x00, 0x14}, btcutil.Hash160(key.PubKey().SerializeCompressed())...)
	case P2TR:
		return append([]byte{0x51, 0x20}, schnorr.SerializePubKey(key.PubKey())...)
	}
	panic("coretest: unknown input kind")
}

func witnessFor(kind InputKind, key *btcec.PrivateKey) wire.TxWitness {
	switch kind {
	case P2WPKH:
		sig := make([]byte, 71)
		sig[0] = 0x30
		return wire.TxWitness{sig, key.PubKey().SerializeCompressed()}
	case P2TR:
		sig := make([]byte, 64)
		sig[0] = 0x01
		return wire.TxWitness{sig}
	}
	panic("coretest: unknown input kind")
}

// merkleRoot is Bitcoin's transaction merkle root: double SHA-256 over txids,
// pairing the last node with itself on an odd level.
func merkleRoot(txs []*wire.MsgTx) chainhash.Hash {
	level := make([]chainhash.Hash, len(txs))
	for i, tx := range txs {
		level[i] = tx.TxHash()
	}
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([]chainhash.Hash, len(level)/2)
		for i := range next {
			var buf [64]byte
			copy(buf[:32], level[2*i][:])
			copy(buf[32:], level[2*i+1][:])
			next[i] = chainhash.DoubleHashH(buf[:])
		}
		level = next
	}
	return level[0]
}
