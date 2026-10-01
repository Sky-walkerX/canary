package testvector

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// Prevout is one output that a transaction in the block spends.
type Prevout struct {
	ScriptPubKey string `json:"scriptPubKey"`
	Value        int64  `json:"value"`
}

// Expected is what a correct implementation computes from the vector.
type Expected struct {
	N      uint32   `json:"n"`      // number of entries in the canonical set
	Leaves []string `json:"leaves"` // each entry as "<txid display hex>:<tweak hex>"
	Root   string   `json:"root"`   // the root, hex, as a signed record carries it
}

// Vector is one test vector, as stored in testdata/vectors.
type Vector struct {
	Name string `json:"name"`
	// Network is a display name. The root binds the 4-byte network magic.
	Network string `json:"network"`
	// Block is the full serialized block, hex.
	Block string `json:"block"`
	// Prevouts is keyed "<txid display hex>:<vout>", the form Core's REST API uses.
	Prevouts  map[string]Prevout `json:"prevouts"`
	Expected  Expected           `json:"expected"`
	Rationale string             `json:"rationale"`
}

// Load reads a vector from path. It rejects unknown fields, so a misspelled
// field name fails loudly instead of leaving a zero value behind.
func Load(path string) (Vector, error) {
	var v Vector
	raw, err := os.ReadFile(path)
	if err != nil {
		return v, fmt.Errorf("testvector: read vector: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, fmt.Errorf("testvector: decode %s: %w", path, err)
	}
	return v, nil
}

// mapPrevouts serves spent outputs from the vector's own map, so no node is
// needed.
type mapPrevouts map[wire.OutPoint]*wire.TxOut

func (m mapPrevouts) Prevout(op wire.OutPoint) (*wire.TxOut, error) {
	out, ok := m[op]
	if !ok {
		return nil, fmt.Errorf("not in the vector's prevouts")
	}
	return out, nil
}

func networkFromName(name string) (canonical.Network, error) {
	switch name {
	case "main", "mainnet":
		return canonical.Network(chaincfg.MainNetParams.Net), nil
	case "signet":
		return canonical.Network(chaincfg.SigNetParams.Net), nil
	case "regtest":
		return canonical.Network(chaincfg.RegressionNetParams.Net), nil
	default:
		return 0, fmt.Errorf("testvector: read network: unknown name %q", name)
	}
}

// Run recomputes the canonical set and the root from the vector's own data and
// compares them with Expected. Because Expected carries the root, a vector
// tests the Merkle tree's tagged hashes and odd-node promotion too, not
// eligibility alone.
func (v Vector) Run() error {
	net, err := networkFromName(v.Network)
	if err != nil {
		return err
	}

	blockBytes, err := hex.DecodeString(v.Block)
	if err != nil {
		return fmt.Errorf("testvector: decode block hex: %w", err)
	}
	var blk wire.MsgBlock
	if err := blk.Deserialize(bytes.NewReader(blockBytes)); err != nil {
		return fmt.Errorf("testvector: deserialize block: %w", err)
	}

	pv := mapPrevouts{}
	for key, p := range v.Prevouts {
		parts := strings.Split(key, ":")
		if len(parts) != 2 {
			return fmt.Errorf("testvector: parse prevout key: %q is not <txid>:<vout>", key)
		}
		h, err := chainhash.NewHashFromStr(parts[0]) // display hex
		if err != nil {
			return fmt.Errorf("testvector: parse prevout key %q: %w", key, err)
		}
		vout, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("testvector: parse prevout key %q: %w", key, err)
		}
		spk, err := hex.DecodeString(p.ScriptPubKey)
		if err != nil {
			return fmt.Errorf("testvector: decode prevout %q scriptPubKey: %w", key, err)
		}
		pv[wire.OutPoint{Hash: *h, Index: uint32(vout)}] = wire.NewTxOut(p.Value, spk)
	}

	leaves, err := canonical.Set(net, &blk, pv)
	if err != nil {
		return fmt.Errorf("testvector: compute canonical set: %w", err)
	}

	if uint32(len(leaves)) != v.Expected.N {
		return fmt.Errorf("testvector: check n: got %d, want %d", len(leaves), v.Expected.N)
	}

	if len(leaves) != len(v.Expected.Leaves) {
		return fmt.Errorf("testvector: check entries: got %d, want %d", len(leaves), len(v.Expected.Leaves))
	}
	for i, l := range leaves {
		var disp [32]byte
		for j := 0; j < 32; j++ {
			disp[j] = l.TxID[31-j] // internal -> display order
		}
		got := hex.EncodeToString(disp[:]) + ":" + hex.EncodeToString(l.Tweak[:])
		if got != v.Expected.Leaves[i] {
			return fmt.Errorf("testvector: check entry %d: got %s, want %s", i, got, v.Expected.Leaves[i])
		}
	}

	blockHash := blk.BlockHash()
	var bh [32]byte
	copy(bh[:], blockHash[:]) // chainhash is already internal order

	gotRoot := commit.Root(net, bh, leaves)
	if got := hex.EncodeToString(gotRoot[:]); got != v.Expected.Root {
		return fmt.Errorf("testvector: check root: got %s, want %s", got, v.Expected.Root)
	}
	return nil
}
