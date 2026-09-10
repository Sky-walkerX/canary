// Package testvector implements §7.4's self-contained vector format. A vector
// carries a whole block plus the prevouts a node would otherwise supply, so any
// implementation can consume it with no node and no network.
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

type Prevout struct {
	ScriptPubKey string `json:"scriptPubKey"`
	Value        int64  `json:"value"`
}

type Expected struct {
	N      uint32   `json:"n"`
	Leaves []string `json:"leaves"` // "<txid display hex>:<tweak hex>"
	Root   string   `json:"root"`
}

type Vector struct {
	Name string `json:"name"`
	// Network is a display name; the root binds the 4-byte magic (§3.2).
	Network string `json:"network"`
	// Block is the full serialized block, hex.
	Block string `json:"block"`
	// Prevouts is keyed "<txid display hex>:<vout>" — Core's REST form.
	Prevouts  map[string]Prevout `json:"prevouts"`
	Expected  Expected           `json:"expected"`
	Rationale string             `json:"rationale"`
}

func Load(path string) (Vector, error) {
	var v Vector
	raw, err := os.ReadFile(path)
	if err != nil {
		return v, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

type mapPrevouts map[wire.OutPoint]*wire.TxOut

func (m mapPrevouts) Prevout(op wire.OutPoint) (*wire.TxOut, error) {
	out, ok := m[op]
	if !ok {
		return nil, fmt.Errorf("prevout %s not in vector", op)
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
		return 0, fmt.Errorf("unknown network %q", name)
	}
}

// Run recomputes the canonical set and the root from the vector's own data and
// compares against expected. Including expected.root means the vectors exercise
// §3.2's tagged hashing and odd-node promotion, not eligibility alone (§7.4).
func (v Vector) Run() error {
	net, err := networkFromName(v.Network)
	if err != nil {
		return err
	}

	blockBytes, err := hex.DecodeString(v.Block)
	if err != nil {
		return fmt.Errorf("block hex: %w", err)
	}
	var blk wire.MsgBlock
	if err := blk.Deserialize(bytes.NewReader(blockBytes)); err != nil {
		return fmt.Errorf("deserialize block: %w", err)
	}

	pv := mapPrevouts{}
	for key, p := range v.Prevouts {
		parts := strings.Split(key, ":")
		if len(parts) != 2 {
			return fmt.Errorf("prevout key %q is not <txid>:<vout>", key)
		}
		h, err := chainhash.NewHashFromStr(parts[0]) // display hex
		if err != nil {
			return fmt.Errorf("prevout key %q: %w", key, err)
		}
		vout, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("prevout key %q: %w", key, err)
		}
		spk, err := hex.DecodeString(p.ScriptPubKey)
		if err != nil {
			return fmt.Errorf("prevout %q scriptPubKey: %w", key, err)
		}
		pv[wire.OutPoint{Hash: *h, Index: uint32(vout)}] = wire.NewTxOut(p.Value, spk)
	}

	leaves, err := canonical.Set(net, &blk, pv)
	if err != nil {
		return fmt.Errorf("canonical.Set: %w", err)
	}

	if uint32(len(leaves)) != v.Expected.N {
		return fmt.Errorf("n = %d, want %d", len(leaves), v.Expected.N)
	}

	if len(leaves) != len(v.Expected.Leaves) {
		return fmt.Errorf("leaves count = %d, want %d", len(leaves), len(v.Expected.Leaves))
	}
	for i, l := range leaves {
		var disp [32]byte
		for j := 0; j < 32; j++ {
			disp[j] = l.TxID[31-j] // internal -> display order
		}
		got := hex.EncodeToString(disp[:]) + ":" + hex.EncodeToString(l.Tweak[:])
		if got != v.Expected.Leaves[i] {
			return fmt.Errorf("leaf %d = %s, want %s", i, got, v.Expected.Leaves[i])
		}
	}

	blockHash := blk.BlockHash()
	var bh [32]byte
	copy(bh[:], blockHash[:]) // chainhash is already internal order

	gotRoot := commit.Root(net, bh, leaves)
	if got := hex.EncodeToString(gotRoot[:]); got != v.Expected.Root {
		return fmt.Errorf("root = %s, want %s", got, v.Expected.Root)
	}
	return nil
}
