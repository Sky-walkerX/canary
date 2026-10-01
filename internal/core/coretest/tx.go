package coretest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// maxUTXOOutpoints is Core's MAX_GETUTXOS_OUTPOINTS.
const maxUTXOOutpoints = 15

// SetTxIndex turns Core's -txindex on or off. With it off, the default as in
// Core, /rest/tx finds no confirmed transaction. The chain has no mempool, so
// it then finds nothing at all.
func (c *Chain) SetTxIndex(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.txindex = on
}

// findTx looks for txid on the active chain. It is what Core's transaction
// index answers.
func (c *Chain) findTx(txid chainhash.Hash) (*wire.MsgTx, chainhash.Hash, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.txindex {
		return nil, chainhash.Hash{}, false
	}
	for _, h := range c.active {
		for _, tx := range c.blocks[h].msg.Transactions {
			if tx.TxHash() == txid {
				return tx, h, true
			}
		}
	}
	return nil, chainhash.Hash{}, false
}

// serveTx answers /rest/tx/<txid>.<ext>. The JSON form carries the fields
// Canary reads, hex and blockhash, as Core's TxToUniv writes them.
func (c *Chain) serveTx(w http.ResponseWriter, part string) {
	param, ext := splitFormat(part)
	txid, err := chainhash.NewHashFromStr(param)
	if err != nil || len(param) != 64 {
		restError(w, http.StatusBadRequest, "Invalid hash: "+param)
		return
	}
	tx, block, ok := c.findTx(*txid)
	if !ok {
		restError(w, http.StatusNotFound, param+" not found")
		return
	}
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		restError(w, http.StatusInternalServerError, err.Error())
		return
	}
	switch ext {
	case "bin":
		reply(w, "application/octet-stream", buf.Bytes())
	case "hex":
		reply(w, "text/plain", []byte(hex.EncodeToString(buf.Bytes())+"\n"))
	case "json":
		body, _ := json.Marshal(struct {
			TxID      string `json:"txid"`
			Hash      string `json:"hash"`
			Hex       string `json:"hex"`
			BlockHash string `json:"blockhash"`
		}{txid.String(), tx.WitnessHash().String(), hex.EncodeToString(buf.Bytes()), block.String()})
		reply(w, "application/json", append(body, '\n'))
	default:
		restError(w, http.StatusNotFound, "output format not found (available: json, bin, hex)")
	}
}

// serveUTXOs answers /rest/getutxos/[checkmempool/]<txid>-<n>/....json with
// the active chain's UTXO set. The chain has no mempool, so checkmempool
// changes nothing. Only the JSON form is served.
func (c *Chain) serveUTXOs(w http.ResponseWriter, part string) {
	param, ext := splitFormat(part)
	if ext != "json" {
		restError(w, http.StatusNotFound, "coretest serves /rest/getutxos only as json")
		return
	}
	parts := strings.Split(strings.TrimPrefix(param, "checkmempool/"), "/")
	if len(parts) > maxUTXOOutpoints {
		restError(w, http.StatusBadRequest, fmt.Sprintf("Error: max outpoints exceeded (max: %d, tried: %d)", maxUTXOOutpoints, len(parts)))
		return
	}
	ops := make([]wire.OutPoint, 0, len(parts))
	for _, p := range parts {
		txidHex, nStr, ok := strings.Cut(p, "-")
		txid, err := chainhash.NewHashFromStr(txidHex)
		n, nerr := strconv.ParseUint(nStr, 10, 32)
		if !ok || err != nil || nerr != nil || len(txidHex) != 64 {
			restError(w, http.StatusBadRequest, "Parse error")
			return
		}
		ops = append(ops, wire.OutPoint{Hash: *txid, Index: uint32(n)})
	}

	type utxo struct {
		Value        float64           `json:"value"`
		ScriptPubKey map[string]string `json:"scriptPubKey"`
	}
	c.mu.Lock()
	tipHeight := len(c.active) - 1
	tipHash := c.active[tipHeight]
	var bitmap strings.Builder
	utxos := []utxo{}
	for _, op := range ops {
		out, ok := c.utxos[op]
		if !ok {
			bitmap.WriteByte('0')
			continue
		}
		bitmap.WriteByte('1')
		utxos = append(utxos, utxo{
			Value:        float64(out.Value) / 1e8,
			ScriptPubKey: map[string]string{"hex": hex.EncodeToString(out.PkScript)},
		})
	}
	c.mu.Unlock()

	body, _ := json.Marshal(struct {
		ChainHeight  int    `json:"chainHeight"`
		ChaintipHash string `json:"chaintipHash"`
		Bitmap       string `json:"bitmap"`
		UTXOs        []utxo `json:"utxos"`
	}{tipHeight, tipHash.String(), bitmap.String(), utxos})
	reply(w, "application/json", append(body, '\n'))
}
