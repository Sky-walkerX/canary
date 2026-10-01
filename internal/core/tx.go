package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// maxTxSize bounds one /rest/tx response. The JSON form carries the
// transaction twice, as hex and decoded.
const maxTxSize = 8 << 20

// maxUTXOBatch is Core's limit on outpoints in one /rest/getutxos request.
const maxUTXOBatch = 15

// Transaction reads one transaction from /rest/tx/<txid>.json. block is the
// confirming block's hash, or nil while the transaction is unconfirmed.
//
// Core finds a confirmed transaction only when it runs with -txindex=1.
// Without the index it searches its mempool alone, and a confirmed
// transaction fails with ErrNotFound.
func (c *Client) Transaction(ctx context.Context, txid chainhash.Hash) (*wire.MsgTx, *chainhash.Hash, error) {
	body, err := c.get(ctx, "/tx/"+DisplayHex(txid)+".json", maxTxSize)
	if err != nil {
		return nil, nil, err
	}
	var raw struct {
		Hex       *string `json:"hex"`
		BlockHash *string `json:"blockhash"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil, fmt.Errorf("core: transaction %s: %w", DisplayHex(txid), err)
	}
	if raw.Hex == nil {
		return nil, nil, fmt.Errorf("core: transaction %s: the response has no hex field", DisplayHex(txid))
	}
	b, err := hex.DecodeString(*raw.Hex)
	if err != nil {
		return nil, nil, fmt.Errorf("core: transaction %s: hex: %w", DisplayHex(txid), err)
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(b)); err != nil {
		return nil, nil, fmt.Errorf("core: transaction %s: %w", DisplayHex(txid), err)
	}
	if got := tx.TxHash(); got != txid {
		return nil, nil, fmt.Errorf("core: transaction %s: Core sent transaction %s instead", DisplayHex(txid), DisplayHex(got))
	}
	if raw.BlockHash == nil {
		return &tx, nil, nil
	}
	h, err := ParseDisplayHash(*raw.BlockHash)
	if err != nil {
		return nil, nil, fmt.Errorf("core: transaction %s: blockhash: %w", DisplayHex(txid), err)
	}
	block := chainhash.Hash(h)
	return &tx, &block, nil
}

// Unspent reports, for each outpoint in order, whether it is in the UTXO set
// of Core's active chain. It reads /rest/getutxos without checkmempool, in
// batches of 15, Core's limit per request.
func (c *Client) Unspent(ctx context.Context, ops []wire.OutPoint) ([]bool, error) {
	out := make([]bool, 0, len(ops))
	for start := 0; start < len(ops); start += maxUTXOBatch {
		end := min(start+maxUTXOBatch, len(ops))
		parts := make([]string, 0, end-start)
		for _, op := range ops[start:end] {
			parts = append(parts, DisplayHex(op.Hash)+"-"+strconv.FormatUint(uint64(op.Index), 10))
		}
		body, err := c.get(ctx, "/getutxos/"+strings.Join(parts, "/")+".json", maxInfoSize)
		if err != nil {
			return nil, err
		}
		var raw struct {
			Bitmap *string `json:"bitmap"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("core: unspent outputs: %w", err)
		}
		if raw.Bitmap == nil || len(*raw.Bitmap) != end-start {
			return nil, errors.New("core: unspent outputs: the bitmap is missing or has the wrong length")
		}
		for _, ch := range *raw.Bitmap {
			switch ch {
			case '1':
				out = append(out, true)
			case '0':
				out = append(out, false)
			default:
				return nil, fmt.Errorf("core: unspent outputs: bitmap holds %q", ch)
			}
		}
	}
	return out, nil
}
