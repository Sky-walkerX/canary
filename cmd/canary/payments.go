package main

import (
	"errors"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/state"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
	"github.com/Sky-walkerX/canary/ladder"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	btcwire "github.com/btcsuite/btcd/wire"
)

// declared is one --expect payment, resolved against Core.
type declared struct {
	txid    [32]byte // internal order
	block   int      // index into the checked blocks, or -1 while unconfirmed
	entry   *canonical.Leaf
	outputs []ladder.Output
}

// resolvePayments computes each declared payment's entry from Core: the
// transaction and the outputs it spends. It also asks Core which of the
// payment's taproot outputs are unspent, which decides whether pruning can
// explain a list that holds the entry back.
func (ch *checker) resolvePayments() ([]declared, int) {
	out := make([]declared, 0, len(ch.cfg.expects))
	for _, e := range ch.cfg.expects {
		txidHex := core.DisplayHex(e.txid)
		var blk *btcwire.MsgBlock
		var tx *btcwire.MsgTx
		if e.block != nil {
			b, err := ch.core.Block(ch.ctx, chainhash.Hash(*e.block))
			if errors.Is(err, core.ErrNotFound) {
				return nil, ch.cmd.usage(wording.CheckExpectBlockUnknown(core.DisplayHex(*e.block)))
			}
			if err != nil {
				return nil, ch.coreFailed(err)
			}
			for _, t := range b.Transactions {
				if [32]byte(t.TxHash()) == e.txid {
					tx = t
					break
				}
			}
			if tx == nil {
				return nil, ch.cmd.usage(wording.CheckExpectNotInBlock(txidHex, core.DisplayHex(*e.block)))
			}
			blk = b
		} else {
			t, where, err := ch.core.Transaction(ch.ctx, chainhash.Hash(e.txid))
			if errors.Is(err, core.ErrNotFound) {
				return nil, ch.cmd.fail(exitFailure, wording.CheckExpectNotFound(txidHex), nil)
			}
			if err != nil {
				return nil, ch.coreFailed(err)
			}
			if where == nil {
				out = append(out, declared{txid: e.txid, block: -1})
				continue
			}
			b, err := ch.core.Block(ch.ctx, *where)
			if err != nil {
				return nil, ch.coreFailed(err)
			}
			tx, blk = t, b
		}

		hash := [32]byte(blk.BlockHash())
		idx, checked := ch.byHash[hash]
		if !checked {
			return nil, ch.cmd.usage(wording.CheckExpectNotChecked(txidHex, core.DisplayHex(hash),
				ch.blocks[0].height, ch.blocks[len(ch.blocks)-1].height))
		}
		d := declared{txid: e.txid, block: idx}

		pv, err := ch.core.Prevouts(ch.ctx, blk)
		if err != nil {
			return nil, ch.coreFailed(err)
		}
		// The payment alone, so no other transaction in the block can stop
		// its entry from being computed.
		leaves, err := canonical.Set(ch.net, &btcwire.MsgBlock{Transactions: []*btcwire.MsgTx{tx}}, pv)
		if err != nil {
			return nil, ch.cmd.fail(exitFailure, wording.CheckPaymentEntry(txidHex), err)
		}
		if len(leaves) == 1 {
			d.entry = &leaves[0]
			if d.outputs, err = ch.taprootOutputs(tx); err != nil {
				return nil, ch.coreFailed(err)
			}
		}
		out = append(out, d)
	}
	return out, 0
}

// taprootOutputs lists the transaction's taproot outputs and whether Core's
// UTXO set still holds each.
func (ch *checker) taprootOutputs(tx *btcwire.MsgTx) ([]ladder.Output, error) {
	var ops []btcwire.OutPoint
	var values []uint64
	for i, o := range tx.TxOut {
		if len(o.PkScript) == 34 && o.PkScript[0] == 0x51 && o.PkScript[1] == 0x20 {
			ops = append(ops, btcwire.OutPoint{Hash: tx.TxHash(), Index: uint32(i)})
			values = append(values, uint64(o.Value))
		}
	}
	unspent, err := ch.core.Unspent(ch.ctx, ops)
	if err != nil {
		return nil, err
	}
	out := make([]ladder.Output, len(ops))
	for i := range ops {
		out[i] = ladder.Output{ValueSat: values[i], Unspent: unspent[i]}
	}
	return out, nil
}

// paymentsIn returns the ladder's view of the payments in one block. Only a
// payment with an entry has anything to check.
func paymentsIn(ds []declared, block int) []ladder.Payment {
	var out []ladder.Payment
	for _, d := range ds {
		if d.block == block && d.entry != nil {
			out = append(out, ladder.Payment{Entry: *d.entry, Outputs: d.outputs})
		}
	}
	return out
}

// paymentState is the state file's row for one declared payment. res is the
// ladder's result for the payment's block. A payment with no block yet
// reads none of it.
func (ch *checker) paymentState(d declared, res ladder.BlockResult) state.Payment {
	p := state.Payment{Txid: core.DisplayHex(d.txid), Servers: []state.PaymentServer{}}
	if d.block < 0 {
		p.Outcome = "pending"
		return p
	}
	b := ch.blocks[d.block]
	p.Block = &state.BlockRef{Height: b.height, Hash: core.DisplayHex(b.hash)}
	if d.entry == nil {
		p.Outcome = "not_eligible"
		return p
	}
	reached := map[string]bool{}
	for _, sr := range res.Servers {
		for _, pr := range sr.Payments {
			if pr.TxID == d.entry.TxID {
				p.Servers = append(p.Servers, state.PaymentServer{Label: sr.Label, Outcome: pr.Outcome})
				reached[pr.Outcome] = true
			}
		}
	}
	// The first of these that any server reached, in the formats doc's order.
	for _, o := range []string{ladder.PaymentWithheld, ladder.PaymentHashOnly, ladder.PaymentUnresolvable} {
		if reached[o] {
			p.Outcome = o
			return p
		}
	}
	if reached[ladder.PaymentNotIndexedYet] {
		p.Outcome = "pending"
		return p
	}
	p.Outcome = ladder.PaymentFound
	return p
}
