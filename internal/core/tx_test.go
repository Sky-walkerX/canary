package core_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/core/coretest"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func TestTransactionNeedsTheTxIndexForAConfirmedTransaction(t *testing.T) {
	ctx := context.Background()
	chain := coretest.NewChain(t)
	chain.MineEmpty(1)
	pay := chain.PayToTaproot(coretest.P2WPKH)
	blk := chain.Mine(pay)
	c := newClient(t, chain)

	// Core without -txindex finds only mempool transactions.
	if _, _, err := c.Transaction(ctx, pay.TxHash()); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("without the index: err = %v, want ErrNotFound", err)
	}

	chain.SetTxIndex(true)
	tx, block, err := c.Transaction(ctx, pay.TxHash())
	if err != nil {
		t.Fatal(err)
	}
	if tx.TxHash() != pay.TxHash() {
		t.Errorf("transaction %s, want %s", tx.TxHash(), pay.TxHash())
	}
	if block == nil || *block != blk.BlockHash() {
		t.Errorf("block = %v, want %s", block, blk.BlockHash())
	}

	var unknown chainhash.Hash
	unknown[0] = 1
	if _, _, err := c.Transaction(ctx, unknown); !errors.Is(err, core.ErrNotFound) {
		t.Errorf("unknown txid: err = %v, want ErrNotFound", err)
	}
}

func TestUnspentFollowsTheUTXOSet(t *testing.T) {
	ctx := context.Background()
	chain := coretest.NewChain(t)
	chain.MineEmpty(1)
	pay := chain.PayToTaproot(coretest.P2WPKH)
	chain.Mine(pay)
	c := newClient(t, chain)

	out := wire.OutPoint{Hash: pay.TxHash(), Index: 0}
	missing := wire.OutPoint{Hash: pay.TxHash(), Index: 7}
	got, err := c.Unspent(ctx, []wire.OutPoint{out, missing})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0] || got[1] {
		t.Fatalf("unspent = %v, want [true false]", got)
	}

	// Core answers at most 15 outpoints per request, so a longer list goes
	// in batches and keeps its order.
	many := make([]wire.OutPoint, 0, 32)
	for i := 0; i < 31; i++ {
		many = append(many, missing)
	}
	many = append(many, out)
	got, err = c.Unspent(ctx, many)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 || !got[31] || got[0] || got[30] {
		t.Fatalf("batched unspent = %v, want only the last true", got)
	}

	if got, err := c.Unspent(ctx, nil); err != nil || len(got) != 0 {
		t.Errorf("no outpoints: %v, %v; want an empty answer", got, err)
	}
}
