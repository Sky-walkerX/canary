package core_test

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/core/coretest"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func serialize(t *testing.T, blk *wire.MsgBlock) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := blk.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newClient(t *testing.T, chain *coretest.Chain) *core.Client {
	t.Helper()
	c, err := core.New(coretest.Serve(t, chain), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientReadsTheChain(t *testing.T) {
	ctx := context.Background()
	chain := coretest.NewChain(t)
	chain.MineEmpty(2)
	eligible := chain.PayToTaproot(coretest.P2WPKH, coretest.P2TR)
	ineligible := chain.PayToWitnessKeyHash(coretest.P2TR)
	blk := chain.Mine(eligible, ineligible)
	c := newClient(t, chain)

	info, err := c.ChainInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Chain != "regtest" || info.Height != 3 || info.BestHash != blk.BlockHash() {
		t.Errorf("chain info = %+v, want regtest at height 3 with hash %s", info, blk.BlockHash())
	}
	if info.InitialBlockDownload {
		t.Error("initial block download reported true, the chain set false")
	}

	hash, err := c.BlockHash(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	if hash != blk.BlockHash() {
		t.Fatalf("hash at height 3 = %s, want %s", hash, blk.BlockHash())
	}

	got, err := c.Block(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(serialize(t, got), serialize(t, blk)) {
		t.Fatal("the block read over REST differs from the block the chain mined")
	}

	pv, err := c.Prevouts(ctx, got)
	if err != nil {
		t.Fatal(err)
	}
	spent := chain.SpentOutputs(hash)
	for i, tx := range got.Transactions[1:] {
		for j, in := range tx.TxIn {
			out, err := pv.Prevout(in.PreviousOutPoint)
			if err != nil {
				t.Fatal(err)
			}
			want := spent[i+1][j]
			if out.Value != want.Value || !bytes.Equal(out.PkScript, want.PkScript) {
				t.Errorf("tx %d input %d spends (%d, %x), want (%d, %x)", i+1, j, out.Value, out.PkScript, want.Value, want.PkScript)
			}
		}
	}

	// The prevouts are enough for the canonical set. Only the taproot-paying
	// transaction is an entry, and its txid stays in internal order.
	leaves, err := canonical.Set(canonical.Network(3669344250), got, pv)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 1 || leaves[0].TxID != [32]byte(eligible.TxHash()) {
		t.Errorf("canonical set = %d entries, want the one taproot-paying transaction", len(leaves))
	}
}

func TestClientReadsGenesis(t *testing.T) {
	ctx := context.Background()
	chain := coretest.NewChain(t)
	c := newClient(t, chain)

	hash, err := c.BlockHash(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := c.Block(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Prevouts(ctx, blk); err != nil {
		t.Errorf("genesis has no undo data, and Core still answers with one empty list: %v", err)
	}
}

func TestClientReportsNotFound(t *testing.T) {
	ctx := context.Background()
	chain := coretest.NewChain(t)
	c := newClient(t, chain)

	if _, err := c.BlockHash(ctx, 99); !errors.Is(err, core.ErrNotFound) {
		t.Errorf("height above the tip: err = %v, want ErrNotFound", err)
	}
	unknown := chainhash.Hash{0x01}
	if _, err := c.Block(ctx, unknown); !errors.Is(err, core.ErrNotFound) {
		t.Errorf("unknown block: err = %v, want ErrNotFound", err)
	}
	if _, err := c.SpentOutputs(ctx, unknown); !errors.Is(err, core.ErrNotFound) {
		t.Errorf("unknown block's spent outputs: err = %v, want ErrNotFound", err)
	}
}

func TestClientReportsInitialBlockDownload(t *testing.T) {
	chain := coretest.NewChain(t)
	chain.SetInitialBlockDownload(true)
	info, err := newClient(t, chain).ChainInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !info.InitialBlockDownload {
		t.Error("initial block download reported false, the chain set true")
	}
}

func TestClientUnreachableIsNotNotFound(t *testing.T) {
	srv := httptest.NewServer(nil)
	url := srv.URL + "/rest"
	srv.Close()

	c, err := core.New(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ChainInfo(context.Background())
	if err == nil || errors.Is(err, core.ErrNotFound) {
		t.Errorf("unreachable Core: err = %v, want a connection error that is not ErrNotFound", err)
	}
}

func TestNewRejectsURLsThatAreNotHTTP(t *testing.T) {
	for _, u := range []string{"", "127.0.0.1:18443/rest", "ftp://127.0.0.1/rest", "http://"} {
		if _, err := core.New(u, nil); err == nil {
			t.Errorf("core.New(%q) succeeded, want an error", u)
		}
	}
}
