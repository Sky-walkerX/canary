package coretest

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"testing"
)

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

// Core writes the genesis block's spent outputs as one empty list, because
// genesis has no undo data: compact size 1, then compact size 0.
func TestGenesisSpentOutputsAreOneEmptyList(t *testing.T) {
	c := NewChain(t)
	base := Serve(t, c)
	_, hash := c.Tip()

	status, body := get(t, base+"/spenttxouts/"+hash.String()+".bin")
	if status != http.StatusOK || !bytes.Equal(body, []byte{0x01, 0x00}) {
		t.Errorf("genesis spent outputs = %d %x, want 200 0100", status, body)
	}
}

// Core serializes a block hash as its raw 32 bytes, in internal order, and
// prints the hex form in display order with a trailing newline.
func TestBlockHashByHeightByteOrder(t *testing.T) {
	c := NewChain(t)
	base := Serve(t, c)
	_, hash := c.Tip()

	_, bin := get(t, base+"/blockhashbyheight/0.bin")
	if !bytes.Equal(bin, hash[:]) {
		t.Errorf("bin = %x, want the internal-order bytes %x", bin, hash[:])
	}
	_, hx := get(t, base+"/blockhashbyheight/0.hex")
	if string(hx) != hash.String()+"\n" {
		t.Errorf("hex = %q, want the display-order string and a newline", hx)
	}
}

func TestErrorsAreCoreStylePlainText(t *testing.T) {
	c := NewChain(t)
	base := Serve(t, c)

	status, body := get(t, base+"/blockhashbyheight/7.bin")
	if status != http.StatusNotFound || string(body) != "Block height out of range\r\n" {
		t.Errorf("height above tip = %d %q", status, body)
	}
	status, body = get(t, base+"/block/nothex.bin")
	if status != http.StatusBadRequest || string(body) != "Invalid hash: nothex\r\n" {
		t.Errorf("bad hash = %d %q", status, body)
	}
	unknown := hex.EncodeToString(make([]byte, 32))
	status, body = get(t, base+"/spenttxouts/"+unknown+".bin")
	if status != http.StatusNotFound || string(body) != unknown+" not found\r\n" {
		t.Errorf("unknown block = %d %q", status, body)
	}
}

func TestReorgReplacesTheTipAndKeepsTheOldBlock(t *testing.T) {
	c := NewChain(t)
	base := Serve(t, c)
	old := c.Mine(c.PayToTaproot(P2WPKH))

	c.Reorg(1)
	replacement := c.Mine(c.PayToTaproot(P2WPKH))

	if replacement.BlockHash() == old.BlockHash() {
		t.Fatal("the replacement block has the old block's hash")
	}
	if h, hash := c.Tip(); h != 1 || hash != replacement.BlockHash() {
		t.Errorf("tip = %d %s, want 1 %s", h, hash, replacement.BlockHash())
	}
	// Core keeps a stale block and its undo data, so both stay readable.
	if status, _ := get(t, base+"/block/"+old.BlockHash().String()+".bin"); status != http.StatusOK {
		t.Errorf("stale block: status %d, want 200", status)
	}
	// The replacement spends the funding output the stale block spent, which
	// the reorg made unspent again.
	if replacement.Transactions[1].TxIn[0].PreviousOutPoint != old.Transactions[1].TxIn[0].PreviousOutPoint {
		t.Error("after the reorg, the oldest funding output should be unspent again")
	}
}
