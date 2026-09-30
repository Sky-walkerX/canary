package indexer_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/core/coretest"
	"github.com/Sky-walkerX/canary/wire"
	"github.com/nbd-wtf/go-nostr"
)

// A client that fetches a block's signed record and its tweak list must be
// able to recompute the record's root from the list, and to check the
// receipt against the key that signed the record.
func TestRecordListAndReceiptAgree(t *testing.T) {
	f := newFixture(t)
	s := startServer(t, f.rest, 1)
	s.sync(t)

	c, _ := s.commitment(t, f.hash())
	if c.Author != s.idx.PubKey() {
		t.Errorf("record author %x, want the server's key %x", c.Author, s.idx.PubKey())
	}
	if c.Network != regtest || c.BlockHash != [32]byte(f.blk.BlockHash()) || c.BlockHeight != 2 || c.N != 3 {
		t.Errorf("record = %+v, want regtest block 2 with 3 entries", c)
	}
	if c.PolicyRef != [32]byte{} {
		t.Errorf("policy_ref = %x, want 64 zeros: v1 publishes no policy declaration", c.PolicyRef)
	}

	positions, body, r := s.tweaks(t, f.hash())
	if uint32(len(positions)) != c.N {
		t.Fatalf("list has %d positions, the record says n = %d", len(positions), c.N)
	}
	leaves := leavesOf(t, positions)
	for i, tx := range f.payers {
		if leaves[i].TxID != [32]byte(tx.TxHash()) {
			t.Errorf("position %d holds txid %x, want %s, the block's next taproot-paying transaction", i, leaves[i].TxID, tx.TxHash())
		}
	}
	if got := commit.Root(c.Network, c.BlockHash, leaves); got != c.Root {
		t.Errorf("root recomputed from the list = %x, the record signs %x", got, c.Root)
	}

	// The receipt: signed by the record's author, over these exact bytes.
	req := wire.ReceiptRequest{Network: c.Network, BlockHash: c.BlockHash, DustSat: 0}
	if err := wire.VerifyReceipt(r, c.Author, req, body); err != nil {
		t.Fatalf("receipt does not verify under the record's author: %v", err)
	}
	tipHeight, tipHash := f.chain.Tip()
	if r.TipHeight != tipHeight || r.TipHash != [32]byte(tipHash) {
		t.Errorf("receipt tip = %d %x, want Core's tip %d %s", r.TipHeight, r.TipHash, tipHeight, tipHash)
	}
	if r.Resource != wire.ResourceTweakList {
		t.Errorf("receipt resource = %#x, want the tweak list", byte(r.Resource))
	}

	tampered := append([]byte{}, body...)
	tampered[len(tampered)-1] ^= 0x01
	if err := wire.VerifyReceipt(r, c.Author, req, tampered); !errors.Is(err, wire.ErrReceiptMismatch) {
		t.Errorf("a flipped body byte gave %v, want ErrReceiptMismatch", err)
	}
}

// With --withhold-txid the server leaves one entry out of what it serves. Its
// signed record still includes the entry, and its receipt still signs the
// list with the gap. That pair is the contradiction Canary looks for.
func TestWithholdingLeavesTheRecordHonest(t *testing.T) {
	f := newFixture(t)
	target := f.payers[1]
	honest := startServer(t, f.rest, 1)
	withholder := startServer(t, f.rest, 2, withholding(target.TxHash()))
	honest.sync(t)
	withholder.sync(t)

	positions, body, r := withholder.tweaks(t, f.hash())
	if len(positions) != 3 {
		t.Fatalf("withheld list has %d positions, want 3: the gap keeps its place", len(positions))
	}
	if positions[1].Kind != wire.KindAbsent {
		t.Errorf("position 1 has kind %d, want absent", positions[1].Kind)
	}
	if positions[0].Kind != wire.KindFull || positions[2].Kind != wire.KindFull {
		t.Error("the other positions must still be served in full")
	}

	c, _ := withholder.commitment(t, f.hash())
	if c.N != 3 {
		t.Fatalf("withholder's record n = %d, want 3: the record stays honest", c.N)
	}

	// Fill the gap from the honest server first, then recompute the root.
	honestPositions, _, _ := honest.tweaks(t, f.hash())
	missing := honestPositions[1].Leaf
	if missing.TxID != [32]byte(target.TxHash()) {
		t.Fatalf("the honest list's position 1 is %x, want the withheld txid %s", missing.TxID, target.TxHash())
	}
	filled := []canonical.Leaf{positions[0].Leaf, missing, positions[2].Leaf}
	if got := commit.Root(c.Network, c.BlockHash, filled); got != c.Root {
		t.Fatalf("filled root %x differs from the withholder's signed root %x", got, c.Root)
	}
	proof, err := commit.Prove(filled, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !commit.VerifyProof(c.Network, c.BlockHash, c.Root, missing, proof) {
		t.Error("the withheld entry does not prove into the withholder's own signed root")
	}

	req := wire.ReceiptRequest{Network: c.Network, BlockHash: c.BlockHash}
	if err := wire.VerifyReceipt(r, withholder.idx.PubKey(), req, body); err != nil {
		t.Fatalf("the receipt over the withheld list does not verify: %v", err)
	}
	if !wire.InsideRetentionWindow(r.TipHeight, c.BlockHeight) {
		t.Errorf("tip %d and height %d put the block outside the window; the demo needs it inside", r.TipHeight, c.BlockHeight)
	}
}

// Canary must catch the server without the server confessing, so /info reads
// the same with and without the switch, apart from the key.
func TestInfoDoesNotRevealTheSwitch(t *testing.T) {
	f := newFixture(t)
	honest := startServer(t, f.rest, 1)
	withholder := startServer(t, f.rest, 2, withholding(f.payers[1].TxHash()))
	honest.sync(t)
	withholder.sync(t)

	decode := func(s *server) map[string]any {
		_, body := s.get(t, "/info")
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatal(err)
		}
		delete(m, "pubkey")
		return m
	}
	if h, w := decode(honest), decode(withholder); !reflect.DeepEqual(h, w) {
		t.Errorf("/info differs with the switch on:\nhonest     %v\nwithholder %v", h, w)
	}

	// The honest server serves the entry in full.
	positions, _, _ := honest.tweaks(t, f.hash())
	leavesOf(t, positions)
}

func TestInfoMatchesTheFormat(t *testing.T) {
	f := newFixture(t)
	s := startServer(t, f.rest, 1)
	s.sync(t)

	resp, body := s.get(t, "/info")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("GET /info: status %d, content type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	// A strict decode: an unknown or renamed field fails here.
	var info struct {
		Format   string `json:"format"`
		Software struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Build   string `json:"build"`
		} `json:"software"`
		Network struct {
			Name  string `json:"name"`
			Magic uint32 `json:"magic"`
		} `json:"network"`
		PubKey string `json:"pubkey"`
		Tip    struct {
			Height uint32 `json:"height"`
			Hash   string `json:"hash"`
		} `json:"tip"`
		StartHeight     uint32 `json:"start_height"`
		RetentionWindow int    `json:"retention_window"`
		Policy          struct {
			PrunesSpent      bool   `json:"prunes_spent"`
			DustThresholdSat uint64 `json:"dust_threshold_sat"`
			DustConfigurable bool   `json:"dust_configurable"`
		} `json:"policy"`
		RecordKind    int  `json:"record_kind"`
		SignsReceipts bool `json:"signs_receipts"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&info); err != nil {
		t.Fatalf("/info does not match the canary-info/1 shape: %v\n%s", err, body)
	}

	pub := s.idx.PubKey()
	tipHeight, tipHash := f.chain.Tip()
	switch {
	case info.Format != "canary-info/1":
		t.Errorf("format = %q", info.Format)
	case info.Software.Name != "canary-indexer" || info.Software.Version != "0.1.0" || info.Software.Build != "test":
		t.Errorf("software = %+v", info.Software)
	case info.Network.Name != "regtest" || info.Network.Magic != 3669344250:
		t.Errorf("network = %+v", info.Network)
	case info.PubKey != hex.EncodeToString(pub[:]):
		t.Errorf("pubkey = %s, want %x", info.PubKey, pub)
	case info.Tip.Height != tipHeight || info.Tip.Hash != tipHash.String():
		t.Errorf("tip = %+v, want %d %s", info.Tip, tipHeight, tipHash)
	case info.StartHeight != 0:
		t.Errorf("start_height = %d, want 0", info.StartHeight)
	case info.RetentionWindow != wire.RetentionWindow:
		t.Errorf("retention_window = %d, want %d", info.RetentionWindow, wire.RetentionWindow)
	case info.Policy.PrunesSpent || info.Policy.DustThresholdSat != 0 || info.Policy.DustConfigurable:
		t.Errorf("policy = %+v, want no pruning, no dust threshold, not configurable", info.Policy)
	case info.RecordKind != 1352:
		t.Errorf("record_kind = %d, want 1352", info.RecordKind)
	case !info.SignsReceipts:
		t.Error("signs_receipts = false, want true")
	}
}

// The URL carries the block hash in display order. The list carries each
// txid in internal order. The server converts once, and a hash typed in the
// wrong order names no block.
func TestByteOrderDisplayInURLInternalInList(t *testing.T) {
	f := newFixture(t)
	s := startServer(t, f.rest, 1)
	s.sync(t)

	blockHash := f.blk.BlockHash()
	positions, _, r := s.tweaks(t, blockHash.String())
	txid := f.payers[0].TxHash()

	if positions[0].Leaf.TxID != [32]byte(txid) {
		t.Errorf("leaf txid %x, want the internal-order bytes %x", positions[0].Leaf.TxID, txid[:])
	}
	if core.DisplayHex(positions[0].Leaf.TxID) != txid.String() {
		t.Errorf("reversed leaf txid %s, want the display-order txid %s", core.DisplayHex(positions[0].Leaf.TxID), txid)
	}
	if r.BlockHash != [32]byte(blockHash) {
		t.Errorf("receipt block hash %x, want internal-order %x", r.BlockHash, blockHash[:])
	}

	// The record's b tag holds the same display-order string as the URL.
	_, raw := s.commitment(t, blockHash.String())
	var ev nostr.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	if tag := ev.Tags.Find("b"); tag == nil || tag[1] != blockHash.String() {
		t.Errorf("b tag = %v, want %s", tag, blockHash)
	}

	internalHex := hex.EncodeToString(blockHash[:])
	for _, route := range []string{"/commitment/", "/tweaks/"} {
		resp, body := s.get(t, route+internalHex)
		wantError(t, resp, body, http.StatusNotFound, "unknown_block")
	}
}

// A block with no eligible transaction still gets a record and a list. The
// list is the four bytes 00000000, not a missing response.
func TestEmptyBlockServesFourZeroBytes(t *testing.T) {
	f := newFixture(t)
	s := startServer(t, f.rest, 1)
	s.sync(t)

	genesis := f.chain.Block(0).BlockHash()
	c, _ := s.commitment(t, genesis.String())
	if c.N != 0 || c.Root != commit.Root(regtest, [32]byte(genesis), nil) {
		t.Errorf("empty record = n %d root %x, want n 0 and the empty-set root", c.N, c.Root)
	}
	positions, body, r := s.tweaks(t, genesis.String())
	if len(positions) != 0 || !bytes.Equal(body, []byte{0, 0, 0, 0}) {
		t.Errorf("empty list body = %x, want 00000000", body)
	}
	if err := wire.VerifyReceipt(r, c.Author, wire.ReceiptRequest{Network: regtest, BlockHash: c.BlockHash}, body); err != nil {
		t.Errorf("receipt over the empty list: %v", err)
	}
	if want := sha256.Sum256([]byte{0, 0, 0, 0}); r.BodySHA256 != want {
		t.Errorf("body_sha256 = %x, want the SHA-256 of 00000000", r.BodySHA256)
	}
}

// Two different records for one block from one key contradict each other, so
// the server signs each block once and serves those bytes forever. The case
// that could re-sign is a block that leaves the chain and comes back.
func TestRecordIsSignedOnceAcrossAReorgAndBack(t *testing.T) {
	chain := coretest.NewChain(t)
	chain.MineEmpty(1)
	block := chain.Mine(chain.PayToTaproot(coretest.P2WPKH))
	s := startServer(t, coretest.Serve(t, chain), 1)
	s.sync(t)
	hash := block.BlockHash().String()
	_, first := s.commitment(t, hash)

	// created_at has one-second resolution and the signature nonce is
	// deterministic, so a record signed again within the same second would
	// come out byte for byte the same. Waiting past a second boundary makes a
	// second signature visible.
	time.Sleep(1100 * time.Millisecond)

	chain.Reorg(1)
	chain.Mine(chain.PayToTaproot(coretest.P2TR))
	s.sync(t)
	chain.Reorg(1)
	chain.Reconnect(block.BlockHash())
	chain.MineEmpty(1)
	s.sync(t)

	resp, second := s.get(t, "/commitment/"+hash)
	if !bytes.Equal(first, second) {
		t.Errorf("the record changed after the block came back:\n%s\n%s", first, second)
	}
	if got := resp.Header.Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q", got)
	}
	if h, _, _ := s.idx.Tip(); h != 3 {
		t.Errorf("server tip height %d, want 3", h)
	}
	positions, _, _ := s.tweaks(t, hash)
	if len(positions) != 1 {
		t.Errorf("the returned block serves %d positions, want 1", len(positions))
	}
}

// A block the server has not indexed yet reads as unknown_block. The client
// tells "not yet" from "never" by the server's tip, which /info reports.
func TestBlockNotYetIndexed(t *testing.T) {
	f := newFixture(t)
	s := startServer(t, f.rest, 1)
	s.sync(t)

	next := f.chain.Mine(f.chain.PayToTaproot(coretest.P2TR))
	resp, body := s.get(t, "/commitment/"+next.BlockHash().String())
	wantError(t, resp, body, http.StatusNotFound, "unknown_block")
	resp, body = s.get(t, "/tweaks/"+next.BlockHash().String())
	wantError(t, resp, body, http.StatusNotFound, "unknown_block")

	s.sync(t)
	c, _ := s.commitment(t, next.BlockHash().String())
	if c.BlockHeight != 5 || c.N != 1 {
		t.Errorf("new record = height %d n %d, want height 5 n 1", c.BlockHeight, c.N)
	}
}

// After a reorg the server indexes the new blocks and keeps serving the old
// block's record by hash. A block hash has one height forever, so the old
// record stays true.
func TestReorgKeepsOldRecordsAndMovesTheTip(t *testing.T) {
	chain := coretest.NewChain(t)
	chain.MineEmpty(1)
	old := chain.Mine(chain.PayToTaproot(coretest.P2WPKH))
	s := startServer(t, coretest.Serve(t, chain), 1)
	s.sync(t)
	_, oldRecord := s.commitment(t, old.BlockHash().String())

	chain.Reorg(1)
	replacement := chain.Mine(chain.PayToTaproot(coretest.P2TR), chain.PayToTaproot(coretest.P2WPKH))
	chain.MineEmpty(1)
	s.sync(t)

	_, again := s.commitment(t, old.BlockHash().String())
	if !bytes.Equal(again, oldRecord) {
		t.Error("the stale block's record changed after the reorg")
	}
	c, _ := s.commitment(t, replacement.BlockHash().String())
	if c.BlockHeight != 2 || c.N != 2 {
		t.Errorf("replacement record = height %d n %d, want height 2 n 2", c.BlockHeight, c.N)
	}
	tipHeight, tipHash := chain.Tip()
	_, _, r := s.tweaks(t, old.BlockHash().String())
	if r.TipHeight != tipHeight || r.TipHash != [32]byte(tipHash) {
		t.Errorf("receipt tip = %d %x, want the new tip %d %s", r.TipHeight, r.TipHash, tipHeight, tipHash)
	}
}
