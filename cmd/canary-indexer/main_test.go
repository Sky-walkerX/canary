package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sky-walkerX/canary/internal/core/coretest"
	"github.com/Sky-walkerX/canary/internal/indexer"
	"github.com/Sky-walkerX/canary/wire"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// syncBuffer is a bytes.Buffer that the server goroutine and the test can
// share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func runArgs(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr syncBuffer
	code := run(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func genKey(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys", "indexer.key")
	code, stdout, stderr := runArgs(t, "--gen-key", path)
	if code != 0 {
		t.Fatalf("--gen-key exited %d: %s", code, stderr)
	}
	return path, strings.TrimSpace(stdout)
}

func TestGenKeyWritesAPrivateFileAndPrintsOnlyTheNpub(t *testing.T) {
	path, npub := genKey(t)

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %o, want 600", st.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}\n$`).Match(raw) {
		t.Fatalf("key file holds %q, want 64 lowercase hex characters and a newline", raw)
	}

	if strings.Contains(npub, "\n") || !strings.HasPrefix(npub, "npub1") {
		t.Fatalf("stdout = %q, want one npub line", npub)
	}
	secretHex := strings.TrimSpace(string(raw))
	if strings.Contains(npub, secretHex) {
		t.Fatal("stdout contains the secret key")
	}

	// The npub is the key file's public key.
	var sk [32]byte
	b, _ := hex.DecodeString(secretHex)
	copy(sk[:], b)
	pub, err := indexer.PublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := nip19.EncodePublicKey(hex.EncodeToString(pub[:]))
	if npub != want {
		t.Errorf("printed %s, the key file's npub is %s", npub, want)
	}
}

func TestGenKeyRefusesToOverwrite(t *testing.T) {
	path, _ := genKey(t)
	before, _ := os.ReadFile(path)

	code, stdout, stderr := runArgs(t, "--gen-key", path)
	if code != 2 || stdout != "" {
		t.Errorf("second --gen-key: exit %d, stdout %q; want exit 2 and nothing on stdout", code, stdout)
	}
	if !strings.Contains(stderr, "already exists") {
		t.Errorf("stderr = %q, want it to say the file already exists", stderr)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("the existing key was overwritten")
	}
}

func TestMissingKeyFilePrintsTheGenKeyCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nothing.key")
	code, _, stderr := runArgs(t, "--core-rest", "http://127.0.0.1:1/rest", "--key-file", path)
	if code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if want := "canary-indexer --gen-key " + path; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want the command %q", stderr, want)
	}
}

func TestLoadKeyRejectsBadContent(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"uppercase": strings.Repeat("AB", 32) + "\n",
		"short":     strings.Repeat("ab", 31) + "\n",
		"zero key":  strings.Repeat("00", 32) + "\n",
		"not hex":   strings.Repeat("zz", 32) + "\n",
	}
	for name, content := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadKey(path); err == nil {
			t.Errorf("%s: loaded without an error", name)
		}
	}
}

func TestLoadKeyWarnsAboutAReadableFile(t *testing.T) {
	path, _ := genKey(t)
	if _, warning, err := loadKey(path); err != nil || warning != "" {
		t.Fatalf("0600 key: warning %q, err %v; want neither", warning, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, warning, err := loadKey(path); err != nil || !strings.Contains(warning, "chmod 600") {
		t.Errorf("0644 key: warning %q, err %v; want a chmod 600 warning", warning, err)
	}
}

func TestHelpDescribesTheWithholdSwitchPlainly(t *testing.T) {
	code, _, stderr := runArgs(t, "--help")
	if code != 0 {
		t.Errorf("--help exited %d, want 0", code)
	}
	for _, want := range []string{
		"--withhold-txid TXID",
		"leave this transaction out of what it serves",
		"still signing it",
		"Repeat it to withhold more than one.",
		"For demos only.",
		"--gen-key PATH",
		"--core-rest URL",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("--help does not contain %q:\n%s", want, stderr)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	path, _ := genKey(t)
	cases := map[string][]string{
		"no core-rest":     {"--key-file", path},
		"bad core-rest":    {"--core-rest", "127.0.0.1:18443/rest", "--key-file", path},
		"short txid":       {"--core-rest", "http://127.0.0.1:1/rest", "--key-file", path, "--withhold-txid", "abcd"},
		"uppercase txid":   {"--core-rest", "http://127.0.0.1:1/rest", "--key-file", path, "--withhold-txid", strings.Repeat("AB", 32)},
		"bad second txid":  {"--core-rest", "http://127.0.0.1:1/rest", "--key-file", path, "--withhold-txid", strings.Repeat("ab", 32), "--withhold-txid", "abcd"},
		"zero poll":        {"--core-rest", "http://127.0.0.1:1/rest", "--key-file", path, "--poll", "0s"},
		"unknown flag":     {"--nope"},
		"stray argument":   {"--core-rest", "http://127.0.0.1:1/rest", "--key-file", path, "extra"},
		"gen-key and more": {"--gen-key", filepath.Join(t.TempDir(), "k"), "--core-rest", "http://127.0.0.1:1/rest"},
	}
	for name, args := range cases {
		if code, _, stderr := runArgs(t, args...); code != 2 {
			t.Errorf("%s: exit %d, want 2; stderr %s", name, code, stderr)
		}
	}
}

// The binary end to end: it warns about the switch at start-up, serves the
// API, withholds the one entry, and exits 0 when stopped.
func TestServesAndWithholds(t *testing.T) {
	chain := coretest.NewChain(t)
	target := chain.PayToTaproot(coretest.P2WPKH)
	blk := chain.Mine(chain.PayToTaproot(coretest.P2TR), target)
	rest := coretest.Serve(t, chain)
	keyPath, _ := genKey(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{
			"--core-rest", rest,
			"--key-file", keyPath,
			"--addr", "127.0.0.1:0",
			"--poll", "20ms",
			"--withhold-txid", target.TxHash().String(),
		}, &stdout, &stderr)
	}()

	base := waitForServer(t, &stderr, done)
	if !strings.Contains(stderr.String(), "WARNING: --withhold-txid is set") ||
		!strings.Contains(stderr.String(), target.TxHash().String()) {
		t.Errorf("no start-up warning naming the txid:\n%s", stderr.String())
	}

	var body []byte
	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		var err error
		resp, err = http.Get(base + "/tweaks/" + blk.BlockHash().String())
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /tweaks: status %d: %s", resp.StatusCode, body)
	}
	positions, err := wire.DecodeResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(positions) != 2 || positions[0].Kind != wire.KindFull || positions[1].Kind != wire.KindAbsent {
		t.Errorf("positions = %+v, want full then absent", positions)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d after stop, want 0; stderr:\n%s", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not stop")
	}
	if stdout.String() != "" {
		t.Errorf("stdout = %q, want nothing: logs go to stderr", stdout.String())
	}
}

// --withhold-txid repeats. The warning names every txid, and the server
// leaves each one out, even when they sit in different blocks.
func TestWithholdTxidRepeats(t *testing.T) {
	chain := coretest.NewChain(t)
	early := chain.PayToTaproot(coretest.P2WPKH)
	earlyBlk := chain.Mine(early)
	recent := chain.PayToTaproot(coretest.P2TR)
	recentBlk := chain.Mine(chain.PayToTaproot(coretest.P2TR), recent)
	rest := coretest.Serve(t, chain)
	keyPath, _ := genKey(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{
			"--core-rest", rest,
			"--key-file", keyPath,
			"--addr", "127.0.0.1:0",
			"--poll", "20ms",
			"--withhold-txid", recent.TxHash().String(),
			"--withhold-txid", early.TxHash().String(),
			"--withhold-txid", recent.TxHash().String(),
		}, &stdout, &stderr)
	}()

	base := waitForServer(t, &stderr, done)
	warning := "WARNING: --withhold-txid is set. This server leaves 2 transactions out of every list it serves, while its signed records still include them: " +
		recent.TxHash().String() + ", " + early.TxHash().String() + ". Use it for demos only."
	if !strings.Contains(stderr.String(), warning) {
		t.Errorf("start-up warning does not name both txids once, in order:\n%s", stderr.String())
	}

	for _, tt := range []struct {
		block string
		want  []wire.PositionKind
	}{
		{earlyBlk.BlockHash().String(), []wire.PositionKind{wire.KindAbsent}},
		{recentBlk.BlockHash().String(), []wire.PositionKind{wire.KindFull, wire.KindAbsent}},
	} {
		positions := servedPositions(t, base, tt.block)
		if len(positions) != len(tt.want) {
			t.Fatalf("block %s: %d positions, want %d", tt.block, len(positions), len(tt.want))
		}
		for i, k := range tt.want {
			if positions[i].Kind != k {
				t.Errorf("block %s position %d: kind %d, want %d", tt.block, i, positions[i].Kind, k)
			}
		}
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d after stop, want 0; stderr:\n%s", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not stop")
	}
}

// servedPositions fetches one block's list, waiting for the first sync.
func servedPositions(t *testing.T, base, block string) []wire.Position {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(base + "/tweaks/" + block)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			positions, err := wire.DecodeResponse(body)
			if err != nil {
				t.Fatal(err)
			}
			return positions
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET /tweaks/%s: status %d: %s", block, resp.StatusCode, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitForServer reads the "serving on" line from the log.
func waitForServer(t *testing.T, stderr *syncBuffer, done chan int) string {
	t.Helper()
	re := regexp.MustCompile(`serving on (http://127\.0\.0\.1:\d+)`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(stderr.String()); m != nil {
			return m[1]
		}
		select {
		case code := <-done:
			t.Fatalf("the server exited %d before serving:\n%s", code, stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatalf("no serving line in the log:\n%s", stderr.String())
	return ""
}
