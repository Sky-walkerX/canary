// Command canary-indexer is Canary's v1 reference index server. It reads a
// Bitcoin Core node over REST, signs one record per block with its key, and
// serves /info, /commitment/{blockhash} and /tweaks/{blockhash}.
//
// It is built and tested on regtest only. It reuses Canary's canonical
// package to compute entries, so it is not an independent implementation.
//
//	canary-indexer --gen-key ~/.canary/indexer.key
//	canary-indexer --core-rest http://127.0.0.1:18443/rest
//
// --withhold-txid makes it leave one transaction out of every list it serves
// while still signing that transaction into the block's record. It exists
// for the demo, so that Canary has something to catch.
//
// Exit codes: 0 after a clean stop, 1 when the server cannot run, 2 for a
// usage error, including a missing or unreadable key file.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/indexer"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// version is the release version. build is the git commit, set at link time
// with -ldflags "-X main.build=abc1234". Without it, the Go build info
// supplies the commit when there is one.
var (
	version = "0.1.0"
	build   = ""
)

// defaultAddr is the listen address when --addr is not given. The v1 formats
// doc fixes no port for the indexer, so it takes the one after canary ui's
// 7352.
const defaultAddr = "127.0.0.1:7353"

const usageHead = `Usage: canary-indexer --core-rest URL [flags]
       canary-indexer --gen-key PATH

canary-indexer is Canary's v1 reference index server. It reads a Bitcoin Core
node over REST, signs one record per block with its key, and serves /info,
/commitment/{blockhash} and /tweaks/{blockhash}. It is built and tested on
regtest only.

Flags:
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// flagHelp is each flag's placeholder and description, in the order --help
// prints them.
var flagHelp = []struct{ name, arg, text string }{
	{"core-rest", "URL", "Bitcoin Core REST base URL, for example http://127.0.0.1:18443/rest. Core must run with -rest=1."},
	{"addr", "HOST:PORT", "Address to serve the HTTP API on."},
	{"key-file", "PATH", "File holding the server's secret key, as 64 hex characters. It signs every record and receipt. Create one with --gen-key."},
	{"gen-key", "PATH", "Write a new random secret key to PATH, readable only by you, print its npub, and exit."},
	{"poll", "DURATION", "How often to ask Bitcoin Core for new blocks."},
	{"withhold-txid", "TXID", "Makes the server leave this transaction out of what it serves, while still signing it into the block's record. For demos only. TXID is in display order, as bitcoin-cli prints it."},
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("canary-indexer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	coreREST := fs.String("core-rest", "", "")
	addr := fs.String("addr", defaultAddr, "")
	keyFile := fs.String("key-file", defaultKeyFile(), "")
	genKey := fs.String("gen-key", "", "")
	poll := fs.Duration("poll", 2*time.Second, "")
	withhold := fs.String("withhold-txid", "", "")
	fs.Usage = func() { printUsage(fs, stderr) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	usageError := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "canary-indexer: "+format+"\n", a...)
		fmt.Fprintln(stderr, "Run canary-indexer --help for the flags.")
		return 2
	}
	if fs.NArg() > 0 {
		return usageError("unexpected argument %q", fs.Arg(0))
	}

	if *genKey != "" {
		if fs.NFlag() > 1 {
			return usageError("--gen-key takes no other flags")
		}
		npub, err := writeNewKey(*genKey)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		fmt.Fprintln(stdout, npub)
		return 0
	}

	if *coreREST == "" {
		return usageError("--core-rest is required, for example --core-rest http://127.0.0.1:18443/rest")
	}
	client, err := core.New(*coreREST, nil)
	if err != nil {
		return usageError("--core-rest: %v", err)
	}
	if *poll <= 0 {
		return usageError("--poll must be positive, got %s", *poll)
	}
	var withholdID *[32]byte
	if *withhold != "" {
		id, err := core.ParseDisplayHash(*withhold)
		if err != nil {
			return usageError("--withhold-txid must be a txid of 64 lowercase hex characters, in display order: %v", err)
		}
		withholdID = &id
	}
	if *keyFile == "" {
		return usageError("--key-file is required, because the home directory for the default is unknown")
	}

	key, warning, err := loadKey(*keyFile)
	if errors.Is(err, errNoKeyFile) {
		fmt.Fprintf(stderr, "canary-indexer: no key file at %s\nCreate one with:\n  canary-indexer --gen-key %s\n", *keyFile, *keyFile)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	logger := log.New(stderr, "canary-indexer: ", log.LstdFlags)
	if warning != "" {
		logger.Printf("warning: %s", warning)
	}
	if withholdID != nil {
		fmt.Fprintf(stderr, "WARNING: --withhold-txid is set. This server leaves transaction %s out of every list it serves, while its signed records still include it. Use it for demos only.\n", *withhold)
	}

	idx, err := indexer.New(indexer.Config{
		Core:         client,
		Key:          key,
		WithholdTxID: withholdID,
		Software:     indexer.Software{Name: "canary-indexer", Version: version, Build: buildID()},
		Logger:       logger,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return serve(ctx, idx, *addr, *coreREST, *poll, logger)
}

// serve runs the sync loop and the HTTP server until ctx ends.
func serve(ctx context.Context, idx *indexer.Indexer, addr, coreREST string, poll time.Duration, logger *log.Logger) int {
	pub := idx.PubKey()
	pubHex := hex.EncodeToString(pub[:])
	npub, _ := nip19.EncodePublicKey(pubHex)
	logger.Printf("canary-indexer %s (%s)", version, buildID())
	logger.Printf("pubkey %s, pin it with canary check --pubkey LABEL=%s", pubHex, pubHex)
	logger.Printf("npub %s", npub)
	logger.Printf("reading Bitcoin Core at %s every %s", coreREST, poll)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Printf("listen on %s: %v", addr, err)
		return 1
	}
	srv := &http.Server{
		Handler:           idx.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	syncDone := make(chan struct{})
	go func() {
		defer close(syncDone)
		idx.Run(ctx, poll)
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	logger.Printf("serving on http://%s", ln.Addr())

	code := 0
	select {
	case <-ctx.Done():
		logger.Printf("stopping")
	case err := <-serveErr:
		logger.Printf("serve: %v", err)
		code = 1
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && code == 0 {
		logger.Printf("shutdown: %v", err)
		code = 1
	}
	<-syncDone
	return code
}

func printUsage(fs *flag.FlagSet, w io.Writer) {
	fmt.Fprint(w, usageHead)
	for _, h := range flagHelp {
		fmt.Fprintf(w, "  --%s %s\n        %s", h.name, h.arg, h.text)
		if f := fs.Lookup(h.name); f != nil && f.DefValue != "" {
			fmt.Fprintf(w, " (default %s)", f.DefValue)
		}
		fmt.Fprintln(w)
	}
}

// defaultKeyFile is ~/.canary/indexer.key, next to the state file and
// evidence directory that canary check keeps in ~/.canary.
func defaultKeyFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".canary", "indexer.key")
}

// buildID returns the git commit the binary was built from, or "unknown".
func buildID() string {
	if build != "" {
		return build
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				return s.Value[:7]
			}
		}
	}
	return "unknown"
}
