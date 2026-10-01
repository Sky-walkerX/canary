package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sky-walkerX/canary/internal/core"
	"github.com/Sky-walkerX/canary/internal/ui/wording"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// checkConfig is canary check's flags, checked and parsed.
type checkConfig struct {
	servers     []serverConfig // in --indexer order
	coreREST    string
	from, to    *uint32 // nil when not given
	expects     []expectation
	statePath   string
	evidenceDir string // absolute
}

// serverConfig is one --indexer and its pin.
type serverConfig struct {
	label  string
	url    string    // base URL with no trailing slash
	pubkey *[32]byte // nil when pinned as none
}

// expectation is one --expect. Hashes are in internal byte order.
type expectation struct {
	txid  [32]byte
	block *[32]byte // nil for a bare TXID
}

// labelRE is the label rule of the state file: 1 to 32 of a-z, 0-9 and -.
var labelRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// checkFlags holds the raw flag values until config checks them.
type checkFlags struct {
	indexers, pubkeys, expects multiFlag
	coreREST, from, to         string
	statePath, evidenceDir     string
}

func newCheckFlags() (*flag.FlagSet, *checkFlags) {
	fs := newFlagSet("check")
	v := &checkFlags{}
	fs.Var(&v.indexers, "indexer", "")
	fs.Var(&v.pubkeys, "pubkey", "")
	fs.StringVar(&v.coreREST, "core-rest", "", "")
	fs.StringVar(&v.from, "from", "", "")
	fs.StringVar(&v.to, "to", "", "")
	fs.Var(&v.expects, "expect", "")
	fs.StringVar(&v.statePath, "state", defaultPath("state.json"), "")
	fs.StringVar(&v.evidenceDir, "evidence-dir", defaultPath("evidence"), "")
	return fs, v
}

// parseCheck parses canary check's arguments. msg is a usage error from the
// wording table, or empty.
func parseCheck(args []string) (cfg checkConfig, msg string) {
	fs, v := newCheckFlags()
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return cfg, wording.CLIFlagError(err.Error())
	}
	return v.config(pos)
}

// config checks every flag in the order the formats doc lists them, and
// returns the first problem as a usage error.
func (v *checkFlags) config(pos []string) (cfg checkConfig, msg string) {
	if len(pos) > 0 {
		return cfg, wording.CLIUnexpectedArgument(pos[0])
	}
	if len(v.indexers) == 0 {
		return cfg, wording.CheckNoIndexer
	}
	index := map[string]int{}
	for _, raw := range v.indexers {
		i := strings.LastIndexByte(raw, '=')
		if i < 0 {
			return cfg, wording.CheckBadIndexer(raw)
		}
		base, label := strings.TrimRight(raw[:i], "/"), raw[i+1:]
		u, err := url.Parse(base)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return cfg, wording.CheckBadIndexer(raw)
		}
		if !localOrTLS(u) {
			return cfg, wording.CheckIndexerPlainHTTP(raw)
		}
		if !labelRE.MatchString(label) {
			return cfg, wording.CheckBadLabel(label)
		}
		if _, dup := index[label]; dup {
			return cfg, wording.CheckDuplicateLabel(label)
		}
		index[label] = len(cfg.servers)
		cfg.servers = append(cfg.servers, serverConfig{label: label, url: base})
	}

	// Canary never learns a key from a server. Every server needs a pin, and
	// no two servers may share one. One key's records counted twice would
	// read as two servers agreeing, and findings, keyed by pubkey, would
	// merge.
	pinned := map[string]bool{}
	keyOf := map[[32]byte]string{}
	for _, raw := range v.pubkeys {
		label, value, ok := strings.Cut(raw, "=")
		if !ok {
			return cfg, wording.CheckBadPubkeyFlag(raw)
		}
		i, known := index[label]
		if !known {
			return cfg, wording.CheckPubkeyUnknownLabel(label)
		}
		if pinned[label] {
			return cfg, wording.CheckDuplicatePubkey(label)
		}
		pinned[label] = true
		if value == "none" {
			continue
		}
		key, err := parsePubkey(value)
		switch {
		case errors.Is(err, errNotOnCurve):
			return cfg, wording.CheckPubkeyNotOnCurve(label)
		case err != nil:
			return cfg, wording.CheckBadPubkey(label)
		}
		if other, dup := keyOf[key]; dup {
			return cfg, wording.CheckPubkeyShared(label, other)
		}
		keyOf[key] = label
		cfg.servers[i].pubkey = &key
	}
	for _, s := range cfg.servers {
		if !pinned[s.label] {
			return cfg, wording.CheckMissingPin(s.label)
		}
	}

	if v.coreREST == "" {
		return cfg, wording.CheckNoCore
	}
	if _, err := core.New(v.coreREST, nil); err != nil {
		return cfg, wording.CheckBadCore(v.coreREST)
	}
	if u, err := url.Parse(v.coreREST); err != nil || !localOrTLS(u) {
		return cfg, wording.CheckCorePlainHTTP(v.coreREST)
	}
	cfg.coreREST = v.coreREST

	for _, h := range []struct {
		flag, value string
		dst         **uint32
	}{{"--from", v.from, &cfg.from}, {"--to", v.to, &cfg.to}} {
		if h.value == "" {
			continue
		}
		n, err := strconv.ParseUint(h.value, 10, 32)
		if err != nil {
			return cfg, wording.CheckBadHeight(h.flag, h.value)
		}
		height := uint32(n)
		*h.dst = &height
	}

	seen := map[[32]byte]bool{}
	for _, raw := range v.expects {
		txHex, blockHex, withBlock := strings.Cut(raw, "@")
		txid, err := core.ParseDisplayHash(txHex)
		if err != nil {
			return cfg, wording.CheckBadExpect(raw)
		}
		e := expectation{txid: txid}
		if withBlock {
			block, err := core.ParseDisplayHash(blockHex)
			if err != nil {
				return cfg, wording.CheckBadExpect(raw)
			}
			e.block = &block
		}
		if seen[txid] {
			return cfg, wording.CheckDuplicateExpect(txHex)
		}
		seen[txid] = true
		cfg.expects = append(cfg.expects, e)
	}

	if v.statePath == "" {
		return cfg, wording.CheckNoHome("state file")
	}
	if v.evidenceDir == "" {
		return cfg, wording.CheckNoHome("evidence directory")
	}
	dir, err := filepath.Abs(v.evidenceDir)
	if err != nil {
		return cfg, wording.CheckNoHome("evidence directory")
	}
	cfg.statePath, cfg.evidenceDir = v.statePath, dir
	return cfg, ""
}

// localOrTLS reports whether Canary may read u: https to any host, or plain
// http to this computer. canary check judges a list with no valid receipt on
// the bytes that arrived, and takes Core's word for the chain. Over plain
// http to another computer, anyone on the path could strip a receipt and
// change a list, or change what Core says, and so make Canary accuse an
// honest server.
func localOrTLS(u *url.URL) bool {
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		if strings.EqualFold(host, "localhost") {
			return true
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	}
	return false
}

// maxRedirects is how many redirects one request may follow, as Go's
// default.
const maxRedirects = 10

// checkRedirect holds a redirect to the rule the flags follow. A server that
// redirects to plain http on another computer would have its answer travel
// where anyone could change it, so Canary does not follow.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if !localOrTLS(req.URL) {
		return fmt.Errorf("canary: redirect to %s: plain http to another computer", req.URL.Redacted())
	}
	if len(via) >= maxRedirects {
		return fmt.Errorf("canary: stopped after %d redirects", maxRedirects)
	}
	return nil
}

// Why a pin fails to parse.
var (
	errNotHex     = errors.New("canary: pubkey: not 64 lowercase hex characters")
	errNotOnCurve = errors.New("canary: pubkey: not a point on secp256k1")
)

// parsePubkey reads a pinned key: 64 lowercase hex characters that name a
// point on the curve, as an x-only BIP-340 key. The error says which of the
// two the value fails, so the usage error can say what to fix.
func parsePubkey(s string) ([32]byte, error) {
	var key [32]byte
	if len(s) != 64 || strings.Trim(s, "0123456789abcdef") != "" {
		return key, errNotHex
	}
	b, _ := hex.DecodeString(s)
	if _, err := schnorr.ParsePubKey(b); err != nil {
		return key, fmt.Errorf("%w: %v", errNotOnCurve, err)
	}
	copy(key[:], b)
	return key, nil
}

// pubkeyHex returns a pin as the state file writes it, or nil for none.
func pubkeyHex(k *[32]byte) *string {
	if k == nil {
		return nil
	}
	s := hex.EncodeToString(k[:])
	return &s
}
