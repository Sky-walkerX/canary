package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sky-walkerX/canary/internal/indexer"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// errNoKeyFile means the key file does not exist. The caller prints the
// command that creates one.
var errNoKeyFile = errors.New("canary-indexer: no key file")

// loadKey reads a secret key written by --gen-key: 64 lowercase hex
// characters, optionally followed by a newline. It returns a warning, not an
// error, when other users can read the file.
func loadKey(path string) (key [32]byte, warning string, err error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return key, "", errNoKeyFile
	}
	if err != nil {
		return key, "", fmt.Errorf("canary-indexer: read key file: %w", err)
	}

	s := strings.TrimSuffix(string(raw), "\n")
	if len(s) != 64 || strings.Trim(s, "0123456789abcdef") != "" {
		return key, "", fmt.Errorf("canary-indexer: read key file: %s must hold 64 lowercase hex characters", path)
	}
	b, _ := hex.DecodeString(s)
	copy(key[:], b)
	if _, err := indexer.PublicKey(key); err != nil {
		return [32]byte{}, "", fmt.Errorf("canary-indexer: read key file: %s: %w", path, err)
	}

	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		warning = fmt.Sprintf("key file %s can be read by other users; run chmod 600 %s", path, path)
	}
	return key, warning, nil
}

// writeNewKey creates path with a fresh random secret key and permissions
// 0600, and returns the key's npub. It refuses to replace an existing file,
// because that would destroy the key a client has pinned.
func writeNewKey(path string) (string, error) {
	var key [32]byte
	var pub [32]byte
	for {
		if _, err := rand.Read(key[:]); err != nil {
			return "", fmt.Errorf("canary-indexer: generate key: %w", err)
		}
		// A random 32 bytes is a valid key except with negligible odds.
		var err error
		if pub, err = indexer.PublicKey(key); err == nil {
			break
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("canary-indexer: generate key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("canary-indexer: generate key: %s already exists; refusing to replace a key that clients may have pinned", path)
	}
	if err != nil {
		return "", fmt.Errorf("canary-indexer: generate key: %w", err)
	}
	if _, err := f.WriteString(hex.EncodeToString(key[:]) + "\n"); err != nil {
		f.Close()
		return "", fmt.Errorf("canary-indexer: generate key: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("canary-indexer: generate key: %w", err)
	}
	return nip19.EncodePublicKey(hex.EncodeToString(pub[:]))
}
