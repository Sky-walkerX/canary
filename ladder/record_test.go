package ladder

import (
	"errors"
	"testing"

	"github.com/Sky-walkerX/canary/canonical"
	"github.com/Sky-walkerX/canary/commit"
	"github.com/Sky-walkerX/canary/feed"
)

func TestCheckRecord(t *testing.T) {
	k := newKey(t, 1)
	hash := blockHash(recent)
	L := leaves(3, "a")
	good := signRecord(t, k, hash, recent, L)

	rec, err := CheckRecord(good, k.pub, hash, regtest)
	if err != nil {
		t.Fatalf("CheckRecord on a good record: %v", err)
	}
	if rec.Commitment.N != 3 || rec.Commitment.Root != commit.Root(regtest, hash, L) || rec.Commitment.BlockHeight != recent {
		t.Errorf("commitment = %+v, want n 3, the set's root and height %d", rec.Commitment, recent)
	}

	cases := []struct {
		name string
		body []byte
		pub  [32]byte
		hash [32]byte
		net  canonical.Network
		is   error
	}{
		{"not JSON", []byte("not json"), k.pub, hash, regtest, ErrBadRecord},
		{"another key", good, newKey(t, 2).pub, hash, regtest, ErrBadRecord},
		{"another block", good, k.pub, blockHash(recent - 1), regtest, ErrBadRecord},
		{"another network", good, k.pub, hash, canonical.Network(3652501241), ErrBadRecord},
		{"tampered", tamper(t, good), k.pub, hash, regtest, feed.ErrBadSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := CheckRecord(c.body, c.pub, c.hash, c.net); !errors.Is(err, c.is) {
				t.Errorf("err = %v, want %v", err, c.is)
			}
		})
	}
}

// tamper changes one character of the record's content, the signed root.
func tamper(t *testing.T, b []byte) []byte {
	t.Helper()
	out := append([]byte(nil), b...)
	key := []byte(`"content":"`)
	for i := 0; i+len(key) < len(out); i++ {
		if string(out[i:i+len(key)]) == string(key) {
			j := i + len(key)
			if out[j] == '0' {
				out[j] = '1'
			} else {
				out[j] = '0'
			}
			return out
		}
	}
	t.Fatal("no content field to tamper with")
	return nil
}
