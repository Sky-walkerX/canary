package feed

import (
	"context"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// houseStyle reports whether msg reads "<pkg>: <what failed>: <detail>".
func houseStyle(msg, pkg string) bool {
	return strings.HasPrefix(msg, pkg+": ") && strings.Count(msg, ": ") >= 2
}

func TestErrorsFollowHouseStyle(t *testing.T) {
	sk, skHex := testKey(t)
	good, err := testCommitment().ToEvent(sk)
	if err != nil {
		t.Fatal(err)
	}

	// resign rewrites one tag or the content, then signs again, so only the
	// field under test is wrong.
	resign := func(mut func(*nostr.Event)) nostr.Event {
		ev := good
		ev.Tags = append(nostr.Tags(nil), good.Tags...)
		mut(&ev)
		ev.ID, ev.Sig = "", ""
		if err := ev.Sign(skHex); err != nil {
			t.Fatal(err)
		}
		return ev
	}
	setTag := func(name, value string) func(*nostr.Event) {
		return func(ev *nostr.Event) {
			for i, tg := range ev.Tags {
				if tg[0] == name {
					ev.Tags[i] = nostr.Tag{name, value}
				}
			}
		}
	}

	badSig := good
	badSig.Sig = strings.Repeat("00", 64)

	wrongKind := good
	wrongKind.Kind = 1

	cases := map[string]nostr.Event{
		"bad signature":      badSig,
		"wrong kind":         wrongKind,
		"bad policy_ref":     resign(setTag("policy_ref", "zz")),
		"bad content":        resign(func(ev *nostr.Event) { ev.Content = "zz" }),
		"bad block hash":     resign(setTag(TagBlockHash, "zz")),
		"root tag disagrees": resign(setTag("root", strings.Repeat("11", 32))),
	}
	for name, ev := range cases {
		_, err := FromEvent(ev)
		if err == nil {
			t.Errorf("%s: want an error", name)
			continue
		}
		if !houseStyle(err.Error(), "feed") {
			t.Errorf("%s: error %q does not read \"feed: <what failed>: <detail>\"", name, err)
		}
	}

	if _, err := NewRelayFeed(context.Background(), nil); err == nil {
		t.Error("no relays: want an error")
	} else if !houseStyle(err.Error(), "feed") {
		t.Errorf("no relays: error %q does not read \"feed: <what failed>: <detail>\"", err)
	}

	f := &relayFeed{queriers: []querier{alwaysFailQuerier{}}}
	if _, err := f.Get(context.Background(), [32]byte{1}, [][32]byte{{2}}); err == nil {
		t.Error("every relay failing: want an error")
	} else if !houseStyle(err.Error(), "feed") {
		t.Errorf("every relay failing: error %q does not read \"feed: <what failed>: <detail>\"", err)
	}
}
