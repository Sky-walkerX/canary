package policy

import (
	"strings"
	"testing"
)

// houseStyle reports whether msg reads "<pkg>: <what failed>: <detail>".
func houseStyle(msg, pkg string) bool {
	return strings.HasPrefix(msg, pkg+": ") && strings.Count(msg, ": ") >= 2
}

func TestFromBlindBitInfoErrorsFollowHouseStyle(t *testing.T) {
	for name, body := range map[string]string{
		"unknown network": `{"network":"testnet4"}`,
		"malformed JSON":  `{`,
	} {
		_, err := FromBlindBitInfo(strings.NewReader(body))
		if err == nil {
			t.Errorf("%s: want an error", name)
			continue
		}
		if !houseStyle(err.Error(), "policy") {
			t.Errorf("%s: error %q does not read \"policy: <what failed>: <detail>\"", name, err)
		}
		if strings.Contains(err.Error(), "unrecognised") {
			t.Errorf("%s: error %q uses UK spelling; code text uses US spelling", name, err)
		}
	}
}
