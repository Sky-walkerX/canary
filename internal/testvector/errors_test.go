package testvector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// houseStyle reports whether msg reads "<pkg>: <what failed>: <detail>".
func houseStyle(msg, pkg string) bool {
	return strings.HasPrefix(msg, pkg+": ") && strings.Count(msg, ": ") >= 2
}

func TestErrorsFollowHouseStyle(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmp, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(tmp); err == nil {
		t.Error("malformed file: want an error")
	} else if !houseStyle(err.Error(), "testvector") {
		t.Errorf("malformed file: error %q does not read \"testvector: <what failed>: <detail>\"", err)
	}

	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file: want an error")
	} else if !houseStyle(err.Error(), "testvector") {
		t.Errorf("missing file: error %q does not read \"testvector: <what failed>: <detail>\"", err)
	}

	good := oneEligibleTxVector(t)
	mutate := map[string]func(*Vector){
		"unknown network":  func(v *Vector) { v.Network = "testnet4" },
		"bad block hex":    func(v *Vector) { v.Block = "zz" },
		"truncated block":  func(v *Vector) { v.Block = v.Block[:20] },
		"bad prevout key":  func(v *Vector) { v.Prevouts = map[string]Prevout{"nocolon": {}} },
		"missing prevout":  func(v *Vector) { v.Prevouts = map[string]Prevout{} },
		"wrong n":          func(v *Vector) { v.Expected.N = 7 },
		"wrong root":       func(v *Vector) { v.Expected.Root = strings.Repeat("00", 32) },
		"wrong leaf count": func(v *Vector) { v.Expected.N = 1; v.Expected.Leaves = nil },
	}
	for name, mut := range mutate {
		v := good
		v.Expected.Leaves = append([]string(nil), good.Expected.Leaves...)
		mut(&v)
		err := v.Run()
		if err == nil {
			t.Errorf("%s: want an error", name)
			continue
		}
		if !houseStyle(err.Error(), "testvector") {
			t.Errorf("%s: error %q does not read \"testvector: <what failed>: <detail>\"", name, err)
		}
	}
}
