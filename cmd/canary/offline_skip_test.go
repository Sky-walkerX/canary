package main

import "testing"

// A shell that is already sandboxed, such as an agent harness, may refuse to
// let the child cut itself off. That says nothing about Canary, so the tests
// that need the cut skip there and name the cause. CI sets CI=true, and
// there a refused cut still fails, so the cut stays enforced where it runs.
func TestARefusedNetworkCutIsRecognised(t *testing.T) {
	tests := []struct {
		name string
		r    result
		want bool
	}{
		{"nested sandbox-exec", result{code: 71, stderr: "sandbox-exec: sandbox_apply: Operation not permitted\n"}, true},
		{"the child could not cut itself off", result{code: exitOfflineSetup, stderr: "offline child: cut off the network: operation not permitted\n"}, true},
		{"exit 71 for another reason", result{code: 71, stderr: "something else\n"}, false},
		{"the command ran", result{code: 0, stdout: "Checks out.\n"}, false},
		{"the cut did not hold", result{code: exitOfflineDialed}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := networkCutRefused(tt.r); got != tt.want {
				t.Errorf("networkCutRefused(%+v) = %v, want %v", tt.r, got, tt.want)
			}
		})
	}
}

func TestARefusedCutFailsInCI(t *testing.T) {
	for _, tt := range []struct {
		ci, require string
		want        bool
	}{
		{"", "", false},
		{"true", "", true},
		{"", "1", true},
	} {
		t.Setenv("CI", tt.ci)
		t.Setenv("CANARY_REQUIRE_OFFLINE", tt.require)
		if got := networkCutRequired(); got != tt.want {
			t.Errorf("CI=%q CANARY_REQUIRE_OFFLINE=%q: required = %v, want %v", tt.ci, tt.require, got, tt.want)
		}
	}
}
