package ui

import "testing"

// TestAfterLabel checks that the report message drops only a leading copy of
// the badge's label, and leaves every other message whole.
func TestAfterLabel(t *testing.T) {
	tests := []struct{ msg, label, want string }{
		{"Checks out. The server signed a record that includes this entry, then signed a list that left it out.", "Checks out",
			"The server signed a record that includes this entry, then signed a list that left it out."},
		{"Does not check out: receipt failed.", "Does not check out", "Receipt failed."},
		{"Can't read this file: not JSON.", "Can't read this file", "Not JSON."},
		{"Inclusion only: you can be sure of this, you can't yet prove it to others.", "Checks out, inclusion only",
			"Inclusion only: you can be sure of this, you can't yet prove it to others."},
		{"Checks out.", "Checks out", "Checks out."},
		{"Checks outright.", "Checks out", "Checks outright."},
	}
	for _, tt := range tests {
		if got := afterLabel(tt.msg, tt.label); got != tt.want {
			t.Errorf("afterLabel(%q, %q) = %q, want %q", tt.msg, tt.label, got, tt.want)
		}
	}
}
