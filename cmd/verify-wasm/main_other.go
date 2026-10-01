//go:build !(js && wasm)

package main

import (
	"fmt"
	"os"
)

// main explains how to build the checker. Only the js/wasm build is useful;
// this one exists so go build ./... and go test ./... cover the shared code.
func main() {
	fmt.Fprintln(os.Stderr, "verify-wasm: this command runs only in a browser: build it with make wasm")
	os.Exit(2)
}
