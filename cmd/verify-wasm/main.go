//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall/js"
)

// main sets the page's two functions and then blocks, so they stay callable.
//
//	canaryVerify(file)    file is a string or a Uint8Array of the file's bytes.
//	                      Returns the output JSON as a string.
//	canaryCheckerInfo()   Returns the build and size-limit JSON as a string.
func main() {
	js.Global().Set("canaryVerify", js.FuncOf(verifyJS))
	js.Global().Set("canaryCheckerInfo", js.FuncOf(func(js.Value, []js.Value) any {
		return string(checkerInfo())
	}))
	select {}
}

// verifyJS is canaryVerify. It always returns a JSON string. A panic comes
// back as {"error": "..."} instead of ending the Go program, which would
// leave every later call failing.
func verifyJS(_ js.Value, args []js.Value) (ret any) {
	defer func() {
		if v := recover(); v != nil {
			j, _ := json.Marshal(map[string]string{"error": fmt.Sprintf("verify-wasm: check panicked: %v", v)})
			ret = string(j)
		}
	}()
	out, err := check(argBytes(args))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	if out == nil {
		j, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(j)
	}
	return string(out)
}

// argBytes copies the file out of the first argument: the bytes of a
// Uint8Array, or the UTF-8 of a string. Anything else gives no bytes, which
// verify reports as a file it can't read.
func argBytes(args []js.Value) []byte {
	if len(args) == 0 {
		return nil
	}
	a := args[0]
	switch {
	case a.Type() == js.TypeString:
		return []byte(a.String())
	case a.InstanceOf(js.Global().Get("Uint8Array")):
		b := make([]byte, a.Get("length").Int())
		js.CopyBytesToGo(b, a)
		return b
	}
	return nil
}
