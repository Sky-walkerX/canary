package main

import "os/exec"

// sandboxNoNetwork is a macOS sandbox profile that allows everything except
// the network: no outbound or inbound connection, and no bind.
const sandboxNoNetwork = "(version 1)(allow default)(deny network*)"

// offlineCommand runs the test binary under sandbox-exec, so the kernel
// refuses every network operation the child tries.
func offlineCommand(self string, args []string) (*exec.Cmd, error) {
	path, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return nil, err
	}
	return exec.Command(path, append([]string{"-p", sandboxNoNetwork, self}, args...)...), nil
}

// cutOffNetwork has nothing to do on macOS: sandbox-exec cut the child off
// before it started. The child's probe dial shows the cut holds.
func cutOffNetwork() error { return nil }
