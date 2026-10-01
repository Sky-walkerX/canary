//go:build !darwin && !(linux && (amd64 || arm64))

package main

import "os/exec"

func offlineCommand(string, []string) (*exec.Cmd, error) { return nil, errNoNetworkCut }

func cutOffNetwork() error { return errNoNetworkCut }
