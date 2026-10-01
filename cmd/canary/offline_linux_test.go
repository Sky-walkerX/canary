//go:build amd64 || arm64

package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"
)

// seccompArch holds, per architecture, the seccomp system call's number
// and the audit architecture the kernel reports to a filter.
var seccompArch = map[string]struct {
	sysSeccomp uintptr
	audit      uint32
}{
	"amd64": {317, 0xc000003e}, // __NR_seccomp, AUDIT_ARCH_X86_64
	"arm64": {277, 0xc00000b7}, // __NR_seccomp, AUDIT_ARCH_AARCH64
}

// offlineCommand runs the test binary as it is. The child cuts itself off
// with a seccomp filter before it does anything else.
func offlineCommand(self string, args []string) (*exec.Cmd, error) {
	if _, ok := seccompArch[runtime.GOARCH]; !ok {
		return nil, fmt.Errorf("%w: no seccomp numbers for %s", errNoNetworkCut, runtime.GOARCH)
	}
	return exec.Command(self, args...), nil
}

// Constants from <linux/prctl.h>, <linux/seccomp.h> and <linux/filter.h>.
const (
	prSetNoNewPrivs        = 38
	seccompSetModeFilter   = 1
	seccompFilterFlagTsync = 1
	seccompRetAllow        = 0x7fff0000
	seccompRetErrno        = 0x00050000
	bpfLoadWordAbs         = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJumpIfEqual         = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfReturn              = 0x06 // BPF_RET | BPF_K
	seccompDataNr          = 0    // offsetof(struct seccomp_data, nr)
	seccompDataArch        = 4    // offsetof(struct seccomp_data, arch)
)

// sockFilter is struct sock_filter, one classic BPF instruction.
type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// sockFprog is struct sock_fprog.
type sockFprog struct {
	len    uint16
	filter *sockFilter
}

// cutOffNetwork makes socket(2) fail with EACCES on every thread of this
// process, and on every thread it starts later. Go opens every network
// connection, and every DNS query, through socket(2), whatever dialer asks,
// so after this nothing in the process can reach the network. A system call
// from another architecture passes the filter untouched, so the filter
// never blocks the wrong call.
func cutOffNetwork() error {
	arch, ok := seccompArch[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("%w: no seccomp numbers for %s", errNoNetworkCut, runtime.GOARCH)
	}
	filter := []sockFilter{
		{bpfLoadWordAbs, 0, 0, seccompDataArch},
		{bpfJumpIfEqual, 0, 3, arch.audit}, // another architecture: allow
		{bpfLoadWordAbs, 0, 0, seccompDataNr},
		{bpfJumpIfEqual, 0, 1, uint32(syscall.SYS_SOCKET)},
		{bpfReturn, 0, 0, seccompRetErrno | uint32(syscall.EACCES)},
		{bpfReturn, 0, 0, seccompRetAllow},
	}
	prog := sockFprog{len: uint16(len(filter)), filter: &filter[0]}

	// no_new_privs belongs to a thread, and seccomp checks the calling
	// thread's. The TSYNC flag then gives both to every other thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); e != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", e)
	}
	tid, _, e := syscall.RawSyscall(arch.sysSeccomp, seccompSetModeFilter, seccompFilterFlagTsync, uintptr(unsafe.Pointer(&prog)))
	runtime.KeepAlive(filter)
	if e != 0 {
		return fmt.Errorf("seccomp(SECCOMP_SET_MODE_FILTER): %w", e)
	}
	if tid != 0 {
		return fmt.Errorf("seccomp: thread %d could not take the filter", tid)
	}
	return nil
}
