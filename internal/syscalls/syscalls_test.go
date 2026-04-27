// SPDX-License-Identifier: Apache-2.0

package syscalls

import "testing"

// TestSyscallName pins ids the package exposes regardless of the call
// site — real syscalls plus a couple of pseudo ids. amd64-specific
// numeric pinning lives in syscalls_amd64_test.go.
func TestSyscallName(t *testing.T) {
	cases := map[int32]string{
		SysExecve:            "execve",
		SysConnect:           "connect",
		SysOpenat:            "openat",
		SysClose:             "close",
		SysSchedProcessExit:  "sched_process_exit",
		SysSecurityBprmCheck: "security_bprm_check",
		SysSetresuid:         "setresuid",
		SysCapset:            "capset",
	}
	for id, want := range cases {
		if got := SyscallName(id); got != want {
			t.Errorf("SyscallName(%d) = %q, want %q", id, got, want)
		}
	}
	if got := SyscallName(99999); got != "syscall_99999" {
		t.Errorf("unknown syscall id rendered as %q", got)
	}
	if got := SyscallName(-1); got != "syscall_-1" {
		t.Errorf("negative syscall id rendered as %q", got)
	}
}

// TestIsRealSyscall covers the predicate's behaviour across real syscall
// ids, pseudo-hook ids, and the negative sentinel.
func TestIsRealSyscall(t *testing.T) {
	real := []int32{SysExecve, SysConnect, SysCapset, SysClone3, SysOpenat2, 0, 999}
	for _, id := range real {
		if !IsRealSyscall(id) {
			t.Errorf("IsRealSyscall(%d) = false, want true", id)
		}
	}
	pseudo := []int32{
		SysSchedProcessExit, SysSecurityBprmCheck, SysSecurityTaskKill,
		SysSecurityFileOpen, SysFilpClose, SysSecurityPathChmod,
		1000, 1500, 9999,
	}
	for _, id := range pseudo {
		if IsRealSyscall(id) {
			t.Errorf("IsRealSyscall(%d) = true, want false (pseudo-hook)", id)
		}
	}
	if IsRealSyscall(-1) {
		t.Errorf("negative id should not be a real syscall")
	}
}
