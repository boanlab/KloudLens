// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

//go:build amd64

package syscalls

import "testing"

// TestSyscallConstantsStableAMD64 pins x86_64 ABI numbers. Changing them
// silently would desync from the BPF program's tracepoint attachments.
func TestSyscallConstantsStableAMD64(t *testing.T) {
	cases := map[string]struct {
		got, want int32
	}{
		"open":    {SysOpen, 2},
		"execve":  {SysExecve, 59},
		"connect": {SysConnect, 42},
		"openat":  {SysOpenat, 257},
		"clone3":  {SysClone3, 435},
		"openat2": {SysOpenat2, 437},
	}
	for name, c := range cases {
		if c.got != c.want {
			t.Errorf("Sys%s id changed: got=%d want=%d", name, c.got, c.want)
		}
	}
}

// TestLegacySyscallsPresentAMD64 confirms the legacy single-step syscalls
// (open, mkdir, rmdir, rename, link, unlink, symlink, chmod, chown) are
// real on amd64.
func TestLegacySyscallsPresentAMD64(t *testing.T) {
	cases := map[string]int32{
		"open":    SysOpen,
		"mkdir":   SysMkdir,
		"rmdir":   SysRmdir,
		"rename":  SysRename,
		"link":    SysLink,
		"unlink":  SysUnlink,
		"symlink": SysSymlink,
		"chmod":   SysChmod,
		"chown":   SysChown,
	}
	for name, id := range cases {
		if !IsRealSyscall(id) {
			t.Errorf("Sys%s(%d) should be a real syscall on amd64", name, id)
		}
		if SyscallName(id) != name {
			t.Errorf("SyscallName(Sys%s=%d) = %q, want %q", name, id, SyscallName(id), name)
		}
	}
}
