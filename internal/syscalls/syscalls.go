// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package syscalls holds the syscall id ↔ name table plus `Sys*` constants
// for the ids the BPF program attaches hooks to. The real-syscall table
// lives in syscalls_amd64.go (KloudLens is amd64-only); the pseudo ids
// below refer to non-syscall hooks (sched tracepoints, security_* kprobes,
// filp_close fentry) that KloudLens emits through the same pipeline.

package syscalls

// Pseudo-syscall ids reserved for non-syscall hooks the BPF program fires
// from sched and security_* kprobes. Numbers chosen well above the real
// syscall range (which tops out around 450) so no collision is possible
// with future kernel releases. Must match KL_PSEUDO_* in bpf/ids.bpf.h.
const (
	SysSchedProcessExit      int32 = 1000
	SysSecurityBprmCheck     int32 = 1001
	SysSecurityTaskKill      int32 = 1002
	SysSecurityPathChroot    int32 = 1003
	SysSecurityFileOpen      int32 = 1004
	SysFilpClose             int32 = 1005
	SysSecurityPathChown     int32 = 1006
	SysSecurityPathChmod     int32 = 1007
	SysSecurityPathUnlink    int32 = 1008
	SysSecurityPathRename    int32 = 1009
	SysSecurityPathLink      int32 = 1010
	SysSecurityPathMkdir     int32 = 1011
	SysSecurityPathRmdir     int32 = 1012
	SysCapCapable            int32 = 1013
	SysSecuritySocketConnect int32 = 1014
	SysSecuritySocketBind    int32 = 1015
	SysSecuritySocketSendmsg int32 = 1016
	SysSecuritySocketRecvmsg int32 = 1017
	SysDNSAnswer             int32 = 1018
)

// pseudoSyscallNames covers ids ≥ pseudoSyscallBase. Shared across arches.
var pseudoSyscallNames = map[int32]string{
	SysSchedProcessExit:      "sched_process_exit",
	SysSecurityBprmCheck:     "security_bprm_check",
	SysSecurityTaskKill:      "security_task_kill",
	SysSecurityPathChroot:    "security_path_chroot",
	SysSecurityFileOpen:      "security_file_open",
	SysFilpClose:             "filp_close",
	SysSecurityPathChown:     "security_path_chown",
	SysSecurityPathChmod:     "security_path_chmod",
	SysSecurityPathUnlink:    "security_path_unlink",
	SysSecurityPathRename:    "security_path_rename",
	SysSecurityPathLink:      "security_path_link",
	SysSecurityPathMkdir:     "security_path_mkdir",
	SysSecurityPathRmdir:     "security_path_rmdir",
	SysCapCapable:            "cap_capable",
	SysSecuritySocketConnect: "security_socket_connect",
	SysSecuritySocketBind:    "security_socket_bind",
	SysSecuritySocketSendmsg: "security_socket_sendmsg",
	SysSecuritySocketRecvmsg: "security_socket_recvmsg",
	SysDNSAnswer:             "dns_answer",
}

// pseudoSyscallBase is the first id reserved for non-syscall hooks. Real
// syscalls live below this cutoff on every supported architecture.
const pseudoSyscallBase = 1000

// SyscallName returns a friendly name; unknown ids render as "syscall_<id>".
// Real-syscall lookup goes through the realSyscallNames table supplied by
// syscalls_amd64.go.
func SyscallName(id int32) string {
	if name, ok := realSyscallNames[id]; ok {
		return name
	}
	if name, ok := pseudoSyscallNames[id]; ok {
		return name
	}
	return "syscall_" + itoa(id)
}

// IsRealSyscall reports whether id refers to an actual Linux syscall (as
// opposed to an LSM / tracepoint hook the BPF program also emits through
// this pipeline). Consumers that build seccomp allowlists or any filter
// that expects a real syscall name should gate insertions on this.
func IsRealSyscall(id int32) bool {
	return id >= 0 && id < pseudoSyscallBase
}

func itoa(n int32) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
