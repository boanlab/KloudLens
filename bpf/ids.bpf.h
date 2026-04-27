// SPDX-License-Identifier: (GPL-2.0-only OR Apache-2.0)
// Copyright 2026 BoanLab @ DKU
//
// ids.bpf.h — syscall id constants and pseudo-syscall ids for non-syscall
// hooks. Real-syscall numbers are amd64-specific (KloudLens is amd64-only);
// keeping them as #defines lets every feature TU compile standalone on any
// cross-host without dragging in <asm/unistd_64.h>. The KL_PSEUDO_* ids must
// match internal/syscalls/syscalls.go — drift between the two breaks
// userspace name resolution silently.
#pragma once

// ---- Real syscall numbers (amd64) ----------------------------------------
#define KL_SYS_READ 0
#define KL_SYS_WRITE 1
#define KL_SYS_OPEN 2
#define KL_SYS_CLOSE 3
#define KL_SYS_FSTAT 5
#define KL_SYS_MMAP 9
#define KL_SYS_MPROTECT 10
#define KL_SYS_PREAD64 17
#define KL_SYS_PWRITE64 18
#define KL_SYS_SOCKET 41
#define KL_SYS_CONNECT 42
#define KL_SYS_ACCEPT 43
#define KL_SYS_SENDMSG 46
#define KL_SYS_RECVMSG 47
#define KL_SYS_SHUTDOWN 48
#define KL_SYS_BIND 49
#define KL_SYS_LISTEN 50
#define KL_SYS_CLONE 56
#define KL_SYS_EXECVE 59
#define KL_SYS_KILL 62
#define KL_SYS_RENAME 82
#define KL_SYS_MKDIR 83
#define KL_SYS_RMDIR 84
#define KL_SYS_LINK 86
#define KL_SYS_UNLINK 87
#define KL_SYS_SYMLINK 88
#define KL_SYS_CHMOD 90
#define KL_SYS_FCHMOD 91
#define KL_SYS_CHOWN 92
#define KL_SYS_FCHOWN 93
#define KL_SYS_PTRACE 101
#define KL_SYS_SETUID 105
#define KL_SYS_SETGID 106
#define KL_SYS_SETREUID 113
#define KL_SYS_SETREGID 114
#define KL_SYS_SETRESUID 117
#define KL_SYS_SETRESGID 119
#define KL_SYS_SETFSUID 122
#define KL_SYS_SETFSGID 123
#define KL_SYS_CAPSET 126
#define KL_SYS_PRCTL 157
#define KL_SYS_CHROOT 161
#define KL_SYS_MOUNT 165
#define KL_SYS_UMOUNT2 166
#define KL_SYS_EXIT_GROUP 231
#define KL_SYS_TGKILL 234
#define KL_SYS_OPENAT 257
#define KL_SYS_MKDIRAT 258
#define KL_SYS_FCHOWNAT 260
#define KL_SYS_NEWFSTATAT 262
#define KL_SYS_UNLINKAT 263
#define KL_SYS_RENAMEAT 264
#define KL_SYS_LINKAT 265
#define KL_SYS_SYMLINKAT 266
#define KL_SYS_FCHMODAT 268
#define KL_SYS_UNSHARE 272
#define KL_SYS_ACCEPT4 288
#define KL_SYS_RECVMMSG 299
#define KL_SYS_SENDMMSG 307
#define KL_SYS_SETNS 308
#define KL_SYS_RENAMEAT2 316
#define KL_SYS_EXECVEAT 322
#define KL_SYS_STATX 332
#define KL_SYS_CLONE3 435
#define KL_SYS_OPENAT2 437
#define KL_SYS_FACCESSAT2 439

// ---- Pseudo-syscall ids for non-syscall hooks ----------------------------
//
// Must match internal/syscalls/syscalls.go. Numbers chosen well above the
// real syscall range (which tops out around 450 on amd64) so no collision
// is possible with future kernel releases.
#define KL_PSEUDO_SCHED_EXIT 1000
#define KL_PSEUDO_SECURITY_BPRM 1001
#define KL_PSEUDO_SECURITY_TASK_KILL 1002
#define KL_PSEUDO_SECURITY_CHROOT 1003
#define KL_PSEUDO_SECURITY_FILE_OPEN 1004
#define KL_PSEUDO_FILP_CLOSE 1005
#define KL_PSEUDO_SECURITY_CHOWN 1006
#define KL_PSEUDO_SECURITY_CHMOD 1007
#define KL_PSEUDO_SECURITY_UNLINK 1008
#define KL_PSEUDO_SECURITY_RENAME 1009
#define KL_PSEUDO_SECURITY_LINK 1010
#define KL_PSEUDO_SECURITY_MKDIR 1011
#define KL_PSEUDO_SECURITY_RMDIR 1012
#define KL_PSEUDO_CAP_CAPABLE 1013
#define KL_PSEUDO_SEC_SOCK_CONNECT 1014
#define KL_PSEUDO_SEC_SOCK_BIND 1015
#define KL_PSEUDO_SEC_SOCK_SENDMSG 1016
#define KL_PSEUDO_SEC_SOCK_RECVMSG 1017
#define KL_PSEUDO_DNS_ANSWER 1018
