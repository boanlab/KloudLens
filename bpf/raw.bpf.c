// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 BoanLab @ DKU
//
// raw.bpf.c — raw_syscalls fallback. Included by kloudlens.bpf.c; not
// compiled standalone.
//
// Programs:
// tp/syscalls/raw_syscalls/sys_enter
// tp/syscalls/raw_syscalls/sys_exit
//
// Captures every syscall as a UNARY record with the 6 raw ulong args so
// userspace can at least count + correlate even for syscalls we haven't
// written a typed decoder for yet. Skipped for ids we already hook
// specifically (in process/file_io/file_meta/network/creds/namespace) to
// avoid duplicates.
//
// Opt-in via LiveOptions.EnableRawSyscalls — these tracepoints fire on
// every syscall system-wide and would drown the bulk_proc ring otherwise.
#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "wire.bpf.h"
#include "maps.bpf.h"
#include "helpers.bpf.h"
#include "ids.bpf.h"

static __always_inline int kl_is_typed_syscall(__s32 id)
{
 return id == KL_SYS_EXECVE ||
 id == KL_SYS_EXECVEAT ||
 id == KL_SYS_OPEN ||
 id == KL_SYS_OPENAT ||
 id == KL_SYS_OPENAT2 ||
 id == KL_SYS_CLOSE ||
 id == KL_SYS_SOCKET ||
 id == KL_SYS_CONNECT ||
 id == KL_SYS_BIND ||
 id == KL_SYS_LISTEN ||
 id == KL_SYS_ACCEPT ||
 id == KL_SYS_ACCEPT4 ||
 id == KL_SYS_SENDMSG ||
 id == KL_SYS_RECVMSG ||
 id == KL_SYS_SENDMMSG ||
 id == KL_SYS_RECVMMSG ||
 id == KL_SYS_SHUTDOWN ||
 id == KL_SYS_CLONE ||
 id == KL_SYS_CLONE3 ||
 id == KL_SYS_UNSHARE ||
 id == KL_SYS_SETNS ||
 id == KL_SYS_EXIT_GROUP ||
 id == KL_SYS_KILL ||
 id == KL_SYS_TGKILL ||
 id == KL_SYS_UNLINK ||
 id == KL_SYS_UNLINKAT ||
 id == KL_SYS_RMDIR ||
 id == KL_SYS_MKDIR ||
 id == KL_SYS_MKDIRAT ||
 id == KL_SYS_RENAME ||
 id == KL_SYS_RENAMEAT ||
 id == KL_SYS_RENAMEAT2 ||
 id == KL_SYS_LINK ||
 id == KL_SYS_LINKAT ||
 id == KL_SYS_SYMLINK ||
 id == KL_SYS_SYMLINKAT ||
 id == KL_SYS_CHMOD ||
 id == KL_SYS_FCHMOD ||
 id == KL_SYS_FCHMODAT ||
 id == KL_SYS_CHOWN ||
 id == KL_SYS_FCHOWN ||
 id == KL_SYS_FCHOWNAT ||
 id == KL_SYS_SETUID ||
 id == KL_SYS_SETGID ||
 id == KL_SYS_SETREUID ||
 id == KL_SYS_SETREGID ||
 id == KL_SYS_SETRESUID ||
 id == KL_SYS_SETRESGID ||
 id == KL_SYS_SETFSUID ||
 id == KL_SYS_SETFSGID ||
 id == KL_SYS_CAPSET ||
 id == KL_SYS_PTRACE ||
 id == KL_SYS_PRCTL ||
 id == KL_SYS_MMAP ||
 id == KL_SYS_MPROTECT ||
 id == KL_SYS_CHROOT ||
 id == KL_SYS_MOUNT ||
 id == KL_SYS_UMOUNT2 ||
 id == KL_SYS_READ ||
 id == KL_SYS_WRITE ||
 id == KL_SYS_PREAD64 ||
 id == KL_SYS_PWRITE64 ||
 id == KL_SYS_FSTAT ||
 id == KL_SYS_NEWFSTATAT ||
 id == KL_SYS_STATX ||
 id == KL_SYS_FACCESSAT2;
}

SEC("tp/syscalls/raw_syscalls/sys_enter")
int kl_raw_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 __s32 id = (__s32)ctx->id;
 if (kl_is_typed_syscall(id)) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, id, EVENT_ENTER, 7) < 0) return 0;

 if (kl_put_ulong(s, (__u64)ctx->args[0]) < 0) return 0;
 if (kl_put_ulong(s, (__u64)ctx->args[1]) < 0) return 0;
 if (kl_put_ulong(s, (__u64)ctx->args[2]) < 0) return 0;
 if (kl_put_ulong(s, (__u64)ctx->args[3]) < 0) return 0;
 if (kl_put_ulong(s, (__u64)ctx->args[4]) < 0) return 0;
 if (kl_put_ulong(s, (__u64)ctx->args[5]) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 6);

 return kl_submit_bulk_proc(s);
}

SEC("tp/syscalls/raw_syscalls/sys_exit")
int kl_raw_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 __s32 id = (__s32)ctx->id;
 if (kl_is_typed_syscall(id)) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, id, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_proc(s);
}
