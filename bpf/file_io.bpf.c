// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 BoanLab @ DKU
//
// file_io.bpf.c — file open/close/read/write/stat-class hooks. Included by
// kloudlens.bpf.c; not compiled standalone.
//
// Programs:
// tp/syscalls/sys_{enter,exit}_open
// tp/syscalls/sys_{enter,exit}_openat
// tp/syscalls/sys_{enter,exit}_openat2
// tp/syscalls/sys_{enter,exit}_close
// tp/syscalls/sys_enter_read / write / pread64 / pwrite64 [coalesced UNARY]
// tp/syscalls/sys_enter_newfstat / newfstatat / statx [coalesced UNARY]
// tp/syscalls/sys_enter_faccessat2 [coalesced UNARY]
// fentry/filp_close
// kprobe/security_file_open
#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "wire.bpf.h"
#include "maps.bpf.h"
#include "helpers.bpf.h"
#include "ids.bpf.h"

// O_* flag bits we branch on for write-vs-read crit/bulk routing. Repeated
// across the open variants below; clang accepts identical-value redefinition
// without warning.
#define KL_O_ACCMODE 0x3
#define KL_O_WRONLY 0x1
#define KL_O_RDWR 0x2
#define KL_O_CREAT 0x40
#define KL_O_TRUNC 0x200

// ============================================================================
// openat — sys_enter: dirfd + path + flags + mode + source
// ============================================================================
//
// Layout follows Pkg 30 (internal/wire/mapper.go): the dirfd leads so the
// userspace resolver can reconstruct cgroup-relative paths.

SEC("tp/syscalls/sys_enter_openat")
int kl_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;

 // arg_num = 5: dirfd, resource(path), flags, mode, source. Patched
 // down to 4 when source is deduped.
 if (kl_fill_header(s, KL_SYS_OPENAT, EVENT_ENTER, 5) < 0) return 0;

 __s32 dirfd = (__s32)ctx->args[0];
 const char *path = (const char *)ctx->args[1];
 __s32 flags = (__s32)ctx->args[2];
 __u32 mode = (__u32)ctx->args[3];

 if (kl_put_int(s, dirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 if (kl_put_int(s, flags) < 0) return 0;
 if (kl_put_uint(s, mode) < 0) return 0;

 // Stash (path_hash, open_ts) so openat exit can commit into
 // kl_fd_state keyed by the returned fd. Doing the hash here (not at
 // exit) keeps all the user-memory read on the enter side where the
 // syscall args are still live.
 __u64 pid_tid = bpf_get_current_pid_tgid();
 struct kl_pending_open po = {
 .path_hash = kl_hash_user_path(path),
 .open_ts_ns = bpf_ktime_get_ns(),
 };
 bpf_map_update_elem(&kl_pending_openat, &pid_tid, &po, BPF_ANY);

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 4);

 // Route writes to crit; plain reads to bulk. isWriteOpenFlags logic
 // in Go lives here too so critical-ring bandwidth isn't wasted on reads.
 int is_write = ((flags & KL_O_ACCMODE) == KL_O_WRONLY) ||
 ((flags & KL_O_ACCMODE) == KL_O_RDWR) ||
 (flags & (KL_O_CREAT | KL_O_TRUNC));
 return is_write ? kl_submit_crit(s) : kl_submit_bulk_file(s);
}

SEC("tp/syscalls/sys_exit_openat")
int kl_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;

 // Commit the fd→state entry on successful opens so close can emit a
 // self-contained record. Failed opens (retval < 0) and opens where
 // the enter side didn't stash a pending context (bpf attach race,
 // LRU eviction) skip the map write.
 __s32 ret = (__s32)ctx->ret;
 __u64 pid_tid = bpf_get_current_pid_tgid();
 struct kl_pending_open *po = bpf_map_lookup_elem(&kl_pending_openat, &pid_tid);
 if (po && ret >= 0) {
 __u64 fd_key = (pid_tid & 0xffffffff00000000ULL) | (__u32)ret;
 struct kl_fd_state st = {
 .path_hash = po->path_hash,
 .open_ts_ns = po->open_ts_ns,
 };
 if (st.path_hash != 0) {
 bpf_map_update_elem(&kl_fd_state, &fd_key, &st, BPF_ANY);
 }
 }
 if (po) bpf_map_delete_elem(&kl_pending_openat, &pid_tid);

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_OPENAT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file(s);
}

// ============================================================================
// Legacy path-based open / modern openat2
// ============================================================================
//
// open(path, flags, mode) — pre-openat callers (strace targets, static binaries
// compiled against old libcs). Same write/read split as openat. openat2 takes
// (dirfd, path, open_how __user*, size) — we peek the flags/mode from the
// struct open_how so the policy pipeline sees the same shape as openat.

SEC("tp/syscalls/sys_enter_open")
int kl_open_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_OPEN, EVENT_ENTER, 4) < 0) return 0;

 const char *path = (const char *)ctx->args[0];
 __s32 flags = (__s32)ctx->args[1];
 __u32 mode = (__u32)ctx->args[2];

 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 if (kl_put_int(s, flags) < 0) return 0;
 if (kl_put_uint(s, mode) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);

 int is_write = ((flags & KL_O_ACCMODE) == KL_O_WRONLY) ||
 ((flags & KL_O_ACCMODE) == KL_O_RDWR) ||
 (flags & (KL_O_CREAT | KL_O_TRUNC));
 return is_write ? kl_submit_crit(s) : kl_submit_bulk_file(s);
}

SEC("tp/syscalls/sys_exit_open")
int kl_open_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_OPEN, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file(s);
}

// `struct open_how` has { flags:u64, mode:u64, resolve:u64 } as its first
// three fields — we only need flags here. bpf_probe_read_user tolerates a
// zero-size read (args[3] is the caller's declared size) by returning the
// prefix.
SEC("tp/syscalls/sys_enter_openat2")
int kl_openat2_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_OPENAT2, EVENT_ENTER, 5) < 0) return 0;

 __s32 dirfd = (__s32)ctx->args[0];
 const char *path = (const char *)ctx->args[1];
 const void *how = (const void *)ctx->args[2];

 __u64 flags64 = 0;
 __u64 mode64 = 0;
 if (how) {
 bpf_probe_read_user(&flags64, sizeof(flags64), how);
 bpf_probe_read_user(&mode64, sizeof(mode64), (const __u8 *)how + 8);
 }

 if (kl_put_int(s, dirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 if (kl_put_ulong(s, flags64) < 0) return 0;
 if (kl_put_ulong(s, mode64) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 4);

 int is_write = ((flags64 & 0x3) == 1) || ((flags64 & 0x3) == 2) ||
 (flags64 & (0x40 | 0x200));
 return is_write ? kl_submit_crit(s) : kl_submit_bulk_file(s);
}

SEC("tp/syscalls/sys_exit_openat2")
int kl_openat2_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_OPENAT2, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file(s);
}

// ============================================================================
// close — enter: fd + source
// ============================================================================

SEC("tp/syscalls/sys_enter_close")
int kl_close_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 // Base layout: arg_num = 2 (fd + source). When the fd was tracked by
 // kl_fd_state we append path_ref + open_ts, bumping to 4 (or 5 with
 // source). Patched to final count at the bottom.
 if (kl_fill_header(s, KL_SYS_CLOSE, EVENT_ENTER, 2) < 0) return 0;

 __s32 fd = (__s32)ctx->args[0];
 if (kl_put_int(s, fd) < 0) return 0;

 // Attach path_ref + open_ts when this fd came from a tracked openat.
 // The hash resolves via the user-space str cache populated by the
 // original openat enter frame's ARG_RESOURCE; a cache miss is benign
 // (user-space surfaces a placeholder), which is still better than no
 // path correlation at all.
 __u64 pid_tid = bpf_get_current_pid_tgid();
 __u64 fd_key = (pid_tid & 0xffffffff00000000ULL) | (__u32)fd;
 struct kl_fd_state *st = bpf_map_lookup_elem(&kl_fd_state, &fd_key);
 int has_state = 0;
 if (st && st->path_hash != 0) {
 if (kl_put_str_ref(s, st->path_hash) < 0) return 0;
 if (kl_put_ulong(s, st->open_ts_ns) < 0) return 0;
 has_state = 1;
 bpf_map_delete_elem(&kl_fd_state, &fd_key);
 }

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) {
 kl_patch_arg_num(s, has_state ? 3 : 1);
 } else if (has_state) {
 kl_patch_arg_num(s, 4);
 }

 return kl_submit_bulk_file(s);
}

SEC("tp/syscalls/sys_exit_close")
int kl_close_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CLOSE, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file(s);
}

// ============================================================================
// filp_close — pseudo-syscall UNARY, canonical absolute path via bpf_d_path
// ============================================================================
//
// Every closed `struct file *` passes through filp_close (do_close_on_exec,
// __fput, close(2) — all roads lead here). filp_close is on the kernel's
// btf_allowlist_d_path, so bpf_d_path can run from a tracing program
// attached here via fentry. We use fentry (not a plain kprobe) because the
// kernel gates bpf_d_path on BPF_PROG_TYPE_TRACING — plain kprobes get
// "program of this type cannot use helper" at load time.

SEC("fentry/filp_close")
int BPF_PROG(kl_filp_close, struct file *file)
{
 if (!kl_should_monitor()) return 0;
 if (!file) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_FILP_CLOSE, EVENT_UNARY, 2) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;

 if (kl_put_dpath(s, &file->f_path) < 0) return 0;

 if (wrote_src == 0) kl_patch_arg_num(s, 1);

 (void)kl_submit_bulk_file(s);
 return 0;
}

// ============================================================================
// High-rate UNARY syscalls — read / write / pread64 / pwrite64 / fstat /
// newfstatat / statx / faccessat2. All go through kl_coalesce_check so
// same-(tgid, kind, disc) bursts within KL_COALESCE_WINDOW_NS collapse to one
// emitted event.
// ============================================================================

// kl_emit_rw is the shared body for read / write / pread64 / pwrite64. All
// four have the same enter signature: (fd, buf, count[, offset]). We emit
// ARG_INT(fd) | ARG_ULONG(count) | ARG_SOURCE(comm, dedup)
// plus the coalesce trailer when applicable.
static __always_inline int kl_emit_rw(__s32 sysid,
 struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;

 __s32 fd = (__s32)ctx->args[0];
 __u64 count = (__u64)ctx->args[2];
 __u64 disc = ((__u64)(__u32)fd) | ((__u64)(__u32)sysid << 32);

 __u32 prev_count = 0;
 __u64 prev_bytes = 0;
 int emit = kl_coalesce_check(KL_COALESCE_RW, disc, count,
 &prev_count, &prev_bytes);
 if (emit == 0) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 __s8 argc = (emit == 2) ? 5 : 3;

 if (kl_try_fill_compact(s, sysid, argc) == 0) {
 if (kl_put_int(s, fd) < 0) return 0;
 if (kl_put_ulong(s, count) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) {
 argc = (__s8)(argc - 1);
 struct compact_event_t *ce = (struct compact_event_t *)&s->buf[0];
 ce->arg_num = argc;
 }
 if (emit == 2) {
 if (kl_put_coalesced_trailer(s, prev_count, prev_bytes) < 0) return 0;
 }
 return kl_submit_bulk_file(s);
 }

 if (kl_fill_header(s, sysid, EVENT_UNARY, argc) < 0) return 0;

 if (kl_put_int(s, fd) < 0) return 0;
 if (kl_put_ulong(s, count) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) {
 argc = (__s8)(argc - 1);
 kl_patch_arg_num(s, argc);
 }

 if (emit == 2) {
 if (kl_put_coalesced_trailer(s, prev_count, prev_bytes) < 0) return 0;
 }
 return kl_submit_bulk_file(s);
}

SEC("tp/syscalls/sys_enter_read")
int kl_read_enter(struct trace_event_raw_sys_enter *ctx)
{
 return kl_emit_rw(KL_SYS_READ, ctx);
}

SEC("tp/syscalls/sys_enter_write")
int kl_write_enter(struct trace_event_raw_sys_enter *ctx)
{
 return kl_emit_rw(KL_SYS_WRITE, ctx);
}

SEC("tp/syscalls/sys_enter_pread64")
int kl_pread64_enter(struct trace_event_raw_sys_enter *ctx)
{
 return kl_emit_rw(KL_SYS_PREAD64, ctx);
}

SEC("tp/syscalls/sys_enter_pwrite64")
int kl_pwrite64_enter(struct trace_event_raw_sys_enter *ctx)
{
 return kl_emit_rw(KL_SYS_PWRITE64, ctx);
}

// kl_emit_path_unary is the shared body for stat/access-style UNARY hooks
// with a const char __user *pathname.
static __always_inline int kl_emit_path_unary(__u32 kind, __s32 sysid,
 const char *up)
{
 if (!kl_should_monitor()) return 0;

 __u64 disc = 0;
 char pbuf[KL_HASH_MAX_BYTES];
 long n = bpf_probe_read_user_str(pbuf, sizeof(pbuf), up);
 if (n > 1) {
 __u32 un = (__u32)n;
 if (un > KL_HASH_MAX_BYTES) un = KL_HASH_MAX_BYTES;
 disc = kl_fnv1a_buf((const __u8 *)pbuf, un - 1);
 }

 __u32 prev_count = 0;
 __u64 prev_bytes = 0;
 int emit = kl_coalesce_check(kind, disc, 0, &prev_count, &prev_bytes);
 if (emit == 0) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 __s8 argc = (emit == 2) ? 4 : 2;
 if (kl_fill_header(s, sysid, EVENT_UNARY, argc) < 0) return 0;

 if (kl_put_str_user(s, ARG_RESOURCE, up) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) {
 argc = (__s8)(argc - 1);
 kl_patch_arg_num(s, argc);
 }

 if (emit == 2) {
 if (kl_put_coalesced_trailer(s, prev_count, prev_bytes) < 0) return 0;
 }
 return kl_submit_bulk_file(s);
}

// kl_emit_fd_unary is the fd-only variant used by fstat(fd, statbuf).
static __always_inline int kl_emit_fd_unary(__u32 kind, __s32 sysid, __s32 fd)
{
 if (!kl_should_monitor()) return 0;

 __u64 disc = (__u64)(__u32)fd;
 __u32 prev_count = 0;
 __u64 prev_bytes = 0;
 int emit = kl_coalesce_check(kind, disc, 0, &prev_count, &prev_bytes);
 if (emit == 0) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 __s8 argc = (emit == 2) ? 4 : 2;
 if (kl_fill_header(s, sysid, EVENT_UNARY, argc) < 0) return 0;

 if (kl_put_int(s, fd) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) {
 argc = (__s8)(argc - 1);
 kl_patch_arg_num(s, argc);
 }

 if (emit == 2) {
 if (kl_put_coalesced_trailer(s, prev_count, prev_bytes) < 0) return 0;
 }
 return kl_submit_bulk_file(s);
}

// Kernel tracepoint naming quirk: fstat(2) (__NR_fstat = 5) is exposed as
// `sys_enter_newfstat` — mirrors the `newfstat`/`newstat` etc. convention the
// kernel uses internally.
SEC("tp/syscalls/sys_enter_newfstat")
int kl_fstat_enter(struct trace_event_raw_sys_enter *ctx)
{
 return kl_emit_fd_unary(KL_COALESCE_STAT, KL_SYS_FSTAT, (__s32)ctx->args[0]);
}

SEC("tp/syscalls/sys_enter_newfstatat")
int kl_newfstatat_enter(struct trace_event_raw_sys_enter *ctx)
{
 return kl_emit_path_unary(KL_COALESCE_STAT, KL_SYS_NEWFSTATAT,
 (const char *)ctx->args[1]);
}

SEC("tp/syscalls/sys_enter_statx")
int kl_statx_enter(struct trace_event_raw_sys_enter *ctx)
{
 return kl_emit_path_unary(KL_COALESCE_STAT, KL_SYS_STATX,
 (const char *)ctx->args[1]);
}

SEC("tp/syscalls/sys_enter_faccessat2")
int kl_faccessat2_enter(struct trace_event_raw_sys_enter *ctx)
{
 return kl_emit_path_unary(KL_COALESCE_ACCESS, KL_SYS_FACCESSAT2,
 (const char *)ctx->args[1]);
}

// ============================================================================
// LSM hook for file_open — pre-check visibility of every open
// ============================================================================

SEC("kprobe/security_file_open")
int BPF_KPROBE(kl_kp_file_open, struct file *file)
{
 if (!kl_should_monitor()) return 0;
 if (!file) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SECURITY_FILE_OPEN, EVENT_UNARY, 3) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;

 struct dentry *leaf = BPF_CORE_READ(file, f_path.dentry);
 struct vfsmount *vm = BPF_CORE_READ(file, f_path.mnt);
 if (kl_put_fullpath(s, leaf, vm) < 0) return 0;

 __u32 flags = BPF_CORE_READ(file, f_flags);
 if (kl_put_uint(s, flags) < 0) return 0;

 if (wrote_src == 0) kl_patch_arg_num(s, 2);

 int is_write = ((flags & 0x3) == 1) || ((flags & 0x3) == 2) ||
 (flags & (0x40 | 0x200));
 (void)(is_write ? kl_submit_crit(s) : kl_submit_bulk_file(s));
 return 0;
}
