// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 BoanLab @ DKU
//
// file_meta.bpf.c — file metadata mutation hooks (path / mode / owner). Included
// by kloudlens.bpf.c; not compiled standalone.
//
// Programs:
// tp/syscalls/sys_{enter,exit}_unlink / unlinkat
// tp/syscalls/sys_{enter,exit}_rename / renameat / renameat2
// tp/syscalls/sys_{enter,exit}_mkdir / mkdirat
// tp/syscalls/sys_{enter,exit}_rmdir
// tp/syscalls/sys_{enter,exit}_link / linkat
// tp/syscalls/sys_{enter,exit}_symlink / symlinkat
// tp/syscalls/sys_{enter,exit}_chmod / fchmod / fchmodat
// tp/syscalls/sys_{enter,exit}_chown / fchown / fchownat
// kprobe/security_path_chmod / chown / unlink / rmdir / mkdir
// kprobe/security_path_symlink / link / rename
#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "wire.bpf.h"
#include "maps.bpf.h"
#include "helpers.bpf.h"
#include "ids.bpf.h"

// ============================================================================
// dirfd-aware mutations — unlinkat / renameat2 / mkdirat
// ============================================================================
//
// We capture paths at sys_enter before any path-walk failure so the event
// shape matches execve/openat — userspace treats dirfd==AT_FDCWD as
// "relative to current dir" and requests CWD resolution from /proc when
// needed.

SEC("tp/syscalls/sys_enter_unlinkat")
int kl_unlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_UNLINKAT, EVENT_ENTER, 4) < 0) return 0;

 __s32 dirfd = (__s32)ctx->args[0];
 const char *path = (const char *)ctx->args[1];
 __s32 flags = (__s32)ctx->args[2];

 if (kl_put_int(s, dirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 if (kl_put_int(s, flags) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);

 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_unlinkat")
int kl_unlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_UNLINKAT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_renameat2")
int kl_renameat2_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_RENAMEAT2, EVENT_ENTER, 6) < 0) return 0;

 __s32 olddirfd = (__s32)ctx->args[0];
 const char *oldpath = (const char *)ctx->args[1];
 __s32 newdirfd = (__s32)ctx->args[2];
 const char *newpath = (const char *)ctx->args[3];
 __u32 flags = (__u32)ctx->args[4];

 if (kl_put_int(s, olddirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, oldpath) < 0) return 0;
 if (kl_put_int(s, newdirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, newpath) < 0) return 0;
 if (kl_put_uint(s, flags) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 5);

 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_renameat2")
int kl_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_RENAMEAT2, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_mkdirat")
int kl_mkdirat_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_MKDIRAT, EVENT_ENTER, 4) < 0) return 0;

 __s32 dirfd = (__s32)ctx->args[0];
 const char *path = (const char *)ctx->args[1];
 __u32 mode = (__u32)ctx->args[2];

 if (kl_put_int(s, dirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 if (kl_put_uint(s, mode) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);

 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_mkdirat")
int kl_mkdirat_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_MKDIRAT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

// ============================================================================
// Permission — chmod / fchmod / fchmodat / chown / fchown / fchownat
// ============================================================================

SEC("tp/syscalls/sys_enter_chmod")
int kl_chmod_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CHMOD, EVENT_ENTER, 3) < 0) return 0;
 const char *path = (const char *)ctx->args[0];
 __u32 mode = (__u32)ctx->args[1];
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 if (kl_put_uint(s, mode) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_chmod")
int kl_chmod_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CHMOD, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_fchmod")
int kl_fchmod_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_FCHMOD, EVENT_ENTER, 3) < 0) return 0;
 __s32 fd = (__s32)ctx->args[0];
 __u32 mode = (__u32)ctx->args[1];
 if (kl_put_int(s, fd) < 0) return 0;
 if (kl_put_uint(s, mode) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_fchmod")
int kl_fchmod_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_FCHMOD, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_fchmodat")
int kl_fchmodat_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_FCHMODAT, EVENT_ENTER, 4) < 0) return 0;
 __s32 dirfd = (__s32)ctx->args[0];
 const char *path = (const char *)ctx->args[1];
 __u32 mode = (__u32)ctx->args[2];
 if (kl_put_int(s, dirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 if (kl_put_uint(s, mode) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_fchmodat")
int kl_fchmodat_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_FCHMODAT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_chown")
int kl_chown_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CHOWN, EVENT_ENTER, 4) < 0) return 0;
 const char *path = (const char *)ctx->args[0];
 __u32 uid = (__u32)ctx->args[1];
 __u32 gid = (__u32)ctx->args[2];
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 if (kl_put_uint(s, uid) < 0) return 0;
 if (kl_put_uint(s, gid) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_chown")
int kl_chown_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CHOWN, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_fchown")
int kl_fchown_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_FCHOWN, EVENT_ENTER, 4) < 0) return 0;
 __s32 fd = (__s32)ctx->args[0];
 __u32 uid = (__u32)ctx->args[1];
 __u32 gid = (__u32)ctx->args[2];
 if (kl_put_int(s, fd) < 0) return 0;
 if (kl_put_uint(s, uid) < 0) return 0;
 if (kl_put_uint(s, gid) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_fchown")
int kl_fchown_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_FCHOWN, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_fchownat")
int kl_fchownat_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_FCHOWNAT, EVENT_ENTER, 6) < 0) return 0;
 __s32 dirfd = (__s32)ctx->args[0];
 const char *path = (const char *)ctx->args[1];
 __u32 uid = (__u32)ctx->args[2];
 __u32 gid = (__u32)ctx->args[3];
 __s32 flags = (__s32)ctx->args[4];
 if (kl_put_int(s, dirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 if (kl_put_uint(s, uid) < 0) return 0;
 if (kl_put_uint(s, gid) < 0) return 0;
 if (kl_put_int(s, flags) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 5);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_fchownat")
int kl_fchownat_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_FCHOWNAT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

// ============================================================================
// Legacy file mutations — unlink / rename / renameat / rmdir / mkdir /
// link / linkat / symlink / symlinkat
// ============================================================================

SEC("tp/syscalls/sys_enter_unlink")
int kl_unlink_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_UNLINK, EVENT_ENTER, 2) < 0) return 0;
 const char *path = (const char *)ctx->args[0];
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_unlink")
int kl_unlink_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_UNLINK, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_rmdir")
int kl_rmdir_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_RMDIR, EVENT_ENTER, 2) < 0) return 0;
 const char *path = (const char *)ctx->args[0];
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_rmdir")
int kl_rmdir_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_RMDIR, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_mkdir")
int kl_mkdir_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_MKDIR, EVENT_ENTER, 3) < 0) return 0;
 const char *path = (const char *)ctx->args[0];
 __u32 mode = (__u32)ctx->args[1];
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 if (kl_put_uint(s, mode) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_mkdir")
int kl_mkdir_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_MKDIR, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_rename")
int kl_rename_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_RENAME, EVENT_ENTER, 3) < 0) return 0;
 const char *oldpath = (const char *)ctx->args[0];
 const char *newpath = (const char *)ctx->args[1];
 if (kl_put_str_user(s, ARG_RESOURCE, oldpath) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, newpath) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_rename")
int kl_rename_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_RENAME, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_renameat")
int kl_renameat_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_RENAMEAT, EVENT_ENTER, 5) < 0) return 0;
 __s32 olddirfd = (__s32)ctx->args[0];
 const char *oldpath = (const char *)ctx->args[1];
 __s32 newdirfd = (__s32)ctx->args[2];
 const char *newpath = (const char *)ctx->args[3];
 if (kl_put_int(s, olddirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, oldpath) < 0) return 0;
 if (kl_put_int(s, newdirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, newpath) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 4);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_renameat")
int kl_renameat_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_RENAMEAT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_link")
int kl_link_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_LINK, EVENT_ENTER, 3) < 0) return 0;
 const char *oldpath = (const char *)ctx->args[0];
 const char *newpath = (const char *)ctx->args[1];
 if (kl_put_str_user(s, ARG_RESOURCE, oldpath) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, newpath) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_link")
int kl_link_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_LINK, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_linkat")
int kl_linkat_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_LINKAT, EVENT_ENTER, 6) < 0) return 0;
 __s32 olddirfd = (__s32)ctx->args[0];
 const char *oldpath = (const char *)ctx->args[1];
 __s32 newdirfd = (__s32)ctx->args[2];
 const char *newpath = (const char *)ctx->args[3];
 __s32 flags = (__s32)ctx->args[4];
 if (kl_put_int(s, olddirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, oldpath) < 0) return 0;
 if (kl_put_int(s, newdirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, newpath) < 0) return 0;
 if (kl_put_int(s, flags) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 5);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_linkat")
int kl_linkat_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_LINKAT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_symlink")
int kl_symlink_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SYMLINK, EVENT_ENTER, 3) < 0) return 0;
 const char *target = (const char *)ctx->args[0];
 const char *linkpath = (const char *)ctx->args[1];
 if (kl_put_str_user(s, ARG_STR, target) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, linkpath) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_symlink")
int kl_symlink_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SYMLINK, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_enter_symlinkat")
int kl_symlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SYMLINKAT, EVENT_ENTER, 4) < 0) return 0;
 const char *target = (const char *)ctx->args[0];
 __s32 newdirfd = (__s32)ctx->args[1];
 const char *linkpath = (const char *)ctx->args[2];
 if (kl_put_str_user(s, ARG_STR, target) < 0) return 0;
 if (kl_put_int(s, newdirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, linkpath) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 return kl_submit_bulk_file_meta(s);
}

SEC("tp/syscalls/sys_exit_symlinkat")
int kl_symlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SYMLINKAT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_file_meta(s);
}

// ============================================================================
// LSM hooks for path mutations — pre-check visibility
// ============================================================================

SEC("kprobe/security_path_chmod")
int BPF_KPROBE(kl_kp_path_chmod, const struct path *path, umode_t mode)
{
 if (!kl_should_monitor()) return 0;
 if (!path) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SECURITY_CHMOD, EVENT_UNARY, 3) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 struct dentry *leaf = BPF_CORE_READ(path, dentry);
 struct vfsmount *vm = BPF_CORE_READ(path, mnt);
 if (kl_put_fullpath(s, leaf, vm) < 0) return 0;
 if (kl_put_uint(s, (__u32)mode) < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 (void)kl_submit_bulk_file_meta(s);
 return 0;
}

// kuid_t/kgid_t are struct wrappers around u32. On x86_64 they're passed by
// value in a register, so PT_REGS_PARMx gives us the raw u32 directly —
// receive as __u32 and avoid the struct-wrapper cast issues that BPF_PROG
// hit when these hooks were LSM-shaped.
SEC("kprobe/security_path_chown")
int BPF_KPROBE(kl_kp_path_chown, const struct path *path, __u32 uid, __u32 gid)
{
 if (!kl_should_monitor()) return 0;
 if (!path) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SECURITY_CHOWN, EVENT_UNARY, 4) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 struct dentry *leaf = BPF_CORE_READ(path, dentry);
 struct vfsmount *vm = BPF_CORE_READ(path, mnt);
 if (kl_put_fullpath(s, leaf, vm) < 0) return 0;
 if (kl_put_uint(s, uid) < 0) return 0;
 if (kl_put_uint(s, gid) < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 (void)kl_submit_bulk_file_meta(s);
 return 0;
}

SEC("kprobe/security_path_unlink")
int BPF_KPROBE(kl_kp_path_unlink, const struct path *dir, struct dentry *dentry)
{
 if (!kl_should_monitor()) return 0;
 if (!dentry) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SECURITY_UNLINK, EVENT_UNARY, 2) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 struct vfsmount *vm = dir ? BPF_CORE_READ(dir, mnt) : NULL;
 if (kl_put_fullpath(s, dentry, vm) < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);
 (void)kl_submit_bulk_file_meta(s);
 return 0;
}

SEC("kprobe/security_path_rmdir")
int BPF_KPROBE(kl_kp_path_rmdir, const struct path *dir, struct dentry *dentry)
{
 if (!kl_should_monitor()) return 0;
 if (!dentry) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SECURITY_RMDIR, EVENT_UNARY, 2) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 struct vfsmount *vm = dir ? BPF_CORE_READ(dir, mnt) : NULL;
 if (kl_put_fullpath(s, dentry, vm) < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);
 (void)kl_submit_bulk_file_meta(s);
 return 0;
}

SEC("kprobe/security_path_mkdir")
int BPF_KPROBE(kl_kp_path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode)
{
 if (!kl_should_monitor()) return 0;
 if (!dentry) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SECURITY_MKDIR, EVENT_UNARY, 3) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 struct vfsmount *vm = dir ? BPF_CORE_READ(dir, mnt) : NULL;
 if (kl_put_fullpath(s, dentry, vm) < 0) return 0;
 if (kl_put_uint(s, (__u32)mode) < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 (void)kl_submit_bulk_file_meta(s);
 return 0;
}

SEC("kprobe/security_path_symlink")
int BPF_KPROBE(kl_kp_path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name)
{
 if (!kl_should_monitor()) return 0;
 if (!dentry) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SECURITY_LINK, EVENT_UNARY, 3) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 struct vfsmount *vm = dir ? BPF_CORE_READ(dir, mnt) : NULL;
 if (kl_put_fullpath(s, dentry, vm) < 0) return 0;
 if (kl_put_str_kernel(s, ARG_STR, old_name) < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 (void)kl_submit_bulk_file_meta(s);
 return 0;
}

SEC("kprobe/security_path_link")
int BPF_KPROBE(kl_kp_path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry)
{
 if (!kl_should_monitor()) return 0;
 if (!new_dentry) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SECURITY_LINK, EVENT_UNARY, 2) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 struct vfsmount *vm = new_dir ? BPF_CORE_READ(new_dir, mnt) : NULL;
 if (kl_put_fullpath(s, new_dentry, vm) < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);
 (void)kl_submit_bulk_file_meta(s);
 return 0;
}

SEC("kprobe/security_path_rename")
int BPF_KPROBE(kl_kp_path_rename, const struct path *old_dir, struct dentry *old_dentry,
 const struct path *new_dir, struct dentry *new_dentry)
{
 if (!kl_should_monitor()) return 0;
 if (!old_dentry || !new_dentry) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SECURITY_RENAME, EVENT_UNARY, 3) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 struct vfsmount *old_vm = old_dir ? BPF_CORE_READ(old_dir, mnt) : NULL;
 struct vfsmount *new_vm = new_dir ? BPF_CORE_READ(new_dir, mnt) : NULL;
 if (kl_put_fullpath(s, old_dentry, old_vm) < 0) return 0;
 if (kl_put_fullpath(s, new_dentry, new_vm) < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 (void)kl_submit_bulk_file_meta(s);
 return 0;
}
