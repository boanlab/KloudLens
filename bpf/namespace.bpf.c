// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 BoanLab @ DKU
//
// namespace.bpf.c — namespace + filesystem-view shifting hooks. Included by
// kloudlens.bpf.c; not compiled standalone.
//
// Programs:
// tp/syscalls/sys_{enter,exit}_clone
// tp/syscalls/sys_{enter,exit}_clone3
// tp/syscalls/sys_{enter,exit}_unshare
// tp/syscalls/sys_{enter,exit}_setns
// tp/syscalls/sys_{enter,exit}_chroot
// tp/syscalls/sys_{enter,exit}_mount
// tp/syscalls/sys_{enter,exit}_umount
// kprobe/security_path_chroot
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
// Namespace-creating syscalls — clone / clone3 / unshare / setns
// ============================================================================
//
// Zero-miss container bootstrap: the race between a container
// runtime's clone(CLONE_NEW*) and the first execve inside the new NS is only
// microseconds wide. Our userspace BirthNotifier polls /proc, which may miss
// the first few events. Emitting the flag vector on sys_enter gives the
// aggregator an authoritative kernel-side signal: "a new pid/mnt NS is being
// created by host_pid=X right now" — enrichment can be pre-populated before
// any child syscall arrives.
//
// All four are flag-bearing. Arg layout on wire:
// clone : ULONG(flags)
// clone3 : ULONG(flags) — read from user-space struct clone_args.flags
// unshare : ULONG(flags)
// setns : INT(fd) + INT(nstype)
// Exit side only carries retval (the new tgid for clone/clone3, 0/-errno
// for the others). Source (comm) is emitted when unknown.

SEC("tp/syscalls/sys_enter_clone")
int kl_clone_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CLONE, EVENT_ENTER, 2) < 0) return 0;

 __u64 flags = (__u64)ctx->args[0];
 if (kl_put_ulong(s, flags) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);

 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_clone")
int kl_clone_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CLONE, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

// clone3 takes `struct clone_args __user *args` + size. `args->flags` is the
// first u64 in the struct — read it with bpf_probe_read_user. If the read
// fails (bad pointer / size-0 args) we fall back to flags=0 so the event
// still goes out with a consistent arg shape.
SEC("tp/syscalls/sys_enter_clone3")
int kl_clone3_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CLONE3, EVENT_ENTER, 2) < 0) return 0;

 __u64 flags = 0;
 const void *uargs = (const void *)ctx->args[0];
 if (uargs) {
 // The flags field is the first 8 bytes of struct clone_args.
 bpf_probe_read_user(&flags, sizeof(flags), uargs);
 }
 if (kl_put_ulong(s, flags) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);

 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_clone3")
int kl_clone3_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CLONE3, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_unshare")
int kl_unshare_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_UNSHARE, EVENT_ENTER, 2) < 0) return 0;

 __u64 flags = (__u64)ctx->args[0];
 if (kl_put_ulong(s, flags) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);

 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_unshare")
int kl_unshare_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_UNSHARE, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_setns")
int kl_setns_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETNS, EVENT_ENTER, 3) < 0) return 0;

 __s32 fd = (__s32)ctx->args[0];
 __s32 nstype = (__s32)ctx->args[1];
 if (kl_put_int(s, fd) < 0) return 0;
 if (kl_put_int(s, nstype) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);

 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_setns")
int kl_setns_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETNS, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

// ============================================================================
// chroot / mount / umount2 — filesystem-view shift surface
// ============================================================================

SEC("tp/syscalls/sys_enter_chroot")
int kl_chroot_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CHROOT, EVENT_ENTER, 2) < 0) return 0;

 const char *path = (const char *)ctx->args[0];
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);

 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_chroot")
int kl_chroot_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CHROOT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_mount")
int kl_mount_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_MOUNT, EVENT_ENTER, 5) < 0) return 0;

 const char *src = (const char *)ctx->args[0];
 const char *target = (const char *)ctx->args[1];
 const char *fstype = (const char *)ctx->args[2];
 __u64 flags = (__u64)ctx->args[3];

 // src can be NULL for bind/remount variants; kl_put_str_user handles that
 // by emitting an empty string.
 if (kl_put_str_user(s, ARG_STR, src) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, target) < 0) return 0;
 if (kl_put_str_user(s, ARG_STR, fstype) < 0) return 0;
 if (kl_put_ulong(s, flags) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 4);

 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_mount")
int kl_mount_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_MOUNT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

// Historical quirk: the kernel exposes the umount2(2) tracepoint as
// `sys_enter_umount` / `sys_exit_umount` — the "2" is dropped even though
// the underlying syscall is __NR_umount2 (166 on x86_64). The BPF program
// name and the KL_SYS_UMOUNT2 id keep the "2" to match the syscall itself.
SEC("tp/syscalls/sys_enter_umount")
int kl_umount2_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_UMOUNT2, EVENT_ENTER, 3) < 0) return 0;

 const char *target = (const char *)ctx->args[0];
 __s32 flags = (__s32)ctx->args[1];

 if (kl_put_str_user(s, ARG_RESOURCE, target) < 0) return 0;
 if (kl_put_int(s, flags) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);

 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_umount")
int kl_umount2_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_UMOUNT2, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

// ============================================================================
// LSM hook for chroot — pre-check visibility even when syscall is denied
// ============================================================================

SEC("kprobe/security_path_chroot")
int BPF_KPROBE(kl_kp_path_chroot, const struct path *path)
{
 if (!kl_should_monitor()) return 0;
 if (!path) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SECURITY_CHROOT, EVENT_UNARY, 2) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 struct dentry *leaf = BPF_CORE_READ(path, dentry);
 struct vfsmount *vm = BPF_CORE_READ(path, mnt);
 if (kl_put_fullpath(s, leaf, vm) < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);
 (void)kl_submit_crit(s);
 return 0;
}
