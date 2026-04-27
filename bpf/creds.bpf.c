// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 BoanLab @ DKU
//
// creds.bpf.c — credential / capability hooks. Included by kloudlens.bpf.c;
// not compiled standalone.
//
// Programs:
// tp/syscalls/sys_{enter,exit}_setuid / setgid
// tp/syscalls/sys_{enter,exit}_setreuid / setregid
// tp/syscalls/sys_{enter,exit}_setresuid / setresgid
// tp/syscalls/sys_{enter,exit}_setfsuid / setfsgid
// tp/syscalls/sys_{enter,exit}_capset
// kprobe/cap_capable [capability-use detection]
//
// Every uid/gid mutation is policy-relevant — a root-suid-to-nobody pattern
// or an unexpected setresuid(0,0,0) is a classic privilege-escalation tell.
// All route to the crit ring.
//
// cap_capable fires on every capability check; emitting the cap number gives
// adapter synthesis a precise allow-list (only the caps actually exercised)
// rather than the broader bitmask capset hands out.
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
// capset — explicit capability-set syscall
// ============================================================================

SEC("tp/syscalls/sys_enter_capset")
int kl_capset_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CAPSET, EVENT_ENTER, 3) < 0) return 0;

 __u64 hdr = (__u64)ctx->args[0];
 __u64 data = (__u64)ctx->args[1];
 if (kl_put_ulong(s, hdr) < 0) return 0;
 if (kl_put_ulong(s, data) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);

 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_capset")
int kl_capset_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CAPSET, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

// ============================================================================
// setuid / setgid family
// ============================================================================

SEC("tp/syscalls/sys_enter_setuid")
int kl_setuid_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETUID, EVENT_ENTER, 2) < 0) return 0;
 __u32 uid = (__u32)ctx->args[0];
 if (kl_put_uint(s, uid) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_setuid")
int kl_setuid_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETUID, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_setgid")
int kl_setgid_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETGID, EVENT_ENTER, 2) < 0) return 0;
 __u32 gid = (__u32)ctx->args[0];
 if (kl_put_uint(s, gid) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_setgid")
int kl_setgid_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETGID, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_setreuid")
int kl_setreuid_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETREUID, EVENT_ENTER, 3) < 0) return 0;
 __u32 ruid = (__u32)ctx->args[0];
 __u32 euid = (__u32)ctx->args[1];
 if (kl_put_uint(s, ruid) < 0) return 0;
 if (kl_put_uint(s, euid) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_setreuid")
int kl_setreuid_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETREUID, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_setregid")
int kl_setregid_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETREGID, EVENT_ENTER, 3) < 0) return 0;
 __u32 rgid = (__u32)ctx->args[0];
 __u32 egid = (__u32)ctx->args[1];
 if (kl_put_uint(s, rgid) < 0) return 0;
 if (kl_put_uint(s, egid) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_setregid")
int kl_setregid_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETREGID, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_setresuid")
int kl_setresuid_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETRESUID, EVENT_ENTER, 4) < 0) return 0;
 __u32 ruid = (__u32)ctx->args[0];
 __u32 euid = (__u32)ctx->args[1];
 __u32 suid = (__u32)ctx->args[2];
 if (kl_put_uint(s, ruid) < 0) return 0;
 if (kl_put_uint(s, euid) < 0) return 0;
 if (kl_put_uint(s, suid) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_setresuid")
int kl_setresuid_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETRESUID, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_setresgid")
int kl_setresgid_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETRESGID, EVENT_ENTER, 4) < 0) return 0;
 __u32 rgid = (__u32)ctx->args[0];
 __u32 egid = (__u32)ctx->args[1];
 __u32 sgid = (__u32)ctx->args[2];
 if (kl_put_uint(s, rgid) < 0) return 0;
 if (kl_put_uint(s, egid) < 0) return 0;
 if (kl_put_uint(s, sgid) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_setresgid")
int kl_setresgid_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETRESGID, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_setfsuid")
int kl_setfsuid_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETFSUID, EVENT_ENTER, 2) < 0) return 0;
 __u32 uid = (__u32)ctx->args[0];
 if (kl_put_uint(s, uid) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_setfsuid")
int kl_setfsuid_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETFSUID, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_setfsgid")
int kl_setfsgid_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETFSGID, EVENT_ENTER, 2) < 0) return 0;
 __u32 gid = (__u32)ctx->args[0];
 if (kl_put_uint(s, gid) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_setfsgid")
int kl_setfsgid_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SETFSGID, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

// ============================================================================
// cap_capable — capability-use detection
// ============================================================================
//
// cap_capable fires on every kernel-side capability check, regardless of
// whether the workload reached the syscall path or the cap was granted via
// SECCOMP_RET_ALLOW. We hook the canonical entry point (cap_capable, the
// commoncap LSM helper) and emit the cap number per check.
//
// Adapter synthesis (kubearmor / apparmor / podsec) consumes this stream as
// the authoritative used-capability set: capset is the *grant point* (often
// over-broad), cap_capable is the *use point*. Using the latter shrinks the
// generated allow-list to only the caps the workload actually exercises.
//
// kprobe-not-lsm: this codebase ships against kernels that may not have "bpf"
// in the active LSM list (see CLAUDE.md memory note); kprobe attaches
// regardless of CONFIG_BPF_LSM and works on the same code site.
//
// Signature in 5.10+:
// int cap_capable(const struct cred *cred, struct user_namespace *targ_ns,
// int cap, unsigned int opts);
SEC("kprobe/cap_capable")
int BPF_KPROBE(kl_kp_cap_capable, const struct cred *cred,
 struct user_namespace *targ_ns, int cap, unsigned int opts)
{
 if (!kl_should_monitor()) return 0;
 // cap is already an int; bound it defensively against the kernel's
 // CAP_LAST_CAP (40 on 5.10+, 41 on 6.x). Beyond-range values mean the
 // call is from an out-of-tree module or a probe corruption — drop.
 if (cap < 0 || cap > 64) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_CAP_CAPABLE, EVENT_UNARY, 3) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;

 if (kl_put_int(s, cap) < 0) return 0;
 if (kl_put_uint(s, opts) < 0) return 0;

 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 (void)kl_submit_crit(s);
 return 0;
}
