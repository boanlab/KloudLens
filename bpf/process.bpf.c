// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 BoanLab @ DKU
//
// process.bpf.c — process-lifecycle and process-control hooks. Included by
// kloudlens.bpf.c; not compiled standalone (the umbrella TU pulls every
// feature file into one BPF object).
//
// Programs:
// tp/syscalls/sys_{enter,exit}_execve
// tp/syscalls/sys_{enter,exit}_execveat
// tp/syscalls/sys_{enter,exit}_exit_group
// tp/syscalls/sys_{enter,exit}_kill
// tp/syscalls/sys_{enter,exit}_tgkill
// tp/syscalls/sys_{enter,exit}_ptrace
// tp/syscalls/sys_enter_prctl [process-control / privesc]
// tp/syscalls/sys_enter_mmap [exec-mapping detection]
// tp/syscalls/sys_enter_mprotect [exec-mapping detection]
// tracepoint/sched/sched_process_exit
// kprobe/security_bprm_check
// kprobe/security_task_kill
//
// prctl/mmap/mprotect emit ENTER frames only (no exit pair) — they're
// observation hooks for adapter synthesis, not policy decisions, so the
// userspace pairer treats them as UNARY-style entries.
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
// execve — sys_enter: path + argv + source
// ============================================================================
//
// execve is the entry point into a new binary; argv/envp live in the old
// task's memory until the kernel's exec flip. We capture at sys_enter so
// the argv reads hit valid pages.

SEC("tp/syscalls/sys_enter_execve")
int kl_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;

 // arg_num = 3 worst case: resource(path) + argv(strarr) + source(comm).
 // We patch it down to 2 when source is skipped via LRU dedup.
 if (kl_fill_header(s, KL_SYS_EXECVE, EVENT_ENTER, 3) < 0) return 0;

 const char *path = (const char *)ctx->args[0];
 const char *const *argv = (const char *const *)ctx->args[1];

 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 if (kl_put_argv(s, argv) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);

 return kl_submit_proc_lc(s);
}

SEC("tp/syscalls/sys_exit_execve")
int kl_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_EXECVE, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_proc_lc(s);
}

// ============================================================================
// Process lifecycle — execveat / exit_group / kill / tgkill / ptrace
// ============================================================================
//
// execveat mirrors execve but with an explicit dirfd + flags; same argv emitter.
// exit_group signals intentional whole-process teardown (distinct from the
// sched_process_exit tracepoint, which fires asynchronously after last-thread
// cleanup and sees the retval instead of the user-requested status).
// kill / tgkill carry signal delivery — critical for detecting process kill
// chains (systemd OOM, container runtime stop-the-world, etc.). ptrace is the
// cross-process memory-access escalation surface.

SEC("tp/syscalls/sys_enter_execveat")
int kl_execveat_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_EXECVEAT, EVENT_ENTER, 5) < 0) return 0;

 __s32 dirfd = (__s32)ctx->args[0];
 const char *path = (const char *)ctx->args[1];
 const char *const *argv = (const char *const *)ctx->args[2];
 __s32 flags = (__s32)ctx->args[4];

 if (kl_put_int(s, dirfd) < 0) return 0;
 if (kl_put_str_user(s, ARG_RESOURCE, path) < 0) return 0;
 if (kl_put_argv(s, argv) < 0) return 0;
 if (kl_put_int(s, flags) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 4);

 return kl_submit_proc_lc(s);
}

SEC("tp/syscalls/sys_exit_execveat")
int kl_execveat_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_EXECVEAT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_proc_lc(s);
}

SEC("tp/syscalls/sys_enter_exit_group")
int kl_exit_group_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_EXIT_GROUP, EVENT_ENTER, 2) < 0) return 0;

 __s32 status = (__s32)ctx->args[0];
 if (kl_put_int(s, status) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);

 return kl_submit_proc_lc(s);
}

// exit_group doesn't return on success — sys_exit only fires on the failing
// paths (bad args caught before teardown). We still hook it for arg-shape
// symmetry with the Pairer in userspace.
SEC("tp/syscalls/sys_exit_exit_group")
int kl_exit_group_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_EXIT_GROUP, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_proc_lc(s);
}

SEC("tp/syscalls/sys_enter_kill")
int kl_kill_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_KILL, EVENT_ENTER, 3) < 0) return 0;

 __s32 pid = (__s32)ctx->args[0];
 __s32 sig = (__s32)ctx->args[1];
 if (kl_put_int(s, pid) < 0) return 0;
 if (kl_put_int(s, sig) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);

 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_kill")
int kl_kill_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_KILL, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_tgkill")
int kl_tgkill_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_TGKILL, EVENT_ENTER, 4) < 0) return 0;

 __s32 tgid = (__s32)ctx->args[0];
 __s32 tid = (__s32)ctx->args[1];
 __s32 sig = (__s32)ctx->args[2];
 if (kl_put_int(s, tgid) < 0) return 0;
 if (kl_put_int(s, tid) < 0) return 0;
 if (kl_put_int(s, sig) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);

 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_tgkill")
int kl_tgkill_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_TGKILL, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_ptrace")
int kl_ptrace_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_PTRACE, EVENT_ENTER, 3) < 0) return 0;

 __s32 request = (__s32)ctx->args[0];
 __s32 pid = (__s32)ctx->args[1];
 if (kl_put_int(s, request) < 0) return 0;
 if (kl_put_int(s, pid) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);

 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_exit_ptrace")
int kl_ptrace_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_PTRACE, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_crit(s);
}

// ============================================================================
// prctl — process-control / privilege-escalation knobs
// ============================================================================
//
// prctl is the kernel's catch-all knob for self-modifying process state. The
// option codes we actually care about for adapter synthesis are PR_SET_NO_NEW_PRIVS
// (38), PR_CAP_AMBIENT (47), PR_SET_DUMPABLE (4), PR_SET_KEEPCAPS (8) — these
// map directly to PodSecurity allowPrivilegeEscalation, AppArmor change_profile
// patterns, and seccomp prerequisite checks.
//
// We emit every prctl call (option + arg2) so userspace can filter; the
// surface is small enough that an enter-only emission is fine. arg2 is
// already a uint64-shaped register on amd64, so we encode it raw.
SEC("tp/syscalls/sys_enter_prctl")
int kl_prctl_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_PRCTL, EVENT_ENTER, 3) < 0) return 0;

 __s32 option = (__s32)ctx->args[0];
 __u64 arg2 = (__u64)ctx->args[1];
 if (kl_put_int(s, option) < 0) return 0;
 if (kl_put_ulong(s, arg2) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);

 return kl_submit_crit(s);
}

// ============================================================================
// mmap / mprotect — exec-mapping detection
// ============================================================================
//
// Filter to PROT_EXEC at the BPF layer so the bulk_proc ring isn't drowned in
// the >99% of mmap calls that map plain data pages. PROT_EXEC = 0x4 in mman.h;
// we keep the literal here to avoid dragging the asm-generic header. The shape
// emitted is (addr, length, prot, flags) — adapter-side seccomp/apparmor
// synthesis only needs prot to know it's an exec mapping; addr/length give
// userspace a hash key for "same region, repeated mprotect" coalescing.
//
// Only enter is hooked: an mprotect that fails still indicates a workload
// *requested* the change, which is what the policy-allow-list cares about.
#define KL_PROT_EXEC 0x4

SEC("tp/syscalls/sys_enter_mmap")
int kl_mmap_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 __u64 prot = (__u64)ctx->args[2];
 if ((prot & KL_PROT_EXEC) == 0) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_MMAP, EVENT_ENTER, 5) < 0) return 0;

 __u64 addr = (__u64)ctx->args[0];
 __u64 length = (__u64)ctx->args[1];
 __u64 flags = (__u64)ctx->args[3];
 if (kl_put_ulong(s, addr) < 0) return 0;
 if (kl_put_ulong(s, length) < 0) return 0;
 if (kl_put_ulong(s, prot) < 0) return 0;
 if (kl_put_ulong(s, flags) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 4);

 return kl_submit_crit(s);
}

SEC("tp/syscalls/sys_enter_mprotect")
int kl_mprotect_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 __u64 prot = (__u64)ctx->args[2];
 if ((prot & KL_PROT_EXEC) == 0) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_MPROTECT, EVENT_ENTER, 4) < 0) return 0;

 __u64 addr = (__u64)ctx->args[0];
 __u64 length = (__u64)ctx->args[1];
 if (kl_put_ulong(s, addr) < 0) return 0;
 if (kl_put_ulong(s, length) < 0) return 0;
 if (kl_put_ulong(s, prot) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);

 return kl_submit_crit(s);
}

// ============================================================================
// sched_process_exit — pseudo-syscall UNARY, emits comm/exe of the dying task
// ============================================================================
//
// Fires after a task's last thread exits. We emit the ARG_SOURCE (comm) so
// the Go aggregator can flush any residual (tgid, fd) state keyed to the
// departing PID. This is the "proc exit flush" the integration test checks.

SEC("tracepoint/sched/sched_process_exit")
int kl_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
 if (!kl_should_monitor()) return 0;

 // The sched tracepoint also fires per-thread; only emit when the
 // thread-group leader exits (tgid == pid). Otherwise short-circuit.
 __u64 pid_tgid = bpf_get_current_pid_tgid();
 __u32 tgid = (__u32)(pid_tgid >> 32);
 __u32 tid = (__u32)(pid_tgid & 0xffffffff);
 if (tgid != tid) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SCHED_EXIT, EVENT_UNARY, 1) < 0) return 0;
 if (kl_put_source_always(s) < 0) return 0;

 // Clear the known-source LRU entry so a subsequent PID reuse resets
 // the comm-emission gate. The LRU would rotate it out anyway, but
 // explicit is cheaper and deterministic.
 bpf_map_delete_elem(&kl_known_src, &tgid);

 return kl_submit_crit(s);
}

// ============================================================================
// LSM hooks for process surface
// ============================================================================
//
// security_bprm_check fires after path resolution but before the exec flip,
// catching denied execs that would never reach sys_exit_execve. security_task_kill
// gives the delivering task's intent for kill/tgkill — kernel threads can also
// raise signals without touching the syscall path, so this is broader than
// the tracepoint surface.

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(kl_kp_bprm_check, struct linux_binprm *bprm)
{
 if (!kl_should_monitor()) return 0;
 if (!bprm) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SECURITY_BPRM, EVENT_UNARY, 2) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;

 // bprm->file->f_path is the resolved leaf — walk its parents for the
 // canonical absolute path, matching what filp_close + bpf_d_path would
 // produce later in the file's lifecycle.
 struct file *bf = BPF_CORE_READ(bprm, file);
 struct dentry *leaf = BPF_CORE_READ(bf, f_path.dentry);
 struct vfsmount *vm = BPF_CORE_READ(bf, f_path.mnt);
 if (leaf) {
 if (kl_put_fullpath(s, leaf, vm) < 0) return 0;
 } else {
 if (kl_put_str_user(s, ARG_RESOURCE, NULL) < 0) return 0;
 }

 if (wrote_src == 0) kl_patch_arg_num(s, 1);
 (void)kl_submit_crit(s);
 return 0;
}

// task_kill sees the delivering task's intent — we emit the target pid + sig
// so userspace can correlate with the adjacent sys_enter_kill/tgkill event
// (the latter may be absent when a kernel thread raises the signal directly).
SEC("kprobe/security_task_kill")
int BPF_KPROBE(kl_kp_task_kill, struct task_struct *target, struct kernel_siginfo *info,
 int sig, const struct cred *cred)
{
 if (!kl_should_monitor()) return 0;
 if (!target) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SECURITY_TASK_KILL, EVENT_UNARY, 3) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 __s32 tgt_tgid = (__s32)BPF_CORE_READ(target, tgid);
 if (kl_put_int(s, tgt_tgid) < 0) return 0;
 if (kl_put_int(s, sig) < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 (void)kl_submit_crit(s);
 return 0;
}
