// SPDX-License-Identifier: (GPL-2.0-only OR Apache-2.0)
// Copyright 2026 BoanLab @ DKU
//
// wire.bpf.h — on-ring-buffer wire format produced by the KloudLens sensor.
// The layout here is load-bearing: it must stay byte-compatible with
// internal/wire/wire.go (Event struct + TypeXxx tags + arg encoding). Tests
// in tests/integration/tracer_test.go also speak this format directly. A
// drift between this header and wire.go silently corrupts every event — if
// you touch either side, run `go test ./internal/wire/...` to verify the
// synthetic fixtures round-trip.
#pragma once

#include "vmlinux.h"

// event_type_t enumerates record shapes:
// ENTER — input args at sys_enter; retval unset
// EXIT — retval only; userspace Pairer merges with ENTER
// UNARY — self-contained record (LSM hooks, sched_process_exit)
// COMPACT_UNARY — 16-byte variant of UNARY. Task-identifying fields
// are omitted from the wire; userspace reconstructs
// them from a per-CPU base it maintains off full
// frames on the same ring. Currently only kl_emit_rw()
// emits this form.
enum kl_event_type_t {
 EVENT_UNARY = 0,
 EVENT_ENTER = 1,
 EVENT_EXIT = 2,
 EVENT_COMPACT_UNARY = 0x13,
};

// arg_type_t tags precede every variadic argument so the userspace parser
// can dispatch without knowing the syscall signature. Values must match the
// TypeXxx constants in internal/wire/wire.go.
enum kl_arg_type_t {
 ARG_INT = 1, // __s32
 ARG_UINT = 2, // __u32
 ARG_ULONG = 3, // __u64
 ARG_STR = 4, // length-prefixed NUL-terminated string
 ARG_STR_ARR = 5, // sequence of ARG_STR items, 0-tag terminator
 ARG_SOURCE = 6, // caller's comm (semantically a string)
 ARG_RESOURCE = 7, // path / address (semantically a string)
 ARG_CURRENT_DIR = 8, // cwd snapshot (semantically a string)
 ARG_STR_REF = 9, // 8-byte fnv1a-64 hash; userspace resolves via
 // hash→string cache populated from prior ARG_STR /
 // ARG_RESOURCE. Emitted by BPF when the same path
 // hash is already present in kl_str_seen.
 ARG_COALESCED_COUNT = 10, // __u32 — trailer on the first event emitted
 // after a coalesce window expires, carries the
 // number of events the PREVIOUS window collapsed
 // (1 = no coalescing happened, Ν>1 = N-1 events
 // were suppressed in-kernel).
 ARG_COALESCED_BYTES = 11, // __u64 — cumulative bytes requested across the
 // coalesced window (r/w syscalls only; 0 for
 // stat/access classes where bytes are undefined).
 ARG_VARINT_U32 = 12, // LEB128 unsigned — same semantic as ARG_UINT but
 // compressed (1-5 bytes). Hot paths (fd, errno,
 // coalesced counts) opt into this encoding; the
 // fixed-width ARG_UINT stays for cold fields so
 // existing fixtures and replay recordings don't
 // need re-encoding. See
 ARG_VARINT_U64 = 13, // LEB128 unsigned — same semantic as ARG_ULONG.
 // Counters (bytes, inode nrs, offsets) that
 // cluster near zero benefit 4-6× here.
 ARG_CPU_SEQ = 14, // LEB128-encoded u64 — monotonic per-CPU
 // emit counter (kl_cpu_seq map value).
 // Userspace tracks the last seen seq per
 // CPU; a gap means records were lost for
 // that CPU specifically. First frame on a
 // CPU after agent start establishes the
 // baseline.
};

// event_t header — 64 bytes, naturally aligned, no padding. Field order and
// widths mirror the Go wire.Event struct one-to-one. Schema v2 layout:
// event_type occupies byte 0 so both full and compact frames share a
// byte-0 dispatch at the reader. The packed attribute is defense-in-
// depth: on x86_64 the natural layout already matches, but packed
// documents the intent and protects against compilers that add tail
// padding.
struct event_t {
 __s8 event_type; // enum event_type_t — full frames use 0..2
 __s8 arg_num; // number of variadic args following the header
 __u16 cpu_id; // bpf_get_smp_processor_id()
 __u32 event_id; // reserved — currently always 0

 __u64 timestamp; // bpf_ktime_get_ns()

 __u32 pid_ns_id; // task->nsproxy->pid_ns_for_children->ns.inum
 __u32 mnt_ns_id; // task->nsproxy->mnt_ns->ns.inum

 __u64 cgroup_id; // bpf_get_current_cgroup_id — primary attribution
 // key. Survives hostPID/hostNetwork/hostMnt cases
 // where (pid_ns_id, mnt_ns_id) collides with host
 // or another container's NS pair.

 __s32 host_ppid; // parent TGID in host pid namespace
 __s32 ppid; // parent TGID in task's own pid namespace

 __s32 host_pid; // TGID in host pid namespace
 __s32 host_tid; // TID in host pid namespace

 __s32 pid; // TGID in task's own pid namespace
 __s32 tid; // TID in task's own pid namespace

 __u32 uid;
 __u32 gid;

 __s32 syscall_id; // Linux syscall nr, or pseudo-id ≥ 1000 for LSM/sched
 __s32 retval; // EVENT_EXIT: real retval; ENTER/UNARY: 0
} __attribute__((packed));

_Static_assert(sizeof(struct event_t) == 72, "event_t must be 72 bytes to match wire.Event");

// compact_event_t is the 16-byte variant emitted by hot paths when the
// per-CPU base (last task's pid_tgid + creds + NS) is still valid.
// Userspace disambiguates at the ringbuf reader: record payload size ==
// 16 → compact; >= 64 → full. The two shapes share the same ringbuf and
// BPF ringbuf FIFO semantics guarantee a full frame refreshing the base
// always arrives before any compact frame referencing it, as long as
// both land on the same ring from the same CPU (currently bulk_file).
struct compact_event_t {
 __u8 event_type; // = EVENT_COMPACT_UNARY
 __u8 arg_num; // bumped by kl_submit_to when ARG_CPU_SEQ appends
 __u16 cpu_id;
 __u32 ts_delta_ns; // current bpf_ktime_get_ns() - base->timestamp
 __s32 syscall_id;
 __s32 retval;
} __attribute__((packed));

_Static_assert(sizeof(struct compact_event_t) == 16, "compact_event_t must be 16 bytes");

// Per-record byte budget. 16 KiB leaves room for a typical execve
// (path + 10-20 short argv entries + comm) while staying inside the
// per-CPU array element size limit the kernel enforces on percpu maps
// (__alloc_percpu caps at ~32 KiB on default configs; the full scratch
// struct is buffer + a 4-byte length header).
#define KL_MAX_RECORD_BYTES (16 * 1024)

// Per-string cap — matches wire.go's ErrStringTooLarge guard. BPF's
// bpf_probe_read_user_str returns at most 4096 by default; we further cap
// at 2048 to keep frames small and to stay inside the verifier's stack /
// bounded-loop comfort zone.
#define KL_MAX_STR_BYTES 2048

// Per-strarr budget — longest execve argv we encode. Beyond this we truncate
// and emit an ARG_STR_ARR terminator; userspace treats it as a valid array.
#define KL_MAX_STR_ARR_ITEMS 20
