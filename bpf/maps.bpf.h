// SPDX-License-Identifier: (GPL-2.0-only OR Apache-2.0)
// Copyright 2026 BoanLab @ DKU
//
// maps.bpf.h — every BPF map the KloudLens sensor owns. Map names are part
// of the Go loader's contract (internal/sensor/live_linux.go looks them up
// by name); renaming one without updating the other breaks loading.
#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "wire.bpf.h"

// ---- Ring buffers ---------------------------------------------------------
//
// One crit ring carrying policy-priority events (kill/ptrace/prctl/mmap-x)
// — never sampled, highest-priority drain. Four category-specific bulk
// rings partition the high-volume tail so a burst in one category cannot
// starve another. Three low-volume isolation rings carry events whose loss
// would corrupt downstream attribution (pod / lineage / peer):
//
// kl_events_bulk_file → read/write/pread/pwrite, open/openat/openat2
// (read-only branch), close/filp_close, stat/
// fstat/statx, access/faccessat2, security_file_open
// (read-only). fd-based I/O is classified by
// syscall name; a read(2) on a socket fd lands here
// rather than on _net.
// kl_events_bulk_net → sendmsg/recvmsg/sendmmsg/recvmmsg, socket
// (enter+exit). bind/listen/accept/connect/shutdown
// are on sock_lc.
// kl_events_bulk_proc → raw_syscalls sys_enter/sys_exit (catch-all debug
// hooks, opt-in via LiveOptions.EnableRawSyscalls).
// kl_events_bulk_file_meta → file metadata mutations: unlink/rename/
// mkdir/rmdir + chmod/fchmod/fchmodat + chown/
// fchown/fchownat/lchown + mount/umount2 enter
// and exit. Heavy on file-churn workloads
// (build trees, log rotation, package managers)
// but lower priority than the crit-ring policy
// events; isolated so a unlinkat storm cannot
// drown kill/ptrace/prctl/mmap-x.
// kl_events_dns → cgroup_skb DNS-answer parser. Drives toFQDNs
// synthesis and the DNS-IP correlation detector.
// kl_events_proc_lc → process lifecycle: execve/execveat enter+exit and
// exit_group enter+exit. A dropped exec leaves
// every subsequent syscall from that pid attributed
// to a stale binary.
// kl_events_sock_lc → socket lifecycle: bind/listen/accept(4)/connect/
// shutdown enter+exit + security_socket_{bind,
// connect}. Feeds PeerMatch: bind on this node
// resolves peer:IP:PORT leaves to cont:<id>.
//
// Userspace (internal/sensor.LiveEBPF) installs one ringbuf reader per map
// and pumps them concurrently, so slow drain on one never blocks the others.
// Sizes are powers-of-two as required by BPF_MAP_TYPE_RINGBUF.

#define KL_RB_CRIT_BYTES (4 * 1024 * 1024) // 4 MiB
#define KL_RB_BULK_FILE_BYTES (4 * 1024 * 1024) // 4 MiB — dominant category
#define KL_RB_BULK_NET_BYTES (2 * 1024 * 1024) // 2 MiB
#define KL_RB_BULK_PROC_BYTES (2 * 1024 * 1024) // 2 MiB — raw_syscalls-only
#define KL_RB_BULK_FILE_META_BYTES (2 * 1024 * 1024) // 2 MiB — unlink/rename/chmod/chown/mount families
#define KL_RB_DNS_BYTES (1 * 1024 * 1024) // 1 MiB — DNS-only
#define KL_RB_PROC_LC_BYTES (1 * 1024 * 1024) // 1 MiB — exec/exit only
#define KL_RB_SOCK_LC_BYTES (1 * 1024 * 1024) // 1 MiB — bind/listen/connect/accept

struct {
 __uint(type, BPF_MAP_TYPE_RINGBUF);
 __uint(max_entries, KL_RB_CRIT_BYTES);
} kl_events_crit SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_RINGBUF);
 __uint(max_entries, KL_RB_BULK_FILE_BYTES);
} kl_events_bulk_file SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_RINGBUF);
 __uint(max_entries, KL_RB_BULK_NET_BYTES);
} kl_events_bulk_net SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_RINGBUF);
 __uint(max_entries, KL_RB_BULK_PROC_BYTES);
} kl_events_bulk_proc SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_RINGBUF);
 __uint(max_entries, KL_RB_BULK_FILE_META_BYTES);
} kl_events_bulk_file_meta SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_RINGBUF);
 __uint(max_entries, KL_RB_DNS_BYTES);
} kl_events_dns SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_RINGBUF);
 __uint(max_entries, KL_RB_PROC_LC_BYTES);
} kl_events_proc_lc SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_RINGBUF);
 __uint(max_entries, KL_RB_SOCK_LC_BYTES);
} kl_events_sock_lc SEC(".maps");

// ---- Namespace filter -----------------------------------------------------
//
// kl_ns_toggle[0] selects filter polarity:
// 0 → "except" mode: kl_ns_filter entries are dropped, everything else
// passes.
// 1 → "target" mode: only kl_ns_filter entries pass.
// Key packing (matches sensor.NSKey.Uint64):
// (__u64(pidNS) << 32) | __u64(mntNS).

struct {
 __uint(type, BPF_MAP_TYPE_ARRAY);
 __type(key, __u32);
 __type(value, __u32);
 __uint(max_entries, 1);
} kl_ns_toggle SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __type(key, __u64);
 __type(value, __u32);
 __uint(max_entries, 1024);
} kl_ns_filter SEC(".maps");

// ---- Self-PID exclusion ---------------------------------------------------
//
// kl_self_tgid[0] holds the kloudlens daemon's own TGID. should_monitor
// short-circuits when the current task matches, so the daemon's own
// /sys/kernel/tracing/events/* opens during BPF setup, /proc walks during
// enrichment, and gRPC handler activity don't drown the crit ringbuf in
// self-noise. Userspace populates the slot in sensor.LiveEBPFWith with
// os.Getpid; a zero value (sentinel) disables the exclusion so tests
// can observe their own activity if they want to.
struct {
 __uint(type, BPF_MAP_TYPE_ARRAY);
 __type(key, __u32);
 __type(value, __u32);
 __uint(max_entries, 1);
} kl_self_tgid SEC(".maps");

// ---- Per-CPU scratch buffer ----------------------------------------------
//
// We assemble each record here before ringbuf-reserving-and-committing. The
// alternative (bpf_ringbuf_reserve upfront) needs a compile-time constant
// size, but a record is variable-length — args can push it well past the
// header size. Scratch + copy-out is the path libbpf tutorials recommend
// for variadic records.

// KL_SCRATCH_SLACK extends the scratch buffer past the logical record cap.
// Rationale: after bitmasking `len & (MAX-1)` in kl_scratch_reserve the
// verifier only learns `len ≤ MAX-1`, so a write at offset `len + k` must
// satisfy `MAX-1 + k < sizeof(buf)`. Slack = largest single reserve we ever
// make (the full string cap, 2048 bytes) — that's the tightest bound that
// still fits inside the per-CPU kmalloc limit (~32 KiB) after counting the
// 4-byte `len` header and any per-entry bookkeeping.
#define KL_SCRATCH_SLACK KL_MAX_STR_BYTES

struct kl_scratch {
 __u32 len; // bytes currently in buf
 __u8 buf[KL_MAX_RECORD_BYTES + KL_SCRATCH_SLACK];
};

struct {
 __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 __type(key, __u32);
 __type(value, struct kl_scratch);
 __uint(max_entries, 1);
} kl_scratch_map SEC(".maps");

// ---- DNS qname parse scratch ---------------------------------------------
//
// Per-CPU destination for kl_dns_parse_qname's variable-offset writes.
// Map values accept variable-offset stores under the verifier rule
// `(masked_offset) + (masked_size) ≤ buffer_len`; the BPF stack does not.
// The physical buffer is oversized so that condition holds for the worst
// case the parser produces:
// * KL_DNS_QNAME_BUF_LEN = 256 — physical buffer.
// * KL_DNS_QNAME_WRITE = 128 — writes only target the lower half
// (mask `& 127`); the upper half is padding the verifier requires.
#define KL_DNS_QNAME_BUF_LEN 256
#define KL_DNS_QNAME_WRITE 128

struct kl_dns_qname_buf {
 __u8 buf[KL_DNS_QNAME_BUF_LEN];
};

struct {
 __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 __type(key, __u32);
 __type(value, struct kl_dns_qname_buf);
 __uint(max_entries, 1);
} kl_dns_qname_scratch SEC(".maps");

// ---- Known-source dedup ---------------------------------------------------
//
// When a task hasn't been seen recently we append an ARG_SOURCE (comm) arg.
// For established tasks we skip it to save bytes. Keyed on host_pid with a
// small LRU — the eviction policy doesn't matter; worst case we re-emit the
// comm, which is correct.

struct {
 __uint(type, BPF_MAP_TYPE_LRU_HASH);
 __type(key, __u32);
 __type(value, __u8);
 __uint(max_entries, 16384);
} kl_known_src SEC(".maps");

// ---- Bulk-ring sampling rate ---------------------------------------------
//
// Userspace (internal/downgrade.Controller) writes a __u32 here to throttle
// the bulk ring under backpressure. Contract:
// 0 or 1 → pass everything (default)
// N (2 ≤ N < max) → keep 1/N events uniformly at random
// 0xFFFFFFFF → drop everything (LevelCriticalOnly)
// The crit ring is never sampled — policy-priority events (exec, kill,
// connect, privilege-change) must survive every throttling tier.

#define KL_SAMPLE_DROP_ALL 0xFFFFFFFFU

struct {
 __uint(type, BPF_MAP_TYPE_ARRAY);
 __type(key, __u32);
 __type(value, __u32);
 __uint(max_entries, 1);
} kl_sampling_rate SEC(".maps");

// ---- Kernel-side ringbuf-full drop counters -------------------------------
//
// bpf_ringbuf_output returns non-zero when the ring is full; without a
// counter the lost record is invisible to userspace (cilium/ebpf's
// ringbuf.Reader only surfaces records it successfully read). Per-CPU array
// keeps the increment lock-free in the hot submit path; userspace sums
// across CPUs for the exported metric.
// Slot 0 (KL_RB_DROP_CRIT) → kl_events_crit overruns
// Slot 1 (KL_RB_DROP_BULK_FILE) → kl_events_bulk_file overruns
// Slot 2 (KL_RB_DROP_BULK_NET) → kl_events_bulk_net overruns
// Slot 3 (KL_RB_DROP_BULK_PROC) → kl_events_bulk_proc overruns
// Slot 4 (KL_RB_DROP_DNS) → kl_events_dns overruns
// Slot 5 (KL_RB_DROP_PROC_LC) → kl_events_proc_lc overruns
// Slot 6 (KL_RB_DROP_SOCK_LC) → kl_events_sock_lc overruns
// Slot 7 (KL_RB_DROP_BULK_FILE_META) → kl_events_bulk_file_meta overruns
// Slot numbers are part of the sensor contract (internal/sensor reads them
// by index); keep these in sync with the RingbufDropSlot Go enum.

#define KL_RB_DROP_CRIT 0
#define KL_RB_DROP_BULK_FILE 1
#define KL_RB_DROP_BULK_NET 2
#define KL_RB_DROP_BULK_PROC 3
#define KL_RB_DROP_DNS 4
#define KL_RB_DROP_PROC_LC 5
#define KL_RB_DROP_SOCK_LC 6
#define KL_RB_DROP_BULK_FILE_META 7
#define KL_RB_DROP_SLOTS 8

struct {
 __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 __type(key, __u32);
 __type(value, __u64);
 __uint(max_entries, KL_RB_DROP_SLOTS);
} kl_rb_drops SEC(".maps");

// ---- Per-CPU emit counter -------------------------------------------------
//
// Every event submission increments this CPU's slot before the ringbuf
// output call. The counter is emitted as ARG_CPU_SEQ on every frame so
// userspace can detect per-CPU gaps — the existing ringbuf-lost counter
// only reports drops aggregated across all CPUs, which makes "CPU N is
// losing records" invisible on heterogeneous nodes. This is also the
// foundation for per-CPU delta encoding: a compact frame format can
// reuse the same counter as its "base seq" so a subsequent compact frame
// references the base by sequence without needing a timestamp anchor.

struct {
 __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 __type(key, __u32);
 __type(value, __u64);
 __uint(max_entries, 1);
} kl_cpu_seq SEC(".maps");

// ---- Per-CPU base for compact frames --------------------------------------
//
// Tracks the task identity + last emitted timestamp on this CPU so a
// high-rate hook (currently kl_emit_rw()) can drop a 64-byte full header
// in favour of a 16-byte compact variant whenever the current task still
// matches the base. Userspace mirrors this on its side off full frames
// read from the same ringbuf; same-ring FIFO ordering guarantees the
// full-frame refresh arrives before any compact frame referencing it.
//
// Populated by kl_fill_header and refreshed on every kl_emit_rw full
// emission. When `pid_tgid` matches the current task and the ts delta
// fits in u32 (4.3 seconds), kl_emit_rw emits compact. Otherwise it
// emits full and re-anchors the base.

struct kl_cpu_base_t {
 __u64 timestamp;
 __u64 pid_tgid;
 __u32 pid_ns_id;
 __u32 mnt_ns_id;
 __u64 cgroup_id;
 __s32 host_ppid;
 __s32 ppid;
 __s32 host_pid;
 __s32 host_tid;
 __s32 pid;
 __s32 tid;
 __u32 uid;
 __u32 gid;
};

struct {
 __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 __type(key, __u32);
 __type(value, struct kl_cpu_base_t);
 __uint(max_entries, 1);
} kl_cpu_base SEC(".maps");

// ---- IPC listener registry (AF_INET) --------------------------------------
//
// Kernel-side record of "which PID bound this (addr, port)". Populated by
// bind(2) exit when retval==0, consulted by connect(2) enter so the wire
// record can carry peer_pid alongside the destination address. Same-node
// cross-container matching piggybacks on this: user-space resolves the
// peer pid to its ContainerID via the enricher's /proc NS map, producing
// a typed `cont:<id>` graph edge instead of an opaque `peer:<addr>` leaf.
//
// Key: packed (addr, port). High 32 bits carry the network-order IPv4
// address as stored in sockaddr_in.sin_addr; low 32 bits carry the port
// (host order). This is the exact shape the wire side emits, so connect
// can rebuild the key without re-decoding the sockaddr.
//
// LRU eviction: dead listeners that never call close age out naturally
// under pressure. Fresh entries from the same (addr, port) overwrite —
// port reuse on the same node is covered.

struct ipc_listener_val {
 __u32 pid; // task_struct->tgid of the binder
 __u32 ts_sec; // wall-ish timestamp (bpf_ktime_get_ns() >> 30)
};

struct {
 __uint(type, BPF_MAP_TYPE_LRU_HASH);
 __type(key, __u64);
 __type(value, struct ipc_listener_val);
 __uint(max_entries, 4096);
} kl_ipc_listener SEC(".maps");

// Per-TID bind context: bind enter stores (family, addr, port) here so
// bind exit can read retval and commit to kl_ipc_listener on success.
// The in-kernel wire record is emitted on enter and doesn't carry retval,
// so we can't use it as the correlator.

struct ipc_bind_ctx {
 __u32 family;
 __u32 addr; // big-endian, as stored in sockaddr_in.sin_addr.s_addr
 __u32 port; // host order
 __u32 _pad;
};

struct {
 __uint(type, BPF_MAP_TYPE_LRU_HASH);
 __type(key, __u64); // (tgid << 32) | tid
 __type(value, struct ipc_bind_ctx);
 __uint(max_entries, 4096);
} kl_ipc_pending_bind SEC(".maps");

// ---- File-descriptor lifetime state ---------------------------------------
//
// Per-(tgid, fd) bookkeeping. When state exists for the closing fd,
// close(2) attaches path_ref (8-byte FNV-1a hash resolvable via the
// user-space str cache) and open_ts_ns as extra wire args, so the close
// record alone carries the full open→close shape for short-lived fds.
//
// Populated on successful openat exit, consumed + deleted on close enter.
// LRU ceiling keeps the table bounded on hosts that leak fds across long
// sequences of opens.

struct kl_fd_state {
 __u64 path_hash; // fnv1a-64 of the open path, matches Go's hashStr
 __u64 open_ts_ns; // bpf_ktime_get_ns at openat exit
};

struct {
 __uint(type, BPF_MAP_TYPE_LRU_HASH);
 __type(key, __u64); // (tgid << 32) | fd
 __type(value, struct kl_fd_state);
 __uint(max_entries, 65536);
} kl_fd_state SEC(".maps");

// Per-TID pending openat context: openat enter computes the path hash,
// openat exit pairs with retval (the new fd) to commit into kl_fd_state.
// Same correlator pattern as kl_ipc_pending_bind.

struct kl_pending_open {
 __u64 path_hash;
 __u64 open_ts_ns;
};

struct {
 __uint(type, BPF_MAP_TYPE_LRU_HASH);
 __type(key, __u64); // tgid_tid
 __type(value, struct kl_pending_open);
 __uint(max_entries, 4096);
} kl_pending_openat SEC(".maps");

// ---- String intern dictionary --------------------------------------------
//
// BPF hashes every ARG_RESOURCE string (fnv1a-64 over the first
// KL_HASH_MAX_BYTES bytes) and checks this map. On hit, the scratch
// emits ARG_STR_REF + 8-byte hash. On miss, the full string bytes are
// stored under that hash so userspace can resolve the reference even
// when its local cache lost the original ARG_RESOURCE frame (ringbuf
// drop, late attach, decoder restart).
//
// Value layout: a fixed-size `{len, bytes}` record. Paths longer than
// KL_INTERN_MAX_BYTES stay as full ARG_RESOURCE and never intern (the
// 254-byte cap covers the overwhelming majority of observed paths).
//
// 16384-entry LRU at 272 bytes/value ≈ 4 MiB. Userspace can LOOKUP
// this map on ARG_STR_REF cache miss (wire.Decoder.cache), so the
// kernel holds the authoritative dictionary and the userspace cache is
// a latency optimisation on top.

#define KL_INTERN_MAX_BYTES 254

struct kl_intern_val {
 __u16 len; // length in bytes, excluding NUL
 __u8 bytes[KL_INTERN_MAX_BYTES];
};

struct {
 __uint(type, BPF_MAP_TYPE_LRU_HASH);
 __type(key, __u64);
 __type(value, struct kl_intern_val);
 __uint(max_entries, 16384);
} kl_str_intern SEC(".maps");

// kl_intern_scratch is the per-CPU staging buffer for kl_str_intern
// upserts. The 256-byte kl_intern_val exceeds BPF's 512-byte stack
// budget when a hook already has other locals (openat enter is the
// tight case), so staging through a per-CPU map keeps the stack slim
// while still giving each CPU a private workspace.
struct {
 __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 __type(key, __u32);
 __type(value, struct kl_intern_val);
 __uint(max_entries, 1);
} kl_intern_scratch SEC(".maps");

// ---- Event coalesce ---------------------------------------
//
// Kernel-side dedup for high-rate UNARY syscalls (read/write/stat/access).
// Keyed by (tgid, kind, discriminator) the helper collapses bursts within
// KL_COALESCE_WINDOW_NS into a single emitted event. The NEXT event after
// the window expires carries ARG_COALESCED_COUNT / ARG_COALESCED_BYTES
// trailers describing the suppressed burst, piggybacked so BPF never has
// to synthesize a separate record from a timer (BPF has no timer hook
// suitable for ring-buffer emission on older kernels).
//
// Size: 16384 entries is enough for steady-state fan-out across a few
// thousand threads × a handful of (class, fd) pairs each. The LRU policy
// ensures cold keys get evicted; an eviction mid-window just means the
// next event emits without a trailer (we lose the tail count/bytes of
// that one window — acceptable).

#define KL_COALESCE_WINDOW_NS 100000000ULL /* 100ms */

enum kl_coalesce_kind {
 KL_COALESCE_RW = 1, // r/w syscalls, discriminator = fd | (class<<32)
 KL_COALESCE_STAT = 2, // stat-class, discriminator = path_hash
 KL_COALESCE_ACCESS = 3, // access-class, discriminator = path_hash
};

struct kl_coalesce_key {
 __u32 tgid;
 __u32 kind; // enum kl_coalesce_kind (widened for alignment)
 __u64 disc;
};

struct kl_coalesce_val {
 __u64 first_ts; // bpf_ktime_get_ns when the window opened
 __u64 bytes; // cumulative bytes requested across the window
 __u32 count; // events observed in the window (emitted + suppressed)
 __u32 _pad;
};

struct {
 __uint(type, BPF_MAP_TYPE_LRU_HASH);
 __type(key, struct kl_coalesce_key);
 __type(value, struct kl_coalesce_val);
 __uint(max_entries, 16384);
} kl_coalesce SEC(".maps");

// ---- DNS parser scratch ---------------------------------------------------
//
// Per-CPU DNS parser scratch: reading the full DNS response into a stack
// buffer (~512 bytes) blows past the verifier's 512-byte stack budget when
// other locals are live, so we stage the buffer through a per-CPU map.
// 512 bytes is the conventional "EDNS0 not requested" UDP DNS message cap;
// truncated responses (TC bit set) re-query over TCP — out of scope for
// this hook.
#define KL_DNS_BUF_SIZE 512

struct kl_dns_buf {
 __u8 bytes[KL_DNS_BUF_SIZE];
};

struct {
 __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 __type(key, __u32);
 __type(value, struct kl_dns_buf);
 __uint(max_entries, 1);
} kl_dns_scratch SEC(".maps");
