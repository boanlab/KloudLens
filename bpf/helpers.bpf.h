// SPDX-License-Identifier: (GPL-2.0-only OR Apache-2.0)
// Copyright 2026 BoanLab @ DKU
//
// helpers.bpf.h — verifier-friendly encoders that append a typed argument
// to the per-CPU scratch buffer, and the header/submit primitives. Every
// writer returns 0 on success and a negative errno-style int on failure so
// hook callers can bail with a single `if (... < 0) return 0;` idiom.
#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "wire.bpf.h"
#include "maps.bpf.h"

// barrier_var forces the compiler to treat `var` as opaque after the call,
// preventing the backend from CSE-ing the value and reusing an unmasked copy
// for dependent pointer arithmetic. Lifted verbatim from cilium/ebpf's
// bpf_macros.h — the idiom is the only reliable way to keep scalar bounds
// attached to the register that actually feeds the map-value access.
#define kl_barrier_var(var) asm volatile("" : "+r"(var))

// ---- Scratch access -------------------------------------------------------

static __always_inline struct kl_scratch *kl_scratch_get(void)
{
 __u32 zero = 0;
 struct kl_scratch *s = bpf_map_lookup_elem(&kl_scratch_map, &zero);
 if (!s) return NULL;
 s->len = 0;
 return s;
}

// kl_scratch_reserve returns a pointer to `n` contiguous bytes inside the
// scratch buffer, advancing s->len. Bounds are phrased so the verifier's
// scalar-range analysis can prove the subsequent access is in-range:
// after the guards, len + n < KL_MAX_RECORD_BYTES. We cap at *less than*
// the buffer size (rather than ≤) so kl_submit_to can apply a bitmask of
// (KL_MAX_RECORD_BYTES - 1) to the record size — the verifier-recommended
// idiom for making the size arg to bpf_ringbuf_output bounded.
static __always_inline void *kl_scratch_reserve(struct kl_scratch *s, __u32 n)
{
 if (n == 0 || n > KL_MAX_RECORD_BYTES) return NULL;
 __u32 len = s->len;
 if (len >= KL_MAX_RECORD_BYTES) return NULL;
 if (len + n >= KL_MAX_RECORD_BYTES) return NULL;
 // Pass the len through an inline-asm "launder" that the compiler can't
 // see through: the asm declares it both reads and writes `idx`, but does
 // nothing, so the bound the verifier *does* attach to the asm output
 // (imposed below by the mask) is the only bound attached to the register
 // feeding the pointer arithmetic. Without this, LLVM cheerfully CSEs the
 // mask into the earlier bounds-check and the pointer derives from the
 // unmasked register → verifier rejects with "unbounded memory access".
 __u32 idx = len;
 kl_barrier_var(idx);
 idx &= (KL_MAX_RECORD_BYTES - 1);
 kl_barrier_var(idx);
 void *p = &s->buf[idx];
 s->len = len + n;
 return p;
}

// ---- Header fill ----------------------------------------------------------
//
// kl_fill_header populates the event_t at the head of the scratch buffer
// from the current task. Caller supplies syscall_id, event_type, and the
// eventual arg_num (we overwrite the latter later if we truncate).
static __always_inline int kl_fill_header(struct kl_scratch *s,
 __s32 syscall_id,
 __s8 event_type,
 __s8 arg_num)
{
 struct event_t *ev = kl_scratch_reserve(s, sizeof(*ev));
 if (!ev) return -1;

 struct task_struct *task = (struct task_struct *)bpf_get_current_task();
 __u64 pid_tgid = bpf_get_current_pid_tgid();
 __u64 uid_gid = bpf_get_current_uid_gid();

 ev->timestamp = bpf_ktime_get_ns();

 // Host-visible IDs come straight from the helpers above.
 ev->host_pid = (__s32)(pid_tgid >> 32);
 ev->host_tid = (__s32)(pid_tgid & 0xffffffff);

 // Namespaced (inside-container) IDs via CO-RE walks. The task's
 // thread_pid points at a struct pid whose per-level numbers[] carry the
 // per-ns (pid, tgid). Level 0 is host; the deepest level is the
 // innermost namespace the task participates in. We want the innermost.
 unsigned int lvl = BPF_CORE_READ(task, thread_pid, level);
 struct pid *tgid_pid = BPF_CORE_READ(task, group_leader, thread_pid);
 struct pid *thr_pid = BPF_CORE_READ(task, thread_pid);
 ev->pid = (__s32)BPF_CORE_READ(tgid_pid, numbers[lvl].nr);
 ev->tid = (__s32)BPF_CORE_READ(thr_pid, numbers[lvl].nr);

 // Parent: the task's real_parent carries host_ppid; its namespaced pid
 // maps to ppid inside the child's innermost ns.
 struct task_struct *parent = BPF_CORE_READ(task, real_parent);
 ev->host_ppid = (__s32)BPF_CORE_READ(parent, tgid);
 struct pid *parent_tgid = BPF_CORE_READ(parent, group_leader, thread_pid);
 unsigned int parent_lvl = BPF_CORE_READ(parent_tgid, level);
 if (parent_lvl > lvl) parent_lvl = lvl;
 ev->ppid = (__s32)BPF_CORE_READ(parent_tgid, numbers[parent_lvl].nr);

 // Namespace inode numbers. nsproxy can be NULL for zombies — if the
 // read fails we leave the fields zero.
 ev->pid_ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
 ev->mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

 // cgroup_id is the kernel's canonical container handle (cgroupv2
 // directory inode) — survives hostPID/hostNetwork/hostMnt cases
 // where the (pid_ns, mnt_ns) pair collides with host or peers.
 ev->cgroup_id = bpf_get_current_cgroup_id();

 ev->uid = (__u32)(uid_gid & 0xffffffff);
 ev->gid = (__u32)(uid_gid >> 32);

 ev->event_id = 0;
 ev->cpu_id = (__u16)bpf_get_smp_processor_id();
 ev->event_type = event_type;
 ev->arg_num = arg_num;

 ev->syscall_id = syscall_id;
 ev->retval = 0;

 // Anchor the per-CPU compact-frame base. Every full header refresh
 // gives compact emitters on this CPU a fresh reference point they
 // can delta against; kl_emit_rw consults this on the hot path.
 __u32 zero = 0;
 struct kl_cpu_base_t *base = bpf_map_lookup_elem(&kl_cpu_base, &zero);
 if (base) {
 base->timestamp = ev->timestamp;
 base->pid_tgid = pid_tgid;
 base->pid_ns_id = ev->pid_ns_id;
 base->mnt_ns_id = ev->mnt_ns_id;
 base->cgroup_id = ev->cgroup_id;
 base->host_ppid = ev->host_ppid;
 base->ppid = ev->ppid;
 base->host_pid = ev->host_pid;
 base->host_tid = ev->host_tid;
 base->pid = ev->pid;
 base->tid = ev->tid;
 base->uid = ev->uid;
 base->gid = ev->gid;
 }

 return 0;
}

// kl_try_fill_compact writes a 16-byte compact header at the head of the
// scratch and returns 0 on success. Fails (-1) when the per-CPU base is
// stale: another task has run on this CPU (pid_tgid mismatch) or the ts
// delta would overflow the u32 field. Callers fall back to
// kl_fill_header in both failure cases.
//
// The compact frame omits every field that matches the base; userspace
// reconstructs them from a mirror it maintains off full frames on the
// same ring. BPF ringbuf FIFO guarantees a full frame refreshing the
// base arrives before any compact frame that references it, provided
// both land on the same ring from the same CPU.
static __always_inline int kl_try_fill_compact(struct kl_scratch *s,
 __s32 syscall_id,
 __s8 arg_num)
{
 __u32 zero = 0;
 struct kl_cpu_base_t *base = bpf_map_lookup_elem(&kl_cpu_base, &zero);
 if (!base || base->timestamp == 0) return -1;
 __u64 pid_tgid = bpf_get_current_pid_tgid();
 if (base->pid_tgid != pid_tgid) return -1;

 __u64 now = bpf_ktime_get_ns();
 if (now < base->timestamp) return -1;
 __u64 delta = now - base->timestamp;
 if (delta > 0xffffffffULL) return -1; // > 4.3 s → refresh via full frame

 struct compact_event_t *ce = kl_scratch_reserve(s, sizeof(*ce));
 if (!ce) return -1;
 ce->event_type = EVENT_COMPACT_UNARY;
 ce->arg_num = arg_num;
 ce->cpu_id = (__u16)bpf_get_smp_processor_id();
 ce->ts_delta_ns = (__u32)delta;
 ce->syscall_id = syscall_id;
 ce->retval = 0;

 // Advance the base timestamp so successive compact frames delta
 // against the most recent anchor. The other base fields don't
 // change because pid_tgid matched.
 base->timestamp = now;
 return 0;
}

// kl_patch_arg_num rewrites the arg_num field post-hoc when a writer bailed
// before appending every argument. Callers that always write all N args
// can skip this.
static __always_inline void kl_patch_arg_num(struct kl_scratch *s, __s8 arg_num)
{
 if (s->len < sizeof(struct event_t)) return;
 struct event_t *ev = (struct event_t *)&s->buf[0];
 ev->arg_num = arg_num;
}

static __always_inline void kl_set_retval(struct kl_scratch *s, __s32 retval)
{
 if (s->len < sizeof(struct event_t)) return;
 struct event_t *ev = (struct event_t *)&s->buf[0];
 ev->retval = retval;
}

// ---- Scalar arg writers ---------------------------------------------------

static __always_inline int kl_put_u32(struct kl_scratch *s, __u32 tag, __u32 v)
{
 __u32 *p = kl_scratch_reserve(s, 4);
 if (!p) return -1;
 *p = tag;
 p = kl_scratch_reserve(s, 4);
 if (!p) return -1;
 *p = v;
 return 0;
}

static __always_inline int kl_put_i32(struct kl_scratch *s, __u32 tag, __s32 v)
{
 return kl_put_u32(s, tag, (__u32)v);
}

static __always_inline int kl_put_u64(struct kl_scratch *s, __u32 tag, __u64 v)
{
 __u32 *p = kl_scratch_reserve(s, 4);
 if (!p) return -1;
 *p = tag;
 __u64 *q = kl_scratch_reserve(s, 8);
 if (!q) return -1;
 *q = v;
 return 0;
}

#define kl_put_int(s, v) kl_put_i32((s), ARG_INT, (v))
#define kl_put_uint(s, v) kl_put_u32((s), ARG_UINT, (v))
#define kl_put_ulong(s, v) kl_put_u64((s), ARG_ULONG, (v))

// ---- Varint (LEB128) writers ----------------------------------------------
//
// kl_put_varint_u64 appends ARG_VARINT_U64 followed by a LEB128 encoding of
// `v` (1-10 bytes). The loop is compile-time bounded at 10 iterations (enough
// for a full u64) so the verifier can unroll it. kl_put_varint_u32 is the
// narrow variant with a 5-byte cap. Both functions return 0 on success and
// -1 on scratch exhaustion; the partially-written bytes stay in scratch but
// the caller will bail before submit, so they're harmless.
static __always_inline int kl_put_varint_u64(struct kl_scratch *s, __u64 v)
{
 __u32 *tagp = kl_scratch_reserve(s, 4);
 if (!tagp) return -1;
 *tagp = ARG_VARINT_U64;
 #pragma unroll
 for (int i = 0; i < 10; i++) {
 __u8 *bp = kl_scratch_reserve(s, 1);
 if (!bp) return -1;
 __u8 b = v & 0x7f;
 v >>= 7;
 if (v) {
 *bp = b | 0x80;
 } else {
 *bp = b;
 return 0;
 }
 }
 return -1; // u64 should always fit in ≤10 bytes; never reached in practice
}

static __always_inline int kl_put_varint_u32(struct kl_scratch *s, __u32 v)
{
 __u32 *tagp = kl_scratch_reserve(s, 4);
 if (!tagp) return -1;
 *tagp = ARG_VARINT_U32;
 #pragma unroll
 for (int i = 0; i < 5; i++) {
 __u8 *bp = kl_scratch_reserve(s, 1);
 if (!bp) return -1;
 __u8 b = v & 0x7f;
 v >>= 7;
 if (v) {
 *bp = b | 0x80;
 } else {
 *bp = b;
 return 0;
 }
 }
 return -1;
}

// ---- String arg writers ---------------------------------------------------

// KL_HASH_MAX_BYTES caps the fnv1a hash input. Paths shorter than this hash
// their full content; longer ones hash only the prefix — collisions between
// long-path suffixes that share a 256-byte prefix go into the userspace
// resolver's miss counter (rare in practice; `/proc/<pid>/*`, `/sys/*`, and
// container-rootfs paths all differ in the first ~60 bytes). 256 is the
// sweet spot between verifier cost and collision resistance.
#define KL_HASH_MAX_BYTES 256

// kl_fnv1a_buf computes a fnv1a-64 hash over the first min(len,
// KL_HASH_MAX_BYTES) bytes of `buf`. Must match the Go-side implementation
// in internal/wire/wire.go (hashStr) byte-for-byte — they key into shared
// LRU caches on both sides of the wire. The loop is bounded by a compile-
// time constant so the verifier can unroll/track it without bpf_loop.
static __always_inline __u64 kl_fnv1a_buf(const __u8 *buf, __u32 len)
{
 __u64 h = 0xcbf29ce484222325ULL;
 __u32 cap = len;
 if (cap > KL_HASH_MAX_BYTES) cap = KL_HASH_MAX_BYTES;
 // Explicit `i < KL_HASH_MAX_BYTES` on both edges of the condition gives
 // the verifier a constant upper bound independent of `cap`; the
 // `i >= cap` break handles the runtime ceiling. This split is what
 // keeps the loop verifier-friendly on 5.10 kernels (no bpf_loop helper).
 for (__u32 i = 0; i < KL_HASH_MAX_BYTES; i++) {
 if (i >= cap) break;
 h ^= (__u64)buf[i];
 h *= 0x100000001b3ULL;
 }
 return h;
}

// kl_hash_user_path reads a NUL-terminated string from userspace memory
// and returns its FNV-1a hash over the first min(len, KL_HASH_MAX_BYTES)
// content bytes. Returns 0 on read failure or empty input. Used by hooks
// that need to correlate a path across enter/exit frames (e.g. openat
// enter → close via kl_fd_state).
static __always_inline __u64 kl_hash_user_path(const void *user_ptr)
{
 char buf[KL_HASH_MAX_BYTES];
 long n = bpf_probe_read_user_str(buf, sizeof(buf), user_ptr);
 if (n <= 1) return 0;
 __u32 un = (__u32)n;
 if (un > KL_HASH_MAX_BYTES) un = KL_HASH_MAX_BYTES;
 return kl_fnv1a_buf((const __u8 *)buf, un - 1);
}

// kl_put_str_ref emits an ARG_STR_REF tag + 8-byte hash. Intended for
// hooks that already know the hash of a previously-emitted ARG_STR /
// ARG_RESOURCE (e.g. via kl_fd_state). Userspace resolves the hash via
// its decoder's strCache — if the cache misses the arg surfaces as a
// synthetic placeholder, which is the same semantics as any ARG_STR_REF.
static __always_inline int kl_put_str_ref(struct kl_scratch *s, __u64 hash)
{
 __u32 *tagp = kl_scratch_reserve(s, 4);
 if (!tagp) return -1;
 *tagp = ARG_STR_REF;
 __u64 *hp = kl_scratch_reserve(s, 8);
 if (!hp) return -1;
 *hp = hash;
 return 0;
}

// kl_maybe_collapse_resource rewrites a just-written ARG_RESOURCE arg into
// the compact ARG_STR_REF shape (4-byte tag + 8-byte hash) when the bytes
// we just committed hash to something already present in kl_str_intern.
// On miss, inserts {len, bytes} so the next sighting across any CPU
// collapses AND so userspace can resolve the hash via map lookup when
// its local cache missed the original ARG_RESOURCE emission.
//
// Invariants required by the caller:
// - The last thing written to scratch was the tag+len+bytes of this
// ARG_RESOURCE (i.e. the bytes occupy [s->len - un, s->len) and the
// 8-byte tag+len header sits immediately before that).
// - `buf` points at those bytes (&s->buf[s->len - un]).
// - `un` is the length including the NUL terminator.
//
// The 12-byte minimum below reflects the break-even point: ARG_STR_REF
// needs 12 bytes (tag+hash), so only strings of 13+ bytes save anything.
// Strings longer than KL_INTERN_MAX_BYTES stay as full ARG_RESOURCE —
// the intern-map value is fixed-size so oversize strings can't fit.
static __always_inline void kl_maybe_collapse_resource(struct kl_scratch *s,
 const __u8 *buf,
 __u32 un)
{
 if (un <= 12) return;
 // Hash the content bytes only (exclude the trailing NUL) — matches
 // hashStr in wire.go which sees the trimmed string.
 __u64 h = kl_fnv1a_buf(buf, un - 1);
 struct kl_intern_val *seen = bpf_map_lookup_elem(&kl_str_intern, &h);
 if (seen) {
 // Rewind the full tag(4) + len(4) + bytes(un) region. Guard against
 // an impossible underflow defensively — the caller's invariant says
 // s->len already includes these bytes plus at least sizeof(event_t).
 __u32 consumed = 8 + un;
 if (s->len <= consumed) return;
 s->len -= consumed;
 __u32 *refp = kl_scratch_reserve(s, 4);
 if (!refp) return;
 *refp = ARG_STR_REF;
 __u64 *hp = kl_scratch_reserve(s, 8);
 if (!hp) return;
 *hp = h;
 return;
 }
 // Miss: populate the intern dictionary so userspace can resolve the
 // hash via map lookup when its local cache missed. content_len =
 // un - 1 (exclude trailing NUL). Skip oversize strings — the intern
 // map value is fixed-size. Staging through kl_intern_scratch keeps
 // the BPF stack under the 512-byte verifier limit.
 __u32 content_len = un - 1;
 if (content_len > KL_INTERN_MAX_BYTES) return;
 __u32 zero = 0;
 struct kl_intern_val *nv = bpf_map_lookup_elem(&kl_intern_scratch, &zero);
 if (!nv) return;
 nv->len = (__u16)content_len;
 // Bounded memcpy — the verifier sees content_len ≤ KL_INTERN_MAX_BYTES
 // and `buf` has at least `un` readable bytes from the earlier probe_read.
 for (__u32 i = 0; i < KL_INTERN_MAX_BYTES; i++) {
 if (i >= content_len) break;
 nv->bytes[i] = buf[i];
 }
 bpf_map_update_elem(&kl_str_intern, &h, nv, BPF_ANY);
}

// kl_put_str_user reads a NUL-terminated string from userspace memory
// (syscall arg pointer) and writes it as:
// __u32 tag | __u32 length_including_NUL | bytes | NUL
// The length is the bpf_probe_read_str return value; per wire.go's readString,
// length includes the NUL terminator.
//
// When tag == ARG_RESOURCE the helper additionally tries to collapse the
// just-written bytes into ARG_STR_REF via kl_maybe_collapse_resource. Other
// tags (ARG_STR for argv items, ARG_CURRENT_DIR, mount's src/fstype) stay
// as-is — they either cost more to hash than they'd save (short argv
// entries) or repeat so rarely the dedup loss from eviction outweighs the
// compression.
static __always_inline int kl_put_str_user(struct kl_scratch *s, __u32 tag,
 const void *user_ptr)
{
 __u32 *tagp = kl_scratch_reserve(s, 4);
 if (!tagp) return -1;
 *tagp = tag;

 __u32 *lenp = kl_scratch_reserve(s, 4);
 if (!lenp) return -1;

 // Reserve the max string cap up front; we'll truncate s->len after the
 // read completes so the scratch doesn't grow past the actual length.
 void *buf = kl_scratch_reserve(s, KL_MAX_STR_BYTES);
 if (!buf) return -1;

 long n = bpf_probe_read_user_str(buf, KL_MAX_STR_BYTES, user_ptr);
 if (n <= 0) {
 // Return an empty string rather than a partial / absent arg so the
 // parser's arg count stays consistent with arg_num.
 *lenp = 1;
 *((__u8 *)buf) = 0;
 s->len -= (KL_MAX_STR_BYTES - 1);
 return 0;
 }
 __u32 un = (__u32)n;
 if (un > KL_MAX_STR_BYTES) un = KL_MAX_STR_BYTES;
 *lenp = un;
 s->len -= (KL_MAX_STR_BYTES - un);

 if (tag == ARG_RESOURCE) {
 kl_maybe_collapse_resource(s, (const __u8 *)buf, un);
 }
 return 0;
}

// kl_put_dpath emits the absolute canonical path of a `struct path *` by
// calling bpf_d_path. The helper is only callable from kprobes on the
// kernel's btf_allowlist_d_path (filp_close, vfs_*, dentry_open, …) or from
// sleepable LSM hooks — callers must guarantee that. Fills the scratch with
// __u32 tag = ARG_RESOURCE
// __u32 len (incl NUL)
// bytes + NUL
// If bpf_d_path fails (eg. unresolvable path, truncated buffer) we emit a
// single-byte empty string so the wire record stays arg-count-consistent.
static __always_inline int kl_put_dpath(struct kl_scratch *s, struct path *p)
{
 __u32 *tagp = kl_scratch_reserve(s, 4);
 if (!tagp) return -1;
 *tagp = ARG_RESOURCE;

 __u32 *lenp = kl_scratch_reserve(s, 4);
 if (!lenp) return -1;

 char *buf = kl_scratch_reserve(s, KL_MAX_STR_BYTES);
 if (!buf) return -1;

 long n = bpf_d_path(p, buf, KL_MAX_STR_BYTES);
 if (n <= 0) {
 *lenp = 1;
 buf[0] = 0;
 s->len -= (KL_MAX_STR_BYTES - 1);
 return 0;
 }
 // bpf_d_path writes a NUL-terminated string and returns the length
 // including the NUL — matches our wire contract with kl_put_str_user.
 // Clamp the verifier-visible upper bound before the scratch rollback.
 __u32 un = (__u32)n;
 if (un > KL_MAX_STR_BYTES) un = KL_MAX_STR_BYTES;
 *lenp = un;
 s->len -= (KL_MAX_STR_BYTES - un);
 kl_maybe_collapse_resource(s, (const __u8 *)buf, un);
 return 0;
}

// kl_put_str_kernel mirrors the above but reads from kernel-space memory —
// used by LSM / kprobe hooks that already have a kernel pointer (e.g.
// `struct file *`'s dentry path).
static __always_inline int kl_put_str_kernel(struct kl_scratch *s, __u32 tag,
 const void *kern_ptr)
{
 __u32 *tagp = kl_scratch_reserve(s, 4);
 if (!tagp) return -1;
 *tagp = tag;

 __u32 *lenp = kl_scratch_reserve(s, 4);
 if (!lenp) return -1;

 void *buf = kl_scratch_reserve(s, KL_MAX_STR_BYTES);
 if (!buf) return -1;

 long n = bpf_probe_read_kernel_str(buf, KL_MAX_STR_BYTES, kern_ptr);
 if (n <= 0) {
 *lenp = 1;
 *((__u8 *)buf) = 0;
 s->len -= (KL_MAX_STR_BYTES - 1);
 return 0;
 }
 // Clamp the verifier-visible upper bound before subtracting from s->len.
 // bpf_probe_read_kernel_str documents `n <= KL_MAX_STR_BYTES`, but kprobe
 // context is strict enough that the verifier tracks `n` as unbounded
 // positive unless we add the explicit clamp — mirrors kl_put_dpath above.
 __u32 un = (__u32)n;
 if (un > KL_MAX_STR_BYTES) un = KL_MAX_STR_BYTES;
 *lenp = un;
 s->len -= (KL_MAX_STR_BYTES - un);
 return 0;
}

// kl_put_fullpath emits the absolute path of a `(dentry, vfsmount)` pair by
// walking d_parent and crossing mount boundaries via `struct mount`. Produces
// the same output shape as kl_put_dpath (ARG_RESOURCE + len + NUL-terminated
// bytes) but works from any BPF program type, including plain kprobes where
// bpf_d_path is not available.
//
// Why `struct vfsmount` is required: a pure d_parent walk stops at each mount
// root (whose d_parent is itself), producing paths rooted at the mount — e.g.
// `/uptime` instead of `/proc/uptime`, `/jn/.../file` instead of
// `/home/jn/.../file` when /home is a separate mount. Crossing mount
// boundaries is how prepend_path in fs/d_path.c assembles the absolute path,
// and we mirror that: when d == mnt->mnt_root and mount has a parent, jump
// via container_of(vm, struct mount, mnt) to mnt->mnt_mountpoint in the
// parent mount.
//
// The walk is two-pass: pass 1 collects up to N dentry pointers on the BPF
// stack walking from leaf → root (mount-crossings don't consume a slot),
// pass 2 re-walks the array root → leaf and writes each segment into the
// scratch with '/' separators. The two-pass shape is the only one that lets
// the unrolled loop iterate over *constant* indices in the emission pass —
// a tail-first single-pass walk would need a variable-offset memmove at the
// end, which the strict kprobe verifier rejects.
#define KL_FULLPATH_MAX_BYTES 256
#define KL_FULLPATH_MAX_DEPTH 16
#define KL_FULLPATH_MAX_STEPS 32
#define KL_FULLPATH_SEGMENT_MAX 64

// kl_real_mount recovers the enclosing `struct mount` from a `struct vfsmount
// *`. `struct mount` embeds a `struct vfsmount mnt;` so the parent struct's
// base pointer is vm - offsetof(struct mount, mnt). bpf_core_field_offset
// makes this CO-RE-safe if future kernels reorder struct mount fields.
static __always_inline struct mount *kl_real_mount(struct vfsmount *vm)
{
 if (!vm) return NULL;
 return (struct mount *)((char *)vm - bpf_core_field_offset(struct mount, mnt));
}

// NOT __always_inline: we want the verifier to check this once as a
// BPF subprogram and let all 12 callers invoke it via bpf_call. Inlining
// it everywhere blew past the 1M-instruction complexity limit.
__attribute__((noinline))
static int kl_put_fullpath(struct kl_scratch *s, struct dentry *leaf,
 struct vfsmount *leaf_vm)
{
 __u32 *tagp = kl_scratch_reserve(s, 4);
 if (!tagp) return -1;
 *tagp = ARG_RESOURCE;

 __u32 *lenp = kl_scratch_reserve(s, 4);
 if (!lenp) return -1;

 char *buf = kl_scratch_reserve(s, KL_FULLPATH_MAX_BYTES);
 if (!buf) return -1;

 struct dentry *chain[KL_FULLPATH_MAX_DEPTH] = {};
 __u32 depth = 0;
 struct dentry *d = leaf;
 struct mount *m = kl_real_mount(leaf_vm);

 // Pass 1: walk leaf → root. Unrolled to KL_FULLPATH_MAX_DEPTH iterations;
 // each iteration may (a) cross one mount boundary at the top, and (b)
 // consume one chain slot for a real d_parent step. Mountpoint dentries
 // live in the parent filesystem (never at a parent mount's root), so at
 // most one crossing per iteration is sufficient for real filesystems.
 #pragma unroll
 for (int i = 0; i < KL_FULLPATH_MAX_DEPTH; i++) {
 if (!d) break;
 if (m) {
 struct dentry *mroot = BPF_CORE_READ(m, mnt.mnt_root);
 if (d == mroot) {
 struct mount *mparent = BPF_CORE_READ(m, mnt_parent);
 if (!mparent || mparent == m) break; // global root
 d = BPF_CORE_READ(m, mnt_mountpoint);
 m = mparent;
 if (!d) break;
 }
 }
 struct dentry *parent = BPF_CORE_READ(d, d_parent);
 if (!parent || parent == d) break;
 chain[i] = d;
 depth = i + 1;
 d = parent;
 }

 // Pass 2: emit root → leaf. The outer loop index is an unrolled constant
 // which lets the verifier accept chain[i] without a runtime bound check.
 __u32 pos = 0;
 #pragma unroll
 for (int i = KL_FULLPATH_MAX_DEPTH - 1; i >= 0; i--) {
 if ((__u32)i >= depth) continue;
 struct dentry *dp = chain[i];
 if (!dp) continue;

 const unsigned char *name = BPF_CORE_READ(dp, d_name.name);
 __u32 name_len = BPF_CORE_READ(dp, d_name.len);
 if (name_len == 0) continue;
 if (name_len > KL_FULLPATH_SEGMENT_MAX) name_len = KL_FULLPATH_SEGMENT_MAX;

 // '/' separator — leave 2 bytes at the tail: one for the next byte,
 // one reserved for NUL termination at the end.
 if (pos + 2 >= KL_FULLPATH_MAX_BYTES) break;
 kl_barrier_var(pos);
 __u32 w = pos & (KL_FULLPATH_MAX_BYTES - 1);
 kl_barrier_var(w);
 buf[w] = '/';
 pos += 1;

 // Segment name.
 if (pos + name_len + 1 >= KL_FULLPATH_MAX_BYTES) break;
 kl_barrier_var(pos);
 w = pos & (KL_FULLPATH_MAX_BYTES - 1);
 kl_barrier_var(w);
 kl_barrier_var(name_len);
 name_len &= (KL_FULLPATH_SEGMENT_MAX - 1);
 kl_barrier_var(name_len);
 if (name_len == 0) { name_len = 1; }
 bpf_probe_read_kernel(&buf[w], name_len, name);
 pos += name_len;
 }

 if (pos == 0) {
 // Bare root or empty walk — emit "/".
 buf[0] = '/';
 pos = 1;
 }
 // NUL terminate.
 {
 __u32 w = pos & (KL_FULLPATH_MAX_BYTES - 1);
 kl_barrier_var(w);
 buf[w] = 0;
 }
 pos += 1;

 // Clamp for verifier, then shrink the scratch's unused tail.
 kl_barrier_var(pos);
 if (pos > KL_FULLPATH_MAX_BYTES) pos = KL_FULLPATH_MAX_BYTES;
 kl_barrier_var(pos);
 *lenp = pos;
 s->len -= (KL_FULLPATH_MAX_BYTES - pos);
 return 0;
}

// kl_put_comm emits the current task's comm under ARG_SOURCE, but only if
// this is the first record we've seen for host_pid (LRU-dedup). Returns:
// 1 if it wrote the arg; 0 if skipped; negative on scratch exhaustion.
// kl_put_comm_bytes is the verifier-friendly primitive used by both
// source writers. We always reserve the full TASK_COMM_LEN (16 bytes) so the
// probe_read size and the reserved region are compile-time constants — the
// verifier can then prove `ptr + 16 ≤ buf_end` without needing to relate two
// runtime scalars. After writing, we roll back s->len by the unused tail and
// patch *lenp to the real string length. This mirrors kl_put_str_user's
// idiom and is the only pattern that consistently passes BPF verification
// across 5.x/6.x kernels for variable-length arg writers.
static __always_inline int kl_put_comm_bytes(struct kl_scratch *s)
{
 __u32 *tagp = kl_scratch_reserve(s, 4);
 if (!tagp) return -1;
 *tagp = ARG_SOURCE;

 __u32 *lenp = kl_scratch_reserve(s, 4);
 if (!lenp) return -1;

 // Reserve TASK_COMM_LEN=16 unconditionally, even though the actual
 // comm string is usually shorter. The scratch rollback below frees the
 // unused tail so subsequent args still pack tightly.
 char *buf = kl_scratch_reserve(s, 16);
 if (!buf) return -1;

 char comm[16];
 bpf_get_current_comm(&comm, sizeof(comm));
 __builtin_memcpy(buf, comm, 16);

 // Compute comm's true length (up to 15 chars) + NUL.
 __u32 n = 0;
 #pragma unroll
 for (int i = 0; i < 15; i++) {
 if (comm[i] == 0) break;
 n++;
 }
 n += 1; // n ∈ [1..16]
 *lenp = n;

 // Roll back the unused tail. n ≤ 16 so (16 - n) ≤ 15 and s->len (just
 // advanced by 16 above) can't underflow.
 s->len -= (16 - n);
 return 0;
}

static __always_inline int kl_put_source_if_unknown(struct kl_scratch *s)
{
 __u32 host_pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
 __u8 *seen = bpf_map_lookup_elem(&kl_known_src, &host_pid);
 if (seen) return 0;

 __u8 one = 1;
 bpf_map_update_elem(&kl_known_src, &host_pid, &one, BPF_ANY);

 if (kl_put_comm_bytes(s) < 0) return -1;
 return 1;
}

// kl_put_source_always — unconditional comm emission; used by hooks that
// don't want the LRU dedup (e.g. sched_process_exit, where we definitely
// want the comm even if it was emitted before).
static __always_inline int kl_put_source_always(struct kl_scratch *s)
{
 return kl_put_comm_bytes(s);
}

// ---- argv emitter (ARG_STR_ARR) ------------------------------------------
//
// execve's argv is a const char *const *user-pointer array, NULL-terminated.
// wire format:
// __u32 tag = ARG_STR_ARR
// repeat up to KL_MAX_STR_ARR_ITEMS:
// __u32 tag = ARG_STR
// __u32 len
// bytes + NUL
// __u32 tag = 0 (terminator)
static __always_inline int kl_put_argv(struct kl_scratch *s,
 const char *const *argv)
{
 __u32 *hdr = kl_scratch_reserve(s, 4);
 if (!hdr) return -1;
 *hdr = ARG_STR_ARR;

 #pragma unroll
 for (int i = 0; i < KL_MAX_STR_ARR_ITEMS; i++) {
 const char *ptr = NULL;
 if (bpf_probe_read_user(&ptr, sizeof(ptr), &argv[i]) < 0 || !ptr) {
 break;
 }
 if (kl_put_str_user(s, ARG_STR, ptr) < 0) break;
 }

 __u32 *term = kl_scratch_reserve(s, 4);
 if (!term) return -1;
 *term = 0;
 return 0;
}

// ---- Submit ---------------------------------------------------------------
//
// kl_put_cpu_seq appends ARG_CPU_SEQ + LEB128 u64 without a separate tag
// allocation (the tag is literal 14 instead of ARG_VARINT_U64). Inlined
// into kl_submit_to so every emitted record carries the current CPU's
// monotonic sequence number.
static __always_inline int kl_put_cpu_seq(struct kl_scratch *s, __u64 seq)
{
 __u32 *tagp = kl_scratch_reserve(s, 4);
 if (!tagp) return -1;
 *tagp = ARG_CPU_SEQ;
 #pragma unroll
 for (int i = 0; i < 10; i++) {
 __u8 *bp = kl_scratch_reserve(s, 1);
 if (!bp) return -1;
 __u8 b = seq & 0x7f;
 seq >>= 7;
 if (seq) {
 *bp = b | 0x80;
 } else {
 *bp = b;
 return 0;
 }
 }
 return -1;
}

// kl_submit_crit / kl_submit_bulk copy the assembled scratch bytes into the
// respective ringbuf. bpf_ringbuf_reserve requires a compile-time-constant
// size, which we can't offer for variadic records, so we use the copy
// flavor (bpf_ringbuf_output) — it's a single-call output that accepts a
// runtime-sized payload. The cost is one extra memcpy per event versus
// reserve-and-commit, amortized against the kmem+ringbuf overhead. Returns
// 0 on success, -1 on ringbuf exhaustion.
//
// Every submit appends a per-CPU sequence number as an ARG_CPU_SEQ tag
// right before the ringbuf_output call. Userspace uses the seq to detect
// per-CPU record loss, and a future compact-frame format can reference
// the base seq as its anchor. arg_num is incremented accordingly so the
// decoder reads the extra arg without knowing the hook-specific layout.
//
// `apply_sampling` opts the record into kl_sampling_rate[0] throttling (bulk
// rings do, crit does not — policy-priority events must survive every
// downgrade tier). `drop_slot` is the kl_rb_drops index incremented on
// ringbuf-full — one slot per ring so per-category drop rates are visible.
static __always_inline int kl_submit_to(void *rb, struct kl_scratch *s,
 __u32 drop_slot, int apply_sampling)
{
 __u32 n = s->len;
 // Minimum size depends on whether this is a full or compact frame.
 // Both share event_type at byte 0; compact starts with the compact
 // marker (0x13) and occupies only 16 bytes of header.
 if (n == 0 || n > KL_MAX_RECORD_BYTES) return -1;
 int is_compact = (s->buf[0] == (__u8)EVENT_COMPACT_UNARY);
 __u32 min_size = is_compact ? sizeof(struct compact_event_t)
 : sizeof(struct event_t);
 if (n < min_size) return -1;
 if (apply_sampling) {
 __u32 zero = 0;
 __u32 *rate_p = bpf_map_lookup_elem(&kl_sampling_rate, &zero);
 __u32 rate = rate_p ? *rate_p : 0;
 if (rate == KL_SAMPLE_DROP_ALL) {
 // LevelCriticalOnly: userspace detached the bulk readers; burn no
 // ringbuf bandwidth on records that would go unread. A single
 // sampling knob still throttles all three bulk rings uniformly —
 // per-category rates can come later if a workload shape needs it.
 return 0;
 }
 if (rate >= 2) {
 // Uniform 1/rate keep. bpf_get_prandom_u32 is a per-CPU xorshift
 // that's cheap enough to call per-event; modulo bias at rate ≤ 10
 // is negligible and over 2^32 events the distribution averages out.
 if ((bpf_get_prandom_u32() % rate) != 0) return 0;
 }
 // rate 0 or 1 → pass-through, no sampling.
 }
 // Increment per-CPU seq + append ARG_CPU_SEQ before the output call.
 // Post-sampling so the counter only advances for records that actually
 // ship — userspace sees contiguous seqs without gaps for sampled drops.
 __u32 seq_zero = 0;
 __u64 *seq_p = bpf_map_lookup_elem(&kl_cpu_seq, &seq_zero);
 if (seq_p) {
 *seq_p += 1;
 if (kl_put_cpu_seq(s, *seq_p) == 0) {
 // Bump arg_num to account for the appended ARG_CPU_SEQ.
 // Both full and compact headers carry event_type at byte 0
 // and arg_num at byte 1, so a single byte update covers
 // both without re-reading the cast.
 s->buf[1] = (__u8)(s->buf[1] + 1);
 n = s->len;
 }
 }
 // Verifier hint: the mask caps n at KL_MAX_RECORD_BYTES-1 so the size
 // arg to bpf_ringbuf_output has a known upper bound. kl_scratch_reserve()
 // stops one byte shy of the top (strict `len + n >= MAX` guard) so this
 // mask never silently truncates a real record. The barriers are load-
 // bearing: without them the compiler CSEs the mask against the earlier
 // `n > KL_MAX_RECORD_BYTES` check and the kprobe-strict verifier loses
 // the bound across the inlined `s->len` reload → "R3 unbounded memory
 // access". Mirrors the kl_scratch_reserve idiom.
 kl_barrier_var(n);
 n &= (KL_MAX_RECORD_BYTES - 1);
 kl_barrier_var(n);
 if (n < sizeof(struct event_t)) return -1;
 int rc = (int)bpf_ringbuf_output(rb, &s->buf[0], n, 0);
 if (rc != 0) {
 __u64 *cnt = bpf_map_lookup_elem(&kl_rb_drops, &drop_slot);
 if (cnt) *cnt += 1;
 }
 return rc;
}

#define kl_submit_crit(s) kl_submit_to(&kl_events_crit, (s), KL_RB_DROP_CRIT, 0)
#define kl_submit_bulk_file(s) kl_submit_to(&kl_events_bulk_file, (s), KL_RB_DROP_BULK_FILE, 1)
#define kl_submit_bulk_net(s) kl_submit_to(&kl_events_bulk_net, (s), KL_RB_DROP_BULK_NET, 1)
#define kl_submit_bulk_proc(s) kl_submit_to(&kl_events_bulk_proc, (s), KL_RB_DROP_BULK_PROC, 1)
#define kl_submit_bulk_file_meta(s) kl_submit_to(&kl_events_bulk_file_meta, (s), KL_RB_DROP_BULK_FILE_META, 1)
// DNS / process-lifecycle / socket-lifecycle isolation rings. The
// `sample_bulk` argument is 0 — these are low-volume, high-value streams
// that should never be sampled away under bulk-ring backpressure (the
// adaptive downgrade controller targets only the bulk_* sampling rate).
#define kl_submit_dns(s) kl_submit_to(&kl_events_dns, (s), KL_RB_DROP_DNS, 0)
#define kl_submit_proc_lc(s) kl_submit_to(&kl_events_proc_lc, (s), KL_RB_DROP_PROC_LC, 0)
#define kl_submit_sock_lc(s) kl_submit_to(&kl_events_sock_lc, (s), KL_RB_DROP_SOCK_LC, 0)

// ---- Event coalesce ---------------------------------------
//
// kl_coalesce_check inspects (current tgid, kind, disc) against kl_coalesce.
// Return values:
// 0 → suppress. Caller MUST abort without submitting (the current window
// absorbs this event; its bytes/count roll into the map for the trailer
// that the next emitted event will carry).
// 1 → emit, no trailer. First event in a fresh window (map miss or the
// previous window's only event — nothing to report).
// 2 → emit with trailer. The previous window had suppressed events; their
// stats land in *out_prev_count / *out_prev_bytes, and the caller must
// append them via kl_put_coalesced_trailer (and bump arg_num by 2).
//
// bytes_now is the bytes requested by the current syscall (arg_count for r/w).
// Pass 0 for stat/access where bytes are undefined — the trailer will still
// carry a count but zero bytes.
static __always_inline int kl_coalesce_check(__u32 kind, __u64 disc, __u64 bytes_now,
 __u32 *out_prev_count,
 __u64 *out_prev_bytes)
{
 struct kl_coalesce_key k = {
 .tgid = (__u32)(bpf_get_current_pid_tgid() >> 32),
 .kind = kind,
 .disc = disc,
 };
 __u64 now = bpf_ktime_get_ns();
 *out_prev_count = 0;
 *out_prev_bytes = 0;

 struct kl_coalesce_val *v = bpf_map_lookup_elem(&kl_coalesce, &k);
 if (!v) {
 struct kl_coalesce_val nv = {
 .first_ts = now,
 .bytes = bytes_now,
 .count = 1,
 };
 bpf_map_update_elem(&kl_coalesce, &k, &nv, BPF_ANY);
 return 1;
 }

 __u64 elapsed = now - v->first_ts;
 if (elapsed > KL_COALESCE_WINDOW_NS) {
 // Window closed. Snapshot the old stats, reset for a fresh window.
 // Racy across CPUs but correctness-bounded: worst case two CPUs both
 // emit a trailer and one is a duplicate; total count ≥ actual, bytes
 // ≥ actual. The alternative (cmpxchg on the whole struct) is not
 // available for LRU_HASH values.
 __u32 prev_count = v->count;
 __u64 prev_bytes = v->bytes;
 v->first_ts = now;
 v->count = 1;
 v->bytes = bytes_now;
 if (prev_count > 1) {
 *out_prev_count = prev_count;
 *out_prev_bytes = prev_bytes;
 return 2;
 }
 return 1;
 }

 // Still inside the window: suppress. Bump counters atomically so concurrent
 // hits on other CPUs don't lose increments.
 __sync_fetch_and_add(&v->count, 1);
 __sync_fetch_and_add(&v->bytes, bytes_now);
 return 0;
}

// kl_put_coalesced_trailer appends the two trailer args that describe a
// coalesced window to the current record. Caller must have already bumped
// arg_num by 2 at kl_fill_header time, OR call kl_patch_arg_num afterwards.
static __always_inline int kl_put_coalesced_trailer(struct kl_scratch *s,
 __u32 count, __u64 bytes)
{
 if (kl_put_u32(s, ARG_COALESCED_COUNT, count) < 0) return -1;
 if (kl_put_u64(s, ARG_COALESCED_BYTES, bytes) < 0) return -1;
 return 0;
}

// ---- Namespace filter -----------------------------------------------------
//
// kl_should_monitor returns true if the current task should produce events
// given the ns filter state. Called at the top of every hook; non-monitored
// tasks short-circuit before any scratch work.
//
// Self-exclusion: when kl_self_tgid[0] is non-zero, tasks whose TGID
// matches are dropped. This keeps the kloudlens daemon's own startup
// scan of /sys/kernel/tracing/events (hundreds of opens) and its
// ongoing /proc walks out of the crit ringbuf, which otherwise saturates
// during the first ~1s and drops short-lived workload exec/socket events.
static __always_inline int kl_should_monitor(void)
{
 __u32 zero = 0;
 __u32 *self = bpf_map_lookup_elem(&kl_self_tgid, &zero);
 if (self && *self != 0) {
 __u32 cur_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
 if (cur_tgid == *self) return 0;
 }

 struct task_struct *task = (struct task_struct *)bpf_get_current_task();
 __u32 pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
 __u32 mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
 __u64 key = ((__u64)pid_ns << 32) | (__u64)mnt_ns;

 __u32 *tog = bpf_map_lookup_elem(&kl_ns_toggle, &zero);
 __u32 mode = tog ? *tog : 0;

 __u32 *hit = bpf_map_lookup_elem(&kl_ns_filter, &key);
 if (mode == 1) {
 return hit != NULL; // target mode: only listed pass
 }
 return hit == NULL; // except mode: listed drop, rest pass
}

// ---- sockaddr emission ---------------------------------------------------
//
// kl_put_sockaddr_user() / kl_put_sockaddr_kernel emit a (family, addr, port)
// triple matching the existing wire shape connect/bind use. AF_INET pulls
// addr+port out of sockaddr_in; everything else (AF_UNIX, AF_INET6,
// AF_PACKET, …) emits family + zeroed addr/port — userspace's
// decodeSockAddr already handles those as "non-routable" empty resources.
//
// Two flavours because tracepoints see a userspace pointer (syscall arg)
// while LSM kprobes see a kernel-space pointer (kernel has already copied
// the sockaddr in via copy_from_user). The wire layout is identical.
static __always_inline int kl_put_sockaddr_common(struct kl_scratch *s,
 __u16 family,
 __u32 addr_be, __u16 port_be)
{
 if (kl_put_int(s, (__s32)family) < 0) return -1;
 __u32 addr = 0;
 __u32 port = 0;
 if (family == 2 /* AF_INET */) {
 addr = addr_be;
 // Network → host byte order for port; addr stays as-is because the
 // userspace decoder bytes-extracts in network order (byte 0 = first
 // octet) — see decodeSockAddr in internal/bpf2frame/mapper.go.
 port = (__u32)((port_be >> 8) | ((port_be & 0xff) << 8));
 }
 if (kl_put_uint(s, addr) < 0) return -1;
 if (kl_put_uint(s, port) < 0) return -1;
 return 0;
}

static __always_inline int kl_put_sockaddr_user(struct kl_scratch *s,
 const struct sockaddr *sa)
{
 if (!sa) return kl_put_sockaddr_common(s, 0, 0, 0);
 __u16 family = 0;
 __u32 be_addr = 0;
 __u16 be_port = 0;
 bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);
 if (family == 2 /* AF_INET */) {
 const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
 bpf_probe_read_user(&be_addr, sizeof(be_addr), &in->sin_addr.s_addr);
 bpf_probe_read_user(&be_port, sizeof(be_port), &in->sin_port);
 }
 return kl_put_sockaddr_common(s, family, be_addr, be_port);
}

static __always_inline int kl_put_sockaddr_kernel(struct kl_scratch *s,
 const struct sockaddr *sa)
{
 if (!sa) return kl_put_sockaddr_common(s, 0, 0, 0);
 __u16 family = 0;
 __u32 be_addr = 0;
 __u16 be_port = 0;
 bpf_probe_read_kernel(&family, sizeof(family), &sa->sa_family);
 if (family == 2 /* AF_INET */) {
 const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
 bpf_probe_read_kernel(&be_addr, sizeof(be_addr), &in->sin_addr.s_addr);
 bpf_probe_read_kernel(&be_port, sizeof(be_port), &in->sin_port);
 }
 return kl_put_sockaddr_common(s, family, be_addr, be_port);
}
