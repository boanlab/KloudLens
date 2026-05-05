// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 BoanLab @ DKU
//
// dns.bpf.c — DNS response parser. Hooks cgroup_skb/ingress at the
// cgroupv2 unified hierarchy root, parses incoming UDP packets with
// src port 53 as DNS responses, and emits one KL_PSEUDO_DNS_ANSWER
// event per A record found. The output (qname + IP) feeds the Cilium
// adapter's toFQDNs synthesis: without this stream the adapter can
// only produce IP-only egress rules.
//
// bpf_skb_cgroup_id supplies the receiving socket's cgroup, which
// the userspace enricher maps back to pod metadata (current_task is
// unreliable in softirq context).
//
// Programs:
// cgroup_skb/ingress (kl_dns_cgroup_ingress())
//
// Wire shape per emitted event (KL_PSEUDO_DNS_ANSWER):
// ARG_RESOURCE(qname, dotted form e.g. "example.com")
// ARG_UINT(rtype = 1 for A; AAAA / CNAME deferred)
// ARG_UINT(addr_be — network-byte-order IPv4 like the connect/bind path)
// ARG_ULONG(cgroup_id — bpf_skb_cgroup_id, used by the enricher to
// attribute the answer to the receiving pod)
//
// Unlike the syscall-tracepoint emitters this path does not stamp
// ARG_SOURCE(comm): the comm dedup key is bpf_get_current_pid_tgid,
// which is unavailable in cgroup_skb context. Userspace consumers
// reconstruct the receiving process via the cgroup_id field instead.
//
// Parser scope:
// - Only DNS responses (QR bit set in header flags).
// - Only the FIRST question's qname; multi-question responses are vanishingly
// rare in practice.
// - Question name parsing handles uncompressed labels (no pointers — the
// question section never contains pointers per RFC 1035 §4.1.4).
// - Answer name accepts the common shape `0xc0 0x0c` (compression pointer
// to the question name at offset 12). Other compression patterns bail.
// - Up to KL_DNS_MAX_ANSWERS answers walked; A-record IPs emitted,
// AAAA / CNAME / others skipped via RDLENGTH.
#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "wire.bpf.h"
#include "maps.bpf.h"
#include "helpers.bpf.h"
#include "ids.bpf.h"

#define KL_DNS_HEADER_LEN 12
// Semantic cap on the qname we expose downstream (NUL-terminated). Distinct
// from the per-CPU scratch sizing in maps.bpf.h: KL_DNS_QNAME_WRITE bounds
// the verifier-visible offset range; this one bounds the value we surface.
#define KL_DNS_MAX_QNAME 127
#define KL_DNS_MAX_LABEL 63 // RFC 1035 §3.1
// Per-iteration verifier state in the qname/answer walks compounds with
// the outer answer loop, so both bounds are kept small to stay inside the
// 1M-instruction budget on Linux 6.x. 4 labels covers the typical FQDN
// shape; 2 answers covers the typical A-record response.
#define KL_DNS_MAX_LABELS 4
#define KL_DNS_MAX_ANSWERS 2
#define KL_DNS_QTYPE_A 1
#define KL_DNS_QTYPE_AAAA 28

// ---- DNS parser helpers --------------------------------------------------
//
// Read 16-bit big-endian word at buf[idx..idx+1]. Caller must have already
// bounds-checked idx+1 < buflen. We use explicit masking so the verifier
// accepts the array access without re-deriving bounds across calls.
static __always_inline __u16 kl_dns_be16(const __u8 *buf, __u32 idx)
{
 __u32 i0 = idx & (KL_DNS_BUF_SIZE - 1);
 __u32 i1 = (idx + 1) & (KL_DNS_BUF_SIZE - 1);
 return ((__u16)buf[i0] << 8) | buf[i1];
}

// Walk the qname starting at buf[idx]. Writes a dotted form into the
// per-CPU kl_dns_qname_scratch map (left-aligned), NUL-terminated, max
// KL_DNS_MAX_QNAME bytes. Returns the new buffer position past the qname
// or 0 on parse failure / oversize. *outlen is set to the byte count
// including the NUL.
//
// __noinline keeps the loop's verifier state contained in this function;
// inlined, each iteration would expand into the caller and exceed the
// 1M-instruction budget.
//
// Destination is a per-CPU map, not the BPF stack: Linux 6.x strict
// verifier rejects variable-offset stack writes once the masked offset's
// tnum isn't a clean power-of-two. Map values accept
// `(masked offset) + (masked size) ≤ buffer_len`, and the oversized
// physical buffer (KL_DNS_QNAME_BUF_LEN=256 vs KL_DNS_QNAME_WRITE=128)
// gives the verifier the headroom it needs.
static __noinline __u32 kl_dns_parse_qname(const __u8 *buf, __u32 buflen,
 __u32 idx, struct kl_dns_qname_buf *out,
 __u32 *outlen)
{
 __u32 j = idx;
 __u32 oj = 0;

 for (int i = 0; i < KL_DNS_MAX_LABELS; i++) {
 kl_barrier_var(j);
 if (j >= buflen) return 0;
 __u8 first = buf[j & (KL_DNS_BUF_SIZE - 1)];
 if (first == 0) {
 j++;
 // NUL-terminate the dotted name (replace the trailing '.' if any).
 if (oj > 0) oj--; // strip last '.'
 __u32 oj_idx = oj & (KL_DNS_QNAME_WRITE - 1);
 out->buf[oj_idx] = 0;
 *outlen = oj + 1; // include NUL
 return j;
 }
 // Compression pointer in the question section is illegal per RFC; if
 // we see one we bail. (Answer-side parser handles pointers separately
 // because answers commonly back-reference the question name.)
 if ((first & 0xc0) != 0) return 0;
 if (first > KL_DNS_MAX_LABEL) return 0;
 j++;
 if (j + first > buflen) return 0;
 if (oj + first >= KL_DNS_QNAME_WRITE - 1) return 0;

 // One bpf_probe_read_kernel per label. Verifier sees a single
 // bounded copy regardless of `first` — keeps cross-iteration state
 // small. Masks: dst into [0, KL_DNS_QNAME_WRITE) (=[0,128)),
 // size into [0, 64). Sum ≤ 128 + 63 = 191 < 256 buffer.
 __u32 copy_len = first;
 kl_barrier_var(copy_len);
 copy_len &= (KL_DNS_MAX_LABEL); // mask 63 — clean power-of-2-1
 if (copy_len == 0) copy_len = 1;
 kl_barrier_var(copy_len);
 __u32 src = j & (KL_DNS_BUF_SIZE - 1);
 __u32 dst = oj & (KL_DNS_QNAME_WRITE - 1);
 bpf_probe_read_kernel(&out->buf[dst], copy_len, &buf[src]);

 oj += first;
 // Append separator '.'; we strip the trailing one when we hit the
 // root label (length 0) above.
 __u32 sep_idx = oj & (KL_DNS_QNAME_WRITE - 1);
 out->buf[sep_idx] = '.';
 oj++;
 j += first;
 }
 return 0;
}

// Skip the answer's NAME field. Returns the new idx, or 0 on bail.
// Compressed pointers (top 2 bits = 11) are 2 bytes; uncompressed names
// are walked label-by-label terminated by 0x00. We accept either shape.
//
// __noinline for the same reason as kl_dns_parse_qname — the loop's
// verifier state stays inside this function so the caller's answer walk
// doesn't multiply iteration cost across both loops at once.
static __noinline __u32 kl_dns_skip_name(const __u8 *buf, __u32 buflen,
 __u32 idx)
{
 __u32 j = idx;

 for (int i = 0; i < KL_DNS_MAX_LABELS; i++) {
 kl_barrier_var(j);
 if (j >= buflen) return 0;
 __u8 first = buf[j & (KL_DNS_BUF_SIZE - 1)];
 if ((first & 0xc0) == 0xc0) {
 // 2-byte pointer; skip and we're done.
 return j + 2;
 }
 if (first == 0) return j + 1;
 if (first > KL_DNS_MAX_LABEL) return 0;
 j += 1 + first;
 }
 return 0;
}

// Emit one DNS answer event. Caller hands in the qname (dotted, NUL-term),
// the rtype, a network-byte-order IPv4 address, and the cgroup_id of the
// receiving socket (from bpf_skb_cgroup_id). The cgroup_id lets userspace
// map the event to a pod even when the standard event_t header's
// pid_ns_id / mnt_ns_id are bogus (cgroup_skb runs in softirq context
// where bpf_get_current_task is whatever happens to be on the CPU).
static __always_inline int kl_dns_emit_answer(const __u8 *qname, __u32 qname_len,
 __u32 rtype, __u32 addr_be,
 __u64 cgroup_id)
{
 if (qname_len <= 1) return 0; // empty / root only
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 // arg_num = 5 nominal: ARG_RESOURCE(qname) + ARG_UINT(rtype)
 // + ARG_UINT(addr_be) + ARG_ULONG(cgroup_id) + ARG_SOURCE(comm).
 // The wire record carries 4 args: ARG_RESOURCE(qname) + ARG_UINT(rtype)
 // + ARG_UINT(addr_be) + ARG_ULONG(cgroup_id). We start the header at 5
 // (the value that includes ARG_SOURCE) for shape parity with the regular
 // tracepoint emitters; kl_put_source_skb is a no-op in this context, so
 // the kl_patch_arg_num call below shrinks the stamped count to 4 before
 // the record is submitted.
 if (kl_fill_header_skb(s, KL_PSEUDO_DNS_ANSWER, EVENT_UNARY, 5, cgroup_id) < 0) return 0;

 int wrote_src = kl_put_source_skb(s);
 if (wrote_src < 0) return 0;

 // ARG_RESOURCE: the qname bytes. We hand-roll the tag/length/bytes write
 // because qname is in kernel-side scratch, not pointed at by a syscall arg
 // — kl_put_str_user()/kernel both expect a probe-readable pointer.
 __u32 *tagp = kl_scratch_reserve(s, 4);
 if (!tagp) return 0;
 *tagp = ARG_RESOURCE;
 __u32 *lenp = kl_scratch_reserve(s, 4);
 if (!lenp) return 0;
 // Cap qname_len for the verifier; KL_DNS_MAX_QNAME is the actual bound.
 __u32 ql = qname_len;
 kl_barrier_var(ql);
 if (ql > KL_DNS_MAX_QNAME) ql = KL_DNS_MAX_QNAME;
 kl_barrier_var(ql);
 *lenp = ql;
 void *qbuf = kl_scratch_reserve(s, KL_DNS_MAX_QNAME);
 if (!qbuf) return 0;
 // bpf_probe_read_kernel rather than a hand-rolled byte loop: clang would
 // lower a byte-by-byte copy to an unsupported memcpy intrinsic on BPF
 // target. qname lives in kernel-side per-CPU map memory, qbuf points
 // into the per-CPU scratch (also kernel memory) — kernel-to-kernel.
 __u32 cl = ql;
 kl_barrier_var(cl);
 cl &= (KL_DNS_MAX_QNAME - 1);
 kl_barrier_var(cl);
 if (cl > 0) {
 bpf_probe_read_kernel(qbuf, cl, qname);
 }
 // Roll back unused tail of the reservation.
 s->len -= (KL_DNS_MAX_QNAME - ql);

 if (kl_put_uint(s, rtype) < 0) return 0;
 if (kl_put_uint(s, addr_be) < 0) return 0;
 if (kl_put_ulong(s, cgroup_id) < 0) return 0;

 // arg_num 4 instead of 5 when source is deduped: ARG_RESOURCE +
 // ARG_UINT(rtype) + ARG_UINT(addr_be) + ARG_ULONG(cgroup_id).
 if (wrote_src == 0) kl_patch_arg_num(s, 4);
 return kl_submit_dns(s);
}

// ---- DNS response parser (shared by skb hooks) ---------------------------
//
// Operates on the per-CPU dns scratch buf already loaded from the network
// packet. Walks the question name, then up to KL_DNS_MAX_ANSWERS answer
// records; emits one DNS_ANSWER event per A record. Caller must have
// validated dns_len >= KL_DNS_HEADER_LEN.
//
// `cgroup_id` is the receiving socket's cgroup ID (from
// bpf_skb_cgroup_id) — passed through to emit_answer so userspace can
// resolve to a pod regardless of the bogus softirq-time task header.
static __always_inline void kl_dns_parse_response(const __u8 *buf, __u32 buflen,
 struct kl_dns_qname_buf *qname,
 __u64 cgroup_id)
{
 // DNS header: ID(2) | flags(2) | QDCOUNT(2) | ANCOUNT(2) | NSCOUNT(2) | ARCOUNT(2)
 __u16 flags = kl_dns_be16(buf, 2);
 __u16 qdcnt = kl_dns_be16(buf, 4);
 __u16 ancnt = kl_dns_be16(buf, 6);

 // Must be a response (QR bit) with at least one question and one answer.
 if ((flags & 0x8000) == 0) return;
 if (qdcnt == 0 || ancnt == 0) return;

 __u32 qname_len = 0;
 __u32 idx = KL_DNS_HEADER_LEN;
 idx = kl_dns_parse_qname(buf, buflen, idx, qname, &qname_len);
 if (idx == 0) return;

 // Skip QTYPE(2) + QCLASS(2).
 if (idx + 4 > buflen) return;
 idx += 4;

 // Walk answer RRs.
 for (int i = 0; i < KL_DNS_MAX_ANSWERS; i++) {
 if (idx >= buflen) break;
 if ((__u32)i >= ancnt) break;

 idx = kl_dns_skip_name(buf, buflen, idx);
 if (idx == 0) break;
 if (idx + 10 > buflen) break; // TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2)

 __u16 rtype = kl_dns_be16(buf, idx);
 idx += 2;
 idx += 2; // skip CLASS
 idx += 4; // skip TTL
 __u16 rdlen = kl_dns_be16(buf, idx);
 idx += 2;
 if (idx + rdlen > buflen) break;

 if (rtype == KL_DNS_QTYPE_A && rdlen == 4) {
 // IPv4 in network byte order; matches the connect/bind shape —
 // userspace bytes-extracts in host order so byte 0 = first octet.
 __u32 i0 = idx & (KL_DNS_BUF_SIZE - 1);
 __u32 i1 = (idx + 1) & (KL_DNS_BUF_SIZE - 1);
 __u32 i2 = (idx + 2) & (KL_DNS_BUF_SIZE - 1);
 __u32 i3 = (idx + 3) & (KL_DNS_BUF_SIZE - 1);
 __u32 addr_be = ((__u32)buf[i0]) |
 ((__u32)buf[i1] << 8) |
 ((__u32)buf[i2] << 16) |
 ((__u32)buf[i3] << 24);
 (void)kl_dns_emit_answer(qname->buf, qname_len, KL_DNS_QTYPE_A, addr_be, cgroup_id);
 }
 // AAAA / CNAME / others: skip over RDATA without emitting (deferred).
 idx += rdlen;
 }
}

// ---- cgroup_skb/ingress — parse incoming UDP DNS responses ---------------
//
// Filters: IPv4, UDP, source port 53. Reads the DNS payload via
// bpf_skb_load_bytes; cgroup_skb runs in skb context so user-pointer
// reads aren't available. Always returns 1 (PASS) — observation-only.
SEC("cgroup_skb/ingress")
int kl_dns_cgroup_ingress(struct __sk_buff *skb)
{
 void *data = (void *)(long)skb->data;
 void *data_end = (void *)(long)skb->data_end;

 // IPv4 header — minimum 20 bytes.
 struct iphdr *ip = data;
 if ((void *)(ip + 1) > data_end) return 1;
 if (ip->version != 4) return 1;
 if (ip->protocol != IPPROTO_UDP) return 1;

 __u32 ihl = ip->ihl * 4;
 if (ihl < sizeof(struct iphdr)) return 1;

 struct udphdr *udp = (void *)ip + ihl;
 if ((void *)(udp + 1) > data_end) return 1;

 // DNS responses come from src port 53.
 __u16 sport = bpf_ntohs(udp->source);
 if (sport != 53) return 1;

 __u16 udp_len = bpf_ntohs(udp->len);
 if (udp_len <= sizeof(struct udphdr) + KL_DNS_HEADER_LEN) return 1;
 __u32 dns_len = (__u32)(udp_len - sizeof(struct udphdr));
 if (dns_len > KL_DNS_BUF_SIZE) dns_len = KL_DNS_BUF_SIZE;
 __u32 dns_off = ihl + sizeof(struct udphdr);

 __u32 zero = 0;
 struct kl_dns_buf *dbuf = bpf_map_lookup_elem(&kl_dns_scratch, &zero);
 if (!dbuf) return 1;
 struct kl_dns_qname_buf *qname = bpf_map_lookup_elem(&kl_dns_qname_scratch, &zero);
 if (!qname) return 1;

 // Load the DNS payload from the packet into the per-CPU scratch.
 if (bpf_skb_load_bytes(skb, dns_off, dbuf->bytes, dns_len) < 0) return 1;

 // Capture the receiving socket's cgroup ID — stable identifier for the
 // pod even though current_task isn't reliably the receiver in softirq.
 __u64 cgroup_id = bpf_skb_cgroup_id(skb);
 kl_dns_parse_response(dbuf->bytes, dns_len, qname, cgroup_id);
 return 1;
}
