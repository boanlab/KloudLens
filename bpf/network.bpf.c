// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 BoanLab @ DKU
//
// network.bpf.c — socket / connect / bind / listen / accept / shutdown +
// sendmsg/recvmsg-class hooks. Includes the new security_socket_* LSM
// kprobes that mirror the file-LSM coverage on the network side. Included
// by kloudlens.bpf.c; not compiled standalone.
//
// Programs:
// tp/syscalls/sys_{enter,exit}_socket
// tp/syscalls/sys_{enter,exit}_connect
// tp/syscalls/sys_{enter,exit}_bind
// tp/syscalls/sys_{enter,exit}_listen
// tp/syscalls/sys_{enter,exit}_accept
// tp/syscalls/sys_{enter,exit}_accept4
// tp/syscalls/sys_{enter,exit}_sendmsg / recvmsg / sendmmsg / recvmmsg
// tp/syscalls/sys_{enter,exit}_shutdown
// kprobe/security_socket_connect
// kprobe/security_socket_bind
// kprobe/security_socket_sendmsg
// kprobe/security_socket_recvmsg
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
// socket — enter: domain + type + protocol + source
// ============================================================================

SEC("tp/syscalls/sys_enter_socket")
int kl_socket_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SOCKET, EVENT_ENTER, 4) < 0) return 0;

 __s32 domain = (__s32)ctx->args[0];
 __s32 type = (__s32)ctx->args[1];
 __s32 protocol = (__s32)ctx->args[2];

 if (kl_put_int(s, domain) < 0) return 0;
 if (kl_put_int(s, type) < 0) return 0;
 if (kl_put_int(s, protocol) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);

 return kl_submit_bulk_net(s);
}

SEC("tp/syscalls/sys_exit_socket")
int kl_socket_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SOCKET, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_net(s);
}

// ============================================================================
// connect — enter: fd + family + addr + port + source
// ============================================================================
//
// connect(2)'s second arg is a struct sockaddr *; we peek at sa_family, then
// for AF_INET dig out sin_addr + sin_port. For AF_UNIX/AF_INET6 we emit
// family=X and skip addr/port (mapper's decodeSockAddr will render them as
// empty resource strings).

SEC("tp/syscalls/sys_enter_connect")
int kl_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;

 // Base arg_num = 5: fd, family, addr, port, source. Bumped to 6 when
 // the listener registry knows the destination (adds peer_pid), patched
 // down as usual when the source tag is deduped.
 if (kl_fill_header(s, KL_SYS_CONNECT, EVENT_ENTER, 5) < 0) return 0;

 __s32 fd = (__s32)ctx->args[0];
 if (kl_put_int(s, fd) < 0) return 0;

 const struct sockaddr *sa = (const struct sockaddr *)ctx->args[1];
 __u16 family = 0;
 bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);

 if (kl_put_int(s, (__s32)family) < 0) return 0;

 __u32 addr_le = 0;
 __u32 port = 0;
 if (family == 2 /* AF_INET */) {
 const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
 __u32 be_addr = 0;
 __u16 be_port = 0;
 bpf_probe_read_user(&be_addr, sizeof(be_addr), &in->sin_addr.s_addr);
 bpf_probe_read_user(&be_port, sizeof(be_port), &in->sin_port);
 addr_le = be_addr;
 port = (__u32)((be_port >> 8) | ((be_port & 0xff) << 8));
 }

 if (kl_put_uint(s, addr_le) < 0) return 0;
 if (kl_put_uint(s, port) < 0) return 0;

 // Listener registry lookup — a hit means another task on this node is
 // bound to (addr, port). Emit peer_pid as a 6th arg so userspace can
 // resolve the pid to its ContainerID directly.
 int has_peer = 0;
 __u32 peer_pid = 0;
 if (family == 2) {
 __u64 key = ((__u64)addr_le << 32) | (__u64)port;
 struct ipc_listener_val *hit = bpf_map_lookup_elem(&kl_ipc_listener, &key);
 if (hit && hit->pid != 0) {
 peer_pid = hit->pid;
 has_peer = 1;
 }
 }
 if (has_peer) {
 if (kl_put_uint(s, peer_pid) < 0) return 0;
 } else {
 kl_patch_arg_num(s, 4);
 }

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) {
 kl_patch_arg_num(s, has_peer ? 5 : 4);
 } else if (has_peer) {
 kl_patch_arg_num(s, 6);
 }

 return kl_submit_sock_lc(s);
}

SEC("tp/syscalls/sys_exit_connect")
int kl_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_CONNECT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_sock_lc(s);
}

// ============================================================================
// bind / listen / accept / accept4
// ============================================================================
//
// bind shares connect's sockaddr decode. listen / accept / accept4 carry only
// fd / flag args — peer info on accept's retval is attached by userspace.

SEC("tp/syscalls/sys_enter_bind")
int kl_bind_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_BIND, EVENT_ENTER, 5) < 0) return 0;

 __s32 fd = (__s32)ctx->args[0];
 if (kl_put_int(s, fd) < 0) return 0;

 const struct sockaddr *sa = (const struct sockaddr *)ctx->args[1];
 __u16 family = 0;
 bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);
 if (kl_put_int(s, (__s32)family) < 0) return 0;

 __u32 addr_le = 0;
 __u32 port = 0;
 if (family == 2 /* AF_INET */) {
 const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
 __u32 be_addr = 0;
 __u16 be_port = 0;
 bpf_probe_read_user(&be_addr, sizeof(be_addr), &in->sin_addr.s_addr);
 bpf_probe_read_user(&be_port, sizeof(be_port), &in->sin_port);
 addr_le = be_addr;
 port = (__u32)((be_port >> 8) | ((be_port & 0xff) << 8));

 // Stash context for bind exit; commit to listener registry on success.
 __u64 pid_tid = bpf_get_current_pid_tgid();
 struct ipc_bind_ctx ctx_val = {
 .family = family,
 .addr = addr_le,
 .port = port,
 };
 bpf_map_update_elem(&kl_ipc_pending_bind, &pid_tid, &ctx_val, BPF_ANY);
 }
 if (kl_put_uint(s, addr_le) < 0) return 0;
 if (kl_put_uint(s, port) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 4);

 return kl_submit_sock_lc(s);
}

SEC("tp/syscalls/sys_exit_bind")
int kl_bind_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;

 __s32 ret = (__s32)ctx->ret;
 __u64 pid_tid = bpf_get_current_pid_tgid();
 struct ipc_bind_ctx *bc = bpf_map_lookup_elem(&kl_ipc_pending_bind, &pid_tid);
 if (bc && ret == 0 && bc->family == 2) {
 __u64 key = ((__u64)bc->addr << 32) | (__u64)bc->port;
 struct ipc_listener_val val = {
 .pid = (__u32)(pid_tid >> 32),
 .ts_sec = (__u32)(bpf_ktime_get_ns() >> 30),
 };
 bpf_map_update_elem(&kl_ipc_listener, &key, &val, BPF_ANY);
 }
 if (bc) bpf_map_delete_elem(&kl_ipc_pending_bind, &pid_tid);

 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_BIND, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_sock_lc(s);
}

SEC("tp/syscalls/sys_enter_listen")
int kl_listen_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_LISTEN, EVENT_ENTER, 3) < 0) return 0;

 __s32 fd = (__s32)ctx->args[0];
 __s32 backlog = (__s32)ctx->args[1];
 if (kl_put_int(s, fd) < 0) return 0;
 if (kl_put_int(s, backlog) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);

 return kl_submit_sock_lc(s);
}

SEC("tp/syscalls/sys_exit_listen")
int kl_listen_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_LISTEN, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_sock_lc(s);
}

SEC("tp/syscalls/sys_enter_accept")
int kl_accept_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_ACCEPT, EVENT_ENTER, 2) < 0) return 0;

 __s32 fd = (__s32)ctx->args[0];
 if (kl_put_int(s, fd) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 1);

 return kl_submit_sock_lc(s);
}

SEC("tp/syscalls/sys_exit_accept")
int kl_accept_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_ACCEPT, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_sock_lc(s);
}

SEC("tp/syscalls/sys_enter_accept4")
int kl_accept4_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_ACCEPT4, EVENT_ENTER, 3) < 0) return 0;

 __s32 fd = (__s32)ctx->args[0];
 __s32 flags = (__s32)ctx->args[3];
 if (kl_put_int(s, fd) < 0) return 0;
 if (kl_put_int(s, flags) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);

 return kl_submit_sock_lc(s);
}

SEC("tp/syscalls/sys_exit_accept4")
int kl_accept4_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_ACCEPT4, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_sock_lc(s);
}

// ============================================================================
// Socket message I/O — sendmsg / recvmsg / sendmmsg / recvmmsg / shutdown
// ============================================================================

SEC("tp/syscalls/sys_enter_sendmsg")
int kl_sendmsg_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SENDMSG, EVENT_ENTER, 3) < 0) return 0;
 __s32 fd = (__s32)ctx->args[0];
 __s32 flags = (__s32)ctx->args[2];
 if (kl_put_int(s, fd) < 0) return 0;
 if (kl_put_int(s, flags) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 return kl_submit_bulk_net(s);
}

SEC("tp/syscalls/sys_exit_sendmsg")
int kl_sendmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SENDMSG, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_net(s);
}

SEC("tp/syscalls/sys_enter_recvmsg")
int kl_recvmsg_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_RECVMSG, EVENT_ENTER, 3) < 0) return 0;
 __s32 fd = (__s32)ctx->args[0];
 __s32 flags = (__s32)ctx->args[2];
 if (kl_put_int(s, fd) < 0) return 0;
 if (kl_put_int(s, flags) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 return kl_submit_bulk_net(s);
}

SEC("tp/syscalls/sys_exit_recvmsg")
int kl_recvmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_RECVMSG, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_net(s);
}

SEC("tp/syscalls/sys_enter_sendmmsg")
int kl_sendmmsg_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SENDMMSG, EVENT_ENTER, 4) < 0) return 0;
 __s32 fd = (__s32)ctx->args[0];
 __u32 vlen = (__u32)ctx->args[2];
 __s32 flags = (__s32)ctx->args[3];
 if (kl_put_int(s, fd) < 0) return 0;
 if (kl_put_uint(s, vlen) < 0) return 0;
 if (kl_put_int(s, flags) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 return kl_submit_bulk_net(s);
}

SEC("tp/syscalls/sys_exit_sendmmsg")
int kl_sendmmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SENDMMSG, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_net(s);
}

SEC("tp/syscalls/sys_enter_recvmmsg")
int kl_recvmmsg_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_RECVMMSG, EVENT_ENTER, 4) < 0) return 0;
 __s32 fd = (__s32)ctx->args[0];
 __u32 vlen = (__u32)ctx->args[2];
 __s32 flags = (__s32)ctx->args[3];
 if (kl_put_int(s, fd) < 0) return 0;
 if (kl_put_uint(s, vlen) < 0) return 0;
 if (kl_put_int(s, flags) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 return kl_submit_bulk_net(s);
}

SEC("tp/syscalls/sys_exit_recvmmsg")
int kl_recvmmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_RECVMMSG, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_bulk_net(s);
}

SEC("tp/syscalls/sys_enter_shutdown")
int kl_shutdown_enter(struct trace_event_raw_sys_enter *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SHUTDOWN, EVENT_ENTER, 3) < 0) return 0;
 __s32 fd = (__s32)ctx->args[0];
 __s32 how = (__s32)ctx->args[1];
 if (kl_put_int(s, fd) < 0) return 0;
 if (kl_put_int(s, how) < 0) return 0;
 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;
 if (wrote_src == 0) kl_patch_arg_num(s, 2);
 return kl_submit_sock_lc(s);
}

SEC("tp/syscalls/sys_exit_shutdown")
int kl_shutdown_exit(struct trace_event_raw_sys_exit *ctx)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_SYS_SHUTDOWN, EVENT_EXIT, 0) < 0) return 0;
 kl_set_retval(s, (__s32)ctx->ret);
 return kl_submit_sock_lc(s);
}

// ============================================================================
// LSM hooks for socket — pre-check visibility symmetric to file LSM coverage
// ============================================================================
//
// security_socket_{connect,bind} fire after the kernel has copied sockaddr in
// from userspace, so the address pointer is kernel-side. They catch denied
// connects/binds (netfilter, SELinux, ...) that the syscall return code
// alone wouldn't reveal as a "policy-relevant attempt".
//
// security_socket_{sendmsg,recvmsg} sit on the message I/O path and see the
// destination address in msghdr->msg_name (kernel pointer) — this is where
// connectionless protocols (UDP/SCTP) actually pin a peer. For TCP the
// msg_name is usually NULL because the socket is already connected; we
// emit family=0 in that case and userspace ignores the address fields.

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(kl_kp_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SEC_SOCK_CONNECT, EVENT_UNARY, 4) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;

 if (kl_put_sockaddr_kernel(s, address) < 0) return 0;

 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 (void)kl_submit_sock_lc(s);
 return 0;
}

SEC("kprobe/security_socket_bind")
int BPF_KPROBE(kl_kp_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SEC_SOCK_BIND, EVENT_UNARY, 4) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;

 if (kl_put_sockaddr_kernel(s, address) < 0) return 0;

 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 (void)kl_submit_sock_lc(s);
 return 0;
}

// security_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
// — msg->msg_name carries the destination sockaddr for connectionless sends.
// We pull it via CO-RE so kernel layout drift is handled.
SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(kl_kp_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SEC_SOCK_SENDMSG, EVENT_UNARY, 4) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;

 struct sockaddr *name = NULL;
 if (msg) {
 name = (struct sockaddr *)BPF_CORE_READ(msg, msg_name);
 }
 if (kl_put_sockaddr_kernel(s, name) < 0) return 0;

 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 (void)kl_submit_bulk_net(s);
 return 0;
}

SEC("kprobe/security_socket_recvmsg")
int BPF_KPROBE(kl_kp_socket_recvmsg, struct socket *sock, struct msghdr *msg, int size, int flags)
{
 if (!kl_should_monitor()) return 0;
 struct kl_scratch *s = kl_scratch_get();
 if (!s) return 0;
 if (kl_fill_header(s, KL_PSEUDO_SEC_SOCK_RECVMSG, EVENT_UNARY, 4) < 0) return 0;

 int wrote_src = kl_put_source_if_unknown(s);
 if (wrote_src < 0) return 0;

 struct sockaddr *name = NULL;
 if (msg) {
 name = (struct sockaddr *)BPF_CORE_READ(msg, msg_name);
 }
 if (kl_put_sockaddr_kernel(s, name) < 0) return 0;

 if (wrote_src == 0) kl_patch_arg_num(s, 3);
 (void)kl_submit_bulk_net(s);
 return 0;
}
