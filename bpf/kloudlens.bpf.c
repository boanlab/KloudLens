// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 BoanLab @ DKU
//
// kloudlens.bpf.c — umbrella TU for the KloudLens sensor.
//
// Per-feature SEC program bodies live in separate `<feature>.bpf.c` files:
//
// process.bpf.c — execve / execveat / exit_group (proc_lc ring) +
// kill / tgkill / ptrace / prctl / mmap / mprotect
// namespace.bpf.c — clone / unshare / setns / chroot / mount
// file_io.bpf.c — open / close / filp_close / read / write / stat
// file_meta.bpf.c — unlink / rename / mkdir / chmod / chown / mount
// families (bulk_file_meta ring)
// network.bpf.c — socket / sendmsg / recvmsg families (bulk_net) +
// connect / bind / listen / accept / shutdown +
// security_socket_{connect,bind} (sock_lc ring)
// creds.bpf.c — setuid / setgid / capset / cap_capable
// dns.bpf.c — cgroup_skb DNS response parser (dns ring)
// raw.bpf.c — raw_syscalls fallback (bulk_proc ring)
//
// They are textually included here so the BPF backend emits a single CO-RE
// object with one ELF section per program; no symbol linking is required.
// The shared headers (wire / maps / helpers / ids) carry #pragma once so
// the per-feature files can also #include them without duplication when an
// IDE or static-analysis tool opens them in isolation.
//
// Verifier notes:
// - All hook bodies bail within the first ~10 lines on any failure so the
// verifier doesn't have to unify long paths.
// - Scratch-buffer writes go through kl_scratch_reserve which clamps to
// KL_MAX_RECORD_BYTES; the verifier accepts the pattern directly.
// - BPF_CORE_READ walks in kl_fill_header dereference nsproxy, which is
// NULL for exiting tasks. The helpers tolerate it via BPF_CORE_READ's
// implicit probe-read.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "wire.bpf.h"
#include "maps.bpf.h"
#include "helpers.bpf.h"
#include "ids.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#include "process.bpf.c"
#include "namespace.bpf.c"
#include "file_io.bpf.c"
#include "file_meta.bpf.c"
#include "network.bpf.c"
#include "creds.bpf.c"
#include "dns.bpf.c"
#include "raw.bpf.c"
