# Troubleshooting (Agent Side)

Symptom-indexed diagnostics for the agent — install, attach, and
streaming issues visible via `/metrics` and the agent logs.

For CLI-side problems (`klctl` cannot connect, streaming is quiet on
the client side, contract simulation failures), see the CLI repo's
troubleshooting doc:
[kloudlens-cli/getting-started/troubleshooting.md](https://github.com/boanlab/kloudlens-cli/blob/main/getting-started/troubleshooting.md).

---

## Install and attach

### The agent pod is `CrashLoopBackOff` immediately after apply

```bash
kubectl -n kloudlens logs ds/kloudlens --previous
```

Common causes:

| Log line fragment | Cause | Fix |
|---|---|---|
| `failed to load BPF object: no BTF available` | Kernel has no `/sys/kernel/btf/vmlinux` | Upgrade kernel or install the matching `kernel-debuginfo` / `linux-image-*-dbg` package |
| `CAP_BPF required` | SecurityContext missing capabilities | Apply the DaemonSet manifest as shipped — do not trim capabilities |
| `failed to attach lsm/...: operation not supported` | BPF-LSM not in the active LSM list | Expected on many distros — the agent auto-falls-back to `kprobe/security_*`. Persistent crash means the kprobe path also failed — check `CONFIG_KPROBES` |
| `open /run/containerd/containerd.sock: no such file` | Containerd not installed or at a non-default path | Install via `contribution/containerd/install-containerd.sh`, or pass `--cri-endpoint=unix:///path/to/containerd.sock` |

### `/metrics` reports `bpf-lsm: false` — is that a problem?

No. KloudLens treats BPF-LSM as *optional* and prefers
`kprobe/security_*` on hosts where `bpf` is not in
`/sys/kernel/security/lsm`. The set of covered security hooks is
equivalent.

### Ring buffer reports a much smaller size than expected

The kernel couldn't allocate the requested contiguous buffer and the
agent fell back to a smaller allocation. Free up kernel memory and
restart the DaemonSet pod. Expect
`kloudlens_ringbuf_kernel_lost_total{ring="…"}` to be non-zero on
the affected ring while the buffer is small.

---

## Streaming

### Consumers report empty streams

Agent-side pipeline walk — the `/metrics` surface is the source of
truth:

```bash
curl -s <agent>:9090/metrics | grep -E 'ringbuf|pair|intent|subscriber'
```

| Where it breaks | Metric signal |
|---|---|
| Tracer is not attached | `kloudlens_bpf_attached_programs` is 0 |
| Tracer fires but pairer drops | `kloudlens_pair_drops_total` climbing |
| Pairer OK but intent stage empty | `kloudlens_intent_emitted_total` is 0 — likely no matching `HookSubscription` |
| Subscriber is filtered out | `kloudlens_subscriber_filtered_total` climbing on the consumer side |

### Ring-buffer drops are growing

- Tighten `HookSubscription` to the syscall families you actually need.
- Accept adaptive downgrade: the agent will automatically drop
 low-priority hooks when `adaptive_downgrade_level` goes up. That is
 the designed-in pressure relief valve, not an error.
- If the host genuinely cannot keep up, lower hook density rather than
 ring-buffer size — drops at the kernel boundary cannot be recovered
 later in the pipeline.

### WAL overflow

Subscribers have fallen behind the WAL retention window. Tune
`--wal-max-bytes` / `--wal-ttl` (the agent flags), or have the
consumer skip ahead to `tail` and accept the gap.

### The aggregator reports all upstream nodes as unhealthy

The cluster fan-in lives in
[boanlab/kloudlens-aggregator](https://github.com/boanlab/kloudlens-aggregator).
If only some nodes are unhealthy from the aggregator's view,
port-forward to one and repeat the upstream section above on that node
to confirm the agent itself is healthy.

---

## Performance

### `kloudlens_pair_drops_total` growing

Enter/exit correlation buffer is under pressure. Reduce the set of
syscalls under `HookSubscription` — narrower hooks are the only
sustainable fix. Track `kloudlens_pair_table_occupancy` — if it is
near the limit, the syscall mix is too broad; if it is low and drops
are still happening, the issue is upstream (ring-buffer drops at the
kernel boundary).

### CPU use of `kloudlens` climbs over time

Almost always the enricher cache growing without bound. Check
`kloudlens_enricher_cache_entries` — if it grows linearly with time,
you have a pod/container leak in enrichment. Confirm by restarting the
agent; CPU should fall back. File a bug with the reproducer.

---

## Getting help

1. Collect the agent's logs and `/metrics` snapshot:
 ```bash
 kubectl -n kloudlens logs ds/kloudlens --all-containers > agent.log
 curl -s <agent>:9090/metrics > agent.metrics
 ```
2. Search existing issues: https://github.com/boanlab/KloudLens/issues
3. Open a new issue with the `bug_report` template and attach both
 files.

For security-sensitive reports, see [`../SECURITY.md`](../SECURITY.md)
— do not open a public issue.
