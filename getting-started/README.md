# KloudLens Agent Quickstart

A 15-minute walk from a fresh cluster to a running KloudLens agent
emitting intents over gRPC and Prometheus metrics. This doc covers the
**agent** only — the `klctl` CLI that consumes the agent's gRPC stream
lives in
[boanlab/kloudlens-cli](https://github.com/boanlab/kloudlens-cli); see
its own quickstart for the CLI-side walkthrough (streaming, baseline,
contract, gap analysis).

## Prerequisites

- Linux kernel 5.4+ with eBPF (6.x recommended). BTF at
 `/sys/kernel/btf/vmlinux` — most distro kernels ship it.
- A Kubernetes cluster whose nodes meet the above. Single-node kubeadm
 is fine; see [`../contribution/k8s/`](../contribution/k8s/) for a
 ready-to-run setup.
- `kubectl` with cluster-admin privileges.

BPF-LSM is **not** required — KloudLens auto-detects and falls back to
`kprobe/security_*` when absent.

## 1. Install the CRDs and the DaemonSet

```bash
kubectl apply -f deployments/crds/
kubectl apply -f deployments/manifests/daemonset.yaml
```

The CRDs introduce four custom resources:

| CRD | What it is |
|---|---|
| `HookSubscription` | Which syscall families / intents a consumer wants |
| `BaselinePolicy` | Learn window + promotion rules for behavioural baselines |
| `BehaviorContract` | Enforcer-neutral IR compiled to seccomp/AppArmor/… |
| `NodeCapabilities` | Per-node LSM / helper / BTF inventory (populated by the agent) |

The DaemonSet manifest creates the `kloudlens` namespace and
deploys the agent there. Wait for it to be Ready:

```bash
kubectl -n kloudlens rollout status ds/kloudlens
kubectl -n kloudlens get pods -o wide
```

## 2. Verify the agent

Without the CLI, probe the agent's HTTP surface:

```bash
kubectl -n kloudlens port-forward ds/kloudlens 9090:9090

curl -s 127.0.0.1:9090/healthz
curl -s 127.0.0.1:9090/readyz
curl -s 127.0.0.1:9090/metrics | grep -E '^kloudlens_(bpf_attached|ringbuf|pair|intent)'
```

Key metric families to confirm a healthy attach:

| Metric | Meaning |
|---|---|
| `kloudlens_bpf_attached_programs` | Count of loaded+attached eBPF programs (non-zero = tracer up) |
| `kloudlens_lsm_mode` | `bpf-lsm` or `kprobe-fallback` (either is healthy) |
| `kloudlens_btf_source` | `/sys/kernel/btf/vmlinux` when present |
| `kloudlens_ringbuf_*` | Ring-buffer sizing, occupancy, drops |
| `kloudlens_intent_emitted_total` | Non-zero once workloads run |

With `klctl` installed (separately — see the
[kloudlens-cli repo](https://github.com/boanlab/kloudlens-cli)):

```bash
kubectl -n kloudlens port-forward ds/kloudlens 8180:8180 8181:8181

klctl status --agent=127.0.0.1:8180
klctl caps --agent=127.0.0.1:8180
klctl stream intents --agent=127.0.0.1:8181
```

## 3. Apply a `HookSubscription`

```yaml
apiVersion: kloudlens.io/v1
kind: HookSubscription
metadata:
 name: default
spec:
 preset: default # one of: minimal, default, full
 # Or, instead of a preset, list the syscalls explicitly:
 # subscribe: [execve, openat, openat2, connect, accept, accept4]
 # exclude: [openat]
```

```bash
kubectl apply -f hooksubscription.yaml
```

Without a subscription the tracer runs in minimal mode (only what the
enricher and WAL need). Pick a `preset` or list `subscribe` syscalls
explicitly.

## 4. Agent flags reference

Selected flags — see `kloudlens --help` for the full list (>40 flags
covering enricher, gRPC export, learn mode, baseline, graph DB,
adaptive downgrade, …).

| Flag | Default | Purpose |
|---|---|---|
| `--subscribe-addr` | *(unset)* | host:port for the `EventService` listener (requires `--wal-dir`); the shipped DaemonSet binds `0.0.0.0:8181` |
| `--admin-addr` | *(unset)* | host:port for the `AdminService` listener; the shipped DaemonSet binds `0.0.0.0:8180` |
| `--metrics-addr` | *(unset)* | host:port for Prometheus `/metrics` + `/healthz` + `/readyz`; the shipped DaemonSet binds `0.0.0.0:9090` |
| `--wal-dir` | *(unset)* | Directory for the intent WAL (empty = no WAL / no subscribe server) |
| `--enrich` | `off` | `off` / `proc` / `cri` / `docker` — pod & container metadata source |
| `--cri-endpoint` | *(unset)* | CRI socket URI (e.g. `unix:///run/containerd/containerd.sock`); empty uses crictl defaults |
| `--except-ns` | *(empty)* | Comma-separated `pidNS:mntNS` keys to skip (ignored if `--target-ns` is set) |
| `--mode` | `monitor` | `monitor` or `learn` — learn writes a `Profile` JSON on shutdown |
| `--no-ebpf` | `false` | Skip the live eBPF loader (pipeline wire-check only — useful for local dev) |

Empty defaults are intentional: the shipped DaemonSet manifest
([`deployments/manifests/daemonset.yaml`](../deployments/manifests/daemonset.yaml))
sets the listener addresses, WAL directory, and enrichment mode
explicitly. Host-binary operators do the same on the command line.

## 5. Deployment modes other than Kubernetes

For host-binary mode and docker-compose mode, see
[docker-mode.md](docker-mode.md).

## Next steps

| Doc | Purpose |
|---|---|
| [docker-mode.md](docker-mode.md) | Host-binary and docker-compose deployment |
| [integrations.md](integrations.md) | Prometheus / OTel scrape config |
| [troubleshooting.md](troubleshooting.md) | Install, attach, and streaming diagnostics |
| [CLI quickstart](https://github.com/boanlab/kloudlens-cli/blob/main/getting-started/README.md) | Drive the agent with `klctl` (streaming, baseline, contracts) |
| [../contribution/README.md](../contribution/README.md) | Agent dev environment & PR process |

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
