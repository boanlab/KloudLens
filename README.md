# KloudLens

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.24%2B-blue.svg)](https://golang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-supported-green.svg)](https://ebpf.io/)

KloudLens is an eBPF-based runtime visibility platform for Kubernetes.
It observes every container from birth to exit by pairing syscall
enter/exit into semantic events, enriching them with pod and process
metadata, and exposing the stream over gRPC.

Beyond raw syscall tracing, KloudLens offers four higher-level
capabilities that operators can consume directly:

- **Semantic Intent Aggregation** — individual syscalls are folded into
 higher-level intents (FileOpen, NetworkExchange, ProcessStart, …) so
 downstream consumers reason about behaviour, not opcodes.
- **Causal Session Graph** — process lineage and cross-container edges
 (fork/exec/file-touch/IPC) are materialised as a graph and queryable
 by session.
- **Behavioural Baseline** — a learner observes a workload for a
 window, snapshots a `Profile`, and a detector emits only the
 deviations from that baseline.
- **Behavioural Contract IR + Gap Analysis** — an enforcer-neutral YAML
 IR compiles to seccomp, AppArmor, KubeArmor, Cilium network policy,
 Kyverno, OPA/Rego, Kubernetes NetworkPolicy, and PodSecurity. Gap
 analysis compares an observed profile against an existing policy to
 surface unused allowances and observed-but-denied actions.

This repo builds the agent (`kloudlens`). The optional cluster fan-in
(`kloudlens-aggregator`) lives in its own repo:
[boanlab/kloudlens-aggregator](https://github.com/boanlab/kloudlens-aggregator).
The operator CLI, `klctl`, lives in
[boanlab/kloudlens-cli](https://github.com/boanlab/kloudlens-cli).

KloudLens supports three deployment modes:

| Mode | Container source | Control plane |
|---|---|---|
| `kubernetes` (default) | containerd CRI + K8s API | 4 CRDs (`HookSubscription`, `BaselinePolicy`, `BehaviorContract`, `NodeCapabilities`) |
| `docker` | containerd CRI | local YAML directory / docker-compose |
| `host` | containerd CRI (optional) | CLI flags only (no CRDs) |

---

## Documentation

New to KloudLens? Start here:

| Doc | Purpose |
|---|---|
| [getting-started/README.md](getting-started/README.md) | 15-minute Kubernetes quickstart for the agent |
| [getting-started/docker-mode.md](getting-started/docker-mode.md) | Host-binary and docker-compose deployment of the agent |
| [getting-started/integrations.md](getting-started/integrations.md) | Prometheus / OTel / metrics wire-up |
| [getting-started/troubleshooting.md](getting-started/troubleshooting.md) | Symptom-indexed diagnostics for install & attach |
| [contribution/README.md](contribution/README.md) | Agent development environment & contribution guide |

For CLI usage, detection recipes, integration pipelines, and the
`BehaviorContract` PR workflow, see the CLI repo's own `getting-started/`:
[boanlab/kloudlens-cli](https://github.com/boanlab/kloudlens-cli).

## Components

| Component | Location |
|---|---|
| `kloudlens` (agent) | [`cmd/kloudlens/`](cmd/kloudlens/) — node DaemonSet; eBPF tracing + intent/graph/baseline/contract pipeline |
| `kloudlens-aggregator` | https://github.com/boanlab/kloudlens-aggregator — multi-node fan-in + re-export |
| `klctl` (CLI) | https://github.com/boanlab/kloudlens-cli |
| gRPC wire format | [`protobuf/`](protobuf/) — `EventService` / `AdminService` / `IntentExporter` `.proto` files and the generated Go stubs |
| Manifests | [`deployments/`](deployments/) — CRDs, DaemonSet, docker-compose |

## Requirements

- Linux kernel 5.4+ with eBPF support (BTF recommended; BPF-LSM
 optional — KloudLens falls back to `kprobe/security_*` when absent)
- Go 1.24+ (build only)
- Clang / LLVM 14+ (only when rebuilding BPF sources)
- `CAP_BPF` + `CAP_PERFMON` (DaemonSet) or root (host binary)

---

## Quick Deploy (Kubernetes)

### Prerequisites

- Kubernetes cluster with containerd runtime
- Linux kernel 5.4+ on every node with BTF at `/sys/kernel/btf/vmlinux`
- `kubectl` with cluster-admin privileges

### Install

```bash
git clone https://github.com/boanlab/KloudLens.git
cd KloudLens

kubectl apply -f deployments/crds/ # 4 CRDs
kubectl apply -f deployments/manifests/daemonset.yaml # DaemonSet + RBAC + ConfigMap
```

For the docker-compose / host-binary install paths, see
[getting-started/docker-mode.md](getting-started/docker-mode.md).

### Verify

```bash
kubectl get pods -n kloudlens -o wide
kubectl -n kloudlens port-forward ds/kloudlens 9090:9090
curl -s 127.0.0.1:9090/healthz
curl -s 127.0.0.1:9090/metrics | head
```

If you have `klctl` installed
([kloudlens-cli](https://github.com/boanlab/kloudlens-cli)),
`klctl status --agent=127.0.0.1:8180` and `klctl caps` give a
higher-level view.

---

## Streaming Events

`kloudlens` ships two gRPC listeners — `--admin-addr` (klctl control
plane) and `--subscribe-addr` (event subscribe). The shipped DaemonSet
binds them on `:8180` and `:8181`; the host-binary defaults are
empty (you supply the address explicitly). The aggregator fan-ins
every node onto a single merged stream.

```bash
kubectl port-forward -n kloudlens daemonset/kloudlens 8180:8180 8181:8181
```

Any gRPC client speaking the services defined in
[`protobuf/`](protobuf/) can subscribe. For an
out-of-the-box consumer with intent / deviation / baseline / contract
workflows, use [`klctl`](https://github.com/boanlab/kloudlens-cli):

```bash
klctl stream intents --agent=127.0.0.1:8181
klctl stream deviations --agent=127.0.0.1:8181
klctl get events --follow --agent=127.0.0.1:8181
```

See [getting-started/integrations.md](getting-started/integrations.md)
for Prometheus scrape config and OTel wire-up, and
[`protobuf/README.md`](protobuf/README.md) for the
raw message definitions.

---

## Observability

`kloudlens` exposes `/metrics` (Prometheus), `/healthz`, and `/readyz`.
Key series include ring-buffer usage and drops, adaptive-downgrade
level, WAL overflow, subscriber backlog, per-sink export counters, and
graph/session gauges.

See [getting-started/integrations.md](getting-started/integrations.md)
for scrape config and the alert shortlist.

---

## Architecture

```
syscall tracepoints + security_* kprobes + fentry/filp_close + cgroup_skb
 → eight category ring buffers
 (crit | bulk_file | bulk_net | bulk_proc | bulk_file_meta | dns | proc_lc | sock_lc)
 → user-space pair / decode / enrich / aggregate
 → intent + graph + deviation streams
 → WAL + gRPC (EventService + AdminService) + Prometheus
```

Per-package map and feature matrix: [contribution/README.md](contribution/README.md#codebase-map).

---

## Development

See [contribution/README.md](contribution/README.md) for the development
environment, build instructions, and contribution guidelines.

```bash
make build test # gofmt + golangci-lint + gosec + build + test (from repo root)
```

Live eBPF smoke tests (require root + a supported kernel):

```bash
KLOUDLENS_LIVE_SENSOR=1 go test -race ./internal/sensor/...
```

## License

The user-space agent (everything under the repo root except
`bpf/kloudlens.bpf.c`) is licensed under the **Apache License 2.0** —
see [LICENSE](LICENSE).

The kernel-space BPF program at `bpf/kloudlens.bpf.c` is
licensed under **GPL-2.0** because it links against GPL-only kernel
helpers (the standard BPF licensing constraint). The BPF headers it
includes (`*.bpf.h`) are dual-licensed as
`(GPL-2.0-only OR Apache-2.0)` so they remain reusable from the
user-space side as well.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
