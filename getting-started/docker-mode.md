# Docker / Single-Host Mode

KloudLens runs on any Linux host with eBPF support — Kubernetes is not
required. This doc covers agent-side deployment in two non-Kubernetes
modes:

1. **Host-binary mode** — `kloudlens` run directly on the host.
2. **docker-compose mode** — agent + OpenTelemetry collector packaged
 under [`../deployments/docker/`](../deployments/docker/).

Driving the agent with `klctl` (streaming, baseline, contracts) is
documented in the CLI repo:
[kloudlens-cli/getting-started/docker-mode.md](https://github.com/boanlab/kloudlens-cli/blob/main/getting-started/docker-mode.md).

Both modes produce the same event surface (gRPC `EventService` +
`AdminService`, `/metrics`, WAL-backed durable subscribe). The only
thing missing compared to the DaemonSet is the Kubernetes-sourced
enrichment (namespace, labels, ownerRef); container-ID and image-ID
enrichment via containerd still works.

---

## 1. Host-binary mode

### Prerequisites

- Linux kernel 5.4+ with eBPF, BTF at `/sys/kernel/btf/vmlinux`
- Containerd running with its CRI socket at
 `/run/containerd/containerd.sock` (see
 [`../contribution/containerd/`](../contribution/containerd/)). Skip
 this if you only want host-level tracing with no container enrichment.
- `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN` + `CAP_SYS_RESOURCE`, or
 simply run as root.

### Run

```bash
sudo ./bin/kloudlens \
 --enrich=cri \
 --cri-endpoint=unix:///run/containerd/containerd.sock \
 --wal-dir=/var/lib/kloudlens/wal \
 --subscribe-addr=127.0.0.1:8181 \
 --admin-addr=127.0.0.1:8180 \
 --metrics-addr=127.0.0.1:9090
```

Flag summary:

| Flag | Purpose |
|---|---|
| `--enrich` | `off` / `proc` / `cri` / `docker` — `cri` adds pod & namespace labels via the containerd socket |
| `--cri-endpoint` | CRI socket URI; required when `--enrich=cri` and the socket is at a non-default path |
| `--wal-dir` | Durable log directory; required for cursor-resume subscribe |
| `--subscribe-addr` | gRPC `EventService` listen address (the CLI defaults to `:8181` on this end) |
| `--admin-addr` | gRPC `AdminService` listen address (the CLI defaults to `:8180`) |
| `--metrics-addr` | Prometheus `/metrics` + `/healthz` + `/readyz` listen address |

### Verify

```bash
curl -s 127.0.0.1:9090/healthz
curl -s 127.0.0.1:9090/metrics | grep kloudlens_bpf_attached_programs
```

---

## 2. docker-compose mode

The compose file under [`../deployments/docker/`](../deployments/docker/)
runs `kloudlens` with the right privileges and an OpenTelemetry
collector preconfigured to pick up `/metrics` and forward events. The
optional cluster fan-in lives in its own repo:
[boanlab/kloudlens-aggregator](https://github.com/boanlab/kloudlens-aggregator).

### Run

```bash
cd deployments/docker
docker compose up -d
```

The compose file mounts:

- `/sys/fs/bpf` (rw) — BPF map pin directory
- `/sys/kernel/debug` (ro) — tracefs / kprobe targets
- `/run/containerd/containerd.sock` (ro) — containerd CRI
- A named volume for the WAL

The agent requires `cap_add: [BPF, PERFMON, SYS_ADMIN, SYS_RESOURCE]`
and `pid: host` to see host PIDs. Those are set in the compose file; do
not remove them.

### Verify

```bash
docker compose ps
curl -s 127.0.0.1:9090/metrics | head
```

OpenTelemetry output is configured in
[`../deployments/docker/otel-config.yaml`](../deployments/docker/otel-config.yaml).
Edit the `exporters:` block to point at your collector, Loki, or
observability backend.

---

## 3. Upgrading

- Host-binary: stop `kloudlens`, replace the binary, restart with the
 same flags. The WAL is forward-compatible — cursors survive agent
 restarts.
- docker-compose: bump the image tag in `docker-compose.yaml`,
 `docker compose pull`, `docker compose up -d`.

---

## 4. When to move to Kubernetes mode

Move to the DaemonSet when any of the following becomes true:

- You need Kubernetes-sourced enrichment (namespace, labels, ownerRef).
- You want the CRD-driven control plane
 (`HookSubscription`, `BaselinePolicy`, `BehaviorContract`) so contract
 updates ride normal `kubectl apply` flows.
- You want multi-node aggregation. The cluster fan-in
 ([boanlab/kloudlens-aggregator](https://github.com/boanlab/kloudlens-aggregator))
 ships as its own Deployment.

For the CRD layout and the daemonset manifest, see
[`../deployments/crds/`](../deployments/crds/) and
[`../deployments/manifests/daemonset.yaml`](../deployments/manifests/daemonset.yaml).

---

See [troubleshooting.md](troubleshooting.md) for symptom-indexed
diagnostics that apply to both single-host modes.
