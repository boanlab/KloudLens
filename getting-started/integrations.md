# Integrations (Agent Side)

Agent-side integrations: Prometheus scrape of `/metrics`.

For CLI-driven pipelines (`klctl` → Loki / Elasticsearch / OTel logs /
Slack / PagerDuty), see the CLI repo's integrations doc:
[kloudlens-cli/getting-started/integrations.md](https://github.com/boanlab/kloudlens-cli/blob/main/getting-started/integrations.md).

---

## 1. Prometheus + Grafana

`/metrics` lives on `--metrics-addr` (default `:9090`). Any Prometheus
scrape config works.

```yaml
# prometheus/scrape_configs.yaml
- job_name: kloudlens
 kubernetes_sd_configs:
 - role: pod
 relabel_configs:
 - source_labels: [__meta_kubernetes_pod_label_app]
 regex: kloudlens
 action: keep
 - source_labels: [__meta_kubernetes_pod_ip]
 target_label: __address__
 replacement: ${1}:9090
```

Key series to alert on:

| Metric | Alert when | Why |
|---|---|---|
| `kloudlens_ringbuf_lost_total` | rate > 0 | Userspace decode failures (proxy for kernel-side loss) |
| `kloudlens_ringbuf_kernel_lost_total{ring="…"}` | rate > 0 | Per-ring kernel `bpf_ringbuf_output` failures — `ring=` label tells you which category (crit / bulk_file / bulk_net / bulk_proc / dns / proc_lc / sock_lc) |
| `kloudlens_adaptive_level` | > 0 | Adaptive controller dropped low-priority hooks to keep up |
| `kloudlens_wal_overflow_total` | rate > 0 | WAL janitor is trimming segments to honor `--wal-max-bytes` / `--wal-ttl`; subscribers may be falling behind |
| `kloudlens_subscriber_dropped_total` | rate > 0 | At least one subscriber is behind its flow-control window |
| `kloudlens_graph_sessions_active` | trend / absolute | Session cardinality — capacity signal |

---

## 2. Multi-node aggregation

The optional cluster fan-in (`kloudlens-aggregator`) lives in its own
repo: [boanlab/kloudlens-aggregator](https://github.com/boanlab/kloudlens-aggregator).
It subscribes to every node's `EventService` and re-exports a single
merged stream so downstream tools talk to one address instead of N.

---

## 3. gRPC client reference

If you're writing your own consumer (not using `klctl`), the
`EventService` and `AdminService` definitions live in
[`../protobuf/`](../protobuf/). A minimal Go consumer:

```go
cc, _ := grpc.NewClient("kloudlens:8181", grpc.WithTransportCredentials(insecure.NewCredentials))
client := protobuf.NewEventServiceClient(cc)
stream, _ := client.Subscribe(ctx, &protobuf.SubscribeRequest{
 Streams: []string{"intents"},
 Filter: &protobuf.EventFilter{
 Namespaces: []string{"default"},
 Kinds: []string{"FileOpen", "NetworkExchange"},
 },
})
for {
 evt, err := stream.Recv
 if err != nil { break }
 // ...
}
```

Full schema and service catalog in
[`../protobuf/README.md`](../protobuf/README.md).

---

## See also

- [troubleshooting.md](troubleshooting.md) — when metrics look wrong.
- [CLI integrations](https://github.com/boanlab/kloudlens-cli/blob/main/getting-started/integrations.md)
 — Loki / ES / OTel logs / Slack / PagerDuty via `klctl`.
