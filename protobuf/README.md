# protobuf

Protobuf definitions and generated Go stubs for the KloudLens gRPC
services. The generated source files are committed alongside the
`.proto` and are imported directly by the KloudLens agent
(`kloudlens`), the cluster fan-in (`kloudlens-aggregator`, in its own
repo), and by the `klctl` CLI.

For consuming these streams with `klctl`, see the
[kloudlens-cli repo](https://github.com/boanlab/kloudlens-cli). For the
end-to-end streaming walkthrough, see
[../getting-started/README.md](../getting-started/README.md).

## Layout

This package is its own Go module — the agent (root module) pulls it
in via a local `replace` directive:

```
protobuf/
 event.proto ← schema
 event.pb.go ← generated (committed)
 event_grpc.pb.go ← generated (committed)
 go.mod ← module github.com/boanlab/kloudlens/protobuf
 Makefile ← regenerates the .pb.go files
```

Importers use `"github.com/boanlab/kloudlens/protobuf"` and call sites
read `protobuf.IntentEvent`, `protobuf.EventEnvelope`, etc.

## Services

```protobuf
service IntentExporter {
 rpc Stream(stream IntentEvent) returns (StreamAck);
}

service EventService {
 rpc Subscribe(SubscribeRequest) returns (stream EventEnvelope);
 rpc Ack(AckRequest) returns (AckResponse);
 rpc Snapshot(SnapshotRequest) returns (stream EventEnvelope);
 rpc SubscribeIntents(IntentStreamRequest) returns (stream IntentEvent);
 rpc SubscribeDeviations(DeviationStreamRequest) returns (stream DeviationEvent);
 rpc SubscribeRaw(RawStreamRequest) returns (stream SyscallEvent);
 rpc QueryGraph(GraphQuery) returns (GraphSnapshot);
 rpc SubscribeSession(SessionStreamRequest) returns (stream SessionUpdate);
}

service AdminService {
 rpc GetStatus(Empty) returns (AgentStatus);
 rpc ListPolicies(Empty) returns (PolicyList);
 rpc ApplyPolicy(Policy) returns (ApplyResult);
 rpc DeletePolicy(PolicyRef) returns (DeleteResult);
 rpc Diagnose(Empty) returns (DiagnoseReport);
 rpc GetCapabilities(Empty) returns (CapabilityReport);
 rpc Top(TopRequest) returns (stream TopSnapshot);
 rpc Dump(DumpRequest) returns (stream EventEnvelope);

 rpc BaselineReset(Empty) returns (Empty);
 rpc BaselinePromote(PromoteRequest) returns (PromoteResponse);
 rpc BaselineActivate(ActivateRequest) returns (ActivateResponse);

 rpc GetConfig(Empty) returns (ConfigResponse);
 rpc SetConfig(SetConfigRequest) returns (SetConfigResponse);
}
```

| Service | Role |
|---|---|
| `IntentExporter` | Agent-initiated push of `IntentEvent` to an aggregator. |
| `EventService` | Pull-side subscribe with durable cursor resume. Carries the `EventEnvelope` oneof (intent / deviation / graph edge / lifecycle / audit / raw syscall) plus typed live-only RPCs for each payload. |
| `AdminService` | `klctl` ↔ daemon control plane — status, policy CRUD, capability probe, baseline lifecycle, runtime config. |

## Key message types

| Message | Purpose |
|---|---|
| `IntentEvent` | Aggregated semantic intent (FileOpen, NetworkExchange, ProcessStart, …). Carries `attributes`, `ContainerMeta`, severity, confidence. |
| `DeviationEvent` | Delta from a promoted baseline — scored, with evidence and related intent IDs. |
| `GraphEdge` | Causal Session Graph edge (fork / exec / file-touch / IPC) with session scoping. |
| `SyscallEvent` | Raw enter/exit-paired syscall. Live-only behind `--enable-raw-stream`; use intents for normal workloads. |
| `ContainerLifecycleEvent` | Container created / started / stopped / candidate phase transitions. |
| `AuditEvent` | Agent-internal events (`dropped_after_wal_overflow`, `adaptive_downgrade`, …). |
| `EventEnvelope` | The multiplexed wrapper used by `EventService.Subscribe`. `Cursor` enables durable resume. |
| `ResolvedPath` | Canonical path resolution payload (container-abs + host-abs + fs identity), used for rule matching. |
| `CapabilityReport` | Per-node inventory of LSM, BPF helpers, hooks, fallbacks — populated by the agent, consumed by `klctl caps`. |

See [`event.proto`](event.proto) for the full schema, including
RBAC / filter fields, baseline promote/activate flow, and
runtime-tunable config schema.

## Regenerating the stubs

```bash
make # installs protoc-gen-go / protoc-gen-go-grpc on demand, then regenerates
make clean # removes the generated .pb.go files
```

The generated files are **committed** — CI and ordinary consumers
never need `protoc` installed. Only contributors editing
`event.proto` run `make`, and they commit the regenerated `.pb.go`
alongside the `.proto` change.

`protoc` itself is a system prerequisite; install it via your
package manager (`apt install -y protobuf-compiler`,
`brew install protobuf`, etc.) before running `make`.

## Import path

```go
import "github.com/boanlab/kloudlens/protobuf"
```

## License

Apache License 2.0 — see the [LICENSE](../LICENSE) file for details.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
