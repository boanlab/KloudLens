---
name: Feature request
about: Suggest an idea for the KloudLens agent
title: '[FEATURE] '
labels: enhancement
assignees: ''
---

> Feature requests for the `klctl` CLI belong in
> [boanlab/kloudlens-cli](https://github.com/boanlab/kloudlens-cli/issues).
> Feature requests for the cluster fan-in belong in
> [boanlab/kloudlens-aggregator](https://github.com/boanlab/kloudlens-aggregator/issues).
> This template is for the on-node agent (`kloudlens`, eBPF programs,
> gRPC wire format).

## Problem Statement
<!-- Describe the problem you're trying to solve -->

## Proposed Solution
<!-- Describe your proposed solution -->

## Use Cases
<!-- Describe specific use cases for this feature -->
1.
2.
3.

## Affected Subsystems
- [ ] eBPF tracer (`internal/sensor/`)
- [ ] Syscall pairing / semantic intent (`internal/pairer/`, `pkg/intent/`)
- [ ] Enricher / pod & process metadata (`internal/enricher/`)
- [ ] Causal session graph (`pkg/graph/`)
- [ ] Behavioural baseline (`pkg/baseline/`)
- [ ] BehaviorContract IR / adapters (`pkg/contract/`)
- [ ] gRPC API / protobuf (`api/`)
- [ ] WAL / durable subscribe
- [ ] Deployments / flat manifest (`deployments/`)
- [ ] Observability (`/metrics`, `/healthz`, `/readyz`)

## CLI-side dependency

- [ ] Self-contained (agent only)
- [ ] Needs a matching change in `kloudlens-cli`: <!-- link -->

## Alternatives Considered

## Implementation Details

## Additional Context

## Checklist
- [ ] I have searched the existing issues
- [ ] I have provided a clear problem statement
- [ ] I have described the proposed solution
- [ ] I have included use cases
- [ ] I have considered alternatives
