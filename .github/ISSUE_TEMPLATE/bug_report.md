---
name: Bug report
about: Create a report to help us improve the KloudLens agent
title: '[BUG] '
labels: bug
assignees: ''
---

> Bugs in the `klctl` CLI belong in
> [boanlab/kloudlens-cli](https://github.com/boanlab/kloudlens-cli/issues).
> Bugs in the cluster fan-in belong in
> [boanlab/kloudlens-aggregator](https://github.com/boanlab/kloudlens-aggregator/issues).
> This template is for the on-node agent (`kloudlens`, eBPF programs,
> gRPC wire format).

## Bug Description
<!-- A clear and concise description of what the bug is -->

## Environment
- OS: [e.g. Ubuntu 22.04]
- Kernel: [e.g. 6.8.0-45-generic]
- BTF available: [yes / no — `ls /sys/kernel/btf/vmlinux`]
- BPF-LSM active: [yes / no — `cat /sys/kernel/security/lsm`]
- Kubernetes version: [e.g. v1.29.0, or N/A for host-only]
- Container runtime: [e.g. containerd v1.7.x]
- KloudLens agent version: [commit SHA or tag]
- Deployment mode: [DaemonSet / host binary / docker-compose]

## Steps to Reproduce
1.
2.
3.

## Expected Behavior

## Actual Behavior

## Logs
<!-- Attach `kloudlens` stderr and relevant /metrics excerpts
 (ring-buffer drops, adaptive-downgrade level, WAL overflow,
 subscriber backlog). -->

## Additional Context
<!-- Which subsystem you suspect (tracer / pairer / enricher /
 aggregator / WAL / gRPC / contract), reproduction frequency,
 whether it reproduces under
 `KLOUDLENS_LIVE_SENSOR=1 go test ./internal/sensor/...`, etc. -->

## Possible Solution

## Checklist
- [ ] I have searched the existing issues
- [ ] I have provided all required environment information
- [ ] I have included relevant logs or metrics
- [ ] I have tested with the latest `main`
