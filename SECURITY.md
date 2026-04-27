# Security Policy

## Supported Versions

KloudLens is under active development and has not yet cut a tagged release.
Only the latest commit on the `main` branch receives security fixes.

| Version | Supported |
|---|---|
| Latest `main` | Yes |
| Forks / older commits | No |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by email to **namjh@dankook.ac.kr** with the subject line `[KloudLens Security]`.

Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Your environment (OS, kernel version, BTF status, BPF-LSM status,
 Kubernetes version, commit SHA of KloudLens)
- Affected component (tracer, pairer, enricher, WAL, gRPC surface,
 contract adapter)
- Any suggested mitigations if you have them

We aim to acknowledge reports within 5 business days.

## Disclosure Policy

We follow a coordinated disclosure model. Please allow us reasonable time to address the vulnerability before any public disclosure. We will credit reporters in the release notes unless you prefer to remain anonymous.

## Scope

The following are in scope (report here):

- The KloudLens agent at the repo root, including its eBPF programs
 (`bpf/`, `internal/sensor/bpf/`)
- User-space pairing, enrichment, intent aggregation, session graph,
 baseline, and contract IR (`internal/`, `pkg/`)
- The gRPC API and `.proto` files (`api/`)
- Deployment manifests and the flat manifest (`deployments/`)
- Contract adapters that generate enforcer policies (seccomp, AppArmor,
 KubeArmor, Cilium, Kyverno, OPA/Rego, NetworkPolicy, PodSecurity)

For components that live in their own repositories, report
vulnerabilities there (same email address applies):

- `klctl` CLI: https://github.com/boanlab/kloudlens-cli
- Cluster fan-in: https://github.com/boanlab/kloudlens-aggregator

The following are out of scope:

- Third-party dependencies (report to the upstream project)
- The Linux kernel, eBPF verifier, or LSM frameworks themselves
- Misconfigurations in user-supplied `BehaviorContract` YAML or cluster RBAC
- Issues that require root on the host the agent is already running on
- Downstream enforcer behavior after a generated policy is loaded (report
 to the enforcer project)
