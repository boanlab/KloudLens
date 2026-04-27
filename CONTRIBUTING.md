# Contributing to KloudLens

Thank you for your interest in contributing to the KloudLens agent.

> The `klctl` CLI lives in its own repo:
> [boanlab/kloudlens-cli](https://github.com/boanlab/kloudlens-cli),
> and the cluster fan-in lives in
> [boanlab/kloudlens-aggregator](https://github.com/boanlab/kloudlens-aggregator).
> Contribute changes to those components in their own repos. This guide
> covers the on-node agent (`kloudlens`, eBPF programs, gRPC wire
> format) only.

This document is a quick entry point. The full guide — including
environment setup, build instructions, commit conventions, and PR
requirements — lives in **[contribution/README.md](contribution/README.md)**.

## Quick Start

```bash
# 1. Fork and clone
git clone https://github.com/your-username/KloudLens.git
cd KloudLens

git remote add upstream https://github.com/boanlab/KloudLens.git

# 2. Set up the dev environment
cd contribution/golang && ./install-golang.sh
cd ../bpf && ./install-deps.sh
cd ../containerd && ./install-containerd.sh
cd ../k8s && ./install-kubeadm.sh && ./initialize-kubeadm.sh && CNI=flannel ./deploy-cni.sh

# 3. Build the agent
cd ../../KloudLens
make

# 4. Create a branch and work
git checkout -b fix/your-bug # or feature/your-feature
```

Install Docker (`contribution/docker/install-docker.sh`) additionally if you need to build the container image. See the [full guide](contribution/README.md) for details.

## Before Submitting a PR

Each Go module runs its checks independently; the commands are documented in [contribution/README.md § Implement and Test](contribution/README.md#3-implement-and-test).

Commit messages follow the `<type>(<scope>): <subject>` convention (e.g. `feat(sensor): add connect-exit pairing`). PRs require linked issues and at least two approvals. See the [full guide](contribution/README.md#commit-message-convention) for the complete rules.

## Where to Start

| What | Where |
|---|---|
| Open issues | [GitHub Issues](https://github.com/boanlab/KloudLens/issues) |
| Good first issues | [`good-first-issue` label](https://github.com/boanlab/KloudLens/issues?q=label%3Agood-first-issue) |
| Full contribution guide | [contribution/README.md](contribution/README.md) |
| `klctl` CLI changes | [boanlab/kloudlens-cli](https://github.com/boanlab/kloudlens-cli) |
| Security vulnerabilities | [SECURITY.md](SECURITY.md) |

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
