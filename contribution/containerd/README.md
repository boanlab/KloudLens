# Containerd Installation

Installs `containerd.io` from the official Docker repository and configures it for use with Kubernetes (systemd cgroup driver).

## What it does

1. Adds the Docker APT repository and GPG key
2. Installs `containerd.io`
3. Generates `/etc/containerd/config.toml` via `containerd config default`
4. Sets `SystemdCgroup = true` (required for Kubernetes with systemd)
5. Restarts the containerd service

## Usage

```bash
cd contribution/containerd
./install-containerd.sh
```

## Requirements

- Ubuntu 22.04 or later
- `sudo` privileges
- Internet access

## After Installation

```bash
systemctl status containerd # should be active (running)
```

## Why KloudLens needs it

The KloudLens enricher subscribes to containerd's CRI events to attach
pod / container / image metadata to raw syscall events. A containerd
socket is therefore required at runtime on every node the agent runs on
(`/run/containerd/containerd.sock` by default). In Kubernetes
deployments the DaemonSet mounts this socket read-only; in host-mode
the binary opens it directly.

## Note

This installs containerd as a standalone container runtime. If you also
need the full Docker CLI (for building images, or for KloudLens's
Docker-mode host deployments), use `../docker/install-docker.sh` instead
— it installs `docker-ce` on top of containerd.
