# Docker Installation

Installs Docker CE from the official Docker repository.

## What it does

1. Adds the Docker APT repository and GPG key
2. Installs `docker-ce`
3. Writes `/etc/docker/daemon.json` with:
 - `cgroupdriver=systemd`
 - JSON log driver with 100 MB log rotation
 - `overlay2` storage driver
4. Restarts Docker and adds the current user to the `docker` group

## Usage

```bash
cd contribution/docker
./install-docker.sh
```

## Requirements

- Ubuntu 22.04 or later
- `sudo` privileges
- Internet access

## After Installation

```bash
docker version
docker run --rm hello-world
```

## Why KloudLens needs it

Docker is **only** required for two local workflows:

1. Building the agent container image — `make build-image` from the
 repo root. The CLI image lives in its own repo (`kloudlens-cli`).
2. Running the single-host docker-compose deployment under
 `deployments/docker/`.

For production Kubernetes nodes that only run the agent, containerd
alone is sufficient — use `../containerd/install-containerd.sh` instead.
