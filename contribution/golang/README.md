# Go Installation

Installs Go 1.24.0 for the current user.

## What it does

1. Downloads `go1.24.0.linux-amd64.tar.gz` from `dl.google.com`
2. Extracts it to `/usr/local/go`
3. Appends `GOROOT`, `GOPATH`, and `PATH` entries to `~/.bashrc`
4. Creates `~/go/` as the Go workspace

## Usage

```bash
cd contribution/golang
./install-golang.sh
source ~/.bashrc
```

## Requirements

- Ubuntu / Debian (uses `apt`)
- `sudo` privileges
- Internet access

## After Installation

```bash
go version # should print go1.24.0 linux/amd64
```

## Note

This script always installs Go 1.24.0 to match the version declared
in this repo's `go.mod`. To install a different version, edit the
`goBinary` variable at the top of `install-golang.sh`.
