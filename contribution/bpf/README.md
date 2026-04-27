# BPF Development Dependencies

Installs the tools required to compile KloudLens's eBPF programs.

## What it installs

| Package | Purpose |
|---|---|
| `build-essential` | C compiler and standard build tools |
| `libbpf-dev` | libbpf headers for BPF program development |
| `linux-tools-generic` | `bpftool` for inspecting loaded programs and maps |
| `clang-14` + `llvm-14` | eBPF bytecode compiler and LLVM toolchain |
| `bpf2go` | Cilium's Go code generator for embedding BPF objects |

Clang 14 and LLVM 14 are set as the default alternatives so `make` can find them without extra configuration.

## Usage

```bash
cd contribution/bpf
./install-deps.sh
```

## Requirements

- Ubuntu 22.04 or later (apt-based)
- Go must already be installed (needed for `bpf2go` — run
 `../golang/install-golang.sh` first)
- `sudo` privileges

## After Installation

Verify the toolchain:

```bash
clang --version # should print clang version 14.x
llvm-strip --version
bpftool version
```

Then rebuild the BPF programs:

```bash
make bpf # rebuilds the object under bpf/
 # bpf2go-generated files live under internal/sensor/bpf/
```

The compiled `.o` files under `internal/sensor/bpf/` are
intentionally tracked in git so plain `go build` works on hosts without
clang. Regenerate them only after editing `.bpf.c` sources, and commit
the updated objects.
