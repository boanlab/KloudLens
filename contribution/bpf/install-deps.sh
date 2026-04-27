#!/bin/bash

# update repo
sudo apt-get update

# install dependencies
sudo apt-get install -y build-essential libbpf-dev linux-tools-common linux-tools-generic

# install clang 14
sudo apt-get install -y clang-14
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 140
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-14 140

# install llvm 14
sudo apt-get install -y llvm-14
sudo update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-14 140
sudo update-alternatives --install /usr/bin/llvm-objcopy llvm-objcopy /usr/bin/llvm-objcopy-14 140
sudo update-alternatives --install /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-14 140

# install bpf2go (used by internal/sensor to regenerate Go bindings
# after editing .bpf.c sources). Requires Go on PATH.
go install github.com/cilium/ebpf/cmd/bpf2go@latest
