# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University
#
# KloudLens BPF build. Produces a CO-RE-enabled object the Go loader embeds.
# Runs the same way in CI and on developer hosts — the only external
# requirements are clang ≥ 10 and llvm-strip on $PATH.
#
# Usage:
#     make                  # build + install the amd64 object
#     make clean            # remove generated artifacts
#     make vmlinux          # regenerate vmlinux.h from the running kernel
#
# vmlinux.h is checked in so builds don't require /sys/kernel/btf/vmlinux at
# compile time. CO-RE relocation handles arch-specific struct layouts at
# load time.

CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool

OUT_DIR    := ../internal/sensor/bpf

# cilium/ebpf's bpf2go convention: <name>_<arch><endianness>.o.
AMD64_OBJ  := $(OUT_DIR)/kloudlens_x86_bpfel.o

SRC        := kloudlens.bpf.c
# Per-feature TUs are included by the umbrella SRC, not compiled standalone.
# Listing them as deps so any change rebuilds the object.
FEATURES   := process.bpf.c namespace.bpf.c file_io.bpf.c file_meta.bpf.c \
              network.bpf.c creds.bpf.c dns.bpf.c raw.bpf.c
HEADERS    := wire.bpf.h maps.bpf.h helpers.bpf.h ids.bpf.h vmlinux.h

CFLAGS_COMMON := \
    -O2 -g -Wall -Werror \
    -target bpf \
    -I. \
    -fno-stack-protector

.PHONY: all
all: amd64

.PHONY: amd64
amd64: $(AMD64_OBJ)

$(AMD64_OBJ): $(SRC) $(FEATURES) $(HEADERS) | $(OUT_DIR)
	@echo "  CLANG   $@ (amd64)"
	$(CLANG) $(CFLAGS_COMMON) -D__TARGET_ARCH_x86 -c $< -o $@.tmp
	@echo "  STRIP   $@"
	$(LLVM_STRIP) -g $@.tmp -o $@
	@rm -f $@.tmp

$(OUT_DIR):
	mkdir -p $@

.PHONY: clean
clean:
	rm -f $(AMD64_OBJ) $(AMD64_OBJ).tmp

# Maintainer target — regenerates the checked-in vmlinux.h from the current
# host's kernel BTF. Requires bpftool + /sys/kernel/btf/vmlinux.
.PHONY: vmlinux
vmlinux:
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
	    echo "ERROR: /sys/kernel/btf/vmlinux missing — kernel not built with CONFIG_DEBUG_INFO_BTF"; \
	    exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo "  DUMP    vmlinux.h ($$(wc -l < vmlinux.h) lines)"
