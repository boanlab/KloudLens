// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

//go:build linux && amd64

package sensor

import _ "embed"

//go:embed bpf/kloudlens_x86_bpfel.o
var bpfObjectBytes []byte
