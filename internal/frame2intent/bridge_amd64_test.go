// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

//go:build amd64

package frame2intent

import (
	"testing"

	"github.com/boanlab/kloudlens/internal/bpf2frame"
	"github.com/boanlab/kloudlens/internal/syscalls"
)

// Plain open(2) carries no dirfd argument — it's a single absolute/relative
// path with the cwd implicit. The *at variants are exercised separately.
func TestBridgeDirfdFromArgsPlainOpen(t *testing.T) {
	se := bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysOpen, RetVal: 5},
		[]any{"/etc/hosts", int32(0), uint32(0), "/bin/cat"},
	)
	if _, ok := DirfdFromArgs(se); ok {
		t.Fatalf("plain open should have no dirfd arg")
	}
}
