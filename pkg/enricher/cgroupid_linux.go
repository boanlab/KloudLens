// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

//go:build linux

package enricher

import (
	"io/fs"
	"syscall"
)

// sysStatT pulls the inode from a fs.FileInfo's underlying syscall.Stat_t.
// Cgroupv2 exposes a directory per cgroup, and the cgroup's kernel ID
// equals that directory's inode number — so a Walk + Stat is the whole
// cache build.
func sysStatT(info fs.FileInfo) (struct{ Ino uint64 }, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return struct{ Ino uint64 }{}, false
	}
	return struct{ Ino uint64 }{Ino: st.Ino}, true
}
