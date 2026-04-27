// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

//go:build !linux

package enricher

import "io/fs"

// sysStatT stub for non-Linux build hosts (CI/dev mac). Returns false so
// the cgroup walker degrades to no-op — KloudLens only runs on Linux in
// production but the package needs to build cross-platform for tests.
func sysStatT(info fs.FileInfo) (struct{ Ino uint64 }, bool) {
	_ = info
	return struct{ Ino uint64 }{}, false
}
