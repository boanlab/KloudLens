// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package main

import (
	pathpkg "path"
	"strings"
	"sync"

	"github.com/boanlab/kloudlens/internal/path"
)

// PathCompleter absolutizes relative file/exec paths captured by BPF before
// they reach the baseline learner, correlation engine, or intent graph.
//
// Background: the BPF program occasionally emits a pathname without
// resolving the containing directory (notably for openat(dirfd, relative)
// on cgroup FDs and for workloads whose cwd the tracer can't chase through
// the dentry cache). Relative entries in the Profile allow-set — e.g.
// `.git/config`, `hugetlb.2MB.current` — leak into every adapter export
// (AppArmor drops non-absolute rules; KubeArmor and seccomp also need
// absolute paths).
//
// PathCompleter does a Go-side pass: absolute paths pass through, relative
// paths are joined with `/proc/<PID>/cwd`, and paths that can't be resolved
// (short-lived PID, cgroup-relative openat) return "" so upstream observers
// short-circuit and the allow-set stays clean. This is a conservative
// filter — we'd rather lose a rule than emit a non-anchored one.
type PathCompleter struct {
	CWD path.ProcessCWD

	mu       sync.Mutex
	resolved uint64
	dropped  uint64
}

// Complete returns the absolute path or "" if a relative input can't be
// reconstructed. Absolute inputs are returned unchanged.
func (c *PathCompleter) Complete(pid int32, raw string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") {
		return raw
	}
	if c == nil || c.CWD == nil {
		c.bumpDropped()
		return ""
	}
	cwd, _, ok := c.CWD.Lookup(pid)
	if !ok || cwd == "" {
		c.bumpDropped()
		return ""
	}
	c.mu.Lock()
	c.resolved++
	c.mu.Unlock()
	return pathpkg.Clean(pathpkg.Join(cwd, raw))
}

func (c *PathCompleter) bumpDropped() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.dropped++
	c.mu.Unlock()
}

// Stats returns (resolved, dropped) counts for periodic logging.
func (c *PathCompleter) Stats() (uint64, uint64) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resolved, c.dropped
}
