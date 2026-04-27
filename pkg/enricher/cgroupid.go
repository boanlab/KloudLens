// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package enricher

import (
	"io/fs"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/boanlab/kloudlens/pkg/types"
)

// CgroupIDIndex maps kernel cgroup IDs (cgroup directory inode) to the
// cgroup path under /sys/fs/cgroup. cgroup_skb BPF programs expose the
// receiving socket's cgroup via bpf_skb_cgroup_id, giving us a stable
// pod attribution channel that doesn't depend on bpf_get_current_task —
// crucial for softirq-context hooks where current_task is whichever task
// happened to be on CPU when the packet was processed.
//
// Refresh strategy mirrors NSMap: a periodic walker rebuilds the cache,
// plus a lazy on-miss rescan in Lookup so new containers are picked up
// between scheduled rebuilds. The walker is cheap on a single node
// (typical k8s host has < 1k cgroup directories).
type CgroupIDIndex struct {
	mu sync.RWMutex
	// id → cgroup-relative path (e.g. "kubepods.slice/.../cri-containerd-XXX.scope")
	byID map[uint64]string
	// stats
	hits   atomic.Uint64
	misses atomic.Uint64
	// root is the cgroupv2 mount we walk. Defaults to /sys/fs/cgroup;
	// production sets it to whatever the agent has bind-mounted.
	root string
}

// NewCgroupIDIndex builds an empty index rooted at the given cgroupv2
// mount. Caller must invoke Rescan at least once before lookups will
// resolve — the enricher Bootstrap path does this synchronously.
func NewCgroupIDIndex(root string) *CgroupIDIndex {
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	return &CgroupIDIndex{
		byID: map[uint64]string{},
		root: root,
	}
}

// Rescan walks the cgroupv2 hierarchy and rebuilds the inode → path map.
// Replaces the table atomically so concurrent Lookups see either the old
// or the new snapshot, never a partial write. Errors from filepath.Walk()
// (typically permission on transient cgroups under teardown) are
// swallowed — best-effort scan is the right policy for an observation
// sensor.
func (c *CgroupIDIndex) Rescan() {
	next := map[uint64]string{}
	rootLen := len(c.root)
	_ = filepath.WalkDir(c.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable subtree but keep walking siblings.
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		stat, ok := sysStatT(info)
		if !ok {
			return nil
		}
		// Cgroup ID == directory inode on cgroupv2. Skip the root (id of
		// /sys/fs/cgroup itself isn't useful for attribution).
		if path == c.root {
			return nil
		}
		// Strip the mount prefix so paths read as "kubepods.slice/...".
		rel := path
		if len(path) > rootLen && path[rootLen] == '/' {
			rel = path[rootLen+1:]
		}
		next[stat.Ino] = rel
		return nil
	})
	c.mu.Lock()
	c.byID = next
	c.mu.Unlock()
}

// Lookup returns the cgroup path for the given kernel cgroup ID. Lookup
// hits update the hit counter; misses bump the miss counter so operators
// can see how often the lazy rescan fires.
func (c *CgroupIDIndex) Lookup(id uint64) (string, bool) {
	c.mu.RLock()
	p, ok := c.byID[id]
	c.mu.RUnlock()
	if ok {
		c.hits.Add(1)
		return p, true
	}
	c.misses.Add(1)
	return "", false
}

// LookupOrRescan tries Lookup once; on miss it triggers Rescan and
// retries. Used by hot-path resolvers to absorb newly-created containers
// without waiting for the periodic refresh.
func (c *CgroupIDIndex) LookupOrRescan(id uint64) (string, bool) {
	if p, ok := c.Lookup(id); ok {
		return p, true
	}
	c.Rescan()
	c.mu.RLock()
	p, ok := c.byID[id]
	c.mu.RUnlock()
	if ok {
		c.hits.Add(1)
	}
	return p, ok
}

// Stats returns the running hit/miss counters and the current map size.
// Plumbed into the daemon's stats line so operators can spot a churning
// cgroup tree (high miss rate → consider tightening the rescan cadence).
func (c *CgroupIDIndex) Stats() (hits, misses uint64, size int) {
	c.mu.RLock()
	size = len(c.byID)
	c.mu.RUnlock()
	return c.hits.Load(), c.misses.Load(), size
}

// ResolveByCgroupID maps a kernel cgroup ID to ContainerMeta. Returns a
// zero-value meta on miss so callers can decide whether to drop the
// event or surface it un-attributed. The lookup path is:
//
//	cgroup_id → cgroup path (CgroupIDIndex)
//	 → containerID (ContainerIDFromCgroup)
//	 → CRIRecord (cri cache populated by crictl)
//	 → ContainerMeta with pod/namespace/labels filled
//
// Cluster + NodeName are stamped from the enricher's options so every
// returned meta carries the node identity even when CRI metadata is
// missing (raw container ID with no pod info is still useful for
// triage).
func (e *Enricher) ResolveByCgroupID(id uint64) types.ContainerMeta {
	if id == 0 || e.cgIDs == nil {
		return types.ContainerMeta{}
	}
	path, ok := e.cgIDs.LookupOrRescan(id)
	if !ok {
		return types.ContainerMeta{}
	}
	containerID := ContainerIDFromCgroup(path)
	if containerID == "" {
		// Not a container cgroup (host process, systemd unit, etc.).
		// Surface the cgroup path via PidNS=0 / ContainerID="" — the
		// caller's existing zero-meta handling already treats this as
		// "unattributed".
		return types.ContainerMeta{
			Cluster:  e.opts.Cluster,
			NodeName: e.opts.NodeName,
		}
	}
	meta := types.ContainerMeta{
		Cluster:     e.opts.Cluster,
		NodeName:    e.opts.NodeName,
		ContainerID: containerID,
	}
	if rec, ok := e.cri.Get(containerID); ok {
		meta.Container = rec.ContainerName
		meta.Pod = rec.PodName
		meta.Namespace = rec.PodNamespace
		meta.Image = rec.Image
		if len(rec.Labels) > 0 {
			meta.Labels = rec.Labels
		}
	}
	return meta
}
