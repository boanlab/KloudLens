// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package enricher

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

// Options tunes the Enricher's behavior. Zero value runs with /proc scanning
// every 30 seconds and no CRI integration — a reasonable baseline for a
// k8s-less host or a smoke test.
type Options struct {
	// RescanInterval sets how often the background scanner rebuilds the NS
	// cache. Zero disables periodic rescans (useful in tests that drive
	// the scan manually via Rescan).
	RescanInterval time.Duration

	// NodeName is copied into every returned ContainerMeta.NodeName. Plumbed
	// through explicitly so the daemon's --node flag wins over any auto-
	// detected hostname.
	NodeName string

	// Cluster is copied into ContainerMeta.Cluster. Typically the k8s cluster
	// name the operator wants to see in exported logs.
	Cluster string

	// CRI is an optional CRI client. When nil, pod/container metadata is
	// limited to the raw ContainerID (cgroup-derived). When set, a periodic
	// crictl snapshot populates pod name/namespace/labels.
	CRI *CRIClient

	// Docker is an optional Docker Engine client for standalone Docker
	// hosts (no Kubernetes, no CRI). If both CRI and Docker are set, CRI
	// wins — containers are typically visible to only one of them, so the
	// redundant probe would just cost extra syscalls.
	Docker *DockerClient

	// Proc is the procfs scanner; defaults to one rooted at /proc.
	Proc *ProcScanner

	// CgroupRoot points at the cgroupv2 unified mount the agent should
	// scan for the cgroup_id → path index. Defaults to /sys/fs/cgroup
	// when empty. The DaemonSet bind-mounts the host's cgroup tree so
	// pod cgroups under kubepods.slice are visible to the indexer.
	CgroupRoot string
}

// Enricher satisfies tracer.MetaResolver. It maintains two caches:
// 1. NSMap — keyed by (pidNS, mntNS), populated by the /proc scanner.
// 2. CRICache — keyed by ContainerID, populated by crictl snapshots.
//
// Resolve looks up the NSKey, attaches any CRI metadata for the resulting
// container ID, and stamps NodeName/Cluster. A miss returns a zero value; the
// bridge preserves the NS pair on Meta when the resolver has nothing to say.
type Enricher struct {
	opts    Options
	ns      *NSMap
	cri     *criCache
	cgIDs   *CgroupIDIndex
	stopped atomic.Bool
	wg      sync.WaitGroup
}

// NewEnricher builds an Enricher from Options and returns it without starting
// any background goroutines. Call Start(ctx) to kick off scanners.
func NewEnricher(opts Options) *Enricher {
	if opts.Proc == nil {
		opts.Proc = NewProcScanner()
	}
	return &Enricher{
		opts:  opts,
		ns:    NewNSMap(),
		cri:   newCRICache(),
		cgIDs: NewCgroupIDIndex(opts.CgroupRoot),
	}
}

// Start spawns the scanner goroutines. It returns immediately; use Stop or
// ctx cancellation to tear them down. Start is idempotent per-instance: a
// second call after Stop has no effect (the stopped flag latches).
func (e *Enricher) Start(ctx context.Context) {
	if e.stopped.Load() {
		return
	}
	// Do an initial sync scan so the first intents out of the tracer already
	// see populated metadata — otherwise the first 30 s of intents carry
	// NS-only Meta, which is exactly the window where the user is most likely
	// verifying enrichment is working.
	e.rescan(ctx)

	interval := e.opts.RescanInterval
	if interval <= 0 {
		return
	}
	e.wg.Add(1)
	go e.runLoop(ctx, interval)
}

// Stop signals any running scanner to exit and waits for it.
func (e *Enricher) Stop() {
	if !e.stopped.CompareAndSwap(false, true) {
		return
	}
	e.wg.Wait()
}

func (e *Enricher) runLoop(ctx context.Context, interval time.Duration) {
	defer e.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if e.stopped.Load() {
				return
			}
			e.rescan(ctx)
		}
	}
}

// rescan refreshes all three caches. Procfs is authoritative for NS →
// containerID; CRI / Docker are authoritative for containerID →
// pod/namespace/labels; CgroupIDIndex maps cgroup_id → cgroup path so
// cgroup_skb-emitted events (where current_task is unreliable) can
// still attribute to a pod. Per-cache failures are isolated — a CRI
// hiccup doesn't stop the cgroup walker.
func (e *Enricher) rescan(ctx context.Context) {
	if snap, err := e.opts.Proc.Scan(); err == nil {
		e.ns.Replace(snap)
	}
	if e.cgIDs != nil {
		e.cgIDs.Rescan()
	}
	switch {
	case e.opts.CRI != nil:
		if recs, err := e.opts.CRI.Snapshot(ctx); err == nil {
			e.cri.Replace(recs)
		}
	case e.opts.Docker != nil:
		if recs, err := e.opts.Docker.Snapshot(ctx); err == nil {
			e.cri.Replace(recs)
		}
	}
}

// Rescan is exposed for tests that want to drive the scanner synchronously.
func (e *Enricher) Rescan(ctx context.Context) { e.rescan(ctx) }

// Resolve returns the ContainerMeta cached for (pidNS, mntNS). Both zero NS
// values short-circuit to a zero return (the host process case) so the bridge
// avoids pointless lookups.
//
// On a cache miss the function returns a partial meta (cluster + node +
// raw NS) without scanning /proc; the next periodic rescan populates the
// cache for subsequent events from the same container. The hot path
// therefore stays O(1) under short-lived process churn (forked workers,
// ephemeral containers). A brand-new container's first events carry
// partial meta until at most RescanInterval (default 30s); after that
// they resolve to full meta like any other.
func (e *Enricher) Resolve(pidNS, mntNS uint32) types.ContainerMeta {
	if pidNS == 0 && mntNS == 0 {
		return types.ContainerMeta{}
	}
	key := NSKey{PidNS: pidNS, MntNS: mntNS}
	entry, ok := e.ns.Lookup(key)
	if !ok {
		// NS pair didn't map to a known container — still stamp node
		// identity so operators can attribute the event to a node even
		// when the pod side is unknown (host process, fresh container the
		// scanner hasn't picked up yet, …). Periodic rescan will fill in.
		return types.ContainerMeta{
			Cluster:  e.opts.Cluster,
			NodeName: e.opts.NodeName,
			PidNS:    pidNS,
			MntNS:    mntNS,
		}
	}
	meta := types.ContainerMeta{
		Cluster:     e.opts.Cluster,
		NodeName:    e.opts.NodeName,
		ContainerID: entry.ContainerID,
		PidNS:       pidNS,
		MntNS:       mntNS,
	}
	if rec, ok := e.cri.Get(entry.ContainerID); ok {
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

// Stats returns a combined view of scanner hit rates — useful for the
// daemon's periodic stats line.
type Stats struct {
	NSHits   uint64
	NSMisses uint64
	NSSize   int
	CRISize  int
}

// Stats returns a snapshot of the enricher's internal counters.
func (e *Enricher) Stats() Stats {
	h, m, s := e.ns.Stats()
	return Stats{NSHits: h, NSMisses: m, NSSize: s, CRISize: e.cri.Size()}
}

// criCache wraps a map[containerID]CRIRecord with an RWMutex so Snapshot
// writes don't block Resolve reads.
type criCache struct {
	mu      sync.RWMutex
	entries map[string]CRIRecord
}

func newCRICache() *criCache { return &criCache{entries: map[string]CRIRecord{}} }

func (c *criCache) Replace(recs []CRIRecord) {
	next := make(map[string]CRIRecord, len(recs))
	for _, r := range recs {
		next[r.ContainerID] = r
	}
	c.mu.Lock()
	c.entries = next
	c.mu.Unlock()
}

func (c *criCache) Get(id string) (CRIRecord, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.entries[id]
	return r, ok
}

func (c *criCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
