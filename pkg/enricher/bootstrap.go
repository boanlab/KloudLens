// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package enricher

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Bootstrap performs a synchronous /proc + CRI scan and waits until the NSMap
// is populated. It is intended to be called by the daemon **before** the
// tracer attaches, so that events from already-running containers see
// populated ContainerMeta on their very first IntentEvent.
//
// Bootstrap is idempotent and safe to call multiple times; subsequent calls
// just replace the cache. When Proc.Scan fails (e.g. a sandboxed test env
// with no /proc), Bootstrap returns the error without touching the cache.
func (e *Enricher) Bootstrap(ctx context.Context) error {
	if e == nil {
		return nil
	}
	snap, err := e.opts.Proc.Scan()
	if err != nil {
		return err
	}
	e.ns.Replace(snap)
	if e.opts.CRI != nil {
		// CRI failure is non-fatal for zero-miss bootstrap — we already have
		// the NS→containerID mapping from /proc. Pod/namespace enrichment
		// arrives on the next periodic rescan.
		if recs, cerr := e.opts.CRI.Snapshot(ctx); cerr == nil {
			e.cri.Replace(recs)
		}
	}
	return nil
}

// BirthNotifier is a debounced hook that triggers a rescan when the bridge
// observes a namespace-creating syscall (clone/clone3 with CLONE_NEWPID|
// CLONE_NEWNS, unshare, or setns). It sits in front of Enricher.Rescan to
// coalesce bursts of births into a single scan — a container start typically
// issues several NS syscalls in a row, and scanning /proc per-syscall would
// burn CPU without improving freshness.
type BirthNotifier struct {
	e        *Enricher
	minGap   time.Duration
	lastScan atomic.Int64 // unix nanos
	pending  atomic.Bool  // a deferred scan is queued
	mu       sync.Mutex
	now      func() time.Time
}

// NewBirthNotifier wires a notifier to the enricher with a min-gap. A typical
// minGap is 250ms — short enough to feel "immediate" to users inspecting a
// newly-started container, long enough to coalesce clone+unshare+setns bursts.
func NewBirthNotifier(e *Enricher, minGap time.Duration) *BirthNotifier {
	if minGap <= 0 {
		minGap = 250 * time.Millisecond
	}
	return &BirthNotifier{e: e, minGap: minGap, now: time.Now}
}

// Notify records a container-birth signal. When the last scan was more than
// minGap ago, it triggers a scan synchronously on the caller's goroutine (the
// bridge already runs off the hot tracer path). Otherwise it arms a deferred
// scan that fires after minGap elapses.
func (b *BirthNotifier) Notify(ctx context.Context) {
	if b == nil || b.e == nil {
		return
	}
	nowNS := b.now().UnixNano()
	last := b.lastScan.Load()
	gap := time.Duration(nowNS - last)
	if gap >= b.minGap {
		b.mu.Lock()
		b.lastScan.Store(nowNS)
		b.mu.Unlock()
		b.e.Rescan(ctx)
		return
	}
	if !b.pending.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer b.pending.Store(false)
		wait := b.minGap - gap
		if wait <= 0 {
			wait = b.minGap
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		b.mu.Lock()
		b.lastScan.Store(b.now().UnixNano())
		b.mu.Unlock()
		b.e.Rescan(ctx)
	}()
}

// LastScanNS returns the unix-nano timestamp of the most recent successful
// scan. Useful for /metrics and for tests that assert on debounce behavior.
func (b *BirthNotifier) LastScanNS() int64 { return b.lastScan.Load() }
