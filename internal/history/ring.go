// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package history implements the Historical Context Ring
//
// For each process and container the store maintains small ring buffers that
// hold the most recent intents, the exec chain, credential transitions, and
// a bootstrap summary of the first 10s of a container's life. Snapshot
// produces a types.HistoricalContext that the enricher attaches inline to
// outgoing events so downstream consumers don't need to query the session
// graph to get "what was this process just doing?".
//
// The store is user-space only, bounded per-key, and trimmed by TTL and by
// a per-type key cap with LRU eviction when a node is under pressure.
package history

import (
	"container/list"
	"slices"
	"sync"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

// Config controls ring sizes and retention windows.
type Config struct {
	ProcExecDepth   int           // default 16
	ProcRecentDepth int           // default 32
	ProcRecentTTL   time.Duration // default 30s
	ContRecentDepth int           // default 16
	ContRecentTTL   time.Duration // default 30s
	BootstrapWindow time.Duration // default 10s
	CredDepth       int           // default 64 (compressed timeline cap)

	// Hard caps on the number of tracked keys. When exceeded, least-recently
	// used entries are evicted. Plan calls out a 128MB node-wide cap;
	// translating that to byte accounting is noisy, so we approximate with
	// per-map key caps and test LRU behavior directly.
	MaxProcKeys int // default 20000
	MaxContKeys int // default 2000

	Clock func() time.Time
}

func (c *Config) withDefaults() {
	if c.ProcExecDepth == 0 {
		c.ProcExecDepth = 16
	}
	if c.ProcRecentDepth == 0 {
		c.ProcRecentDepth = 32
	}
	if c.ProcRecentTTL == 0 {
		c.ProcRecentTTL = 30 * time.Second
	}
	if c.ContRecentDepth == 0 {
		c.ContRecentDepth = 16
	}
	if c.ContRecentTTL == 0 {
		c.ContRecentTTL = 30 * time.Second
	}
	if c.BootstrapWindow == 0 {
		c.BootstrapWindow = 10 * time.Second
	}
	if c.CredDepth == 0 {
		c.CredDepth = 64
	}
	if c.MaxProcKeys == 0 {
		c.MaxProcKeys = 20000
	}
	if c.MaxContKeys == 0 {
		c.MaxContKeys = 2000
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
}

// Store is goroutine-safe.
type Store struct {
	mu  sync.Mutex
	cfg Config

	procExec   map[int32]*ring[types.ProcessAncestor]
	procRecent map[int32]*ring[types.HistoryEntry]
	contRecent map[string]*ring[types.HistoryEntry]
	credTL     map[int32]*ring[types.CredTransition]
	bootstrap  map[string]*bootstrapState

	procLRU *keyLRU[int32]
	contLRU *keyLRU[string]
}

type bootstrapState struct {
	summary types.ContainerBootstrapSummary
	// Time at which the bootstrap window started. All RecordBootstrap calls
	// after start+BootstrapWindow are ignored.
	start time.Time
}

// New returns a Store with defaults applied.
func New(cfg Config) *Store {
	cfg.withDefaults()
	return &Store{
		cfg:        cfg,
		procExec:   map[int32]*ring[types.ProcessAncestor]{},
		procRecent: map[int32]*ring[types.HistoryEntry]{},
		contRecent: map[string]*ring[types.HistoryEntry]{},
		credTL:     map[int32]*ring[types.CredTransition]{},
		bootstrap:  map[string]*bootstrapState{},
		procLRU:    newKeyLRU[int32](),
		contLRU:    newKeyLRU[string](),
	}
}

// RecordExec appends a new ancestor entry on the process exec chain.
func (s *Store) RecordExec(pid int32, ancestor types.ProcessAncestor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.procExec[pid]
	if r == nil {
		r = newRing[types.ProcessAncestor](s.cfg.ProcExecDepth)
		s.procExec[pid] = r
	}
	r.push(ancestor)
	s.procLRU.touch(pid)
	s.enforceProcCap()
}

// RecordProcessIntent adds an intent to the per-process recent ring.
func (s *Store) RecordProcessIntent(pid int32, entry types.HistoryEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.procRecent[pid]
	if r == nil {
		r = newRing[types.HistoryEntry](s.cfg.ProcRecentDepth)
		s.procRecent[pid] = r
	}
	r.push(entry)
	s.procLRU.touch(pid)
	s.enforceProcCap()
}

// RecordContainerIntent adds a container-scoped intent.
func (s *Store) RecordContainerIntent(cid string, entry types.HistoryEntry) {
	if cid == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.contRecent[cid]
	if r == nil {
		r = newRing[types.HistoryEntry](s.cfg.ContRecentDepth)
		s.contRecent[cid] = r
	}
	r.push(entry)
	s.contLRU.touch(cid)
	s.enforceContCap()
}

// RecordCred adds a credential transition to the pid timeline.
func (s *Store) RecordCred(pid int32, ct types.CredTransition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.credTL[pid]
	if r == nil {
		r = newRing[types.CredTransition](s.cfg.CredDepth)
		s.credTL[pid] = r
	}
	r.push(ct)
	s.procLRU.touch(pid)
	s.enforceProcCap()
}

// StartBootstrap begins a bootstrap window for cid. Subsequent RecordBootstrap
// calls within the configured window append to the summary.
func (s *Store) StartBootstrap(cid string, startNS uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bootstrap[cid] = &bootstrapState{
		summary: types.ContainerBootstrapSummary{StartNS: startNS, BootstrapOngoing: true},
		start:   s.cfg.Clock(),
	}
	s.contLRU.touch(cid)
	s.enforceContCap()
}

// RecordBootstrap appends to the container bootstrap summary if we're still
// inside the window. kind ∈ {"exec","read","peer"}.
func (s *Store) RecordBootstrap(cid, kind, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bootstrap[cid]
	if !ok {
		return
	}
	if s.cfg.Clock().Sub(b.start) > s.cfg.BootstrapWindow {
		b.summary.BootstrapOngoing = false
		return
	}
	switch kind {
	case "exec":
		b.summary.FirstExecs = appendUnique(b.summary.FirstExecs, value, 8)
	case "read":
		b.summary.FirstReads = appendUnique(b.summary.FirstReads, value, 8)
	case "peer":
		b.summary.FirstPeers = appendUnique(b.summary.FirstPeers, value, 8)
	}
	s.contLRU.touch(cid)
}

// SetHistoryDepth resizes the per-pid + per-container recent rings to cap,
// preserving the most-recent entries when shrinking. Non-positive values are
// ignored so callers can pass 0 to mean "leave unchanged" — this maps the
// YAML default (HistoryDepth omitted → 0) onto a no-op.
//
// Exec-chain, bootstrap, and credential rings intentionally stay put: they're
// tied to audit semantics (ancestor preservation, boot window, cred timeline)
// that operators shouldn't knob at runtime via a single HookSubscription knob.
func (s *Store) SetHistoryDepth(depth int) {
	if depth <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.ProcRecentDepth = depth
	s.cfg.ContRecentDepth = depth
	for _, r := range s.procRecent {
		r.resize(depth)
	}
	for _, r := range s.contRecent {
		r.resize(depth)
	}
}

// SetHistoryTTL replaces the recent-intent TTL used by Snapshot to filter
// expired entries. Applies to both proc and container rings (the HookSubscription
// schema exposes one scalar HistoryWindowSecs). Non-positive values are ignored.
func (s *Store) SetHistoryTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.ProcRecentTTL = ttl
	s.cfg.ContRecentTTL = ttl
}

// OnProcessExit drops the pid's rings. The exec chain is preserved only until
// exit
func (s *Store) OnProcessExit(pid int32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.procExec, pid)
	delete(s.procRecent, pid)
	delete(s.credTL, pid)
	s.procLRU.remove(pid)
}

// OnContainerStop drops all container-scoped rings for cid.
func (s *Store) OnContainerStop(cid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.contRecent, cid)
	delete(s.bootstrap, cid)
	s.contLRU.remove(cid)
}

// Snapshot builds a HistoricalContext for the given pid/cid at the current
// clock time, filtering TTL-expired intents.
func (s *Store) Snapshot(pid int32, cid string) types.HistoricalContext {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Clock()
	out := types.HistoricalContext{}

	if r := s.procExec[pid]; r != nil {
		out.Ancestors = r.snapshot()
	}
	if r := s.procRecent[pid]; r != nil {
		out.RecentProcess = filterHistoryByTTL(r.snapshot(), now, s.cfg.ProcRecentTTL)
	}
	if cid != "" {
		if r := s.contRecent[cid]; r != nil {
			out.RecentContainer = filterHistoryByTTL(r.snapshot(), now, s.cfg.ContRecentTTL)
		}
		if b, ok := s.bootstrap[cid]; ok {
			cp := b.summary
			if now.Sub(b.start) > s.cfg.BootstrapWindow {
				cp.BootstrapOngoing = false
			}
			out.Bootstrap = &cp
		}
	}
	if r := s.credTL[pid]; r != nil {
		out.CredTimeline = r.snapshot()
	}
	if pid != 0 {
		s.procLRU.touch(pid)
	}
	if cid != "" {
		s.contLRU.touch(cid)
	}
	return out
}

// Sizes returns approximate key counts, useful for metrics and tests.
type Sizes struct {
	ProcKeys int
	ContKeys int
}

func (s *Store) Sizes() Sizes {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Count distinct pids across the three proc-scoped maps.
	procs := make(map[int32]struct{}, len(s.procExec)+len(s.procRecent)+len(s.credTL))
	for pid := range s.procExec {
		procs[pid] = struct{}{}
	}
	for pid := range s.procRecent {
		procs[pid] = struct{}{}
	}
	for pid := range s.credTL {
		procs[pid] = struct{}{}
	}
	conts := make(map[string]struct{}, len(s.contRecent)+len(s.bootstrap))
	for cid := range s.contRecent {
		conts[cid] = struct{}{}
	}
	for cid := range s.bootstrap {
		conts[cid] = struct{}{}
	}
	return Sizes{ProcKeys: len(procs), ContKeys: len(conts)}
}

func (s *Store) enforceProcCap() {
	for s.procLRU.len() > s.cfg.MaxProcKeys {
		victim, ok := s.procLRU.evictOldest()
		if !ok {
			return
		}
		delete(s.procExec, victim)
		delete(s.procRecent, victim)
		delete(s.credTL, victim)
	}
}

func (s *Store) enforceContCap() {
	for s.contLRU.len() > s.cfg.MaxContKeys {
		victim, ok := s.contLRU.evictOldest()
		if !ok {
			return
		}
		delete(s.contRecent, victim)
		delete(s.bootstrap, victim)
	}
}

func filterHistoryByTTL(entries []types.HistoryEntry, now time.Time, ttl time.Duration) []types.HistoryEntry {
	// Compute in signed nanoseconds so `now` near epoch doesn't underflow.
	cutoff := now.Add(-ttl).UnixNano()
	out := entries[:0:len(entries)]
	for _, e := range entries {
		if int64(e.TSNS) >= cutoff { // #nosec G115 -- TSNS is a monotonic nanosecond timestamp that fits int64 well beyond year 2262
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func appendUnique(ss []string, v string, cap int) []string {
	if slices.Contains(ss, v) {
		return ss
	}
	if len(ss) >= cap {
		return ss
	}
	return append(ss, v)
}

// ring is a fixed-capacity FIFO ring. Oldest entries are overwritten on push.
type ring[T any] struct {
	buf   []T
	start int
	size  int
}

func newRing[T any](cap int) *ring[T] {
	if cap < 1 {
		cap = 1
	}
	return &ring[T]{buf: make([]T, cap)}
}

func (r *ring[T]) push(v T) {
	if r.size < len(r.buf) {
		r.buf[(r.start+r.size)%len(r.buf)] = v
		r.size++
		return
	}
	r.buf[r.start] = v
	r.start = (r.start + 1) % len(r.buf)
}

// resize rebuilds the underlying buffer with a new capacity, preserving
// the most-recent min(size, newCap) entries in arrival order. Called from
// Store.SetHistoryDepth under the store mutex — no separate locking here.
func (r *ring[T]) resize(newCap int) {
	if newCap < 1 {
		newCap = 1
	}
	if newCap == len(r.buf) {
		return
	}
	snap := r.snapshot()
	r.buf = make([]T, newCap)
	r.start = 0
	r.size = 0
	for _, v := range snap {
		r.push(v)
	}
}

func (r *ring[T]) snapshot() []T {
	out := make([]T, r.size)
	for i := range r.size {
		out[i] = r.buf[(r.start+i)%len(r.buf)]
	}
	return out
}

// keyLRU tracks last-access ordering for a set of keys so the store can evict
// the least-recently-used entry when the per-map key cap is exceeded.
type keyLRU[K comparable] struct {
	ll    *list.List
	index map[K]*list.Element
}

func newKeyLRU[K comparable]() *keyLRU[K] {
	return &keyLRU[K]{ll: list.New(), index: map[K]*list.Element{}}
}

func (l *keyLRU[K]) touch(k K) {
	if e, ok := l.index[k]; ok {
		l.ll.MoveToFront(e)
		return
	}
	l.index[k] = l.ll.PushFront(k)
}

func (l *keyLRU[K]) remove(k K) {
	if e, ok := l.index[k]; ok {
		l.ll.Remove(e)
		delete(l.index, k)
	}
}

func (l *keyLRU[K]) evictOldest() (K, bool) {
	var zero K
	e := l.ll.Back()
	if e == nil {
		return zero, false
	}
	k := e.Value.(K)
	l.ll.Remove(e)
	delete(l.index, k)
	return k, true
}

func (l *keyLRU[K]) len() int { return l.ll.Len() }
