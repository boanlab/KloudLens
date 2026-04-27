// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package intent implements the Intent Aggregator. Syscalls on the same
// (tgid,fd) or (tgid,sock) are folded into a single semantic event
// (FileRead/FileWrite/NetworkExchange/ProcessStart/...).
//
// This implementation is pure Go — no BPF here. The BPF side will feed
// raw observations via Observe*; the aggregator keeps the per-key state
// and emits IntentEvents via the Emitter callback on boundary conditions:
//
//	(1) close (or equivalent) — explicit end
//	(2) reopen of the same fd with different inode — new intent
//	(3) process exit — flush all keys owned by tgid
//	(4) idle timeout (default 5s) — emit with confidence<1.0
//	(5) session Stop — drain all state
package intent

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

// Emitter is invoked synchronously when the aggregator produces a finished
// intent event. Pipelines wrap this to push into their export channel.
type Emitter func(types.IntentEvent)

// Clock is separated so tests can drive time without time.Sleep.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Config controls aggregator policy.
type Config struct {
	IdleTimeout time.Duration // default 5s — forced emit if no new activity
	MaxPerKey   int           // cap on contributing events kept per key (default 256)
	NodeName    string
	Cluster     string
}

// Aggregator holds per-key state machines for one node.
type Aggregator struct {
	cfg   Config
	clock Clock
	emit  Emitter
	mu    sync.Mutex

	fileKeys map[fileKey]*fileState
	sockKeys map[sockKey]*sockState
	execKeys map[int32]*execState // tgid → pending ProcessStart
}

type fileKey struct {
	TGID int32
	FD   int32
}

type sockKey struct {
	TGID int32
	FD   int32
}

type fileState struct {
	path       string
	openFlags  string
	bytesRead  uint64
	bytesWrite uint64
	firstTS    uint64
	lastTS     uint64
	meta       types.ContainerMeta
	events     []string
	openKind   string // Open|OpenRead|OpenWrite|OpenRW
	closed     bool
	updatedAt  time.Time
}

type sockState struct {
	peer    string
	proto   string
	tx      uint64
	rx      uint64
	firstTS uint64
	lastTS  uint64
	meta    types.ContainerMeta
	events  []string
	updated time.Time
	closed  bool
}

type execState struct {
	binary    string
	argv      []string
	argvHash  string
	tsStart   uint64
	meta      types.ContainerMeta
	events    []string
	completed bool
	updated   time.Time
}

// NewAggregator returns an Aggregator ready to accept observations.
func NewAggregator(cfg Config, emit Emitter) *Aggregator {
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Second
	}
	if cfg.MaxPerKey == 0 {
		cfg.MaxPerKey = 256
	}
	return &Aggregator{
		cfg:      cfg,
		clock:    realClock{},
		emit:     emit,
		fileKeys: map[fileKey]*fileState{},
		sockKeys: map[sockKey]*sockState{},
		execKeys: map[int32]*execState{},
	}
}

// SetClock is for tests.
func (a *Aggregator) SetClock(c Clock) { a.clock = c }

// dispatch is the single emission gateway. It normalizes the timestamps
// (EndNS ≥ StartNS) and forwards to the user-supplied emit callback.
//
// Why the clamp: BPF tracepoints fire on different CPUs and userspace
// drains the rings concurrently, so frame ordering can invert by a few ms.
// Worse, ObserveFileCloseWithState seeds firstTS from the kernel-attached
// open_ts in kl_fd_state — if that value is stale (LRU-evicted slot
// reused, fd-table sharing across fork/exec), firstTS can land past the
// close ts. Either way, downstream consumers (klctl, exporters,
// dashboards) treat end < start as corrupt input. Clamping here keeps the
// wire well-formed without papering over the underlying ordering quirk
// in the source data.
func (a *Aggregator) dispatch(ev types.IntentEvent) {
	if ev.EndNS != 0 && ev.StartNS != 0 && ev.EndNS < ev.StartNS {
		ev.EndNS = ev.StartNS
	}
	a.emit(ev)
}

// ObserveFileOpen records an open/openat that produced fd for tgid.
// `flags` carries a normalized access-mode hint: "openr" (O_RDONLY),
// "openw" (O_WRONLY|O_CREAT|O_TRUNC), "openrw" (O_RDWR), or "" / "open"
// when the direction is unknown. The hint seeds openKind so emitFile can
// classify FileRead vs FileWrite even when BPF never reports byte counters.
func (a *Aggregator) ObserveFileOpen(tgid, fd int32, path, flags, eventID string, ts uint64, meta types.ContainerMeta) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// If fd already tracked, the previous intent closes (reopen semantics).
	if old, ok := a.fileKeys[fileKey{tgid, fd}]; ok {
		a.emitFile(old)
		delete(a.fileKeys, fileKey{tgid, fd})
	}
	a.fileKeys[fileKey{tgid, fd}] = &fileState{
		path:      path,
		openFlags: flags,
		firstTS:   ts,
		lastTS:    ts,
		meta:      meta,
		events:    appendCapped(nil, eventID, a.cfg.MaxPerKey),
		openKind:  openKindFromFlags(flags),
		updatedAt: a.clock.Now(),
	}
}

// openKindFromFlags maps the bridge's access-mode hint to the fileState
// openKind tag used by emitFileWithConf. Unknown / empty flags default to
// the opaque "Open" placeholder so downstream consumers can still tell this
// was an open event (vs a synthetic late observation).
func openKindFromFlags(flags string) string {
	switch flags {
	case "openr":
		return "OpenRead"
	case "openw":
		return "OpenWrite"
	case "openrw":
		return "OpenRW"
	}
	return "Open"
}

// ObserveFileIO records a read or write on fd. kind="read"|"write".
func (a *Aggregator) ObserveFileIO(tgid, fd int32, kind string, bytes uint64, eventID string, ts uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st, ok := a.fileKeys[fileKey{tgid, fd}]
	if !ok {
		// Late observation — create a synthetic key so we don't lose it.
		st = &fileState{firstTS: ts, lastTS: ts, openKind: "SyntheticOpen", updatedAt: a.clock.Now()}
		a.fileKeys[fileKey{tgid, fd}] = st
	}
	if kind == "read" {
		st.bytesRead += bytes
	} else if kind == "write" {
		st.bytesWrite += bytes
	}
	st.events = appendCapped(st.events, eventID, a.cfg.MaxPerKey)
	st.lastTS = ts
	st.updatedAt = a.clock.Now()
}

// ObserveFileClose finalizes a file key on close(fd).
func (a *Aggregator) ObserveFileClose(tgid, fd int32, eventID string, ts uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st, ok := a.fileKeys[fileKey{tgid, fd}]
	if !ok {
		return
	}
	st.events = appendCapped(st.events, eventID, a.cfg.MaxPerKey)
	st.lastTS = ts
	st.closed = true
	a.emitFile(st)
	delete(a.fileKeys, fileKey{tgid, fd})
}

// ObserveFileCloseWithState finalizes a file key on close(fd), seeding a
// fresh fileState from kernel-attached data (path, open_ts) when no prior
// open was observed. This is the hot path when the BPF kl_fd_state map
// hits on close: user-space no longer depends on having paired with the
// original openat frame to produce a FileAccess intent. If openTsNs is 0
// or path is empty, falls back to the regular ObserveFileClose path.
func (a *Aggregator) ObserveFileCloseWithState(tgid, fd int32, path, flags, eventID string, openTsNs, ts uint64, meta types.ContainerMeta) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st, ok := a.fileKeys[fileKey{tgid, fd}]
	if !ok && path != "" {
		// Kernel saw the open but user-space didn't. Synthesize the
		// state so emitFile has a non-empty record.
		firstTS := openTsNs
		if firstTS == 0 {
			firstTS = ts
		}
		st = &fileState{
			path:      path,
			openFlags: flags,
			openKind:  openKindFromFlags(flags),
			events:    []string{eventID},
			firstTS:   firstTS,
			lastTS:    ts,
			meta:      meta,
			updatedAt: a.clock.Now(),
		}
		a.fileKeys[fileKey{tgid, fd}] = st
	}
	if st == nil {
		return
	}
	st.events = appendCapped(st.events, eventID, a.cfg.MaxPerKey)
	st.lastTS = ts
	st.closed = true
	a.emitFile(st)
	delete(a.fileKeys, fileKey{tgid, fd})
}

// ObserveSocketConnect records connect.
func (a *Aggregator) ObserveSocketConnect(tgid, fd int32, peer, proto, eventID string, ts uint64, meta types.ContainerMeta) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if old, ok := a.sockKeys[sockKey{tgid, fd}]; ok {
		a.emitSock(old)
		delete(a.sockKeys, sockKey{tgid, fd})
	}
	a.sockKeys[sockKey{tgid, fd}] = &sockState{
		peer:    peer,
		proto:   proto,
		firstTS: ts,
		lastTS:  ts,
		meta:    meta,
		events:  appendCapped(nil, eventID, a.cfg.MaxPerKey),
		updated: a.clock.Now(),
	}
}

// ObserveSocketIO records tx/rx on an active socket. kind="tx"|"rx".
// meta stamps the sockState if no prior connect/accept did so — covers
// fd flows that skipped connect (dup'd / inherited / accepted sockets,
// connection-less sendto/recvfrom). When a later observation has a
// richer meta (the bridge stamps freshly resolved meta on every event)
// the upgrade only fires on still-empty Container/Cluster fields so an
// already-enriched sockState isn't blanked.
func (a *Aggregator) ObserveSocketIO(tgid, fd int32, kind string, bytes uint64, eventID string, ts uint64, meta types.ContainerMeta) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st, ok := a.sockKeys[sockKey{tgid, fd}]
	if !ok {
		st = &sockState{firstTS: ts, lastTS: ts, meta: meta, updated: a.clock.Now()}
		a.sockKeys[sockKey{tgid, fd}] = st
	} else if st.meta.Cluster == "" && st.meta.ContainerID == "" {
		st.meta = meta
	}
	if kind == "tx" {
		st.tx += bytes
	} else if kind == "rx" {
		st.rx += bytes
	}
	st.events = appendCapped(st.events, eventID, a.cfg.MaxPerKey)
	st.lastTS = ts
	st.updated = a.clock.Now()
}

// ObserveSocketClose finalizes a socket key.
func (a *Aggregator) ObserveSocketClose(tgid, fd int32, eventID string, ts uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st, ok := a.sockKeys[sockKey{tgid, fd}]
	if !ok {
		return
	}
	st.events = appendCapped(st.events, eventID, a.cfg.MaxPerKey)
	st.lastTS = ts
	st.closed = true
	a.emitSock(st)
	delete(a.sockKeys, sockKey{tgid, fd})
}

// ObserveExec records clone/execve chain → ProcessStart intent.
func (a *Aggregator) ObserveExec(tgid int32, binary string, argv []string, argvHash, eventID string, ts uint64, meta types.ContainerMeta) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.execKeys[tgid]
	if st == nil {
		st = &execState{tsStart: ts, meta: meta, updated: a.clock.Now()}
		a.execKeys[tgid] = st
	}
	st.binary = binary
	st.argv = argv
	st.argvHash = argvHash
	st.events = appendCapped(st.events, eventID, a.cfg.MaxPerKey)
	st.updated = a.clock.Now()
}

// FinalizeExec emits the ProcessStart (usually called after close_fds/prctl).
func (a *Aggregator) FinalizeExec(tgid int32, ts uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st, ok := a.execKeys[tgid]
	if !ok || st.completed {
		return
	}
	st.completed = true
	a.dispatch(types.IntentEvent{
		IntentID:             types.UUIDv7(),
		Kind:                 "ProcessStart",
		StartNS:              st.tsStart,
		EndNS:                ts,
		ContributingEventIDs: append([]string(nil), st.events...),
		Attributes: map[string]string{
			"binary":    st.binary,
			"argv":      joinArgv(st.argv),
			"argv_hash": st.argvHash,
		},
		Meta:       st.meta,
		Severity:   types.SeverityMedium,
		Confidence: 1.0,
	})
	delete(a.execKeys, tgid)
}

// OnProcessExit flushes every open key owned by tgid.
func (a *Aggregator) OnProcessExit(tgid int32, ts uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, st := range a.fileKeys {
		if k.TGID == tgid {
			st.lastTS = ts
			a.emitFileWithConf(st, 0.7)
			delete(a.fileKeys, k)
		}
	}
	for k, st := range a.sockKeys {
		if k.TGID == tgid {
			st.lastTS = ts
			a.emitSock(st)
			delete(a.sockKeys, k)
		}
	}
	if st, ok := a.execKeys[tgid]; ok && !st.completed {
		a.execKeys[tgid].completed = true
		a.dispatch(types.IntentEvent{
			IntentID:             types.UUIDv7(),
			Kind:                 "ProcessStart",
			StartNS:              st.tsStart,
			EndNS:                ts,
			ContributingEventIDs: append([]string(nil), st.events...),
			Attributes: map[string]string{
				"binary":    st.binary,
				"argv":      joinArgv(st.argv),
				"argv_hash": st.argvHash,
				"truncated": "true",
			},
			Meta:       st.meta,
			Severity:   types.SeverityMedium,
			Confidence: 0.7,
		})
		delete(a.execKeys, tgid)
	}
}

// Reap scans every key and emits anything that has been idle longer
// than cfg.IdleTimeout. Returns number of intents flushed.
func (a *Aggregator) Reap() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	now := a.clock.Now()
	for k, st := range a.fileKeys {
		if now.Sub(st.updatedAt) >= a.cfg.IdleTimeout {
			a.emitFileWithConf(st, 0.7)
			delete(a.fileKeys, k)
			n++
		}
	}
	for k, st := range a.sockKeys {
		if now.Sub(st.updated) >= a.cfg.IdleTimeout {
			a.emitSock(st)
			delete(a.sockKeys, k)
			n++
		}
	}
	for k, st := range a.execKeys {
		if !st.completed && now.Sub(st.updated) >= a.cfg.IdleTimeout {
			st.completed = true
			a.dispatch(types.IntentEvent{
				IntentID: types.UUIDv7(), Kind: "ProcessStart",
				StartNS: st.tsStart, EndNS: uint64(now.UnixNano()),
				ContributingEventIDs: st.events,
				Attributes: map[string]string{
					"binary": st.binary, "argv_hash": st.argvHash, "truncated": "true",
				},
				Meta: st.meta, Severity: types.SeverityMedium, Confidence: 0.5,
			})
			delete(a.execKeys, k)
			n++
		}
	}
	return n
}

// Flush emits all open state with reduced confidence — call on shutdown.
func (a *Aggregator) Flush() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for k, st := range a.fileKeys {
		a.emitFileWithConf(st, 0.7)
		delete(a.fileKeys, k)
		n++
	}
	for k, st := range a.sockKeys {
		a.emitSock(st)
		delete(a.sockKeys, k)
		n++
	}
	for k, st := range a.execKeys {
		if !st.completed {
			st.completed = true
			a.dispatch(types.IntentEvent{
				IntentID: types.UUIDv7(), Kind: "ProcessStart",
				StartNS: st.tsStart, EndNS: uint64(a.clock.Now().UnixNano()),
				ContributingEventIDs: st.events, Meta: st.meta,
				Attributes: map[string]string{"binary": st.binary, "truncated": "true"},
				Severity:   types.SeverityMedium, Confidence: 0.4,
			})
			delete(a.execKeys, k)
			n++
		}
	}
	return n
}

// emitFile resolves which Intent kind best fits bytes_read/write ratio.
// Confidence is 1.0 on explicit close, 0.7 on any other terminator.
func (a *Aggregator) emitFile(st *fileState) {
	conf := 1.0
	if !st.closed {
		conf = 0.7
	}
	a.emitFileWithConf(st, conf)
}

func (a *Aggregator) emitFileWithConf(st *fileState, conf float64) {
	kind := "FileAccess"
	switch {
	case st.bytesRead > 0 && st.bytesWrite == 0:
		kind = "FileRead"
	case st.bytesWrite > 0 && st.bytesRead == 0:
		kind = "FileWrite"
	case st.bytesRead > 0 && st.bytesWrite > 0:
		kind = "FileReadWrite"
	}
	// Without per-fd byte counters, emitFile would collapse every
	// open→close into "FileAccess". Fall back to the open-flags direction
	// hint: O_WRONLY → FileWrite, O_RDONLY → FileRead, O_RDWR → FileReadWrite.
	// The hint is only applied when no byte-counter signal exists, so any
	// real I/O observation overrides it.
	if kind == "FileAccess" {
		switch st.openKind {
		case "OpenRead":
			kind = "FileRead"
		case "OpenWrite":
			kind = "FileWrite"
		case "OpenRW":
			kind = "FileReadWrite"
		}
	}
	attrs := map[string]string{
		"path":        st.path,
		"bytes_read":  fmt.Sprintf("%d", st.bytesRead),
		"bytes_write": fmt.Sprintf("%d", st.bytesWrite),
		"flags":       st.openFlags,
	}
	sev := types.SeverityLow
	if kind == "FileWrite" || kind == "FileReadWrite" {
		sev = types.SeverityMedium
	}
	a.dispatch(types.IntentEvent{
		IntentID:             types.UUIDv7(),
		Kind:                 kind,
		StartNS:              st.firstTS,
		EndNS:                st.lastTS,
		ContributingEventIDs: append([]string(nil), st.events...),
		Attributes:           attrs,
		Meta:                 st.meta,
		Severity:             sev,
		Confidence:           conf,
	})
}

func (a *Aggregator) emitSock(st *sockState) {
	conf := 1.0
	if !st.closed {
		conf = 0.7
	}
	a.dispatch(types.IntentEvent{
		IntentID:             types.UUIDv7(),
		Kind:                 "NetworkExchange",
		StartNS:              st.firstTS,
		EndNS:                st.lastTS,
		ContributingEventIDs: append([]string(nil), st.events...),
		Attributes: map[string]string{
			"peer":  st.peer,
			"proto": st.proto,
			"tx":    fmt.Sprintf("%d", st.tx),
			"rx":    fmt.Sprintf("%d", st.rx),
		},
		Meta:       st.meta,
		Severity:   types.SeverityMedium,
		Confidence: conf,
	})
}

func appendCapped(xs []string, x string, cap int) []string {
	if cap <= 0 {
		return append(xs, x)
	}
	if len(xs) >= cap {
		// Drop oldest — keep the most recent contributing ids.
		xs = xs[1:]
	}
	return append(xs, x)
}

func joinArgv(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	// Keep the order deterministic; no quoting — callers can inspect raw.
	sorted := make([]string, len(argv))
	copy(sorted, argv)
	// Stable, deterministic representation: leave original order,
	// but normalize whitespace within each token.
	for i := range sorted {
		sorted[i] = normalizeToken(sorted[i])
	}
	return concatSep(sorted, " ")
}

func concatSep(xs []string, sep string) string {
	if len(xs) == 0 {
		return ""
	}
	n := 0
	for _, x := range xs {
		n += len(x) + len(sep)
	}
	out := make([]byte, 0, n)
	for i, x := range xs {
		if i > 0 {
			out = append(out, sep...)
		}
		out = append(out, x...)
	}
	return string(out)
}

func normalizeToken(s string) string {
	// Only collapse CR/NL to spaces so argvs stay single-line.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' || c == '\r' || c == '\t' {
			out = append(out, ' ')
		} else {
			out = append(out, c)
		}
	}
	return string(out)
}

// StateSnapshot is a debugging / metrics helper.
type StateSnapshot struct {
	FileKeys int
	SockKeys int
	ExecKeys int
	KeyDump  []string // deterministic summaries for test assertions
}

// Snapshot returns current counts; useful to confirm no leaks in tests.
func (a *Aggregator) Snapshot() StateSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := StateSnapshot{
		FileKeys: len(a.fileKeys),
		SockKeys: len(a.sockKeys),
		ExecKeys: len(a.execKeys),
	}
	for k := range a.fileKeys {
		s.KeyDump = append(s.KeyDump, fmt.Sprintf("file:%d:%d", k.TGID, k.FD))
	}
	for k := range a.sockKeys {
		s.KeyDump = append(s.KeyDump, fmt.Sprintf("sock:%d:%d", k.TGID, k.FD))
	}
	for k := range a.execKeys {
		s.KeyDump = append(s.KeyDump, fmt.Sprintf("exec:%d", k))
	}
	sort.Strings(s.KeyDump)
	return s
}
