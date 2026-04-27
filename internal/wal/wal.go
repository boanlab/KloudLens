// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package wal implements a bounded append-only write-ahead log for the
// agent's in-flight IntentEvent stream. It lets subscribers
// resume from a cursor after disconnects without losing events, up to the
// retention window (TTL + size cap, LRU trim).
package wal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

// Entry is one record in the WAL — a sequence number assigned by the
// WAL itself, plus the payload (intent, deviation, or raw syscall) and a
// node-scoped stream tag. Exactly one of Event/Deviation/Syscall is
// populated per entry; the stream field is the authoritative discriminator.
type Entry struct {
	Seq       uint64                `json:"seq"`
	Stream    string                `json:"stream"` // intent | deviation | raw | graph-edge | ...
	Event     types.IntentEvent     `json:"event"`
	Deviation *types.DeviationEvent `json:"deviation,omitempty"`
	Syscall   *types.SyscallEvent   `json:"syscall,omitempty"`
	TS        int64                 `json:"ts_ns"` // time.Now.UnixNano when appended
}

// Options configures the WAL.
type Options struct {
	Dir         string
	MaxBytes    int64         // soft cap; trim oldest segments on overflow
	SegmentSize int64         // rotate current segment at this size
	TTL         time.Duration // remove segments older than this
}

// WAL is a single append-only log. Events are grouped by `stream` so a
// reader can subscribe to just one subset. Internally segments are
// JSONL files — each line is one Entry.
type WAL struct {
	opts     Options
	mu       sync.Mutex
	seq      uint64
	segments []*segment
	cur      *segment

	// overflowTrims counts how many segments GC dropped to honor MaxBytes.
	// Surfaced on /metrics as kloudlens_wal_overflow_total so operators can
	// detect chronic under-provisioning of the retention cap.
	overflowTrims uint64
}

// OverflowCount returns the cumulative number of size-cap-induced segment
// trims since startup. Safe to call concurrently with Append/GC.
func (w *WAL) OverflowCount() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.overflowTrims
}

type segment struct {
	path      string
	startSeq  uint64
	endSeq    uint64
	bytes     int64
	createdAt int64
	f         *os.File
}

// Open creates or resumes a WAL in Dir. If segments exist, their seq
// numbers are reloaded so subsequent appends continue the sequence.
func Open(opts Options) (*WAL, error) {
	if opts.Dir == "" {
		return nil, errors.New("wal: empty dir")
	}
	if opts.SegmentSize <= 0 {
		opts.SegmentSize = 32 << 20
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 2 << 30
	}
	if opts.TTL <= 0 {
		opts.TTL = 2 * time.Hour
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, err
	}
	w := &WAL{opts: opts}
	if err := w.reload(); err != nil {
		return nil, err
	}
	if len(w.segments) > 0 {
		last := w.segments[len(w.segments)-1]
		w.seq = last.endSeq
	}
	if err := w.openSegment(); err != nil {
		return nil, err
	}
	return w, nil
}

// Append writes an intent entry, assigning the next seq. Rotates the active
// segment when it crosses SegmentSize. Returns the assigned seq.
func (w *WAL) Append(stream string, ev types.IntentEvent) (uint64, error) {
	return w.writeEntry(Entry{Stream: stream, Event: ev})
}

// AppendDeviation writes a deviation entry to the "deviation" stream.
// Kept separate from Append so the caller doesn't have to fabricate an
// empty IntentEvent to route a DeviationEvent through the WAL; "deviation"
// is a first-class cursor stream.
func (w *WAL) AppendDeviation(ev types.DeviationEvent) (uint64, error) {
	dv := ev
	return w.writeEntry(Entry{Stream: "deviation", Deviation: &dv})
}

// AppendSyscall writes a raw SyscallEvent to the "raw" stream. Volume is
// much higher than intents, so callers typically gate this with a config
// flag.
func (w *WAL) AppendSyscall(ev types.SyscallEvent) (uint64, error) {
	sc := ev
	return w.writeEntry(Entry{Stream: "raw", Syscall: &sc})
}

// writeEntry stamps Seq+TS and persists the entry. Callers fill Stream and
// exactly one of Event/Deviation/Syscall.
func (w *WAL) writeEntry(entry Entry) (uint64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur == nil || w.cur.f == nil {
		return 0, ErrClosed
	}
	w.seq++
	entry.Seq = w.seq
	entry.TS = time.Now().UnixNano()
	line, err := json.Marshal(entry)
	if err != nil {
		return 0, err
	}
	if _, err := w.cur.f.Write(line); err != nil {
		return 0, err
	}
	if _, err := w.cur.f.Write([]byte("\n")); err != nil {
		return 0, err
	}
	w.cur.bytes += int64(len(line)) + 1
	w.cur.endSeq = w.seq
	if w.cur.bytes >= w.opts.SegmentSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	return w.seq, nil
}

// LastSeq returns the most recently assigned sequence (0 if empty).
func (w *WAL) LastSeq() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seq
}

// ReadFrom streams entries with seq > fromSeq through the callback. If
// fromSeq < oldest retained seq, ErrCursorExpired is returned — callers
// should consult `on_expired` policy.
func (w *WAL) ReadFrom(fromSeq uint64, stream string, cb func(Entry) error) error {
	// Snapshot segment metadata under the lock. Copying *segment pointers
	// would race with Append — Append mutates cur.endSeq / cur.bytes after
	// ReadFrom has unlocked — so we capture the immutable path + a point-
	// in-time endSeq into a small value struct the iteration below uses.
	type segView struct {
		path   string
		endSeq uint64
	}
	w.mu.Lock()
	if len(w.segments) == 0 {
		w.mu.Unlock()
		return nil
	}
	oldest := w.segments[0].startSeq
	views := make([]segView, len(w.segments))
	for i, s := range w.segments {
		views[i] = segView{path: s.path, endSeq: s.endSeq}
	}
	w.mu.Unlock()
	if fromSeq > 0 && fromSeq < oldest-1 {
		return ErrCursorExpired
	}
	for _, s := range views {
		if s.endSeq < fromSeq {
			continue
		}
		f, err := os.Open(s.path)
		if err != nil {
			return err
		}
		dec := json.NewDecoder(f)
		for dec.More() {
			var e Entry
			if err := dec.Decode(&e); err != nil {
				_ = f.Close()
				return err
			}
			if e.Seq <= fromSeq {
				continue
			}
			if stream != "" && e.Stream != stream {
				continue
			}
			if err := cb(e); err != nil {
				_ = f.Close()
				return err
			}
		}
		_ = f.Close()
	}
	return nil
}

// GC trims segments older than TTL or beyond MaxBytes. Safe to call
// periodically from a janitor goroutine.
func (w *WAL) GC() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now().UnixNano()
	ttl := int64(w.opts.TTL)

	// 1) TTL
	keep := w.segments[:0]
	for _, s := range w.segments {
		if s == w.cur {
			keep = append(keep, s)
			continue
		}
		if now-s.createdAt > ttl {
			_ = os.Remove(s.path)
			continue
		}
		keep = append(keep, s)
	}
	w.segments = keep

	// 2) Size cap
	var total int64
	for _, s := range w.segments {
		total += s.bytes
	}
	for total > w.opts.MaxBytes && len(w.segments) > 1 {
		victim := w.segments[0]
		if victim == w.cur {
			break
		}
		_ = os.Remove(victim.path)
		total -= victim.bytes
		w.segments = w.segments[1:]
		w.overflowTrims++
	}
	return nil
}

// RunJanitor ticks every interval and calls GC, exiting when ctx is
// cancelled. Without this, --wal-ttl and --wal-max-bytes are dead
// settings: the WAL would grow unbounded (modulo SegmentSize rotation)
// until process exit, and OverflowCount would stay at zero even when
// the retention cap was exceeded. A non-positive interval parks the
// janitor on ctx.Done only so operators can disable the cadence
// explicitly without silently losing GC.
func (w *WAL) RunJanitor(ctx context.Context, interval time.Duration) {
	w.RunJanitorWithReconfig(ctx, interval, nil)
}

// RunJanitorWithReconfig is RunJanitor plus a live-reconfigure channel:
// any duration sent on `changes` swaps the ticker cadence without
// restarting the goroutine, so `klctl config set wal-gc-every=…` can
// retarget GC pressure during incident response. Sending <= 0 on
// `changes` parks the janitor (no GC until either another change
// re-enables it or ctx is cancelled). A nil channel keeps the previous
// fire-and-forget semantics.
func (w *WAL) RunJanitorWithReconfig(ctx context.Context, interval time.Duration, changes <-chan time.Duration) {
	var t *time.Ticker
	var tickC <-chan time.Time
	if interval > 0 {
		t = time.NewTicker(interval)
		tickC = t.C
	}
	defer func() {
		if t != nil {
			t.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-changes:
			if t != nil {
				t.Stop()
				t = nil
				tickC = nil
			}
			if d > 0 {
				t = time.NewTicker(d)
				tickC = t.C
			}
		case <-tickC:
			_ = w.GC()
		}
	}
}

// Close flushes and closes the current segment.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur != nil && w.cur.f != nil {
		err := w.cur.f.Close()
		w.cur.f = nil
		return err
	}
	return nil
}

func (w *WAL) rotate() error {
	if w.cur != nil && w.cur.f != nil {
		_ = w.cur.f.Close()
		w.cur.f = nil
	}
	return w.openSegment()
}

func (w *WAL) openSegment() error {
	name := fmt.Sprintf("wal-%020d.jsonl", w.seq+1)
	p := filepath.Join(w.opts.Dir, name)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- p is derived from opts.Dir (operator-configured) + a segment name we just generated
	if err != nil {
		return err
	}
	s := &segment{path: p, startSeq: w.seq + 1, endSeq: w.seq, createdAt: time.Now().UnixNano(), f: f}
	w.cur = s
	w.segments = append(w.segments, s)
	return nil
}

// reload scans the dir for existing segments and parses their seq range.
// Used both at Open for resume and in tests.
func (w *WAL) reload() error {
	entries, err := os.ReadDir(w.opts.Dir)
	if err != nil {
		return err
	}
	var segs []*segment
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) < 5 || name[:4] != "wal-" {
			continue
		}
		full := filepath.Join(w.opts.Dir, name)
		info, err := os.Stat(full)
		if err != nil {
			continue
		}
		s := &segment{
			path:      full,
			bytes:     info.Size(),
			createdAt: info.ModTime().UnixNano(),
		}
		// Parse seq range by reading the file (small cost at startup only).
		f, err := os.Open(full) // #nosec G304 -- full is derived from opts.Dir (operator-configured) + a glob-matched segment name we just generated
		if err != nil {
			continue
		}
		dec := json.NewDecoder(f)
		first := true
		for dec.More() {
			var e Entry
			if err := dec.Decode(&e); err != nil {
				break
			}
			if first {
				s.startSeq = e.Seq
				first = false
			}
			s.endSeq = e.Seq
		}
		_ = f.Close()
		if !first {
			segs = append(segs, s)
		}
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].startSeq < segs[j].startSeq })
	w.segments = segs
	return nil
}

// ErrCursorExpired means the subscriber's resume seq is older than
// anything retained in the WAL; the caller should fall back per
var ErrCursorExpired = errors.New("wal: cursor expired")

// ErrClosed is returned by Append/AppendDeviation when the WAL has been
// Closed (or its segment file was never opened). Previously these paths
// nil-derefed on the first post-Close write; returning a plain error lets
// the SubscribeServer bump its wal_append_errors counter and drop the
// event instead of panicking the pipeline.
var ErrClosed = errors.New("wal: closed")

// TrimForTest bumps the oldest segment's startSeq so ReadFrom(fromSeq<x)
// yields ErrCursorExpired without actually deleting files. Test-only.
func (w *WAL) TrimForTest(startSeq uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.segments) > 0 {
		w.segments[0].startSeq = startSeq
	}
}
