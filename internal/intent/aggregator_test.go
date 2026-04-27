// SPDX-License-Identifier: Apache-2.0

package intent

import (
	"sync"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

type capturingEmitter struct {
	mu sync.Mutex
	ev []types.IntentEvent
}

func (c *capturingEmitter) emit(e types.IntentEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ev = append(c.ev, e)
}

func (c *capturingEmitter) drain() []types.IntentEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.ev
	c.ev = nil
	return out
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

func newAgg() (*Aggregator, *capturingEmitter, *fakeClock) {
	cap := &capturingEmitter{}
	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	a := NewAggregator(Config{IdleTimeout: 2 * time.Second, MaxPerKey: 8, NodeName: "n"}, cap.emit)
	a.SetClock(clk)
	return a, cap, clk
}

func TestFileReadThenClose(t *testing.T) {
	a, cap, _ := newAgg()
	meta := types.ContainerMeta{Namespace: "default", Pod: "p", Container: "c"}
	a.ObserveFileOpen(42, 5, "/etc/passwd", "O_RDONLY", "e1", 1000, meta)
	a.ObserveFileIO(42, 5, "read", 200, "e2", 1100)
	a.ObserveFileIO(42, 5, "read", 300, "e3", 1200)
	a.ObserveFileClose(42, 5, "e4", 1500)

	ev := cap.drain()
	if len(ev) != 1 {
		t.Fatalf("expected 1 event, got %d", len(ev))
	}
	i := ev[0]
	if i.Kind != "FileRead" {
		t.Fatalf("kind=%s", i.Kind)
	}
	if i.Attributes["path"] != "/etc/passwd" {
		t.Fatalf("path=%s", i.Attributes["path"])
	}
	if i.Attributes["bytes_read"] != "500" {
		t.Fatalf("bytes_read=%s", i.Attributes["bytes_read"])
	}
	if i.Confidence != 1.0 {
		t.Fatalf("closed intent should have confidence 1.0, got %v", i.Confidence)
	}
	if len(i.ContributingEventIDs) != 4 {
		t.Fatalf("events=%v", i.ContributingEventIDs)
	}
	if got := a.Snapshot(); got.FileKeys != 0 {
		t.Fatalf("state leak: %+v", got)
	}
}

func TestFileWriteClassifies(t *testing.T) {
	a, cap, _ := newAgg()
	a.ObserveFileOpen(1, 2, "/tmp/out", "O_WRONLY|O_CREAT", "a", 0, types.ContainerMeta{})
	a.ObserveFileIO(1, 2, "write", 512, "b", 1)
	a.ObserveFileClose(1, 2, "c", 2)
	ev := cap.drain()
	if ev[0].Kind != "FileWrite" {
		t.Fatalf("kind=%s", ev[0].Kind)
	}
}

// TestFileOpenKindFallbackFromFlags covers the Pkg 27 fallback: when BPF
// never reports byte counters (bytesRead=bytesWrite=0), the open-flag
// direction hint is what distinguishes FileRead from FileWrite. Without
// this fallback every open→close would collapse to "FileAccess" and the
// downstream detector would lose its read/write signal.
func TestFileOpenKindFallbackFromFlags(t *testing.T) {
	for _, tc := range []struct {
		flags    string
		wantKind string
	}{
		{"openr", "FileRead"},
		{"openw", "FileWrite"},
		{"openrw", "FileReadWrite"},
		{"", "FileAccess"},     // unknown — preserve pre-Pkg-27 behavior
		{"open", "FileAccess"}, // opaque — same
	} {
		t.Run(tc.flags, func(t *testing.T) {
			a, cap, _ := newAgg()
			a.ObserveFileOpen(1, 2, "/tmp/x", tc.flags, "a", 0, types.ContainerMeta{})
			a.ObserveFileClose(1, 2, "c", 2)
			ev := cap.drain()
			if len(ev) != 1 {
				t.Fatalf("expected 1 event, got %d", len(ev))
			}
			if ev[0].Kind != tc.wantKind {
				t.Fatalf("flags=%q kind=%q want %q", tc.flags, ev[0].Kind, tc.wantKind)
			}
		})
	}
}

func TestFileReopenEmitsPrior(t *testing.T) {
	a, cap, _ := newAgg()
	meta := types.ContainerMeta{Pod: "p"}
	a.ObserveFileOpen(1, 5, "/a", "", "e1", 1, meta)
	a.ObserveFileIO(1, 5, "read", 10, "e2", 2)
	// Reopen same fd (kernel recycles fd after close)
	a.ObserveFileOpen(1, 5, "/b", "", "e3", 3, meta)
	ev := cap.drain()
	if len(ev) != 1 || ev[0].Attributes["path"] != "/a" {
		t.Fatalf("expected /a emitted on reopen, got %+v", ev)
	}
	if ev[0].Confidence >= 1.0 {
		t.Fatalf("reopened file without close should have reduced confidence, got %v", ev[0].Confidence)
	}
}

func TestSocketExchange(t *testing.T) {
	a, cap, _ := newAgg()
	a.ObserveSocketConnect(10, 7, "1.2.3.4:443", "tcp", "e1", 100, types.ContainerMeta{})
	a.ObserveSocketIO(10, 7, "tx", 500, "e2", 110, types.ContainerMeta{})
	a.ObserveSocketIO(10, 7, "rx", 700, "e3", 120, types.ContainerMeta{})
	a.ObserveSocketClose(10, 7, "e4", 200)
	ev := cap.drain()
	if len(ev) != 1 {
		t.Fatalf("n=%d", len(ev))
	}
	if ev[0].Kind != "NetworkExchange" {
		t.Fatalf("kind=%s", ev[0].Kind)
	}
	if ev[0].Attributes["peer"] != "1.2.3.4:443" {
		t.Fatalf("peer=%s", ev[0].Attributes["peer"])
	}
	if ev[0].Attributes["tx"] != "500" || ev[0].Attributes["rx"] != "700" {
		t.Fatalf("bytes: %+v", ev[0].Attributes)
	}
}

func TestOnProcessExitFlushes(t *testing.T) {
	a, cap, _ := newAgg()
	a.ObserveFileOpen(99, 3, "/x", "", "e1", 0, types.ContainerMeta{})
	a.ObserveFileIO(99, 3, "write", 10, "e2", 1)
	a.ObserveSocketConnect(99, 4, "10.0.0.1:53", "udp", "e3", 2, types.ContainerMeta{})
	a.OnProcessExit(99, 100)
	ev := cap.drain()
	if len(ev) != 2 {
		t.Fatalf("expected 2 events, got %d", len(ev))
	}
	for _, e := range ev {
		if e.Confidence >= 1.0 {
			t.Fatalf("process-exit flushed events should have reduced confidence: %+v", e)
		}
	}
	if snap := a.Snapshot(); snap.FileKeys+snap.SockKeys != 0 {
		t.Fatalf("leak: %+v", snap)
	}
}

func TestReapIdleTimeout(t *testing.T) {
	a, cap, clk := newAgg()
	a.ObserveFileOpen(1, 1, "/tmp/a", "", "e1", 0, types.ContainerMeta{})
	a.ObserveFileIO(1, 1, "read", 10, "e2", 1)
	// Not enough time elapsed — shouldn't reap.
	n := a.Reap()
	if n != 0 {
		t.Fatalf("premature reap: %d", n)
	}
	clk.advance(3 * time.Second)
	n = a.Reap()
	if n != 1 {
		t.Fatalf("expected 1 reap, got %d", n)
	}
	if len(cap.drain()) != 1 {
		t.Fatalf("expected emit on reap")
	}
}

func TestExecProcessStart(t *testing.T) {
	a, cap, _ := newAgg()
	meta := types.ContainerMeta{Pod: "p"}
	a.ObserveExec(77, "/usr/bin/python3", []string{"python3", "app.py"}, "h", "e1", 1, meta)
	a.FinalizeExec(77, 10)
	ev := cap.drain()
	if len(ev) != 1 || ev[0].Kind != "ProcessStart" {
		t.Fatalf("got %+v", ev)
	}
	if ev[0].Attributes["binary"] != "/usr/bin/python3" {
		t.Fatalf("binary=%s", ev[0].Attributes["binary"])
	}
	if ev[0].Attributes["argv"] != "python3 app.py" {
		t.Fatalf("argv=%q", ev[0].Attributes["argv"])
	}
}

func TestMaxPerKeyDropsOldest(t *testing.T) {
	a, cap, _ := newAgg()
	a.ObserveFileOpen(1, 1, "/a", "", "first", 0, types.ContainerMeta{})
	for i := 0; i < 20; i++ {
		a.ObserveFileIO(1, 1, "read", 1, "io", uint64(i))
	}
	a.ObserveFileClose(1, 1, "close", 99)
	ev := cap.drain()
	if got := len(ev[0].ContributingEventIDs); got != 8 {
		t.Fatalf("cap should enforce len=8, got %d", got)
	}
	// "first" got dropped because of cap; "close" must still be present as last entry
	last := ev[0].ContributingEventIDs[len(ev[0].ContributingEventIDs)-1]
	if last != "close" {
		t.Fatalf("last contributing id should be close, got %s", last)
	}
}

func TestFlushDrains(t *testing.T) {
	a, cap, _ := newAgg()
	a.ObserveFileOpen(1, 1, "/a", "", "", 0, types.ContainerMeta{})
	a.ObserveSocketConnect(2, 1, "x:1", "tcp", "", 0, types.ContainerMeta{})
	a.ObserveExec(3, "/bin/sh", []string{"sh"}, "", "", 0, types.ContainerMeta{})
	n := a.Flush()
	if n != 3 {
		t.Fatalf("expected 3 flushes, got %d", n)
	}
	if got := len(cap.drain()); got != 3 {
		t.Fatalf("expected 3 emits, got %d", got)
	}
	snap := a.Snapshot()
	if snap.FileKeys+snap.SockKeys+snap.ExecKeys != 0 {
		t.Fatalf("flush should empty state: %+v", snap)
	}
}

// TestFileCloseWithStateSynthesizesMissingOpen covers the kernel-attached
// path on close: when the aggregator never saw the openat frame (attach
// race, LRU eviction) but the BPF side supplied path + open_ts on close,
// the aggregator must still emit a complete FileAccess intent with the
// correct path set.
func TestFileCloseWithStateSynthesizesMissingOpen(t *testing.T) {
	a, cap, _ := newAgg()
	meta := types.ContainerMeta{ContainerID: "cont-a"}
	// No ObserveFileOpen call — simulates a kernel-side open that user
	// space missed. ObserveFileCloseWithState must still produce an intent.
	a.ObserveFileCloseWithState(42, 5, "/var/log/app.log", "O_WRONLY", "e1",
		/*openTsNs*/ uint64(1_000_000_000) /*ts*/, uint64(2_000_000_000), meta)

	ev := cap.drain()
	if len(ev) != 1 {
		t.Fatalf("expected 1 event, got %d", len(ev))
	}
	i := ev[0]
	if i.Attributes["path"] != "/var/log/app.log" {
		t.Errorf("path = %q, want /var/log/app.log", i.Attributes["path"])
	}
	if i.StartNS != 1_000_000_000 {
		t.Errorf("StartNS = %d, want open_ts_ns", i.StartNS)
	}
	if i.Meta.ContainerID != "cont-a" {
		t.Errorf("meta container = %q", i.Meta.ContainerID)
	}
	if i.Confidence != 1.0 {
		t.Errorf("closed intent should have confidence 1.0, got %v", i.Confidence)
	}
	if got := a.Snapshot(); got.FileKeys != 0 {
		t.Errorf("state leak after close-with-state: %+v", got)
	}
}

// TestFileCloseWithStatePrefersExistingState: when user-space already had
// an open key for (tgid, fd), kernel-attached path on close is redundant.
// ObserveFileCloseWithState should finalize the existing state without
// clobbering it.
func TestFileCloseWithStatePrefersExistingState(t *testing.T) {
	a, cap, _ := newAgg()
	meta := types.ContainerMeta{ContainerID: "cont-b"}
	a.ObserveFileOpen(42, 5, "/etc/real", "O_RDONLY", "e1", 1000, meta)
	a.ObserveFileIO(42, 5, "read", 100, "e2", 1100)
	// Kernel passes a different path on close — existing state must win,
	// otherwise stale kl_fd_state entries could clobber fresher user-space
	// observations. emitFile should still use /etc/real.
	a.ObserveFileCloseWithState(42, 5, "/etc/stale", "", "e3",
		/*openTsNs*/ 900 /*ts*/, 1500, meta)

	ev := cap.drain()
	if len(ev) != 1 {
		t.Fatalf("expected 1 event, got %d", len(ev))
	}
	if ev[0].Attributes["path"] != "/etc/real" {
		t.Errorf("path = %q, want /etc/real (existing state wins)", ev[0].Attributes["path"])
	}
}

// TestFileCloseWithStateEmptyPathNoOp: the fallback path through
// ObserveFileCloseWithState when there's no state AND no kernel path
// must be a no-op (matches ObserveFileClose's existing semantics).
func TestFileCloseWithStateEmptyPathNoOp(t *testing.T) {
	a, cap, _ := newAgg()
	a.ObserveFileCloseWithState(1, 2, "", "", "e", 0, 0, types.ContainerMeta{})
	if ev := cap.drain(); len(ev) != 0 {
		t.Errorf("no-op close should emit nothing, got %d", len(ev))
	}
	if got := a.Snapshot(); got.FileKeys != 0 {
		t.Errorf("state leak: %+v", got)
	}
}

// TestEmitClampsReversedTimestamps guards the dispatch normalizer:
// BPF tracepoints fire on multiple CPUs and userspace drains the rings
// concurrently, so timestamps can land out of order; ObserveFileCloseWithState
// can also pull a stale openTs from a recycled kl_fd_state slot. Both
// surface as EndNS < StartNS in the emitted IntentEvent. Downstream
// consumers treat that as corrupt input — clamp end := start so the wire
// stays well-formed without papering over the underlying ordering quirk
// in the source data (the original timestamps are still recoverable from
// the contributing event IDs if a debugger needs them).
//
// Reproduction path: ObserveFileCloseWithState with no prior open and a
// stale-from-kernel openTsNs that's larger than the close ts. The fresh
// state synthesizer copies firstTS = openTsNs and lastTS = ts, so without
// the dispatch clamp emitFile would publish start > end.
func TestEmitClampsReversedTimestamps(t *testing.T) {
	a, cap, _ := newAgg()
	meta := types.ContainerMeta{Namespace: "default", Pod: "p"}

	// No ObserveFileOpen first — go straight to close-with-state so the
	// !ok branch creates state from openTsNs (stale "future" value).
	a.ObserveFileCloseWithState(42, 5, "/tmp/x", "", "e1",
		/*openTsNs*/ 2000 /*ts*/, 1500, meta)

	ev := cap.drain()
	if len(ev) != 1 {
		t.Fatalf("expected 1 event, got %d", len(ev))
	}
	if ev[0].EndNS < ev[0].StartNS {
		t.Errorf("dispatch did not clamp: start=%d end=%d", ev[0].StartNS, ev[0].EndNS)
	}
	if ev[0].EndNS != ev[0].StartNS {
		t.Errorf("after clamp end should equal start, got start=%d end=%d", ev[0].StartNS, ev[0].EndNS)
	}
}
