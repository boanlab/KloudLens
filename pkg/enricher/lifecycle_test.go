// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package enricher

import (
	"context"
	"testing"
	"time"
)

// TestEnricherStartRunsImmediateScan: Start always does one synchronous scan
// before returning so the first batch of intents already sees populated NS
// metadata. Without this, agents would emit ~30 s of NS-only Meta on cold
// boot — the precise window where operators most often verify enrichment.
func TestEnricherStartRunsImmediateScan(t *testing.T) {
	root := t.TempDir()
	writePID(t, root, 100,
		"pid:[4026532001]", "mnt:[4026532002]",
		"0::/kubepods.slice/cri-containerd-"+hex64("c1")+".scope")

	e := NewEnricher(Options{Proc: &ProcScanner{Root: root}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Start(ctx)
	defer e.Stop()

	got := e.Resolve(4026532001, 4026532002)
	if got.ContainerID != hex64("c1") {
		t.Errorf("Start did not perform immediate scan: %+v", got)
	}
}

// TestEnricherStartTicksOnInterval: with a non-zero RescanInterval, the
// background goroutine must keep refreshing the NS map. We seed a new
// container after Start has finished its initial scan and assert the next
// tick picks it up without a manual Rescan call.
func TestEnricherStartTicksOnInterval(t *testing.T) {
	root := t.TempDir()

	e := NewEnricher(Options{
		Proc:           &ProcScanner{Root: root},
		RescanInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Start(ctx)
	defer e.Stop()

	// New container appears AFTER Start's initial scan ran.
	writePID(t, root, 200,
		"pid:[4026532010]", "mnt:[4026532011]",
		"0::/kubepods.slice/cri-containerd-"+hex64("aa")+".scope")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got := e.Resolve(4026532010, 4026532011)
		if got.ContainerID == hex64("aa") {
			return // periodic tick saw it
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("ticker did not pick up new container within 2s")
}

// TestEnricherStopIsIdempotent: a second Stop must not block, double-decrement,
// or panic — the wait group is guarded by an atomic CAS so callers that wire
// Stop into both ctx-cancel and an explicit Close path stay safe.
func TestEnricherStopIsIdempotent(t *testing.T) {
	e := NewEnricher(Options{Proc: &ProcScanner{Root: t.TempDir()}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Start(ctx)

	done := make(chan struct{})
	go func() {
		e.Stop()
		e.Stop()
		close(done)
	}()
	select {
	case <-done:
		// ok
	case <-time.After(500 * time.Millisecond):
		t.Errorf("second Stop blocked")
	}
}

// TestEnricherStartAfterStopIsNoOp: once stopped, Start should not re-launch
// any goroutines (the stopped flag latches). Otherwise a misuse pattern
// (Stop → Start) would silently leak workers.
func TestEnricherStartAfterStopIsNoOp(t *testing.T) {
	e := NewEnricher(Options{
		Proc:           &ProcScanner{Root: t.TempDir()},
		RescanInterval: 5 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Start(ctx)
	e.Stop()
	// Re-Start: should not block, should not launch a runner.
	done := make(chan struct{})
	go func() {
		e.Start(ctx)
		close(done)
	}()
	select {
	case <-done:
		// ok
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Start after Stop blocked")
	}
}

// TestEnricherStats reports cache sizes and NS hit/miss counters; the
// daemon prints these on its periodic stats line and the metrics exporter
// surfaces NSSize / CRISize as gauges. A regression that left them at zero
// would silently mislead operators about agent health.
func TestEnricherStats(t *testing.T) {
	root := t.TempDir()
	writePID(t, root, 100,
		"pid:[4026532001]", "mnt:[4026532002]",
		"0::/kubepods.slice/cri-containerd-"+hex64("c1")+".scope")
	e := NewEnricher(Options{Proc: &ProcScanner{Root: root}})
	e.cri.Replace([]CRIRecord{{ContainerID: hex64("c1"), PodName: "p1"}})
	e.Rescan(context.Background())

	// Hit + miss to drive the counters.
	_ = e.Resolve(4026532001, 4026532002) // hit
	_ = e.Resolve(4026539999, 4026539998) // miss

	st := e.Stats()
	if st.NSSize == 0 {
		t.Errorf("NSSize=0 after scan with one container")
	}
	if st.CRISize != 1 {
		t.Errorf("CRISize=%d, want 1", st.CRISize)
	}
	if st.NSHits == 0 {
		t.Errorf("NSHits=0 after a successful Resolve")
	}
	if st.NSMisses == 0 {
		t.Errorf("NSMisses=0 after an unmatched Resolve")
	}
}
