// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package wal

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

func TestWALAppendReadFromRoundtrip(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 256, MaxBytes: 1 << 20, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		seq, err := w.Append("intent", types.IntentEvent{IntentID: "evt", Kind: "FileRead"})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if seq != uint64(i+1) {
			t.Errorf("seq = %d, want %d", seq, i+1)
		}
	}
	var got []uint64
	if err := w.ReadFrom(0, "intent", func(e Entry) error {
		got = append(got, e.Seq)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 20 {
		t.Errorf("got %d entries, want 20", len(got))
	}
	// partial resume
	got = got[:0]
	_ = w.ReadFrom(15, "intent", func(e Entry) error {
		got = append(got, e.Seq)
		return nil
	})
	if len(got) != 5 {
		t.Errorf("got %d entries for seq>15, want 5", len(got))
	}
	_ = w.Close()

	// Reopen and verify seq continues from 20.
	w2, err := Open(Options{Dir: dir, SegmentSize: 256})
	if err != nil {
		t.Fatal(err)
	}
	if w2.LastSeq() != 20 {
		t.Errorf("lastSeq after reopen = %d, want 20", w2.LastSeq())
	}
	seq, _ := w2.Append("intent", types.IntentEvent{IntentID: "e21", Kind: "FileRead"})
	if seq != 21 {
		t.Errorf("next seq = %d, want 21", seq)
	}
	_ = w2.Close()
}

func TestWALStreamFilter(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(Options{Dir: dir})
	_, _ = w.Append("intent", types.IntentEvent{IntentID: "a"})
	_, _ = w.Append("deviation", types.IntentEvent{IntentID: "b"})
	_, _ = w.Append("intent", types.IntentEvent{IntentID: "c"})

	var kinds []string
	_ = w.ReadFrom(0, "intent", func(e Entry) error {
		kinds = append(kinds, e.Event.IntentID)
		return nil
	})
	if len(kinds) != 2 || kinds[0] != "a" || kinds[1] != "c" {
		t.Errorf("filtered = %v", kinds)
	}
	_ = w.Close()
}

// Deviation entries have to survive reopen so cursor-based resume of the
// SubscribeDeviations envelope path works across agent restarts (plan,
// ). Regression: pre-AppendDeviation the WAL could only express
// IntentEvents, so deviations were live-only and lost on restart.
func TestWALAppendDeviationPersists(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 1 << 20, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Append("intent", types.IntentEvent{IntentID: "i1", Kind: "FileRead"})
	devSeq, err := w.AppendDeviation(types.DeviationEvent{
		DeviationID:    "d1",
		ProfileID:      "profile-x",
		Kind:           "new_exec",
		DeviationScore: 0.8,
		Evidence:       "unseen binary /usr/bin/cron",
	})
	if err != nil {
		t.Fatal(err)
	}
	if devSeq != 2 {
		t.Fatalf("devSeq=%d, want 2", devSeq)
	}
	_, _ = w.Append("intent", types.IntentEvent{IntentID: "i2", Kind: "FileWrite"})
	_ = w.Close()

	// Reopen and replay the deviation stream only.
	w2, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	var got []Entry
	if err := w2.ReadFrom(0, "deviation", func(e Entry) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("deviation replay got %d entries, want 1", len(got))
	}
	e := got[0]
	if e.Stream != "deviation" {
		t.Errorf("stream=%q, want deviation", e.Stream)
	}
	if e.Deviation == nil {
		t.Fatalf("Deviation pointer nil — entry dropped payload on round-trip")
	}
	if e.Deviation.DeviationID != "d1" || e.Deviation.Kind != "new_exec" {
		t.Errorf("payload lost fields: %+v", e.Deviation)
	}
	if e.Deviation.DeviationScore != 0.8 {
		t.Errorf("score=%v, want 0.8", e.Deviation.DeviationScore)
	}

	// Intent-stream replay must skip the deviation row — the stream filter
	// is the only discriminator, so a regression here would fan deviations
	// out to intent consumers.
	got = got[:0]
	_ = w2.ReadFrom(0, "intent", func(e Entry) error {
		got = append(got, e)
		return nil
	})
	if len(got) != 2 {
		t.Fatalf("intent replay got %d entries, want 2", len(got))
	}
	for _, e := range got {
		if e.Deviation != nil {
			t.Errorf("intent row carries Deviation payload: %+v", e)
		}
	}
}

func TestWALGCByTTL(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(Options{Dir: dir, SegmentSize: 32, TTL: time.Nanosecond})
	// Force multiple segments.
	for i := 0; i < 10; i++ {
		_, _ = w.Append("intent", types.IntentEvent{IntentID: "e", Kind: "FileRead"})
	}
	time.Sleep(10 * time.Millisecond)
	if err := w.GC(); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "wal-*.jsonl"))
	if len(matches) > 2 {
		t.Errorf("after GC: %d segments (expected current only)", len(matches))
	}
	_ = w.Close()
}

// TestWALGCByMaxBytesAdvancesOverflow ensures the size-cap path actually
// trims and bumps OverflowCount. Regression: the previous state shipped
// with no janitor wired from main.go, so --wal-max-bytes was a dead
// setting and operators had no way to tell the cap was under-sized.
func TestWALGCByMaxBytesAdvancesOverflow(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(Options{Dir: dir, SegmentSize: 32, MaxBytes: 64, TTL: time.Hour})
	for i := 0; i < 20; i++ {
		_, _ = w.Append("intent", types.IntentEvent{IntentID: "e", Kind: "FileRead"})
	}
	if err := w.GC(); err != nil {
		t.Fatal(err)
	}
	if got := w.OverflowCount(); got == 0 {
		t.Errorf("OverflowCount=0 after GC with MaxBytes=64 across 20 writes; expected >0")
	}
	_ = w.Close()
}

// TestWALRunJanitorTicks wires the same janitor goroutine main.go uses()
// and verifies GC actually runs on its cadence. A regression here would
// mean --wal-gc-every never fires, which is exactly the class of bug the
// janitor was added to fix.
func TestWALRunJanitorTicks(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(Options{Dir: dir, SegmentSize: 32, TTL: time.Nanosecond})
	for i := 0; i < 10; i++ {
		_, _ = w.Append("intent", types.IntentEvent{IntentID: "e", Kind: "FileRead"})
	}
	// Let TTL elapse before the janitor ticks so the first sweep trims.
	time.Sleep(5 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.RunJanitor(ctx, 2*time.Millisecond)
	}()
	// Give the ticker a handful of opportunities to fire.
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	matches, _ := filepath.Glob(filepath.Join(dir, "wal-*.jsonl"))
	if len(matches) > 2 {
		t.Errorf("after janitor ran: %d segments retained; TTL sweep did not fire", len(matches))
	}
	_ = w.Close()
}

// TestWALRunJanitorZeroIntervalParks verifies that --wal-gc-every=0 is
// honored as "never" instead of silently busy-looping. The goroutine
// must return promptly on ctx cancel regardless.
func TestWALRunJanitorZeroIntervalParks(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(Options{Dir: dir})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.RunJanitor(ctx, 0)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("RunJanitor(ctx, 0) did not return on ctx.Done")
	}
	_ = w.Close()
}

// TestWALRunJanitorReconfigEnablesAfterPark verifies the "park-then-enable"
// transition operators can reach through `klctl config set
// wal-gc-every=…`: a janitor started with interval=0 must NOT GC, then
// after a positive duration arrives on the changes channel the next tick
// must actually trim overdue segments. Without this, the live-reconfig
// path is advertised but the ticker never gets (re)armed.
func TestWALRunJanitorReconfigEnablesAfterPark(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(Options{Dir: dir, SegmentSize: 32, TTL: time.Nanosecond})
	for i := 0; i < 10; i++ {
		_, _ = w.Append("intent", types.IntentEvent{IntentID: "e", Kind: "FileRead"})
	}
	time.Sleep(5 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	changes := make(chan time.Duration, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.RunJanitorWithReconfig(ctx, 0, changes)
	}()
	// Parked: nothing should happen. Let enough real time pass that any
	// accidental ticker would have fired multiple times.
	time.Sleep(20 * time.Millisecond)
	before, _ := filepath.Glob(filepath.Join(dir, "wal-*.jsonl"))

	// Live-enable; the next few ticks must collapse retention.
	changes <- 2 * time.Millisecond
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	after, _ := filepath.Glob(filepath.Join(dir, "wal-*.jsonl"))
	if len(after) >= len(before) {
		t.Errorf("reconfig did not arm janitor: before=%d after=%d", len(before), len(after))
	}
	if len(after) > 2 {
		t.Errorf("post-reconfig retention still fat: %d segments", len(after))
	}
	_ = w.Close()
}

// TestWALRunJanitorReconfigDisablesOnZero verifies the reverse transition:
// a running janitor that receives 0 on `changes` must park, leaving
// retention alone until either a positive duration re-arms it or the
// context is cancelled. Regression guard for operators temporarily
// silencing GC during a backfill investigation.
func TestWALRunJanitorReconfigDisablesOnZero(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(Options{Dir: dir, SegmentSize: 32, TTL: time.Hour})
	for i := 0; i < 5; i++ {
		_, _ = w.Append("intent", types.IntentEvent{IntentID: "e", Kind: "FileRead"})
	}
	ctx, cancel := context.WithCancel(context.Background())
	changes := make(chan time.Duration, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.RunJanitorWithReconfig(ctx, 1*time.Millisecond, changes)
	}()
	// Hand the goroutine time to enter its select and then park it.
	changes <- 0
	// If the ticker is truly stopped, GC isn't running, so no races on
	// the segments slice occur when we cancel below.
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("janitor did not exit after park + cancel")
	}
	_ = w.Close()
}

func TestWALCursorExpired(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(Options{Dir: dir, SegmentSize: 32, TTL: time.Hour})
	for i := 0; i < 5; i++ {
		_, _ = w.Append("intent", types.IntentEvent{IntentID: "e"})
	}
	// Reach into internals: drop the only segment manually to simulate
	// trim beyond cursor.
	w.mu.Lock()
	w.segments[0].startSeq = 100 // pretend oldest has been trimmed
	w.mu.Unlock()
	err := w.ReadFrom(1, "intent", func(Entry) error { return nil })
	if !errors.Is(err, ErrCursorExpired) {
		t.Errorf("got %v, want ErrCursorExpired", err)
	}
	_ = w.Close()
}
