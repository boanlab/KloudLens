// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/internal/downgrade"
	"github.com/boanlab/kloudlens/internal/sensor"
)

// fakeUsage feeds scripted ringbuf-usage readings to the supervisor. The
// sequence is replayed once; after it's drained `tail` is returned
// forever so the supervisor's ticker has something stable to read
// during shutdown.
type fakeUsage struct {
	mu   sync.Mutex
	seq  []float64
	tail float64
	idx  int
}

func (f *fakeUsage) Counters() (uint64, uint64, uint64, uint64, float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.idx < len(f.seq) {
		v := f.seq[f.idx]
		f.idx++
		return 0, 0, 0, 0, v
	}
	return 0, 0, 0, 0, f.tail
}

func (f *fakeUsage) drained() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.idx >= len(f.seq)
}

// fakeSink records every sampling rate the supervisor tries to apply.
// rateErr is returned from SetBulkSamplingRate — tests exercise both
// the happy path and ErrSamplerUnavailable.
type fakeSink struct {
	mu      sync.Mutex
	rates   []uint32
	rateErr error
}

func (s *fakeSink) SetBulkSamplingRate(r uint32) error {
	s.mu.Lock()
	s.rates = append(s.rates, r)
	err := s.rateErr
	s.mu.Unlock()
	return err
}

func (s *fakeSink) snapshot() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uint32, len(s.rates))
	copy(out, s.rates)
	return out
}

func TestSupervisorEscalatesAndDeEscalates(t *testing.T) {
	src := &fakeUsage{
		// Walk through every transition: normal → sampled → heavily →
		// critical → step-down by hysteresis.
		seq:  []float64{0.05, 0.61, 0.81, 0.96, 0.10, 0.10, 0.10, 0.10},
		tail: 0.10,
	}
	sink := &fakeSink{}
	ctrl := downgrade.New(downgrade.DefaultThresholds(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runDowngradeSupervisor(ctx, 5*time.Millisecond, ctrl, src, sink, io.Discard)
		close(done)
	}()

	// Wait for the scripted readings to be consumed.
	deadline := time.After(2 * time.Second)
	for !src.drained() {
		select {
		case <-deadline:
			t.Fatal("scripted readings never drained")
		case <-time.After(5 * time.Millisecond):
		}
	}
	// Give the supervisor one more tick to flush the final de-escalation.
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	rates := sink.snapshot()
	if len(rates) < 2 {
		t.Fatalf("expected multiple sampling rate writes, got %v", rates)
	}
	// First write must be the Normal level's 1/1 (the applyLevel call
	// the supervisor does before entering its loop).
	if rates[0] != 1 {
		t.Errorf("first rate = %d, want 1 (normal)", rates[0])
	}
	// Among the subsequent writes we must see 2 (sampled), 10 (heavily),
	// and the DropAll sentinel (critical-only).
	seen := map[uint32]bool{}
	for _, r := range rates {
		seen[r] = true
	}
	for _, want := range []uint32{2, 10, sensor.BulkSamplingDropAll} {
		if !seen[want] {
			t.Errorf("missing rate %d in sequence %v", want, rates)
		}
	}
	// Controller must end below critical — usage settled at 0.10 which
	// is below RecoveryDown (0.40), so the hysteresis path should have
	// walked the level back down.
	if ctrl.Level() >= downgrade.LevelCriticalOnly {
		t.Errorf("final level = %s, want demoted below critical_only", ctrl.Level())
	}
}

func TestSupervisorTolerantOfSamplerUnavailable(t *testing.T) {
	src := &fakeUsage{tail: 0.61}
	sink := &fakeSink{rateErr: sensor.ErrSamplerUnavailable}
	ctrl := downgrade.New(downgrade.DefaultThresholds(), nil)

	buf := &bytes.Buffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runDowngradeSupervisor(ctx, 5*time.Millisecond, ctrl, src, sink, buf)
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	// ErrSamplerUnavailable must be swallowed silently — the log should
	// have transition lines but no "sampling_rate=... failed" line.
	if bytes.Contains(buf.Bytes(), []byte("failed:")) {
		t.Errorf("expected silent tolerance of ErrSamplerUnavailable, got log:\n%s", buf.String())
	}
}

func TestSupervisorSurfacesUnknownSinkErrors(t *testing.T) {
	src := &fakeUsage{tail: 0.61}
	boom := errors.New("bpf map write: broken pipe")
	sink := &fakeSink{rateErr: boom}
	ctrl := downgrade.New(downgrade.DefaultThresholds(), nil)

	buf := &bytes.Buffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runDowngradeSupervisor(ctx, 5*time.Millisecond, ctrl, src, sink, buf)
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	if !bytes.Contains(buf.Bytes(), []byte("broken pipe")) {
		t.Errorf("expected error surfaced in log; got:\n%s", buf.String())
	}
}

func TestSupervisorExitsOnCancel(t *testing.T) {
	src := &fakeUsage{tail: 0.0}
	sink := &fakeSink{}
	ctrl := downgrade.New(downgrade.DefaultThresholds(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	var returned atomic.Bool
	done := make(chan struct{})
	go func() {
		runDowngradeSupervisor(ctx, 10*time.Millisecond, ctrl, src, sink, io.Discard)
		returned.Store(true)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("supervisor did not exit after ctx cancel")
	}
	if !returned.Load() {
		t.Fatal("supervisor did not return")
	}
}

func TestSamplingRateForLevel(t *testing.T) {
	cases := []struct {
		lvl  downgrade.Level
		want uint32
	}{
		{downgrade.LevelNormal, 1},
		{downgrade.LevelSampled, 2},
		{downgrade.LevelHeavilySampled, 10},
		{downgrade.LevelCriticalOnly, sensor.BulkSamplingDropAll},
	}
	for _, c := range cases {
		if got := samplingRateForLevel(c.lvl); got != c.want {
			t.Errorf("samplingRateForLevel(%s) = %d, want %d", c.lvl, got, c.want)
		}
	}
}
