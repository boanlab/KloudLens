// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package sensor

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

// DropSource is the narrow contract an OverflowMonitor needs from the sensor:
// a cumulative (read, dropped) pair where dropped is monotonic. EBPFSensor
// satisfies this via DropStats; tests inject a counter pair directly.
type DropSource interface {
	DropStats() (read, dropped uint64)
}

// OverflowEmit is invoked once per sample interval when the drop counter has
// advanced. The callback receives a fully-formed OverflowSummary IntentEvent
// so consumers can route it through the same pipeline as regular intents
// (JSONL, live subscribe, WAL()).
type OverflowEmit func(types.IntentEvent)

// OverflowMonitor samples a DropSource on a ticker and emits an
// OverflowSummary whenever the dropped counter increased in the last window.
// It is the userspace fallback for kernel-side ringbuf loss: even when the
// BPF side doesn't publish an explicit loss counter, the decoder-side drops
// (malformed / truncated frames) are a reliable proxy and they surface here
// as a discrete event that subscribers can reason about.
//
// The emitted Kind is "OverflowSummary" with attributes:
//
//	"dropped" — events lost since the last emit (delta)
//	"read" — events observed in the same window (delta)
//	"loss_ratio" — dropped / (read + dropped) as a fractional string
//	"window_ms" — sample interval, for context
//	"node" — NodeName (copied from config); empty when unset
type OverflowMonitor struct {
	src      DropSource
	emit     OverflowEmit
	interval time.Duration
	nodeName string
	cluster  string
	lastRead uint64
	lastDrop uint64
	emitted  atomic.Uint64
	stopped  atomic.Bool
	now      func() time.Time
}

// OverflowConfig parametrizes the monitor.
type OverflowConfig struct {
	// Source supplies the drop counters; typically *EBPFSensor.
	Source DropSource
	// Emit is called once per sample when drops have advanced.
	Emit OverflowEmit
	// Interval between samples. Defaults to 10 s when zero.
	Interval time.Duration
	// NodeName / Cluster are stamped onto every emitted OverflowSummary's
	// Meta so subscribers can filter by node even when the upstream event's
	// container meta is unavailable (a dropped frame has no container).
	NodeName string
	Cluster  string
	// Now supplies the event timestamp. Defaults to time.Now.
	Now func() time.Time
}

// NewOverflowMonitor constructs a monitor with the given config.
func NewOverflowMonitor(cfg OverflowConfig) *OverflowMonitor {
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &OverflowMonitor{
		src:      cfg.Source,
		emit:     cfg.Emit,
		interval: cfg.Interval,
		nodeName: cfg.NodeName,
		cluster:  cfg.Cluster,
		now:      cfg.Now,
	}
}

// Run blocks until ctx is canceled, polling the drop source every Interval.
// Safe to call once per monitor; repeated calls return immediately.
func (m *OverflowMonitor) Run(ctx context.Context) {
	if m.src == nil || m.emit == nil {
		return
	}
	if !m.stopped.CompareAndSwap(false, false) {
		return
	}
	// Seed baselines so the first tick reports only the next delta, not the
	// cumulative counter at startup.
	m.lastRead, m.lastDrop = m.src.DropStats()
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if m.stopped.Load() {
				return
			}
			m.sample()
		}
	}
}

// Sample forces one read-emit cycle. Exposed for tests that drive the monitor
// synchronously instead of through Run.
func (m *OverflowMonitor) Sample() { m.sample() }

// Emitted returns how many OverflowSummary events this monitor has emitted.
// Useful for metrics and for tests that need to assert on emit behavior.
func (m *OverflowMonitor) Emitted() uint64 { return m.emitted.Load() }

func (m *OverflowMonitor) sample() {
	read, drop := m.src.DropStats()
	dDrop := drop - m.lastDrop
	dRead := read - m.lastRead
	m.lastRead, m.lastDrop = read, drop
	if dDrop == 0 {
		return
	}
	total := dRead + dDrop
	ratio := float64(dDrop) / float64(total)
	ts := uint64(m.now().UnixNano())
	ev := types.IntentEvent{
		IntentID: types.UUIDv7(),
		Kind:     "OverflowSummary",
		StartNS:  ts - uint64(m.interval), // #nosec G115 -- m.interval is a positive time.Duration (int64 nanoseconds) that fits uint64
		EndNS:    ts,
		Attributes: map[string]string{
			"dropped":    fmt.Sprintf("%d", dDrop),
			"read":       fmt.Sprintf("%d", dRead),
			"loss_ratio": fmt.Sprintf("%.6f", ratio),
			"window_ms":  fmt.Sprintf("%d", m.interval.Milliseconds()),
			"node":       m.nodeName,
		},
		Meta: types.ContainerMeta{
			NodeName: m.nodeName,
			Cluster:  m.cluster,
		},
		Severity:   types.SeverityLow,
		Confidence: 1.0,
	}
	m.emitted.Add(1)
	m.emit(ev)
}
