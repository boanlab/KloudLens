// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package sensor

import (
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

type counterSource struct{ read, drop uint64 }

func (c *counterSource) DropStats() (uint64, uint64) { return c.read, c.drop }

func TestOverflowEmitsOnDropDelta(t *testing.T) {
	src := &counterSource{read: 100, drop: 0}
	var got []types.IntentEvent
	mon := NewOverflowMonitor(OverflowConfig{
		Source:   src,
		Emit:     func(ev types.IntentEvent) { got = append(got, ev) },
		Interval: 5 * time.Second,
		NodeName: "node-a",
		Cluster:  "test",
		Now:      func() time.Time { return time.Unix(1, 0) },
	})
	// Seed baseline: first internal read happens at Run start, but we invoke
	// Sample directly — so bump baselines to current before advancing.
	mon.lastRead, mon.lastDrop = src.read, src.drop

	src.read += 50
	src.drop += 3
	mon.Sample()

	if len(got) != 1 {
		t.Fatalf("expected 1 emit, got %d", len(got))
	}
	ev := got[0]
	if ev.Kind != "OverflowSummary" {
		t.Errorf("kind = %q, want OverflowSummary", ev.Kind)
	}
	if ev.Attributes["dropped"] != "3" {
		t.Errorf("dropped = %q, want 3", ev.Attributes["dropped"])
	}
	if ev.Attributes["read"] != "50" {
		t.Errorf("read = %q, want 50", ev.Attributes["read"])
	}
	if ev.Meta.NodeName != "node-a" || ev.Meta.Cluster != "test" {
		t.Errorf("meta not stamped: %+v", ev.Meta)
	}
	if ev.Severity != types.SeverityLow {
		t.Errorf("severity = %v, want Low", ev.Severity)
	}
}

func TestOverflowNoEmitWhenFlat(t *testing.T) {
	src := &counterSource{read: 100, drop: 5}
	emits := 0
	mon := NewOverflowMonitor(OverflowConfig{
		Source: src,
		Emit:   func(types.IntentEvent) { emits++ },
	})
	mon.lastRead, mon.lastDrop = src.read, src.drop
	src.read += 20 // reads move, drops flat
	mon.Sample()
	if emits != 0 {
		t.Fatalf("expected no emit when drops flat, got %d", emits)
	}
	if mon.Emitted() != 0 {
		t.Fatalf("Emitted counter should be 0, got %d", mon.Emitted())
	}
}
