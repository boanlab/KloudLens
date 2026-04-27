// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package main

import (
	"runtime"

	"github.com/boanlab/kloudlens/internal/exporter"
	"github.com/boanlab/kloudlens/internal/metrics"
	"github.com/boanlab/kloudlens/internal/sensor"
	"github.com/boanlab/kloudlens/internal/wal"
)

// metricsSource adapts the Pipeline + WAL + SubscribeServer to the
// metrics.Source interface. A dedicated type keeps the metrics package
// ignorant of the pipeline struct (no circular import risk) and lets main.go
// pass a nil WAL / nil SubscribeServer cleanly for --wal-dir-less
// deployments.
type metricsSource struct {
	pipe *Pipeline
	wal  *wal.WAL
	sub  *exporter.SubscribeServer
	grpc *exporter.GRPCClient
}

func (m *metricsSource) RingbufStats() (read, dropped uint64) {
	return m.pipe.RingbufStats()
}

func (m *metricsSource) CoalesceStats() (syscalls, intents uint64) {
	return m.pipe.CoalesceStats()
}

func (m *metricsSource) InternStats() (hits, misses uint64) {
	return m.pipe.InternStats()
}

func (m *metricsSource) PathResolveStats() (resolved, missed uint64) {
	return m.pipe.PathResolveStats()
}

func (m *metricsSource) AdaptiveLevel() int     { return m.pipe.AdaptiveLevel() }
func (m *metricsSource) AdaptiveUsage() float64 { return m.pipe.AdaptiveUsage() }

func (m *metricsSource) OverflowSummaryCount() uint64 {
	return m.pipe.OverflowSummaryCount()
}

func (m *metricsSource) WALOverflowCount() uint64 {
	if m.wal == nil {
		return 0
	}
	return m.wal.OverflowCount()
}

func (m *metricsSource) KernelRingbufDrops() sensor.RingbufDrops {
	return m.pipe.KernelRingbufDrops()
}

func (m *metricsSource) PairerStats() (pending, evicted uint64) {
	return m.pipe.PairerStats()
}

func (m *metricsSource) WALAppendErrorCount() uint64 {
	if m.sub == nil {
		return 0
	}
	return m.sub.WALAppendErrors()
}

func (m *metricsSource) DeviationCount() uint64 {
	return m.pipe.DeviationCount()
}

// GraphStats forwards the session graph snapshot. Deployments without a
// Graph (memory-only builds that disable) return zeros so the
// metric series stay flat rather than disappearing between scrapes.
func (m *metricsSource) GraphStats() (sessions, nodes, edges int, purgedTotal uint64) {
	g := m.pipe.Graph
	if g == nil {
		return 0, 0, 0, 0
	}
	return g.SessionCount(), g.NodeCount(), g.EdgeCount(), g.PurgedTotal()
}

func (m *metricsSource) SubscriberDroppedCount() uint64 {
	if m.sub == nil {
		return 0
	}
	return m.sub.SubscriberDropped()
}

// SubscriberCounts forwards the per-stream live listener counts. Non-k8s /
// --no-server deployments without a SubscribeServer return all zeros so
// the metric series stays flat instead of disappearing between scrapes.
func (m *metricsSource) SubscriberCounts() (envelope, deviation, session int) {
	if m.sub == nil {
		return 0, 0, 0
	}
	return m.sub.SubscriberCount()
}

// ExporterStats walks the optional per-sink clients and builds a
// snapshot for the /metrics sink collector. Unconfigured sinks are
// omitted so unused series don't pollute dashboards.
func (m *metricsSource) ExporterStats() []metrics.ExporterStat {
	var out []metrics.ExporterStat
	if m.grpc != nil {
		s, d, lastErr := m.grpc.Stats()
		out = append(out, metrics.ExporterStat{
			Name: "grpc", Sent: s, Dropped: d, LastErr: errString(lastErr),
			QueuePending: m.grpc.QueueLen(),
		})
	}
	return out
}

// runtimeGOARCH exposes the compiled GOARCH so the metrics capability_info
// label matches the binary that's running, not the host reported by uname.
func runtimeGOARCH() string { return runtime.GOARCH }

// errString flattens a possibly-nil error into the "" / msg string the
// metrics collector uses to decide whether to emit a last_error_info
// series.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
