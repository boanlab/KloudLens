// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package metrics

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/boanlab/kloudlens/internal/sensor"
)

type fakeSrc struct {
	read, drop                            uint64
	syscalls, ints                        uint64
	hits, misses                          uint64
	resolved, miss                        uint64
	level                                 int
	usage                                 float64
	overflow                              uint64
	walOverflow                           uint64
	rbCrit, rbFile, rbNet, rbProc         uint64
	rbFileMeta                            uint64
	rbDNS, rbProcLC, rbSockLC             uint64
	pairPending, pairEvicted              uint64
	walAppendErr                          uint64
	subDropped                            uint64
	deviationCount                        uint64
	graphSessions, graphNodes, graphEdges int
	graphPurged                           uint64
	subEnv, subDev, subSess               int
	exporters                             []ExporterStat
}

func (f *fakeSrc) RingbufStats() (uint64, uint64)     { return f.read, f.drop }
func (f *fakeSrc) CoalesceStats() (uint64, uint64)    { return f.syscalls, f.ints }
func (f *fakeSrc) InternStats() (uint64, uint64)      { return f.hits, f.misses }
func (f *fakeSrc) PathResolveStats() (uint64, uint64) { return f.resolved, f.miss }
func (f *fakeSrc) AdaptiveLevel() int                 { return f.level }
func (f *fakeSrc) AdaptiveUsage() float64             { return f.usage }
func (f *fakeSrc) OverflowSummaryCount() uint64       { return f.overflow }
func (f *fakeSrc) WALOverflowCount() uint64           { return f.walOverflow }
func (f *fakeSrc) KernelRingbufDrops() sensor.RingbufDrops {
	return sensor.RingbufDrops{
		Crit: f.rbCrit, BulkFile: f.rbFile, BulkNet: f.rbNet, BulkProc: f.rbProc,
		BulkFileMeta: f.rbFileMeta,
		DNS:          f.rbDNS, ProcLC: f.rbProcLC, SockLC: f.rbSockLC,
	}
}
func (f *fakeSrc) PairerStats() (uint64, uint64)  { return f.pairPending, f.pairEvicted }
func (f *fakeSrc) WALAppendErrorCount() uint64    { return f.walAppendErr }
func (f *fakeSrc) SubscriberDroppedCount() uint64 { return f.subDropped }
func (f *fakeSrc) SubscriberCounts() (int, int, int) {
	return f.subEnv, f.subDev, f.subSess
}
func (f *fakeSrc) ExporterStats() []ExporterStat { return f.exporters }
func (f *fakeSrc) DeviationCount() uint64        { return f.deviationCount }
func (f *fakeSrc) GraphStats() (int, int, int, uint64) {
	return f.graphSessions, f.graphNodes, f.graphEdges, f.graphPurged
}

func TestCollectorEmitsAllFamilies(t *testing.T) {
	src := &fakeSrc{
		read: 1000, drop: 37,
		syscalls: 2500, ints: 250,
		hits: 900, misses: 100,
		resolved: 500, miss: 12,
		level:       1,
		usage:       0.73,
		overflow:    2,
		walOverflow: 1,
		rbCrit:      3, rbFile: 11, rbNet: 5, rbProc: 7,
		rbFileMeta: 9,
		rbDNS:      2, rbProcLC: 4, rbSockLC: 6,
		pairPending: 5, pairEvicted: 12,
		walAppendErr:   4,
		subDropped:     17,
		deviationCount: 8,
		graphSessions:  42, graphNodes: 137, graphEdges: 256,
		graphPurged: 19,
		subEnv:      3, subDev: 1, subSess: 2,
		exporters: []ExporterStat{
			{Name: "grpc", Sent: 42, Dropped: 3, QueuePending: 11},
		},
	}
	c := NewCollector(src)
	c.SetVersion("0.1.0-test")
	c.SetCapabilities(CapabilitySnapshot{
		NodeID: "node-a", Kernel: "6.6.0", Arch: "amd64",
		BTF: true, BPFLSM: true, Ringbuf: true, Fentry: false, KprobeMulti: true,
		Hooks: map[string]bool{
			"tracepoint:sys_enter_execve": true,
			"lsm_bpf:bprm_check_security": false,
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	c.Handler().ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	text := string(body)

	wants := []string{
		"kloudlens_ringbuf_usage_ratio",
		"kloudlens_ringbuf_lost_total 37",
		`kloudlens_ringbuf_kernel_lost_total{ring="crit"} 3`,
		`kloudlens_ringbuf_kernel_lost_total{ring="bulk_file"} 11`,
		`kloudlens_ringbuf_kernel_lost_total{ring="bulk_net"} 5`,
		`kloudlens_ringbuf_kernel_lost_total{ring="bulk_proc"} 7`,
		`kloudlens_ringbuf_kernel_lost_total{ring="bulk_file_meta"} 9`,
		`kloudlens_ringbuf_kernel_lost_total{ring="dns"} 2`,
		`kloudlens_ringbuf_kernel_lost_total{ring="proc_lc"} 4`,
		`kloudlens_ringbuf_kernel_lost_total{ring="sock_lc"} 6`,
		"kloudlens_coalesce_ratio",
		"kloudlens_intern_hit_ratio",
		"kloudlens_adaptive_level 1",
		"kloudlens_adaptive_usage 0.73",
		"kloudlens_overflow_summary_total 2",
		"kloudlens_path_resolve_miss_total 12",
		"kloudlens_wal_overflow_total 1",
		"kloudlens_syscalls_observed_total 2500",
		"kloudlens_intents_emitted_total 250",
		"kloudlens_pair_pending_frames 5",
		"kloudlens_pair_evicted_total 12",
		"kloudlens_wal_append_errors_total 4",
		"kloudlens_subscriber_dropped_total 17",
		`kloudlens_subscribers_active{stream="envelope"} 3`,
		`kloudlens_subscribers_active{stream="deviation"} 1`,
		`kloudlens_subscribers_active{stream="session"} 2`,
		"kloudlens_deviations_emitted_total 8",
		"kloudlens_graph_sessions_active 42",
		"kloudlens_graph_nodes 137",
		"kloudlens_graph_edges 256",
		"kloudlens_graph_sessions_purged_total 19",
		`kloudlens_exporter_sent_total{sink="grpc"} 42`,
		`kloudlens_exporter_dropped_total{sink="grpc"} 3`,
		`kloudlens_exporter_retry_failed_total{sink="grpc"} 0`,
		`kloudlens_exporter_dlq_total{sink="grpc"} 0`,
		`kloudlens_exporter_queue_pending{sink="grpc"} 11`,
		`kloudlens_capability_info{arch="amd64"`,
		`kloudlens_hook_available{kind="tracepoint",name="sys_enter_execve"} 1`,
		`kloudlens_hook_available{kind="lsm_bpf",name="bprm_check_security"} 0`,
		`kloudlens_build_info{version="0.1.0-test"} 1`,
	}
	for _, w := range wants {
		if !strings.Contains(text, w) {
			t.Errorf("missing %q in /metrics output", w)
		}
	}
}

// TestPolicyCounterRegisterAndScrape confirms the counter flows through
// Collector.Register and shows up on /metrics. The build-early / register-
// late wiring in kloudlens is the reason PolicyCounter exists — if
// Register silently failed, the dashboard would be empty and no test in
// admin_test would catch it (admin sees the Observe call via the fake).
func TestPolicyCounterRegisterAndScrape(t *testing.T) {
	src := &fakeSrc{}
	c := NewCollector(src)
	pc := NewPolicyCounter()
	if err := c.Register(pc.Collector()); err != nil {
		t.Fatalf("register: %v", err)
	}
	pc.Observe("HookSubscription", "ok")
	pc.Observe("HookSubscription", "rejected")
	pc.Observe("HookSubscription", "rejected")
	pc.Observe("BaselinePolicy", "ok")

	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	text := string(body)
	wants := []string{
		`kloudlens_policies_applied_total{kind="HookSubscription",result="ok"} 1`,
		`kloudlens_policies_applied_total{kind="HookSubscription",result="rejected"} 2`,
		`kloudlens_policies_applied_total{kind="BaselinePolicy",result="ok"} 1`,
	}
	for _, w := range wants {
		if !strings.Contains(text, w) {
			t.Errorf("missing %q in /metrics output", w)
		}
	}
}

func TestExporterLastErrorInfoEmittedOnlyWhenSet(t *testing.T) {
	longMsg := strings.Repeat("x", lastErrMaxLen+40)
	src := &fakeSrc{
		exporters: []ExporterStat{
			// Empty LastErr: series must not appear at all.
			{Name: "grpc", Sent: 1},
			// Short LastErr: emitted verbatim on the message label.
			{Name: "secondary", Sent: 2, Failed: 1, LastErr: "rpc unavailable"},
			// Overlong LastErr: truncated to lastErrMaxLen.
			{Name: "file", Sent: 3, Failed: 2, LastErr: longMsg},
		},
	}
	c := NewCollector(src)
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	text := rec.Body.String()

	if !strings.Contains(text, `kloudlens_exporter_last_error_info{message="rpc unavailable",sink="secondary"} 1`) {
		t.Errorf("expected secondary last-error info gauge, got:\n%s", text)
	}
	wantTrunc := `kloudlens_exporter_last_error_info{message="` + strings.Repeat("x", lastErrMaxLen) + `",sink="file"} 1`
	if !strings.Contains(text, wantTrunc) {
		t.Errorf("expected truncated file last-error info gauge, got:\n%s", text)
	}
	for line := range strings.SplitSeq(text, "\n") {
		if strings.HasPrefix(line, "kloudlens_exporter_last_error_info") && strings.Contains(line, `sink="grpc"`) {
			t.Errorf("grpc sink with empty LastErr must not emit last_error_info, got line: %q", line)
		}
	}
}

func TestRatiosZeroOnEmptyCounters(t *testing.T) {
	src := &fakeSrc{} // all zero
	c := NewCollector(src)
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "kloudlens_ringbuf_usage_ratio 0") {
		t.Errorf("expected ringbuf ratio 0 on empty counters, got:\n%s", body)
	}
}
