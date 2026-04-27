// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package metrics exposes KloudLens runtime counters on a Prometheus-style
// /metrics endpoint. Names and semantics follow the plan.md observability
// section: ringbuf_usage_ratio, ringbuf_lost_total, coalesce_ratio,
// intern_hit_ratio, adaptive_level, overflow_summary_total,
// path_resolve_miss_total, capability_info, hook_available, wal_overflow_total.
//
// The Source interface lets the daemon plug in its live pipeline without the
// metrics package depending on internal/* packages (which would cycle).
package metrics

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/boanlab/kloudlens/internal/sensor"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Source provides the counters Collect needs. All methods are polled on
// each scrape; implementations should keep them cheap (constant-time reads
// from atomics / protected counters).
type Source interface {
	// RingbufStats returns (framesRead, framesDropped). Dropped is the count
	// of userspace decode failures — treated as a proxy for kernel-side
	// ringbuf loss when no explicit BPF-side loss counter is available.
	RingbufStats() (read, dropped uint64)
	// CoalesceStats returns (syscallsObserved, intentsEmitted). The ratio
	// intents / syscalls drives coalesce_ratio.
	CoalesceStats() (syscalls, intents uint64)
	// InternStats returns (hits, misses) from the string-interning table.
	InternStats() (hits, misses uint64)
	// PathResolveStats returns (resolved, missed) from the PathCompleter.
	PathResolveStats() (resolved, missed uint64)
	// AdaptiveLevel is the current tracer adaptive subscription level
	// (0=minimal, 1=default, 2=full). Exposed so dashboards can alert on
	// downgrades induced by overload detection.
	AdaptiveLevel() int
	// AdaptiveUsage is the last ring-buffer usage fraction observed by
	// the downgrade.Controller, in [0,1]. The *input* that drives
	// AdaptiveLevel transitions — useful paired with the level gauge so
	// operators can see both why the controller moved and where it is.
	// Zero when no controller is attached.
	AdaptiveUsage() float64
	// OverflowSummaryCount is the number of OverflowSummary IntentEvents
	// the tracer's OverflowMonitor has emitted since startup.
	OverflowSummaryCount() uint64
	// WALOverflowCount is the number of segment-trim events the WAL has
	// performed (old segments dropped to honor the size cap).
	WALOverflowCount() uint64
	// KernelRingbufDrops returns the summed-across-CPUs count of
	// bpf_ringbuf_output failures for every category ring. A non-running
	// live sensor returns the zero value. These counts are strictly
	// additive — the userspace RingbufStats decode-failure proxy overlaps
	// semantically with the per-ring losses but is reported separately to
	// keep the two loss surfaces distinct (decoder errors vs. kernel
	// producer overruns).
	KernelRingbufDrops() sensor.RingbufDrops
	// PairerStats returns the wire-level ENTER/EXIT pairer's current
	// pending-frame count (gauge) and the running total of evictions
	// caused by the pending-map cap (monotonic counter). A rising evicted
	// counter is an early BPF ringbuf loss signal — the kernel produced
	// an EXIT but the matching ENTER never reached userspace.
	PairerStats() (pending, evicted uint64)
	// WALAppendErrorCount is the number of WAL append failures the
	// SubscribeServer has silently absorbed. A non-zero rate means
	// intents/deviations were produced but never persisted — dashboards
	// should alert on rate > 0.
	WALAppendErrorCount() uint64
	// SubscriberDroppedCount is the monotonic sum of envelopes the live
	// fan-out had to drop across every SubscribeServer listener type
	// (Subscribe, SubscribeDeviations, SubscribeSession) because a
	// consumer's per-connection queue was full. rate > 0 means at
	// least one subscriber is behind its flow-control window.
	SubscriberDroppedCount() uint64
	// SubscriberCounts returns the number of live listeners per stream
	// type right now (envelope/deviation/session). Zero for any stream
	// with no current consumers — the gauge stays at 0 rather than
	// disappearing so dashboards can alert on "subscribers dropped to 0".
	SubscriberCounts() (envelope, deviation, session int)
	// ExporterStats returns a snapshot of per-sink counters for every
	// off-node shipper currently configured (grpc). Sinks that aren't
	// wired are omitted; the returned slice may be empty. Counters are
	// monotonic since sink Dial-time.
	ExporterStats() []ExporterStat
	// DeviationCount is the monotonic count of DeviationEvents the
	// pipeline has emitted since startup. Grouped with intents
	// on dashboards: a rising deviation rate with flat intents means
	// the monitor is catching real baseline breaks, not just volume.
	DeviationCount() uint64
	// GraphStats returns the session-graph store snapshot: currently
	// active sessions / nodes / edges (gauges) and the monotonic count
	// of sessions the TTL purger has evicted since startup (counter).
	// Non-k8s / memory-only deployments without a Graph should return
	// all zeros — the metrics then stay at 0 instead of being absent
	// (matches the handling of wal counters).
	GraphStats() (sessions, nodes, edges int, purgedTotal uint64)
}

// ExporterStat carries one off-node sink's live counters. Name matches
// the `--export-*` flag stem (e.g. "grpc") so it becomes the
// sink="..." label on the exported kloudlens_exporter_* metrics.
//
// Failed and DLQ are retained in the schema but stay zero for the current
// sink (grpc drops on queue overflow rather than retry). Prometheus then
// reports a constant-zero series for sink="grpc", which is the accurate
// reflection of "no retry failures observed at the exporter boundary."
type ExporterStat struct {
	Name    string
	Sent    uint64
	Dropped uint64
	Failed  uint64
	DLQ     uint64
	// LastErr is the most recent transport-level error text observed by
	// the sink ("" when the sink has never failed or has recovered). When
	// non-empty, Collect emits a kloudlens_exporter_last_error_info series
	// with message=<text> so on-call can diagnose *why* failed/dlq are
	// climbing. Sinks without a last-error surface (or that have
	// recovered) should leave this empty.
	LastErr string
	// QueuePending is the live depth of the sink's send queue at scrape
	// time (len of its buffered channel). Exposed as
	// kloudlens_exporter_queue_pending so dashboards can distinguish a
	// sink that's keeping up with ingest (depth ~ 0) from one that's
	// filling its buffer and about to start dropping (depth approaching
	// QueueLen). Sinks without a queue (none currently) should leave
	// this zero.
	QueuePending int
}

// CapabilitySnapshot describes the node's kernel capabilities. Call
// Collector.SetCapabilities once at startup (or on SIGHUP) to update the
// capability_info + hook_available gauges.
type CapabilitySnapshot struct {
	NodeID      string
	Kernel      string
	Arch        string
	BTF         bool
	BPFLSM      bool
	KprobeMulti bool
	Ringbuf     bool
	Fentry      bool
	// Hooks maps "<kind>:<name>" → available.
	Hooks map[string]bool
}

// Collector owns the Prometheus registry and the gauge/counter set.
type Collector struct {
	src Source
	reg *prometheus.Registry

	ringbufUsage   prometheus.Gauge
	ringbufLostTot prometheus.CounterFunc
	// Per-category kernel-side ringbuf overrun counters. One CounterFunc
	// per ring, distinguished by a ring="..." label set via ConstLabels.
	// Separate series (instead of a single unlabeled total) let dashboards
	// attribute drops back to the category whose producer starved its ring —
	// the whole point of the Intent-kind subdivision Tier 2.
	rbKernelCrit         prometheus.CounterFunc
	rbKernelBulkFile     prometheus.CounterFunc
	rbKernelBulkNet      prometheus.CounterFunc
	rbKernelBulkProc     prometheus.CounterFunc
	rbKernelBulkFileMeta prometheus.CounterFunc
	rbKernelDNS          prometheus.CounterFunc
	rbKernelProcLC       prometheus.CounterFunc
	rbKernelSockLC       prometheus.CounterFunc
	coalesceRatio        prometheus.Gauge
	internHitRatio       prometheus.Gauge
	adaptiveLevel        prometheus.Gauge
	adaptiveUsage        prometheus.Gauge
	overflowSummary      prometheus.CounterFunc
	pathMiss             prometheus.CounterFunc
	walOverflow          prometheus.CounterFunc
	syscallsTotal        prometheus.CounterFunc
	intentsTotal         prometheus.CounterFunc
	pairPending          prometheus.GaugeFunc
	pairEvicted          prometheus.CounterFunc
	walAppendErrs        prometheus.CounterFunc
	subDropped           prometheus.CounterFunc
	subActive            *prometheus.GaugeVec
	deviationsTotal      prometheus.CounterFunc
	graphSessions        prometheus.GaugeFunc
	graphNodes           prometheus.GaugeFunc
	graphEdges           prometheus.GaugeFunc
	graphPurged          prometheus.CounterFunc
	exporterSinks        *exporterSinkCollector
	capabilityInfo       *prometheus.GaugeVec
	hookAvailable        *prometheus.GaugeVec
	buildInfo            *prometheus.GaugeVec
}

// NewCollector returns a Collector bound to src. The Collector does not
// spawn any goroutines on its own — scrape values are pulled from src each
// time /metrics is requested via the CounterFunc/refresh path.
func NewCollector(src Source) *Collector {
	reg := prometheus.NewRegistry()
	c := &Collector{src: src, reg: reg}

	c.ringbufUsage = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kloudlens_ringbuf_usage_ratio",
		Help: "Fraction of observed tracer frames that failed decode (proxy for kernel ringbuf loss) since startup.",
	})
	c.ringbufLostTot = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kloudlens_ringbuf_lost_total",
		Help: "Total ringbuf frames the tracer dropped (userspace decode failures + kernel-loss proxy).",
	}, func() float64 {
		_, d := src.RingbufStats()
		return float64(d)
	})
	// kloudlens_ringbuf_kernel_lost_total{ring="..."} — one series per
	// category ring. Monotonic: values only grow (or stay) as the kernel
	// accumulates bpf_ringbuf_output failures. Alert rules should fire on
	// rate being non-zero, indicating sustained producer overrun.
	const kernelDropName = "kloudlens_ringbuf_kernel_lost_total"
	const kernelDropHelp = "bpf_ringbuf_output failures per kernel ring, summed across CPUs, since sensor start."
	c.rbKernelCrit = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: kernelDropName, Help: kernelDropHelp,
		ConstLabels: prometheus.Labels{"ring": "crit"},
	}, func() float64 { return float64(src.KernelRingbufDrops().Crit) })
	c.rbKernelBulkFile = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: kernelDropName, Help: kernelDropHelp,
		ConstLabels: prometheus.Labels{"ring": "bulk_file"},
	}, func() float64 { return float64(src.KernelRingbufDrops().BulkFile) })
	c.rbKernelBulkNet = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: kernelDropName, Help: kernelDropHelp,
		ConstLabels: prometheus.Labels{"ring": "bulk_net"},
	}, func() float64 { return float64(src.KernelRingbufDrops().BulkNet) })
	c.rbKernelBulkProc = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: kernelDropName, Help: kernelDropHelp,
		ConstLabels: prometheus.Labels{"ring": "bulk_proc"},
	}, func() float64 { return float64(src.KernelRingbufDrops().BulkProc) })
	c.rbKernelBulkFileMeta = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: kernelDropName, Help: kernelDropHelp,
		ConstLabels: prometheus.Labels{"ring": "bulk_file_meta"},
	}, func() float64 { return float64(src.KernelRingbufDrops().BulkFileMeta) })
	c.rbKernelDNS = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: kernelDropName, Help: kernelDropHelp,
		ConstLabels: prometheus.Labels{"ring": "dns"},
	}, func() float64 { return float64(src.KernelRingbufDrops().DNS) })
	c.rbKernelProcLC = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: kernelDropName, Help: kernelDropHelp,
		ConstLabels: prometheus.Labels{"ring": "proc_lc"},
	}, func() float64 { return float64(src.KernelRingbufDrops().ProcLC) })
	c.rbKernelSockLC = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: kernelDropName, Help: kernelDropHelp,
		ConstLabels: prometheus.Labels{"ring": "sock_lc"},
	}, func() float64 { return float64(src.KernelRingbufDrops().SockLC) })
	c.coalesceRatio = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kloudlens_coalesce_ratio",
		Help: "IntentEvents emitted per raw syscall observed (lower = more aggressive coalescing).",
	})
	c.internHitRatio = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kloudlens_intern_hit_ratio",
		Help: "String-intern table hit ratio since startup.",
	})
	c.adaptiveLevel = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kloudlens_adaptive_level",
		Help: "Tracer adaptive subscription level (0=minimal, 1=default, 2=full).",
	})
	c.adaptiveUsage = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kloudlens_adaptive_usage",
		Help: "Last ring-buffer usage fraction fed into the downgrade controller (0..1). Paired with kloudlens_adaptive_level: usage is the input, level is the state the controller moved to.",
	})
	c.overflowSummary = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kloudlens_overflow_summary_total",
		Help: "OverflowSummary intent events emitted since startup.",
	}, func() float64 { return float64(src.OverflowSummaryCount()) })
	c.pathMiss = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kloudlens_path_resolve_miss_total",
		Help: "Relative paths the PathCompleter could not absolutize (dropped from intent).",
	}, func() float64 {
		_, m := src.PathResolveStats()
		return float64(m)
	})
	c.walOverflow = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kloudlens_wal_overflow_total",
		Help: "WAL segment trims performed to honor the size cap.",
	}, func() float64 { return float64(src.WALOverflowCount()) })
	c.syscallsTotal = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kloudlens_syscalls_observed_total",
		Help: "Total syscall events the pipeline ingested (post-decode).",
	}, func() float64 {
		s, _ := src.CoalesceStats()
		return float64(s)
	})
	c.intentsTotal = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kloudlens_intents_emitted_total",
		Help: "Total IntentEvents emitted by the aggregator.",
	}, func() float64 {
		_, i := src.CoalesceStats()
		return float64(i)
	})
	c.pairPending = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "kloudlens_pair_pending_frames",
		Help: "ENTER syscall frames currently stashed in the wire-level Pairer waiting for their EXIT partner.",
	}, func() float64 {
		p, _ := src.PairerStats()
		return float64(p)
	})
	c.pairEvicted = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kloudlens_pair_evicted_total",
		Help: "ENTER frames dropped from the Pairer's pending map due to the cap — a proxy for BPF ringbuf loss of matching EXITs.",
	}, func() float64 {
		_, e := src.PairerStats()
		return float64(e)
	})
	c.walAppendErrs = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kloudlens_wal_append_errors_total",
		Help: "Intents/deviations the SubscribeServer tried to append to the WAL but dropped because of a write error (closed segment, full disk).",
	}, func() float64 { return float64(src.WALAppendErrorCount()) })
	c.subDropped = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kloudlens_subscriber_dropped_total",
		Help: "Envelopes dropped by the live fan-out because a subscriber's per-connection queue was full. Summed across Subscribe, SubscribeDeviations(), and SubscribeSession.",
	}, func() float64 { return float64(src.SubscriberDroppedCount()) })
	c.subActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kloudlens_subscribers_active",
		Help: "Live listener count on the agent's SubscribeServer per stream type (envelope/deviation/session). Mirrors the aggregator's kloudlens_aggregator_subscribers_active for cluster-level symmetry.",
	}, []string{"stream"})
	c.deviationsTotal = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kloudlens_deviations_emitted_total",
		Help: "DeviationEvents emitted by the monitor-mode pipeline since startup.",
	}, func() float64 { return float64(src.DeviationCount()) })
	c.graphSessions = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "kloudlens_graph_sessions_active",
		Help: "Currently tracked sessions in the node-local session graph.",
	}, func() float64 { s, _, _, _ := src.GraphStats(); return float64(s) })
	c.graphNodes = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "kloudlens_graph_nodes",
		Help: "Vertices currently held in the session graph.",
	}, func() float64 { _, n, _, _ := src.GraphStats(); return float64(n) })
	c.graphEdges = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "kloudlens_graph_edges",
		Help: "Edges currently held in the session graph.",
	}, func() float64 { _, _, e, _ := src.GraphStats(); return float64(e) })
	c.graphPurged = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "kloudlens_graph_sessions_purged_total",
		Help: "Sessions evicted by the TTL purger since startup. A flat series across a long-running node indicates the purger is not firing or SessionTTL is never reached.",
	}, func() float64 { _, _, _, p := src.GraphStats(); return float64(p) })
	c.exporterSinks = newExporterSinkCollector(src)
	c.capabilityInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kloudlens_capability_info",
		Help: "Kernel capability inventory — always 1; labels carry the detail.",
	}, []string{"node", "kernel", "arch", "btf", "bpf_lsm", "kprobe_multi", "ringbuf", "fentry"})
	c.hookAvailable = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kloudlens_hook_available",
		Help: "1 if the named probe is attachable on this kernel, 0 otherwise.",
	}, []string{"kind", "name"})
	c.buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kloudlens_build_info",
		Help: "Build metadata — always 1; labels carry version.",
	}, []string{"version"})

	reg.MustRegister(
		c.ringbufUsage, c.ringbufLostTot,
		c.rbKernelCrit, c.rbKernelBulkFile, c.rbKernelBulkNet, c.rbKernelBulkProc,
		c.rbKernelBulkFileMeta, c.rbKernelDNS, c.rbKernelProcLC, c.rbKernelSockLC,
		c.coalesceRatio, c.internHitRatio,
		c.adaptiveLevel, c.adaptiveUsage, c.overflowSummary, c.pathMiss, c.walOverflow,
		c.syscallsTotal, c.intentsTotal,
		c.pairPending, c.pairEvicted, c.walAppendErrs, c.subDropped,
		c.subActive,
		c.deviationsTotal,
		c.graphSessions, c.graphNodes, c.graphEdges, c.graphPurged,
		c.exporterSinks,
		c.capabilityInfo, c.hookAvailable, c.buildInfo,
	)
	return c
}

// Register hands an externally-built Collector to this Collector's
// internal registry. Used for subsystems that pre-build their own
// CounterVec before the main collector exists (e.g. admin.PolicyObserver()
// wired at admin init, metrics Collector created much later — the
// CounterVec must exist up-front to satisfy the observer interface).
func (c *Collector) Register(ext prometheus.Collector) error {
	return c.reg.Register(ext)
}

// PolicyCounter wraps a kloudlens_policies_applied_total{kind,result}
// CounterVec. kloudlens builds it early (so it can be handed to
// admin.NewServer as a PolicyObserver), then registers it with the
// metrics Collector once the Collector exists.
type PolicyCounter struct {
	vec *prometheus.CounterVec
}

// NewPolicyCounter returns an unregistered kloudlens_policies_applied_total
// counter vector. Call Collector.Register(pc.Describe()) to expose it on
// /metrics.
func NewPolicyCounter() *PolicyCounter {
	return &PolicyCounter{
		vec: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kloudlens_policies_applied_total",
			Help: "Total ApplyPolicy calls partitioned by kind and result (ok|rejected). Ops watch this to detect klctl push churn and malformed-policy spikes without tailing admin logs.",
		}, []string{"kind", "result"}),
	}
}

// Observe implements admin.PolicyObserver. `kind` is the Policy.Kind()
// (HookSubscription etc.); `result` is "ok" or "rejected".
func (p *PolicyCounter) Observe(kind, result string) {
	if kind == "" {
		kind = "unknown"
	}
	p.vec.WithLabelValues(kind, result).Inc()
}

// Collector returns the underlying prometheus.Collector for registration.
func (p *PolicyCounter) Collector() prometheus.Collector { return p.vec }

// SetCapabilities refreshes the capability_info/hook_available gauges. Call
// once the probe discovery finishes; the values are sticky until the next
// call.
func (c *Collector) SetCapabilities(snap CapabilitySnapshot) {
	c.capabilityInfo.Reset()
	c.capabilityInfo.WithLabelValues(
		snap.NodeID, snap.Kernel, snap.Arch,
		boolLabel(snap.BTF), boolLabel(snap.BPFLSM),
		boolLabel(snap.KprobeMulti), boolLabel(snap.Ringbuf),
		boolLabel(snap.Fentry),
	).Set(1)
	c.hookAvailable.Reset()
	for name, ok := range snap.Hooks {
		kind, hookName := splitHook(name)
		v := 0.0
		if ok {
			v = 1
		}
		c.hookAvailable.WithLabelValues(kind, hookName).Set(v)
	}
}

// SetVersion stamps the build_info gauge. Called once at startup.
func (c *Collector) SetVersion(version string) {
	c.buildInfo.Reset()
	c.buildInfo.WithLabelValues(version).Set(1)
}

// refresh recomputes the gauge values that can't be CounterFunc-backed
// (ratios derived from two counters). Wired to every scrape via
// ScrapeHandler.
func (c *Collector) refresh() {
	read, dropped := c.src.RingbufStats()
	if total := read + dropped; total > 0 {
		c.ringbufUsage.Set(float64(dropped) / float64(total))
	} else {
		c.ringbufUsage.Set(0)
	}
	syscalls, intents := c.src.CoalesceStats()
	if syscalls > 0 {
		c.coalesceRatio.Set(float64(intents) / float64(syscalls))
	} else {
		c.coalesceRatio.Set(0)
	}
	h, m := c.src.InternStats()
	if total := h + m; total > 0 {
		c.internHitRatio.Set(float64(h) / float64(total))
	} else {
		c.internHitRatio.Set(0)
	}
	c.adaptiveLevel.Set(float64(c.src.AdaptiveLevel()))
	c.adaptiveUsage.Set(c.src.AdaptiveUsage())
	env, dev, sess := c.src.SubscriberCounts()
	c.subActive.WithLabelValues("envelope").Set(float64(env))
	c.subActive.WithLabelValues("deviation").Set(float64(dev))
	c.subActive.WithLabelValues("session").Set(float64(sess))
}

// Handler returns an http.Handler that serves /metrics for this collector.
// Every scrape runs refresh first so ratio gauges reflect the current
// scrape, not the last one.
func (c *Collector) Handler() http.Handler {
	inner := promhttp.HandlerFor(c.reg, promhttp.HandlerOpts{})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.refresh()
		inner.ServeHTTP(w, r)
	})
}

// Serve binds a dedicated /metrics HTTP server on addr until ctx is done.
// Returns when the listener closes or the server exits.
func (c *Collector) Serve(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", c.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(lis) }()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// exporterSinkCollector emits kloudlens_exporter_sent_total{sink="..."}
// and kloudlens_exporter_dropped_total{sink="..."} for each configured
// off-node sink. Using a custom prometheus.Collector keeps the label set
// open — sinks wired via --export-* flags at startup appear without
// having to pre-register every (sink, metric) pair.
type exporterSinkCollector struct {
	src         Source
	sentDesc    *prometheus.Desc
	dropDesc    *prometheus.Desc
	failedDesc  *prometheus.Desc
	dlqDesc     *prometheus.Desc
	lastErrDesc *prometheus.Desc
	queueDesc   *prometheus.Desc
}

// lastErrMaxLen caps the message label to keep cardinality predictable
// when a misconfigured sink produces verbose error strings (e.g. full
// TLS handshake dumps). 120 chars is enough for the "http <code>" /
// "dial tcp: <host>: <reason>" forms that actually matter for triage.
const lastErrMaxLen = 120

func newExporterSinkCollector(src Source) *exporterSinkCollector {
	return &exporterSinkCollector{
		src: src,
		sentDesc: prometheus.NewDesc(
			"kloudlens_exporter_sent_total",
			"IntentEvents/DeviationEvents successfully shipped by an off-node sink since startup.",
			[]string{"sink"}, nil,
		),
		dropDesc: prometheus.NewDesc(
			"kloudlens_exporter_dropped_total",
			"Events dropped by an off-node sink because its per-sink queue was full.",
			[]string{"sink"}, nil,
		),
		failedDesc: prometheus.NewDesc(
			"kloudlens_exporter_retry_failed_total",
			"Transient transport failures encountered by an off-node sink (may succeed on retry). Currently always zero — the grpc sink drops on queue overflow rather than retry.",
			[]string{"sink"}, nil,
		),
		dlqDesc: prometheus.NewDesc(
			"kloudlens_exporter_dlq_total",
			"Batches an off-node sink gave up on after exhausting retries (routed to DLQ file or discarded). Currently always zero.",
			[]string{"sink"}, nil,
		),
		lastErrDesc: prometheus.NewDesc(
			"kloudlens_exporter_last_error_info",
			"1 while an off-node sink (grpc) has a non-empty last-error string; the message label carries the truncated error text. Absent for sinks that have never failed or have since recovered.",
			[]string{"sink", "message"}, nil,
		),
		queueDesc: prometheus.NewDesc(
			"kloudlens_exporter_queue_pending",
			"Events currently buffered in the sink's send queue (len of the internal channel). Approaches the configured QueueLen when the sink is falling behind ingest; sustained high values precede the dropped_total counter climbing.",
			[]string{"sink"}, nil,
		),
	}
}

func (c *exporterSinkCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.sentDesc
	ch <- c.dropDesc
	ch <- c.failedDesc
	ch <- c.dlqDesc
	ch <- c.lastErrDesc
	ch <- c.queueDesc
}

func (c *exporterSinkCollector) Collect(ch chan<- prometheus.Metric) {
	for _, s := range c.src.ExporterStats() {
		ch <- prometheus.MustNewConstMetric(c.sentDesc, prometheus.CounterValue, float64(s.Sent), s.Name)
		ch <- prometheus.MustNewConstMetric(c.dropDesc, prometheus.CounterValue, float64(s.Dropped), s.Name)
		ch <- prometheus.MustNewConstMetric(c.failedDesc, prometheus.CounterValue, float64(s.Failed), s.Name)
		ch <- prometheus.MustNewConstMetric(c.dlqDesc, prometheus.CounterValue, float64(s.DLQ), s.Name)
		ch <- prometheus.MustNewConstMetric(c.queueDesc, prometheus.GaugeValue, float64(s.QueuePending), s.Name)
		if s.LastErr != "" {
			msg := s.LastErr
			if len(msg) > lastErrMaxLen {
				msg = msg[:lastErrMaxLen]
			}
			ch <- prometheus.MustNewConstMetric(c.lastErrDesc, prometheus.GaugeValue, 1, s.Name, msg)
		}
	}
}

// splitHook turns "kind:name" back into a (kind, name) pair. If the input
// has no colon, kind defaults to "unknown" so the gauge is still emittable
// instead of silently dropped.
func splitHook(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:]
		}
	}
	return "unknown", s
}
