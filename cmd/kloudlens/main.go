// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Command kloudlens is the node-local orchestrator. It loads the live eBPF
// tracer, wires the six foundation layers (intent · history · graph ·
// correlation · baseline · contract) through the Pipeline, and writes each
// emitted IntentEvent to stdout (or a file) as newline-delimited JSON.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"net"

	"github.com/boanlab/kloudlens/internal/admin"
	"github.com/boanlab/kloudlens/internal/downgrade"
	"github.com/boanlab/kloudlens/internal/exporter"
	"github.com/boanlab/kloudlens/internal/graph"
	"github.com/boanlab/kloudlens/internal/hookprobe"
	"github.com/boanlab/kloudlens/internal/hookprobe/publisher"
	"github.com/boanlab/kloudlens/internal/lineage"
	"github.com/boanlab/kloudlens/internal/metrics"
	"github.com/boanlab/kloudlens/internal/sensor"
	"github.com/boanlab/kloudlens/internal/wal"
	"github.com/boanlab/kloudlens/pkg/baseline"
	"github.com/boanlab/kloudlens/pkg/enricher"
	"github.com/boanlab/kloudlens/pkg/types"

	"github.com/boanlab/kloudlens/protobuf"
	"google.golang.org/grpc"
)

type cliFlags struct {
	duration   time.Duration
	output     string
	statsEvery time.Duration
	noEBPF     bool

	mode          string
	profileOut    string
	profileIn     string
	deviationsOut string
	minSamples    uint64
	imageRef      string
	labelHash     string

	rawSyscalls  bool
	targetNS     string
	exceptNS     string
	skipPrograms string

	exportGRPC     string
	exportQueueLen int

	enrich         string
	enrichInterval time.Duration
	criEndpoint    string
	dockerEndpoint string
	graphMode      string
	nodeName       string
	clusterName    string

	walDir        string
	walMaxBytes   int64
	walSegSize    int64
	walTTL        time.Duration
	walGCEvery    time.Duration
	subscribeAddr string

	graphDB      string
	graphTimeout time.Duration

	adminAddr    string
	metricsAddr  string
	version      string
	enableRawStm bool

	publishCaps      bool
	publishCapsEvery time.Duration
	publishCapsAPI   string

	downgradeEnabled  bool
	downgradeInterval time.Duration
}

// defaultVersion is stamped at build time via -ldflags "-X main.defaultVersion=$(TAG)".
var defaultVersion = "dev"

func parseFlags() cliFlags {
	var f cliFlags
	flag.DurationVar(&f.duration, "duration", 0, "stop after this long (0 = run until SIGINT)")
	flag.StringVar(&f.output, "output", "-", "intent JSONL output path (\"-\" = stdout)")
	flag.DurationVar(&f.statsEvery, "stats-every", 5*time.Second, "periodic stats interval on stderr (0 = off)")
	flag.BoolVar(&f.noEBPF, "no-ebpf", false, "skip live eBPF loader (pipeline wire-check only)")
	flag.StringVar(&f.mode, "mode", "monitor", "execution mode: monitor | learn")
	flag.StringVar(&f.profileOut, "profile-out", "", "learn mode: write promoted Profile JSON here on shutdown")
	flag.StringVar(&f.profileIn, "profile-in", "", "monitor mode: load Profile JSON to drive Detector + DeviationEvent emission")
	flag.StringVar(&f.deviationsOut, "deviations-out", "-", "monitor mode: JSONL path for DeviationEvents (\"-\" = stderr; empty = discard)")
	flag.Uint64Var(&f.minSamples, "min-samples", 50, "learn mode: minimum syscall samples required to promote")
	flag.StringVar(&f.imageRef, "image-ref", "kloudlens/node", "learn mode: image reference seed for profile ID")
	flag.StringVar(&f.labelHash, "label-hash", "", "learn mode: workload label hash seed for profile ID")
	flag.BoolVar(&f.rawSyscalls, "enable-raw-syscalls", false, "attach raw_syscalls tracepoints (high volume; duplicates per-syscall tracepoints)")
	flag.StringVar(&f.targetNS, "target-ns", "", "comma-separated pidNS:mntNS keys; when set, monitor ONLY these namespaces")
	flag.StringVar(&f.exceptNS, "except-ns", "", "comma-separated pidNS:mntNS keys to skip (ignored if --target-ns is set)")
	flag.StringVar(&f.skipPrograms, "skip-bpf-programs", "", "comma-separated BPF program names to drop from the spec before load (escape hatch for kernel-version-specific verifier rejections; production runs leave empty)")
	flag.StringVar(&f.exportGRPC, "export-grpc", "", "host:port of an IntentExporter gRPC collector; when set, each intent is shipped there in addition to the JSONL output")
	flag.IntVar(&f.exportQueueLen, "export-queue", 1024, "in-flight intent queue depth for --export-grpc; on overflow the oldest is dropped")
	flag.StringVar(&f.enrich, "enrich", "off", "enrichment mode: off | proc | cri | docker (proc = /proc NS scanner; cri = proc + crictl pod/namespace lookup; docker = proc + Docker Engine /containers/json)")
	flag.DurationVar(&f.enrichInterval, "enrich-interval", 30*time.Second, "how often the enricher rebuilds its NS/CRI caches")
	flag.StringVar(&f.criEndpoint, "cri-endpoint", "", "CRI runtime socket URI for crictl (e.g. unix:///run/containerd/containerd.sock); empty uses crictl defaults")
	flag.StringVar(&f.dockerEndpoint, "docker-endpoint", "unix:///var/run/docker.sock", "Docker Engine API endpoint (unix:///path or tcp://host:port) for --enrich=docker")
	flag.StringVar(&f.graphMode, "graph", "on", "causal session graph mode: on | off. Off skips Graph.AddEdge on the hot path; live edge subscribers (klctl stream graph) still receive events. Reduces per-event CPU on syscall-heavy workloads.")
	flag.StringVar(&f.nodeName, "node", "", "node.name / host.name stamp on every ContainerMeta")
	flag.StringVar(&f.clusterName, "cluster", "", "cluster name stamp on every ContainerMeta")
	flag.StringVar(&f.walDir, "wal-dir", "", "directory for the intent WAL (empty = no WAL / no subscribe server)")
	flag.Int64Var(&f.walMaxBytes, "wal-max-bytes", 2<<30, "WAL retention size cap in bytes; oldest segments are trimmed on overflow")
	flag.Int64Var(&f.walSegSize, "wal-segment-size", 32<<20, "WAL segment rotation size in bytes")
	flag.DurationVar(&f.walTTL, "wal-ttl", 2*time.Hour, "WAL retention time; segments older than this are garbage-collected")
	flag.DurationVar(&f.walGCEvery, "wal-gc-every", 30*time.Second, "how often the WAL janitor enforces --wal-ttl / --wal-max-bytes (0 = never)")
	flag.StringVar(&f.subscribeAddr, "subscribe-addr", "", "host:port to serve the EventService pull API on (requires --wal-dir)")
	flag.StringVar(&f.graphDB, "graph-db", "", "bbolt file path for session graph persistence (empty = memory-only)")
	flag.DurationVar(&f.graphTimeout, "graph-db-timeout", 2*time.Second, "bbolt file-lock wait for --graph-db")
	flag.StringVar(&f.adminAddr, "admin-addr", "", "host:port to serve the AdminService (klctl) on")
	flag.StringVar(&f.metricsAddr, "metrics-addr", "", "host:port to serve Prometheus /metrics on (e.g. 0.0.0.0:9090)")
	flag.StringVar(&f.version, "version-tag", defaultVersion, "version label for the kloudlens_build_info metric and AgentStatus.Version (defaults to the ldflags-stamped build tag, or \"dev\")")
	flag.BoolVar(&f.enableRawStm, "enable-raw-stream", false, "append raw SyscallEvents to the WAL \"raw\" stream and fan out to SubscribeRaw (high volume; off by default)")
	flag.BoolVar(&f.publishCaps, "publish-caps", false, "publish NodeCapability CR (kloudlens.io/v1) using the in-cluster ServiceAccount (requires --node)")
	flag.DurationVar(&f.publishCapsEvery, "publish-caps-interval", 5*time.Minute, "re-publish cadence for --publish-caps")
	flag.StringVar(&f.publishCapsAPI, "publish-caps-apiserver", "", "override apiserver URL for --publish-caps (empty = https://kubernetes.default.svc)")
	flag.BoolVar(&f.downgradeEnabled, "auto-downgrade", true, "enable the adaptive sampling controller that reacts to ringbuf pressure")
	flag.DurationVar(&f.downgradeInterval, "auto-downgrade-interval", 1*time.Second, "how often the downgrade controller samples ringbuf usage")
	flag.Parse()
	return f
}

func main() {
	if err := run(parseFlags()); err != nil {
		log.SetFlags(0)
		log.Fatalf("kloudlens: %v", err)
	}
}

func run(f cliFlags) error {
	switch f.mode {
	case "monitor", "learn":
	default:
		return fmt.Errorf("invalid --mode=%q (want monitor|learn)", f.mode)
	}
	if f.mode == "learn" && f.profileOut == "" {
		return fmt.Errorf("--mode=learn requires --profile-out=<path>")
	}

	// Output sink.
	out, closeOut, err := openOutput(f.output)
	if err != nil {
		return err
	}
	defer closeOut()

	pipe := NewPipeline(out, time.Now)
	pipe.Lineage = &lineage.Walker{} // defaults to /proc, cap=16
	switch f.graphMode {
	case "on":
		// default — graph store maintained on hot path
	case "off":
		pipe.GraphDisabled = true
		fmt.Fprintln(os.Stderr, "kloudlens: graph=off — Graph.AddEdge skipped on hot path; live edge sinks still fan out, QueryGraph returns empty")
	default:
		return fmt.Errorf("invalid --graph=%q (want on|off)", f.graphMode)
	}
	learnStart := time.Now()

	// Load a frozen Profile and attach a Detector. The detector is meaningful
	// only in monitor mode; in learn mode the incoming events are supposed to
	// teach the baseline, so flagging deviations would circular-reference the
	// allow-set under construction.
	var devOutCloser func()
	if f.profileIn != "" {
		if f.mode != "monitor" {
			return fmt.Errorf("--profile-in requires --mode=monitor")
		}
		profData, rerr := os.ReadFile(f.profileIn)
		if rerr != nil {
			return fmt.Errorf("read profile %s: %w", f.profileIn, rerr)
		}
		prof, perr := baseline.UnmarshalProfile(profData)
		if perr != nil {
			return fmt.Errorf("parse profile %s: %w", f.profileIn, perr)
		}
		devW, closer, derr := openDeviationsOut(f.deviationsOut)
		if derr != nil {
			return derr
		}
		devOutCloser = closer
		pipe.AttachDetector(baseline.NewDetector(prof), devW)
		fmt.Fprintf(os.Stderr,
			"kloudlens: detector profile=%s execs=%d paths=%d peers=%d syscalls=%d deviations-out=%q\n",
			prof.ID, len(prof.ExecBinaries), len(prof.FilePaths), len(prof.EgressPeers),
			len(prof.SyscallAllowlist), f.deviationsOut)
	}

	// Optional bbolt persistence for the session graph. When enabled, on-disk
	// state is replayed into the in-memory Store first so existing sessions
	// survive an agent restart; subsequent mutations are write-through.
	var graphDB *graph.BoltPersister
	if f.graphDB != "" {
		graphDB, err = graph.OpenBolt(f.graphDB, f.graphTimeout)
		if err != nil {
			return fmt.Errorf("graph-db: %w", err)
		}
		if err := pipe.Graph.LoadInto(graphDB); err != nil {
			_ = graphDB.Close()
			return fmt.Errorf("graph-db replay: %w", err)
		}
		pipe.Graph.Persist(graphDB)
		fmt.Fprintf(os.Stderr, "kloudlens: graph-db=%s nodes=%d edges=%d sessions=%d\n",
			f.graphDB, pipe.Graph.NodeCount(), pipe.Graph.EdgeCount(), pipe.Graph.SessionCount())
	}

	// Enricher: optional pod/container metadata resolver. proc mode is /proc
	// scanning only (ContainerID + PodUID from cgroups); cri mode adds crictl
	// snapshots for pod name/namespace/labels. Off leaves ContainerMeta
	// empty.
	var enrichClient *enricher.Enricher
	switch f.enrich {
	case "off":
		// no enricher
	case "proc", "cri", "docker":
		opts := enricher.Options{
			RescanInterval: f.enrichInterval,
			NodeName:       f.nodeName,
			Cluster:        f.clusterName,
		}
		switch f.enrich {
		case "cri":
			opts.CRI = &enricher.CRIClient{Endpoint: f.criEndpoint}
		case "docker":
			opts.Docker = &enricher.DockerClient{Endpoint: f.dockerEndpoint}
		}
		enrichClient = enricher.NewEnricher(opts)
		pipe.AttachEnricher(enrichClient)
		fmt.Fprintf(os.Stderr, "kloudlens: enricher mode=%s interval=%s cri-endpoint=%q docker-endpoint=%q node=%q cluster=%q\n",
			f.enrich, f.enrichInterval, f.criEndpoint, f.dockerEndpoint, f.nodeName, f.clusterName)
	default:
		return fmt.Errorf("invalid --enrich=%q (want off|proc|cri|docker)", f.enrich)
	}

	// Off-node shipping (optional). The sink runs its own goroutine + queue
	// so onIntent stays non-blocking; on exit we close it to drain pending
	// sends best-effort.
	var grpcClient *exporter.GRPCClient
	if f.exportGRPC != "" {
		grpcClient = exporter.DialGRPC(f.exportGRPC, f.exportQueueLen)
		pipe.Sinks = append(pipe.Sinks, grpcClient)
		fmt.Fprintf(os.Stderr, "kloudlens: exporter grpc=%s queue=%d\n", f.exportGRPC, f.exportQueueLen)
	}
	// WAL + EventService pull API. Optional; requires --wal-dir. When set,
	// every emitted intent is appended to the WAL so external subscribers
	// (klctl, other agents) can pull with a durable cursor from
	var walStore *wal.WAL
	var subServer *exporter.SubscribeServer
	var subGRPC *grpc.Server
	var subLis net.Listener
	if f.walDir != "" {
		walStore, err = wal.Open(wal.Options{
			Dir:         f.walDir,
			MaxBytes:    f.walMaxBytes,
			SegmentSize: f.walSegSize,
			TTL:         f.walTTL,
		})
		if err != nil {
			return fmt.Errorf("open wal %s: %w", f.walDir, err)
		}
		subServer = exporter.NewSubscribeServer(walStore, nil, f.nodeName)
		pipe.Sinks = append(pipe.Sinks, subServer)
		pipe.DevSinks = append(pipe.DevSinks, subServer)
		pipe.EdgeSinks = append(pipe.EdgeSinks, subServer)
		if f.enableRawStm {
			pipe.RawSinks = append(pipe.RawSinks, subServer)
			fmt.Fprintln(os.Stderr, "kloudlens: raw syscall stream enabled (WAL \"raw\" + SubscribeRaw)")
		}
		subServer.SetGraph(pipe.Graph)
		fmt.Fprintf(os.Stderr, "kloudlens: wal dir=%s max=%d segment=%d ttl=%s\n",
			f.walDir, f.walMaxBytes, f.walSegSize, f.walTTL)
		if f.subscribeAddr != "" {
			subLis, err = net.Listen("tcp", f.subscribeAddr)
			if err != nil {
				return fmt.Errorf("listen %s: %w", f.subscribeAddr, err)
			}
			subGRPC = grpc.NewServer()
			protobuf.RegisterEventServiceServer(subGRPC, subServer)
			go func() { _ = subGRPC.Serve(subLis) }()
			fmt.Fprintf(os.Stderr, "kloudlens: subscribe listening on %s\n", f.subscribeAddr)
		}
	} else if f.subscribeAddr != "" {
		return fmt.Errorf("--subscribe-addr requires --wal-dir")
	}

	// Runtime config controller (klctl config get/set). The stats-interval
	// and wal-gc-every channels are wired to their respective goroutines
	// below. walGCCh is only populated when --wal-dir was set, so the
	// controller rejects the key on WAL-less builds instead of silently
	// dropping the change.
	statsIntervalCh := make(chan time.Duration, 1)
	var walGCCh chan time.Duration
	if walStore != nil {
		walGCCh = make(chan time.Duration, 1)
	}
	cfgCtrl := &configController{
		statsInterval:   f.statsEvery,
		statsIntervalCh: statsIntervalCh,
		walGCEvery:      f.walGCEvery,
		walGCCh:         walGCCh,
		enrichLevel:     pipe,
	}

	// Built up-front so admin.NewServer can hold a live observer — the
	// metrics Collector below registers it once it exists.
	policyCounter := metrics.NewPolicyCounter()

	// Best-effort capability snapshot, used by admin.ApplyPolicy to run
	// HookSubscription documents through policy.Resolve. Probing can fail
	// on non-Linux test hosts or in sandboxes — in that case we pass nil
	// and admin falls back to shape-only validation (prior behavior).
	capReport, capErr := hookprobe.DefaultProbe(f.nodeName).Discover()
	if capErr != nil {
		fmt.Fprintf(os.Stderr, "kloudlens: capability probe skipped: %v\n", capErr)
		capReport = nil
	}

	// AdminService (klctl).
	var adminGRPC *grpc.Server
	var adminLis net.Listener
	if f.adminAddr != "" {
		adminLis, err = net.Listen("tcp", f.adminAddr)
		if err != nil {
			return fmt.Errorf("listen admin %s: %w", f.adminAddr, err)
		}
		adminSrv := admin.NewServer(pipe, admin.Options{
			NodeName:                  f.nodeName,
			Cluster:                   f.clusterName,
			Version:                   f.version,
			WAL:                       walStore,
			Baseline:                  pipe,
			Config:                    cfgCtrl,
			PolicyObserver:            policyCounter,
			CorrelationDispatcher:     pipe,
			HistoryDispatcher:         pipe,
			EnrichmentLevelDispatcher: pipe,
			EnrichmentLevelSource:     pipe,
			Capabilities:              capReport,
		})
		adminGRPC = grpc.NewServer()
		protobuf.RegisterAdminServiceServer(adminGRPC, adminSrv)
		go func() { _ = adminGRPC.Serve(adminLis) }()
		fmt.Fprintf(os.Stderr, "kloudlens: admin listening on %s\n", f.adminAddr)
	}

	// Signal handling.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if f.duration > 0 {
		var stopTimer context.CancelFunc
		ctx, stopTimer = context.WithTimeout(ctx, f.duration)
		defer stopTimer()
	}

	// Live tracer. --no-ebpf lets us smoke-test the wiring without root.
	var tr *sensor.EBPFSensor
	if !f.noEBPF {
		target, err := sensor.ParseNSList(f.targetNS)
		if err != nil {
			return fmt.Errorf("--target-ns: %w", err)
		}
		except, err := sensor.ParseNSList(f.exceptNS)
		if err != nil {
			return fmt.Errorf("--except-ns: %w", err)
		}
		var skipProgs []string
		if s := strings.TrimSpace(f.skipPrograms); s != "" {
			for _, p := range strings.Split(s, ",") {
				if p = strings.TrimSpace(p); p != "" {
					skipProgs = append(skipProgs, p)
				}
			}
		}
		opts := sensor.LiveOptions{
			EnableRawSyscalls: f.rawSyscalls,
			TargetNS:          target,
			ExceptNS:          except,
			SkipPrograms:      skipProgs,
		}
		tr, err = sensor.LiveEBPFWith(opts)
		if err != nil {
			if errors.Is(err, sensor.ErrNotSupported) {
				return fmt.Errorf("live eBPF not supported on this build; rerun with --no-ebpf for dry-run")
			}
			return fmt.Errorf("load eBPF: %w (try sudo)", err)
		}
		pipe.Sensor = tr
		fmt.Fprintf(os.Stderr, "kloudlens: tracer mode=%s raw_syscalls=%v\n", opts.Mode(), opts.EnableRawSyscalls)
	}

	// Zero-miss container bootstrap: scan /proc synchronously BEFORE the
	// tracer starts streaming events so the first event from an already-
	// running container already sees populated ContainerMeta. A lazy scan
	// on every miss still runs in Enricher.Resolve, but the bootstrap here
	// removes the first-hit gap for the vast majority of workloads.
	if enrichClient != nil {
		if berr := enrichClient.Bootstrap(ctx); berr != nil {
			fmt.Fprintf(os.Stderr, "kloudlens: enricher bootstrap: %v (continuing)\n", berr)
		}
		enrichClient.Start(ctx)
		defer enrichClient.Stop()
		// Wire the bridge's birth notifier to the agent ctx so the
		// debounced /proc rescan goroutine cancels on SIGINT/SIGTERM.
		pipe.AttachLifecycleContext(ctx)
	}

	// Prometheus /metrics server. Runs in its own goroutine on
	// --metrics-addr (typically :9090). The collector reads live from
	// pipe + wal so every scrape reflects the current state.
	metricsDone := make(chan struct{})
	if f.metricsAddr != "" {
		mc := metrics.NewCollector(&metricsSource{
			pipe: pipe,
			wal:  walStore,
			sub:  subServer,
			grpc: grpcClient,
		})
		mc.SetVersion(f.version)
		if rerr := mc.Register(policyCounter.Collector()); rerr != nil {
			fmt.Fprintf(os.Stderr, "kloudlens: register policy counter: %v\n", rerr)
		}
		// Best-effort capability stamp — the probe may not be available on
		// non-Linux builds, so a failure is logged and the metric stays
		// empty (downstream dashboards tolerate absent labels).
		if rep, perr := hookprobe.DefaultProbe(f.nodeName).Discover(); perr == nil {
			hooks := make(map[string]bool, len(rep.Hooks))
			for _, h := range rep.Hooks {
				hooks[h.Kind+":"+h.Name] = h.Available
			}
			mc.SetCapabilities(metrics.CapabilitySnapshot{
				NodeID: f.nodeName, Kernel: rep.Kernel.Version, Arch: runtimeGOARCH(),
				BTF: rep.Kernel.HasBTF, Hooks: hooks,
			})
		}
		go func() {
			defer close(metricsDone)
			if err := mc.Serve(ctx, f.metricsAddr); err != nil {
				fmt.Fprintf(os.Stderr, "kloudlens: metrics server: %v\n", err)
			}
		}()
		fmt.Fprintf(os.Stderr, "kloudlens: metrics listening on %s\n", f.metricsAddr)
	} else {
		close(metricsDone)
	}

	// NodeCapability CR publisher (Tier 5). Keeps cluster-wide tooling off
	// the per-agent /metrics endpoint by mirroring capability_info into
	// etcd. Each tick re-runs the probe so a mid-life module load or LSM
	// policy change surfaces without an agent restart.
	publisherDone := make(chan struct{})
	if f.publishCaps {
		if f.nodeName == "" {
			close(publisherDone)
			fmt.Fprintln(os.Stderr, "kloudlens: --publish-caps requires --node")
		} else {
			pub := &publisher.Publisher{
				APIServer: f.publishCapsAPI,
				NodeName:  f.nodeName,
				Interval:  f.publishCapsEvery,
				Report: func() (*types.CapabilityReport, error) {
					return hookprobe.DefaultProbe(f.nodeName).Discover()
				},
			}
			go func() {
				defer close(publisherDone)
				if err := pub.Run(ctx); err != nil {
					fmt.Fprintf(os.Stderr, "kloudlens: capability publisher: %v\n", err)
				}
			}()
			fmt.Fprintf(os.Stderr, "kloudlens: NodeCapability publisher enabled node=%s interval=%s\n", f.nodeName, f.publishCapsEvery)
		}
	} else {
		close(publisherDone)
	}

	// Overflow monitor: sample tracer drop counters on a 10 s cadence and
	// emit an OverflowSummary IntentEvent whenever kernel-side ringbuf loss
	// or userspace decode drops advanced. This is the userspace fallback
	// until a BPF-side explicit lost-events counter is plumbed through.
	overflowDone := make(chan struct{})
	if tr != nil {
		om := sensor.NewOverflowMonitor(sensor.OverflowConfig{
			Source:   tr,
			Emit:     func(ev types.IntentEvent) { pipe.EmitSynthetic(ev) },
			Interval: 10 * time.Second,
			NodeName: f.nodeName,
			Cluster:  f.clusterName,
		})
		go func() {
			defer close(overflowDone)
			om.Run(ctx)
		}()
	} else {
		close(overflowDone)
	}

	// Start tracer + background goroutines.
	tracerDone := make(chan error, 1)
	if tr != nil {
		go func() { tracerDone <- tr.Start(ctx, pipe.Handle) }()
	} else {
		close(tracerDone)
	}

	reaperDone := make(chan struct{})
	go func() {
		defer close(reaperDone)
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pipe.Reap()
			}
		}
	}()

	// Session graph purger — closed sessions are kept for SessionTTL so
	// late Lineage/Peers queries can still resolve, then evicted. Without
	// a periodic Purge the store would only shrink via LRU eviction,
	// which on a low-churn node means closed sessions accumulate
	// indefinitely past their retention window.
	graphPurgeDone := make(chan struct{})
	if pipe.Graph != nil {
		go func() {
			defer close(graphPurgeDone)
			t := time.NewTicker(1 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					pipe.Graph.Purge()
				}
			}
		}()
	} else {
		close(graphPurgeDone)
	}

	// WAL janitor — enforces --wal-ttl and --wal-max-bytes on a cadence.
	// Without this goroutine GC is never called, so retention settings
	// are dead and disk grows unbounded until restart; OverflowCount also
	// stays at zero so the kloudlens_wal_overflow_total dashboard never
	// fires, masking under-provisioned caps.
	walGCDone := make(chan struct{})
	if walStore != nil {
		go func() {
			defer close(walGCDone)
			walStore.RunJanitorWithReconfig(ctx, f.walGCEvery, walGCCh)
		}()
	} else {
		close(walGCDone)
	}

	// Stats goroutine — always running so `klctl config set
	// stats-interval=10s` can turn printing back on without a restart.
	// A zero interval parks the goroutine on ctx.Done + cadence-change
	// channel only.
	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
		interval := f.statsEvery
		var ticker *time.Ticker
		var tickC <-chan time.Time
		if interval > 0 {
			ticker = time.NewTicker(interval)
			tickC = ticker.C
			defer func() {
				if ticker != nil {
					ticker.Stop()
				}
			}()
		}
		for {
			select {
			case <-ctx.Done():
				return
			case newInterval := <-statsIntervalCh:
				if ticker != nil {
					ticker.Stop()
					ticker = nil
					tickC = nil
				}
				interval = newInterval
				if interval > 0 {
					ticker = time.NewTicker(interval)
					tickC = ticker.C
				}
			case <-tickC:
				fmt.Fprintln(os.Stderr, pipe.Stats())
			}
		}
	}()

	// Adaptive downgrade supervisor — polls ringbuf usage and pushes a
	// matching sampling rate into the BPF bulk-sampler map on every
	// level transition. Gated behind --auto-downgrade so
	// operators can pin a specific rate for benchmarking.
	downgradeDone := make(chan struct{})
	if f.downgradeEnabled && tr != nil {
		// The onChange closure composes with klctl/ApplyPolicy operator
		// intent via Pipeline.ApplyDowngradeLevel — see pipeline.go's
		// recomputeEnrichLevelLocked for the most-restrictive-wins rule.
		ctrl := downgrade.New(downgrade.DefaultThresholds(), func(tr downgrade.Transition) {
			pipe.ApplyDowngradeLevel(tr.To)
		})
		pipe.SetDowngradeController(ctrl)
		cfgCtrl.mu.Lock()
		cfgCtrl.downgradeCtrl = ctrl
		cfgCtrl.mu.Unlock()
		go func() {
			defer close(downgradeDone)
			runDowngradeSupervisor(ctx, f.downgradeInterval, ctrl, pipe, tr, os.Stderr)
		}()
		fmt.Fprintf(os.Stderr, "kloudlens: auto-downgrade enabled (interval=%s)\n", f.downgradeInterval)
	} else {
		close(downgradeDone)
	}

	fmt.Fprintln(os.Stderr, "kloudlens: running — send SIGINT to stop")
	<-ctx.Done()

	// Graceful shutdown.
	if tr != nil {
		_ = tr.Stop()
	}
	<-tracerDone
	<-reaperDone
	<-graphPurgeDone
	<-statsDone
	<-downgradeDone
	<-overflowDone
	<-publisherDone
	<-metricsDone
	<-walGCDone

	// Flush any residual aggregator state to the JSONL sink.
	for pipe.Reap() > 0 {
	}

	// Close each sink so pending sends drain (up to 2s) before the
	// process exits. Stats is read AFTER Close so the count includes
	// the final drain that Close itself triggers (parent-ctx cancel →
	// drain queue → flush), otherwise the log undercounts by however
	// many intents the reaper produced on the way out.
	if grpcClient != nil {
		_ = grpcClient.Close()
		sent, dropped, lastErr := grpcClient.Stats()
		if lastErr != nil {
			fmt.Fprintf(os.Stderr, "kloudlens: exporter grpc sent=%d dropped=%d lastErr=%v\n", sent, dropped, lastErr)
		} else {
			fmt.Fprintf(os.Stderr, "kloudlens: exporter grpc sent=%d dropped=%d\n", sent, dropped)
		}
	}
	if subGRPC != nil {
		subGRPC.GracefulStop()
	}
	if adminGRPC != nil {
		adminGRPC.GracefulStop()
	}
	if walStore != nil {
		_ = walStore.Close()
	}
	if graphDB != nil {
		_ = graphDB.Close()
	}
	if devOutCloser != nil {
		devOutCloser()
	}

	fmt.Fprintln(os.Stderr, "kloudlens: final "+pipe.Stats())

	if f.mode == "learn" {
		if err := promoteAndWriteProfile(pipe, f, learnStart); err != nil {
			return err
		}
	}
	return nil
}

func promoteAndWriteProfile(pipe *Pipeline, f cliFlags, learnStart time.Time) error {
	profile, err := pipe.Learner.Promote(time.Now(), f.imageRef, f.labelHash, f.minSamples)
	if err != nil {
		if err == baseline.ErrInsufficientSamples {
			return fmt.Errorf("learn: not enough samples to promote (need %d, set --min-samples lower or run longer): %w", f.minSamples, err)
		}
		return fmt.Errorf("learn: promote: %w", err)
	}
	data, err := baseline.MarshalProfile(profile)
	if err != nil {
		return fmt.Errorf("learn: marshal profile: %w", err)
	}
	if err := os.WriteFile(f.profileOut, data, 0o600); err != nil {
		return fmt.Errorf("learn: write %s: %w", f.profileOut, err)
	}
	fmt.Fprintf(os.Stderr,
		"kloudlens: promoted profile id=%s samples=%d confidence=%.3f execs=%d paths=%d peers=%d → %s (learn window %s)\n",
		profile.ID, profile.SampleCount, profile.Confidence,
		len(profile.ExecBinaries), len(profile.FilePaths), len(profile.EgressPeers),
		f.profileOut, time.Since(learnStart).Truncate(time.Millisecond),
	)
	return nil
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "-" || path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- path is an operator-supplied output path
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// openDeviationsOut maps --deviations-out to a writer. "-" → stderr (keeps
// intent JSONL on stdout separable for tools that pipe them), "" → discard,
// anything else is O_APPEND so multiple daemon runs accumulate.
func openDeviationsOut(p string) (io.Writer, func(), error) {
	switch p {
	case "":
		return nil, func() {}, nil
	case "-":
		return os.Stderr, func() {}, nil
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- p is the operator-supplied deviations sink path
	if err != nil {
		return nil, nil, fmt.Errorf("open deviations %s: %w", p, err)
	}
	return f, func() { _ = f.Close() }, nil
}
