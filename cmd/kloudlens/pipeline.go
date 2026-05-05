// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boanlab/kloudlens/internal/correlation"
	"github.com/boanlab/kloudlens/internal/downgrade"
	"github.com/boanlab/kloudlens/internal/frame2intent"
	"github.com/boanlab/kloudlens/internal/graph"
	"github.com/boanlab/kloudlens/internal/history"
	"github.com/boanlab/kloudlens/internal/intent"
	"github.com/boanlab/kloudlens/internal/lineage"
	"github.com/boanlab/kloudlens/internal/path"
	"github.com/boanlab/kloudlens/internal/peers"
	"github.com/boanlab/kloudlens/internal/sensor"
	"github.com/boanlab/kloudlens/internal/syscalls"
	"github.com/boanlab/kloudlens/pkg/baseline"
	"github.com/boanlab/kloudlens/pkg/enricher"
	"github.com/boanlab/kloudlens/pkg/types"
)

// Pipeline wires the six foundation layers behind one Handler / Emitter pair.
//
//	SyscallEvent → Pipeline.Handle → { bridge → aggregator → IntentEvent → OnIntent }
//	 + { history · graph · baseline · correlation }
//
// Pipeline.Handle dual-observes the raw event: the aggregator gets routed
// calls via the bridge, and the side layers (history / graph / baseline /
// correlation) observe the SyscallEvent directly so they record state that
// IntentEvent has already abstracted away (PID, ancestor info, file-write
// timestamps, etc).
// IntentSink is the narrow interface Pipeline needs from an exporter.
// internal/exporter.GRPCClient satisfies it; tests use inline fakes. An
// empty Sinks slice disables off-node shipping (JSONL only).
type IntentSink interface {
	Submit(types.IntentEvent)
}

// DeviationSink receives every DeviationEvent emitted by the Detector.
// The gRPC SubscribeServer implements it; tests attach fakes.
// Submit must be non-blocking — slow consumers drop internally.
type DeviationSink interface {
	SubmitDeviation(types.DeviationEvent)
}

// RawSink receives every SyscallEvent that passes through Handle when
// raw-stream shipment is enabled. The gRPC SubscribeServer implements it.
// Submit must be non-blocking.
type RawSink interface {
	SubmitSyscall(types.SyscallEvent)
}

// GraphEdgeSink is notified for every edge added to the Session Graph. Used
// by SubscribeSession to stream session-scoped edges live; edges with no
// SessionID are still forwarded (the sink filters at its own layer).
type GraphEdgeSink interface {
	OnLiveGraphEdge(types.GraphEdge)
}

type Pipeline struct {
	Agg     *intent.Aggregator
	History *history.Store
	Graph   *graph.Store
	// GraphDisabled gates Graph.AddEdge on the hot path. Live edge sinks
	// (klctl stream graph) still receive every edge regardless. Set by
	// --graph=off; QueryGraph returns empty in that mode.
	GraphDisabled bool
	Corr          *correlation.Detector
	Learner       *baseline.Learner
	// detector is a read-mostly atomic pointer so the hot Handle path reads
	// without locking. AttachDetector / BaselineActivate / BaselineDeactivate
	// are the only writers; they CAS'd to swap. Legacy field name preserved
	// via the Detector accessor.
	detector atomic.Pointer[baseline.Detector]
	PathComp *PathCompleter
	Enricher *enricher.Enricher // may be nil; bridge tolerates nil via NopResolver
	Lineage  *lineage.Walker    // may be nil; nil skips ancestor walk on exec

	Sinks     []IntentSink
	DevSinks  []DeviationSink
	RawSinks  []RawSink
	EdgeSinks []GraphEdgeSink

	// PeerMatch resolves connect destinations to the container that
	// bound the listener on this node. Populated by observed bind
	// events, consulted on connect to upgrade IPC_CONNECT edges from
	// opaque peer:IP:PORT leaves to typed cont:<id> targets.
	PeerMatch *peers.Registry

	Sensor *sensor.EBPFSensor // wired by main when live mode; read-only for stats.

	// downgrade is set when --auto-downgrade is enabled. AdaptiveLevel reads
	// through this pointer so kloudlens_adaptive_level and AgentStatus track
	// the live controller state instead of the zero-value stub.
	downgrade atomic.Pointer[downgrade.Controller]

	// Enrichment level is a composition of two inputs:
	// - operatorLevel: what the HookSubscription spec.enrichment.level or
	// `klctl config set enrichment-level=…` asked for.
	// - downgradeLevel: what the adaptive downgrade supervisor pushed in
	// response to ringbuf pressure (maps Normal/Sampled→"full",
	// HeavilySampled→"minimal", CriticalOnly→"none").
	// enrichLevel holds the effective value (most-restrictive-wins) that
	// recordHistory / runCorrelation read on the hot path. The mutex
	// serializes Apply* writes so a racing operator + supervisor pair can't
	// interleave and leave the three atomics in an inconsistent state.
	// "full" runs every side observation; "minimal" skips correlation
	// heuristics; "none" also skips historical context recording. The
	// baseline Learner and Detector are unaffected at any level — enrichment
	// level gates the G2 context layer, not security-critical policy
	// evaluation.
	enrichLevelMu  sync.Mutex
	operatorLevel  atomic.Value // string — operator intent (default "full")
	downgradeLevel atomic.Value // string — adaptive controller forcing (default "full")
	enrichLevel    atomic.Value // string — effective (most-restrictive of the two)

	bridge      *frame2intent.Bridge
	now         func() time.Time
	mu          sync.Mutex
	out         io.Writer
	devOut      io.Writer // JSONL sink for DeviationEvents; nil disables emission
	intentCount int
	devCount    int
	syscallCnt  int
	overflowCnt int
}

// NewPipeline composes every layer with sensible defaults and returns a
// Pipeline whose Handle method is the SyscallEvent entry point. `out`
// receives newline-delimited JSON for every IntentEvent produced.
func NewPipeline(out io.Writer, clock func() time.Time) *Pipeline {
	if clock == nil {
		clock = time.Now
	}
	p := &Pipeline{
		History: history.New(history.Config{Clock: clock}),
		Graph:   graph.New(graph.Config{Clock: clock}),
		Corr:    correlation.New(correlation.Config{Clock: clock, Window: 60 * time.Second}),
		Learner: baseline.NewLearner(baseline.LearnerConfig{
			CMSEps:          0.01,
			CMSDelta:        0.01,
			RarityFreqFloor: 0.02,
			MarkovProbFloor: 0.10,
		}, clock()),
		PathComp:  &PathCompleter{CWD: path.NewProcCWD()},
		PeerMatch: peers.NewRegistry(),
		now:       clock,
		out:       out,
	}
	p.Agg = intent.NewAggregator(intent.Config{IdleTimeout: 2 * time.Second}, p.onIntent)
	p.bridge = frame2intent.NewBridge(p.Agg, nil)
	p.operatorLevel.Store("full")
	p.downgradeLevel.Store("full")
	p.enrichLevel.Store("full")
	return p
}

// recordHistory reports whether side layers that populate the Historical
// Context ring should run for the current enrichment level. Level "none"
// suppresses exec/container/cred recording; every other level records.
func (p *Pipeline) recordHistory() bool {
	v, _ := p.enrichLevel.Load().(string)
	return v != "none"
}

// runCorrelation reports whether correlation.Detector heuristics should
// observe this event. Only "full" enables correlation — "minimal" and
// "none" skip the writes/dns/connect sweep so saturated agents stop
// spending hot-path CPU on heuristics that the operator has dialed down.
func (p *Pipeline) runCorrelation() bool {
	v, _ := p.enrichLevel.Load().(string)
	return v == "" || v == "full"
}

// AttachEnricher swaps the bridge's resolver for the given Enricher.
// Passing nil reverts to the tracer's NopMetaResolver so tests that
// don't care about enrichment stay simple. The BirthNotifier
// (clone/unshare/setns → immediate NSMap rescan) is wired separately
// via AttachLifecycleContext once the agent's lifetime ctx exists, so
// the deferred-rescan goroutine can be cancelled cleanly on shutdown.
func (p *Pipeline) AttachEnricher(e *enricher.Enricher) {
	p.Enricher = e
	if e == nil {
		p.bridge = frame2intent.NewBridge(p.Agg, nil)
		return
	}
	p.bridge = frame2intent.NewBridge(p.Agg, e)
}

// AttachLifecycleContext wires the bridge's BirthNotifier to the
// enricher under ctx, so a CLONE_NEWPID/setns syscall triggers an
// immediate NSMap rescan. Called once from main after the agent's
// signal-aware ctx is available; safe no-op when no enricher is
// attached.
func (p *Pipeline) AttachLifecycleContext(ctx context.Context) {
	if p.Enricher == nil || p.bridge == nil {
		return
	}
	p.bridge.AttachBirthNotifier(ctx, enricher.NewBirthNotifier(p.Enricher, 0))
}

// Handle is the sensor.Handler registered with the EBPFSensor. It hands the
// event to the bridge, then observes the raw syscall in the side layers.
func (p *Pipeline) Handle(e types.SyscallEvent) {
	p.mu.Lock()
	p.syscallCnt++
	p.mu.Unlock()

	// Raw-stream fan-out (opt-in; off by default via an empty RawSinks).
	// Fires on every observed syscall, including frames that the intent
	// aggregator would later drop — that's the whole point of the raw
	// tier for debugging and custom downstream processing.
	for _, s := range p.RawSinks {
		s.SubmitSyscall(e)
	}

	// Absolutize relative file/exec paths before anyone observes them.
	// Relatives that can't be reconstructed (short-lived PID or cgroup-
	// relative openat whose dirfd we don't track) are cleared so downstream
	// allow-set recording short-circuits on e.Resource == "".
	if e.Resource != "" && (e.Category == "file" || e.Category == "process") &&
		!strings.HasPrefix(e.Resource, "/") {
		// If this is openat/openat2 with a non-AT_FDCWD dirfd, try
		// the bridge's fd cache first. A known dirfd whose entry isn't
		// cached means the earlier open was missed (BPF drop, late
		// attach); CWD-join would produce a misleading absolute, so we
		// clear Resource in that case and let the allow-set short-circuit.
		handled := false
		if e.Category == "file" && (e.SyscallName == "openat" || e.SyscallName == "openat2") {
			if dirfd, ok := frame2intent.DirfdFromArgs(e); ok && dirfd != frame2intent.AtFDCWD {
				if abs, found := p.bridge.ResolveDirfd(e.PID, dirfd, e.Resource); found {
					e.Resource = abs
				} else {
					e.Resource = ""
				}
				handled = true
			}
		}
		if !handled && e.Resource != "" {
			if resolved := p.PathComp.Complete(e.PID, e.Resource); resolved != "" {
				e.Resource = resolved
				if e.Category == "process" && e.ExePath != "" && !strings.HasPrefix(e.ExePath, "/") {
					e.ExePath = resolved
				}
			} else {
				e.Resource = ""
			}
		}
	}

	// 1) Bridge → Aggregator → (eventually) OnIntent.
	p.bridge.Handle(e)

	// 2) Side observations that don't fit the IntentEvent boundary.
	ts := time.Unix(0, int64(e.TimestampNS)) // #nosec G115 -- BPF-emitted uint64 nanosecond timestamp fits into int64 well beyond year 2262
	if ts.IsZero() {
		ts = p.now()
	}
	switch e.Category {
	case "process":
		switch e.Operation {
		case "execute":
			if e.RetVal != 0 {
				return
			}
			// history: push the ancestor chain (oldest → leaf-parent)
			// followed by the leaf itself. Lineage.Walker reads
			// /proc/PID/status; chain stays empty when the walker
			// isn't attached or the process exits before we read it
			// — the leaf push always succeeds. enrichment.level=none
			// short-circuits the writes so RecentProcesses Snapshot
			// stays empty (same shape as a brand-new agent).
			if p.recordHistory() {
				if p.Lineage != nil {
					for _, a := range p.Lineage.Chain(e.PID) {
						p.History.RecordExec(e.PID, types.ProcessAncestor{
							PID:         a.PID,
							Binary:      a.Binary,
							ContainerID: e.Meta.ContainerID,
						})
					}
				}
				p.History.RecordExec(e.PID, types.ProcessAncestor{
					PID:         e.PID,
					Binary:      e.Resource,
					ExecTSNS:    e.TimestampNS,
					ContainerID: e.Meta.ContainerID,
				})
			}
			// graph: container → exec'd process.
			if e.Meta.ContainerID != "" {
				p.addEdge(types.GraphEdge{
					EdgeID:    types.UUIDv7(),
					Kind:      graph.EdgeExec,
					SrcNode:   "cont:" + e.Meta.ContainerID,
					DstNode:   fmt.Sprintf("proc:%d", e.PID),
					TSNS:      e.TimestampNS,
					SessionID: e.Meta.ContainerID,
				})
			}
			// baseline: the exec candidate + the syscall name.
			if e.Resource != "" {
				p.Learner.ObserveExec(e.Resource)
				if d := p.detector.Load(); d != nil {
					if dv := d.CheckExec(e.Resource, e.Meta); dv != nil {
						p.emitDeviation(*dv)
					}
				}
			}
		case "exit":
			if p.recordHistory() {
				p.History.OnProcessExit(e.PID)
			}
			// Drop listener entries so a later connect to the same port
			// doesn't mis-resolve to a dead process. Safe when the PID had
			// no binds; ObserveExit is O(entries-for-this-pid).
			p.PeerMatch.ObserveExit(e.PID)
		}
	case "file":
		// Resource-bearing ops (open/chmod/unlink/...) populate the graph +
		// allow-set; resourceless ops (close/read/write without path) still
		// fall through to the trailing ObserveSyscall so the syscall shows
		// up in the CMS and seccomp allowlist.
		if e.Resource != "" {
			// mapper.go decodes open(2) flags: O_WRONLY/O_RDWR/O_CREAT/
			// O_TRUNC flip the operation to "open_write". The ops below are
			// unambiguous writes; all of them land in FilePathsWrite so
			// FromProfile can route them to Spec.File.Write on export.
			switch e.Operation {
			case "open":
				p.Learner.ObserveFilePath(e.Resource)
			case "open_write", "chmod", "chown", "unlink", "rename",
				"mkdir", "rmdir", "link", "linkat", "symlink", "symlinkat":
				p.Learner.ObserveFilePathWrite(e.Resource)
			}
			if d := p.detector.Load(); d != nil {
				switch e.Operation {
				case "open", "open_write", "chmod", "chown", "unlink", "rename",
					"mkdir", "rmdir", "link", "linkat", "symlink", "symlinkat":
					if dv := d.CheckFilePath(e.Resource, e.Meta); dv != nil {
						p.emitDeviation(*dv)
					}
				}
			}
			switch e.Operation {
			case "open", "open_write", "chmod", "chown", "unlink", "rename",
				"mkdir", "rmdir", "link", "linkat", "symlink", "symlinkat":
				p.addEdge(types.GraphEdge{
					EdgeID:    types.UUIDv7(),
					Kind:      graph.EdgeFileTouch,
					SrcNode:   fmt.Sprintf("proc:%d", e.PID),
					DstNode:   "file:" + e.Resource,
					TSNS:      e.TimestampNS,
					SessionID: e.Meta.ContainerID,
				})
			}
			if e.Operation == "chmod" && p.runCorrelation() {
				// Approximate "chmod +x": we don't see the mode bits from the
				// current mapper output, so optimistically record it. Correlation
				// layer ignores stale entries via its window sweep.
				p.Corr.RecordChmodX(e.Resource, ts)
			}
		}
	case "network":
		if e.Operation == "dns_answer" {
			p.handleDNSAnswer(e, ts)
			break
		}
		if e.Operation == "bind" && e.Resource != "" && e.RetVal == 0 {
			// Record the listener so a future connect to this addr from a
			// different container resolves to a typed cross-container edge
			// instead of an opaque peer leaf.
			p.PeerMatch.ObserveBind(e.Resource, e.PID, e.Meta.ContainerID, e.TimestampNS)
		}
		if e.Operation == "connect" && e.Resource != "" {
			p.Learner.ObserveEgressPeer(e.Resource)
			if p.runCorrelation() {
				if host, _, ok := splitHostPort(e.Resource); ok {
					_ = p.Corr.CheckConnect(e.PID, host, ts)
				}
			}
			// Same-node peer resolution: if the kernel listener registry
			// tagged this connect with peer_pid, OR the user-space mirror
			// knows who bound this addr, upgrade the DstNode from the
			// opaque peer:<addr> leaf to a typed cont:<id> target. Kernel
			// takes precedence — its map sees every bind, including ones
			// that happened before kloudlens started scraping events.
			edge := types.GraphEdge{
				EdgeID:    types.UUIDv7(),
				Kind:      graph.EdgeIPCConnect,
				SrcNode:   fmt.Sprintf("proc:%d", e.PID),
				DstNode:   "peer:" + e.Resource,
				TSNS:      e.TimestampNS,
				SessionID: e.Meta.ContainerID,
			}
			var peerPID int32
			var peerContainerID string
			if kp := kernelPeerPID(e); kp != 0 && kp != e.PID {
				peerPID = kp
				// The kernel only knows pid; user-space already tracks
				// bind→ContainerID via peers.ObserveBind, so reconcile
				// by walking the registry for any entry owned by kp.
				// Falling back to the addr lookup is safe if the first
				// scan misses (e.g. BPF caught the bind, but the mirroring
				// user-space event hasn't been flushed yet).
				if peer, ok := p.PeerMatch.Lookup(e.Resource); ok {
					peerContainerID = peer.ContainerID
				}
			} else if peer, ok := p.PeerMatch.Lookup(e.Resource); ok &&
				peer.ContainerID != "" && peer.ContainerID != e.Meta.ContainerID {
				peerPID = peer.PID
				peerContainerID = peer.ContainerID
			}
			if peerContainerID != "" && peerContainerID != e.Meta.ContainerID {
				edge.DstNode = "cont:" + peerContainerID
				if edge.Attributes == nil {
					edge.Attributes = map[string]string{}
				}
				edge.Attributes["peer_addr"] = e.Resource
				edge.Attributes["peer_pid"] = fmt.Sprint(peerPID)
			} else if peerPID != 0 {
				// Kernel tagged the connect but user-space hasn't seen
				// the bind yet — still surface peer_pid in attributes so
				// downstream consumers don't lose the signal. DstNode
				// stays opaque until the ContainerID catches up.
				if edge.Attributes == nil {
					edge.Attributes = map[string]string{}
				}
				edge.Attributes["peer_addr"] = e.Resource
				edge.Attributes["peer_pid"] = fmt.Sprint(peerPID)
			}
			p.addEdge(edge)
			if d := p.detector.Load(); d != nil {
				if dv := d.CheckConnect(e.Resource, e.Meta); dv != nil {
					p.emitDeviation(*dv)
				}
			}
		}
	case "creds":
		// Emit a CredTransition into history.credTL so HistoricalContext
		// snapshots expose the privilege timeline for this pid. Only the
		// return==0 path counts: a failed setuid/setgid doesn't change
		// kernel creds, so recording it would poison the "did this process
		// escalate" signal correlation.privilege_escalation_window relies on.
		if e.RetVal == 0 && p.recordHistory() {
			if ct, ok := credTransitionFromEvent(e); ok {
				p.History.RecordCred(e.PID, ct)
			}
		}
	}
	// The BPF program multiplexes real syscalls and LSM/tracepoint hooks
	// through the same event shape; only real syscalls belong in the
	// learner's CMS/Markov/allowlist because downstream consumers (seccomp
	// export in particular) can't use hook names.
	if e.SyscallName != "" && syscalls.IsRealSyscall(e.SyscallID) {
		p.Learner.ObserveSyscall(e.SyscallName)
		if d := p.detector.Load(); d != nil {
			for _, dv := range d.ObserveSyscall(e.PID, e.SyscallName, e.Meta) {
				p.emitDeviation(dv)
			}
		}
	}
}

// EmitSynthetic routes a pipeline-generated IntentEvent (e.g. OverflowSummary
// from the tracer drop monitor) through the same emit path as aggregator-
// produced intents. This keeps JSONL output, fan-out to sinks, and history
// ring recording consistent regardless of whether the event originated from
// the aggregator or from a side channel.
func (p *Pipeline) EmitSynthetic(ev types.IntentEvent) {
	if ev.Kind == "OverflowSummary" {
		p.mu.Lock()
		p.overflowCnt++
		p.mu.Unlock()
	}
	p.onIntent(ev)
}

// onIntent is the Aggregator emitter. It writes JSONL and records each intent
// in the history ring so later Snapshot calls can expose it.
func (p *Pipeline) onIntent(ev types.IntentEvent) {
	p.mu.Lock()
	p.intentCount++
	if p.out != nil {
		_ = writeJSONLine(p.out, ev)
	}
	p.mu.Unlock()

	// Fan-out to every attached off-node sink. Submit is non-blocking
	// on each sink (queue-based drop-on-full policy inside the sink),
	// so slow collectors can't stall the live aggregator.
	for _, s := range p.Sinks {
		s.Submit(ev)
	}

	entry := types.HistoryEntry{
		TSNS:    ev.EndNS,
		Kind:    ev.Kind,
		Summary: summarize(ev),
		RefID:   ev.IntentID,
	}
	if ev.Meta.ContainerID != "" && p.recordHistory() {
		p.History.RecordContainerIntent(ev.Meta.ContainerID, entry)
	}
	// RecordProcessIntent needs a PID, which IntentEvent doesn't carry,
	// so per-process intent recording is intentionally skipped here;
	// container-level recording carries the same information for the
	// downstream HistoricalContext snapshot.
}

// AttachDetector wires the baseline Detector + its JSONL output sink. Passing
// a nil detector disables deviation emission; passing a nil writer keeps the
// Detector active but silences the local JSONL stream (useful when
// DeviationEvents are fanned out to remote sinks instead).
func (p *Pipeline) AttachDetector(d *baseline.Detector, out io.Writer) {
	p.detector.Store(d)
	p.mu.Lock()
	p.devOut = out
	p.mu.Unlock()
}

// Detector returns the currently-attached Detector, or nil when deactivated.
// Hot-path readers call p.detector.Load directly; this accessor exists for
// tests and status callers.
func (p *Pipeline) Detector() *baseline.Detector { return p.detector.Load() }

// BaselineReset rebuilds the learner window from the current clock time. Any
// samples observed so far are discarded. Safe to call while the pipeline is
// running — the learner's own mutex serializes the swap.
func (p *Pipeline) BaselineReset() {
	p.Learner.Reset(p.now())
}

// BaselinePromote freezes the learner into a Profile. minSamples is the floor
// that guards under-trained promotions (ErrInsufficientSamples when unmet).
// imageRef + labelHash seed the Profile's deterministic ID.
func (p *Pipeline) BaselinePromote(minSamples uint64, imageRef, labelHash string) (*baseline.Profile, error) {
	return p.Learner.Promote(p.now(), imageRef, labelHash, minSamples)
}

// BaselineActivate attaches a Detector built from the given serialized Profile.
// Empty bytes deactivate the currently-attached Detector. Returns the resolved
// profile ID (empty when deactivating) and a deactivated flag.
func (p *Pipeline) BaselineActivate(profileJSON []byte) (profileID string, deactivated bool, err error) {
	if len(profileJSON) == 0 {
		p.detector.Store(nil)
		return "", true, nil
	}
	prof, err := baseline.UnmarshalProfile(profileJSON)
	if err != nil {
		return "", false, fmt.Errorf("baseline: unmarshal profile: %w", err)
	}
	if prof == nil {
		return "", false, errors.New("baseline: profile is nil after unmarshal")
	}
	p.detector.Store(baseline.NewDetector(prof))
	return prof.ID, false, nil
}

// emitDeviation fills DeviationID when missing, increments the counter, and
// writes the event as a JSON line to devOut. Safe for concurrent callers; the
// write is serialized on the pipeline mutex like intent emission.
func (p *Pipeline) emitDeviation(ev types.DeviationEvent) {
	if ev.DeviationID == "" {
		ev.DeviationID = types.UUIDv7()
	}
	p.mu.Lock()
	p.devCount++
	w := p.devOut
	p.mu.Unlock()
	if w != nil {
		_ = writeJSONLine(w, ev)
	}
	for _, s := range p.DevSinks {
		s.SubmitDeviation(ev)
	}
}

// addEdge is the single gateway every Handle-path uses to insert a graph edge.
// It wraps Graph.AddEdge so each successful insertion fans out to registered
// GraphEdgeSinks (e.g. the gRPC SubscribeSession handler). Callers stay the
// same shape — they still pass a fully-populated types.GraphEdge.
//
// When GraphDisabled is true the in-memory store update is skipped to keep
// the hot path O(1); subscribers (klctl stream graph) still receive every
// edge so live consumers are unaffected, but QueryGraph returns empty.
func (p *Pipeline) addEdge(e types.GraphEdge) {
	if !p.GraphDisabled {
		if err := p.Graph.AddEdge(e); err != nil {
			return
		}
	}
	for _, s := range p.EdgeSinks {
		s.OnLiveGraphEdge(e)
	}
}

// DeviationCount returns the total number of DeviationEvents emitted so far.
func (p *Pipeline) DeviationCount() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return uint64(p.devCount) // #nosec G115 -- monotonically increasing counter, never negative
}

// Reap drains idle aggregator state. Call periodically from the daemon loop.
func (p *Pipeline) Reap() int { return p.Agg.Reap() }

// Counters satisfies the admin.StatsSource interface. Zero values are
// returned for any source not wired in (e.g. tracer when --no-ebpf).
func (p *Pipeline) Counters() (syscalls, intents, framesRead, framesDropped uint64, ringbufUsage float64) {
	p.mu.Lock()
	syscalls = uint64(p.syscallCnt) // #nosec G115 -- monotonically increasing counter, never negative
	intents = uint64(p.intentCount) // #nosec G115 -- monotonically increasing counter, never negative
	p.mu.Unlock()
	if p.Sensor != nil {
		fr, fd := p.Sensor.DropStats()
		framesRead = fr
		framesDropped = fd
		if fr > 0 {
			ringbufUsage = float64(fd) / float64(fr+fd)
		}
	}
	return
}

// overflowCnt is bumped by EmitSynthetic when an OverflowSummary intent
// flows through; exposed via OverflowSummaryCount for the metrics collector.
func (p *Pipeline) OverflowSummaryCount() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return uint64(p.overflowCnt) // #nosec G115 -- monotonically increasing counter, never negative
}

// RingbufStats / CoalesceStats / InternStats / PathResolveStats / AdaptiveLevel
// implement internal/metrics.Source on the pipeline. They're thin passthroughs
// to the underlying sources — the metrics package does not depend on this
// file so these accessors are the public shape of the contract.
func (p *Pipeline) RingbufStats() (read, dropped uint64) {
	if p.Sensor == nil {
		return 0, 0
	}
	return p.Sensor.DropStats()
}

// KernelRingbufDrops reports per-category BPF ringbuf overruns. Returns a
// zero-value struct on --no-ebpf deployments or when the map read fails —
// metrics callers treat zero as "no loss observed" either way.
func (p *Pipeline) KernelRingbufDrops() sensor.RingbufDrops {
	if p.Sensor == nil {
		return sensor.RingbufDrops{}
	}
	rb, err := p.Sensor.KernelRingbufDrops()
	if err != nil {
		return sensor.RingbufDrops{}
	}
	return rb
}

// PairerStats returns (pendingFrames, evictedTotal) from the wire-level
// Pairer. pending is a gauge (current enter-frames awaiting exit); evicted
// is a monotonic counter (overflow drops since startup). Both zero on
// --no-ebpf / test deployments.
func (p *Pipeline) PairerStats() (pending, evicted uint64) {
	if p.Sensor == nil {
		return 0, 0
	}
	return uint64(p.Sensor.PendingPairs()), p.Sensor.PairerEvicted() // #nosec G115 -- PendingPairs is a non-negative length counter
}

func (p *Pipeline) CoalesceStats() (syscalls, intents uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return uint64(p.syscallCnt), uint64(p.intentCount) // #nosec G115 -- monotonically increasing counters, never negative
}

func (p *Pipeline) PathResolveStats() (resolved, missed uint64) {
	if p.PathComp == nil {
		return 0, 0
	}
	r, m := p.PathComp.Stats()
	return uint64(r), uint64(m)
}

// InternStats / AdaptiveLevel default to zero when the underlying components
// aren't wired (e.g. a daemon started without interning or without the
// downgrade controller). The metrics collector handles zero values gracefully.
func (p *Pipeline) InternStats() (hits, misses uint64) { return 0, 0 }
func (p *Pipeline) AdaptiveLevel() int {
	if c := p.downgrade.Load(); c != nil {
		return int(c.Level())
	}
	return 0
}

// AdaptiveUsage returns the most recent ring buffer usage fraction fed into
// the downgrade.Controller (range [0,1]). Surfaces the *input* signal that
// drives LevelNormal→Sampled transitions; paired with AdaptiveLevel so a
// dashboard can show both "why the controller moved" and "where it is now".
// Returns 0 when no controller is attached.
func (p *Pipeline) AdaptiveUsage() float64 {
	if c := p.downgrade.Load(); c != nil {
		return c.LastUsage()
	}
	return 0
}

// SetDowngradeController attaches the adaptive controller main.go creates()
// when --auto-downgrade is enabled, so AdaptiveLevel reports the live
// throttling state. Safe to call at most once during startup; passing nil
// detaches (used in tests that reuse a Pipeline).
func (p *Pipeline) SetDowngradeController(c *downgrade.Controller) {
	p.downgrade.Store(c)
}

// ApplyEnrichmentCorrelations satisfies admin.CorrelationDispatcher — the
// hook admin.ApplyPolicy invokes after validating a HookSubscription.
// Turns the validated spec.enrichment.correlations list into a
// Config.Enabled map via correlation.EnabledFromNames and swaps it into
// the running Detector with SetEnabled. An empty list is distinct from
// nil: nil leaves every heuristic on (boot default), [] disables all.
func (p *Pipeline) ApplyEnrichmentCorrelations(names []string) {
	if p.Corr == nil {
		return
	}
	p.Corr.SetEnabled(correlation.EnabledFromNames(names))
}

// ApplyEnrichmentLevel satisfies admin.EnrichmentLevelDispatcher — invoked
// after ApplyPolicy validates a HookSubscription payload. Pushes the
// validated spec.enrichment.level ("full" | "minimal" | "none") into the
// running pipeline so the next SyscallEvent observation runs the selected
// side layers. Empty string or unrecognized values snap back to "full" so
// a misrouted call can't silently disable enrichment — admin's strict
// parser already rejected unrecognized values upstream.
func (p *Pipeline) ApplyEnrichmentLevel(level string) {
	p.enrichLevelMu.Lock()
	defer p.enrichLevelMu.Unlock()
	switch level {
	case "full", "minimal", "none":
		p.operatorLevel.Store(level)
	default:
		p.operatorLevel.Store("full")
	}
	p.recomputeEnrichLevelLocked()
}

// ApplyDowngradeLevel maps a downgrade.Controller level onto an enrichment
// tier and recomputes the effective level. Wired as the Controller's
// onChange callback when --auto-downgrade is enabled. The mapping:
//
//	Normal, Sampled → "full" (plenty of headroom for side layers)
//	HeavilySampled → "minimal" (drop correlation to save CPU)
//	CriticalOnly → "none" (emergency — drop history too)
//
// Recovery walks the mapping backwards: once the controller demotes below
// HeavilySampled, downgradeLevel returns to "full" and the effective
// level collapses to operator intent — so a user who set "minimal" via
// klctl stays at "minimal" after the pressure clears instead of being
// silently reset to "full".
func (p *Pipeline) ApplyDowngradeLevel(lvl downgrade.Level) {
	var s string
	switch lvl {
	case downgrade.LevelNormal, downgrade.LevelSampled:
		s = "full"
	case downgrade.LevelHeavilySampled:
		s = "minimal"
	case downgrade.LevelCriticalOnly:
		s = "none"
	default:
		s = "full"
	}
	p.enrichLevelMu.Lock()
	defer p.enrichLevelMu.Unlock()
	p.downgradeLevel.Store(s)
	p.recomputeEnrichLevelLocked()
}

// recomputeEnrichLevelLocked stores the most-restrictive of operator and
// downgrade intent into enrichLevel. Must be called with enrichLevelMu
// held. Order: none < minimal < full — so the minimum rank wins.
func (p *Pipeline) recomputeEnrichLevelLocked() {
	op, _ := p.operatorLevel.Load().(string)
	dg, _ := p.downgradeLevel.Load().(string)
	p.enrichLevel.Store(mostRestrictiveLevel(op, dg))
}

// mostRestrictiveLevel returns whichever of two enrichment level strings
// reduces more work. Unknown / empty inputs collapse to "full" so a stale
// atomic read can never silence the pipeline below operator intent.
func mostRestrictiveLevel(a, b string) string {
	if levelRank(a) <= levelRank(b) {
		return canonLevel(a)
	}
	return canonLevel(b)
}

func levelRank(s string) int {
	switch s {
	case "none":
		return 0
	case "minimal":
		return 1
	}
	return 2 // "full", "" , anything unexpected
}

func canonLevel(s string) string {
	switch s {
	case "full", "minimal", "none":
		return s
	}
	return "full"
}

// OperatorEnrichmentLevel returns the last value an operator (klctl
// config set enrichment-level=… or an ApplyPolicy HookSubscription)
// asked for. Used by admin's EnrichmentLevelSource to surface in
// AgentStatus.Info so `klctl status` can tell the difference between
// "operator set minimal" and "pressure forced a demotion from full".
// Defaults to "full" when never set.
func (p *Pipeline) OperatorEnrichmentLevel() string {
	if v, ok := p.operatorLevel.Load().(string); ok && v != "" {
		return v
	}
	return "full"
}

// EnrichmentLevel returns the current level ("full" by default). Exposed
// for metrics and AgentStatus so operators can see which level a live
// klctl apply resolved to, without having to re-read the stored policy.
func (p *Pipeline) EnrichmentLevel() string {
	if v, ok := p.enrichLevel.Load().(string); ok && v != "" {
		return v
	}
	return "full"
}

// ApplyEnrichmentHistory satisfies admin.HistoryDispatcher — invoked after
// ApplyPolicy validates a HookSubscription payload. Pushes the validated
// spec.enrichment.{historyDepth,historyWindowSecs} into the running Store
// via SetHistoryDepth / SetHistoryTTL. Non-positive values are no-ops on
// the Store side, so the YAML default (omitted → 0) leaves the boot cap alone.
func (p *Pipeline) ApplyEnrichmentHistory(depth, windowSec int) {
	if p.History == nil {
		return
	}
	p.History.SetHistoryDepth(depth)
	if windowSec > 0 {
		p.History.SetHistoryTTL(time.Duration(windowSec) * time.Second)
	}
}

// Stats returns a one-line snapshot of the pipeline for periodic logging.
func (p *Pipeline) Stats() string {
	p.mu.Lock()
	sc, ic, dc := p.syscallCnt, p.intentCount, p.devCount
	p.mu.Unlock()
	hasDet := p.detector.Load() != nil
	s := p.Agg.Snapshot()
	hs := p.History.Sizes()
	cs := p.Corr.Sizes()
	pr, pd := p.PathComp.Stats()
	base := fmt.Sprintf(
		"syscalls=%d intents=%d agg={file=%d sock=%d exec=%d} hist={proc=%d cont=%d} graph={nodes=%d edges=%d} corr={w=%d x=%d d=%d} paths={resolved=%d dropped=%d}",
		sc, ic, s.FileKeys, s.SockKeys, s.ExecKeys,
		hs.ProcKeys, hs.ContKeys,
		p.Graph.NodeCount(), p.Graph.EdgeCount(),
		cs.Writes, cs.ChmodX, cs.DNS,
		pr, pd,
	)
	if hasDet {
		base += fmt.Sprintf(" deviations=%d", dc)
	}
	if p.Enricher != nil {
		es := p.Enricher.Stats()
		base += fmt.Sprintf(" enrich={ns=%d hits=%d miss=%d cri=%d}", es.NSSize, es.NSHits, es.NSMisses, es.CRISize)
	}
	if p.Sensor != nil {
		read, dropped := p.Sensor.DropStats()
		base += fmt.Sprintf(" tracer={frames=%d drops=%d}", read, dropped)
		if rb, err := p.Sensor.KernelRingbufDrops(); err == nil && rb.Any() {
			base += fmt.Sprintf(" rb_drops={crit=%d file=%d file_meta=%d net=%d proc=%d dns=%d proc_lc=%d sock_lc=%d}",
				rb.Crit, rb.BulkFile, rb.BulkFileMeta, rb.BulkNet, rb.BulkProc, rb.DNS, rb.ProcLC, rb.SockLC)
		}
	}
	return base
}

// credTransitionFromEvent turns a creds-category SyscallEvent into a
// CredTransition. The mapper surfaces uid/gid args as "new_uid"/"new_gid"
// (plus the variant-specific r/e/s components); we lift the primary "new"
// field into CredTransition.To and the caller's current uid/gid (snapshotted
// by BPF in the event header) into From. Cause captures the variant name,
// not just "setuid", so post-mortem callers can tell setreuid from
// setresuid without re-parsing Args.
//
// Returns ok=false for shapes that don't carry an actionable delta (e.g.
// capset, whose payload is a capability bitmask pair that the cred
// timeline does not model — the mapper still classifies it so the
// learner/detector observes the syscall name).
func credTransitionFromEvent(e types.SyscallEvent) (types.CredTransition, bool) {
	var newVal string
	for _, a := range e.Args {
		if a.Name == "new_uid" || a.Name == "new_gid" {
			newVal = a.Value
			break
		}
	}
	if newVal == "" {
		return types.CredTransition{}, false
	}
	kind := "uid"
	if e.Operation == "setgid" {
		kind = "gid"
	}
	var from string
	switch kind {
	case "uid":
		from = fmt.Sprintf("uid=%d", e.UID)
	case "gid":
		from = fmt.Sprintf("gid=%d", e.GID)
	}
	return types.CredTransition{
		TSNS:  e.TimestampNS,
		From:  from,
		To:    fmt.Sprintf("%s=%s", kind, newVal),
		Cause: e.SyscallName,
	}, true
}

func summarize(ev types.IntentEvent) string {
	switch ev.Kind {
	case "ProcessStart":
		return ev.Attributes["binary"]
	case "FileRead", "FileWrite", "FileReadWrite", "FileAccess":
		return ev.Attributes["path"]
	case "NetworkExchange":
		return ev.Attributes["peer"]
	case "DNSAnswer":
		// "evil.com → 1.2.3.4" reads better than just the qname or addr alone
		// in the history ring's per-container view.
		return ev.Attributes["query"] + " → " + ev.Attributes["addr"]
	}
	return ev.Kind
}

func writeJSONLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// splitHostPort splits "host:port" without the net package allocation. The
// Resource strings come out of the mapper in that exact format.
func splitHostPort(peer string) (host, port string, ok bool) {
	i := strings.LastIndex(peer, ":")
	if i < 0 {
		return "", "", false
	}
	return peer[:i], peer[i+1:], true
}

// kernelPeerPID returns the peer_pid attached by the BPF connect hook's
// listener-registry lookup. Returns 0 when absent (older BPF build, miss
// on this connect, or the source-tag dedup path didn't emit it).
func kernelPeerPID(e types.SyscallEvent) int32 {
	for _, a := range e.Args {
		if a.Name == "peer_pid" {
			if n, err := strconv.ParseInt(a.Value, 10, 32); err == nil {
				return int32(n)
			}
			return 0
		}
	}
	return 0
}

// handleDNSAnswer dispatches one A/AAAA record from a DNS response. The
// BPF cgroup_skb/ingress hook parses the response and emits one synthetic
// "dns_answer" SyscallEvent per record; mapper.go renders it with
// e.Resource = qname (FQDN) and named args carrying rtype + addr +
// cgroup_id.
//
// Two consumer paths:
//
// - correlation.RecordDNSAnswer ties the IP to its FQDN so a later
// connect to that IP can be cross-referenced ("connect to evil.com").
// Only invoked when correlation is enabled at the current enrichment
// level — same gate the chmod/connect heuristics use.
//
// - EmitSynthetic publishes a DNSAnswer IntentEvent through the same
// fan-out as aggregator-produced intents (JSONL, gRPC sinks, history
// ring). Lets klctl / dashboards see DNS resolution alongside
// ProcessStart/NetworkExchange without scraping a separate stream.
//
// Pod attribution: cgroup_skb runs in softirq context so e.Meta's
// pid_ns/mnt_ns are unreliable (whichever task was on CPU when the
// packet was processed). Instead we use bpf_skb_cgroup_id which
// identifies the receiving SOCKET's cgroup — a stable channel —
// and ask the enricher to map it to pod metadata. Falls back to
// e.Meta when the enricher isn't attached or the cgroup id is missing.
//
// Empty/missing fields short-circuit silently — DNS over TCP, AAAA(), and
// CNAME records reach this hook with addr unset and we don't want to
// emit a useless half-record.
func (p *Pipeline) handleDNSAnswer(e types.SyscallEvent, ts time.Time) {
	query := e.Resource
	if query == "" {
		return
	}
	var addr, rtype string
	var cgroupID uint64
	for _, a := range e.Args {
		switch a.Name {
		case "addr":
			addr = a.Value
		case "rtype":
			rtype = a.Value
		case "cgroup_id":
			if v, err := strconv.ParseUint(a.Value, 10, 64); err == nil {
				cgroupID = v
			}
		}
	}
	if addr == "" {
		return
	}
	meta := e.Meta
	if cgroupID != 0 && p.Enricher != nil {
		if resolved := p.Enricher.ResolveByCgroupID(cgroupID); resolved.ContainerID != "" || resolved.Pod != "" {
			meta = resolved
		}
	}
	if p.runCorrelation() {
		p.Corr.RecordDNSAnswer(addr, query, ts)
	}
	p.EmitSynthetic(types.IntentEvent{
		IntentID: types.UUIDv7(),
		Kind:     "DNSAnswer",
		StartNS:  e.TimestampNS,
		EndNS:    e.TimestampNS,
		Attributes: map[string]string{
			"query": query,
			"addr":  addr,
			"rtype": rtype,
		},
		Meta:       meta,
		Severity:   types.SeverityLow,
		Confidence: 1.0,
	})
}
