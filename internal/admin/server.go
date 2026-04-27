// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package admin implements the klctl ↔ kloudlens control plane
// . It exposes AgentStatus, policy CRUD (HookSubscription,
// BaselinePolicy, BehaviorContract()), capability + diagnose reporting,
// `top` streaming, and container `dump` replay.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/boanlab/kloudlens/internal/hookprobe"
	"github.com/boanlab/kloudlens/internal/policy"
	"github.com/boanlab/kloudlens/internal/wal"
	"github.com/boanlab/kloudlens/pkg/baseline"
	"github.com/boanlab/kloudlens/pkg/contract"
	"github.com/boanlab/kloudlens/pkg/types"
	"github.com/boanlab/kloudlens/protobuf"
)

// StatsSource is the narrow interface admin uses to read live pipeline
// counters. kloudlens's Pipeline satisfies it. AdaptiveLevel reflects the
// auto-downgrade controller's current throttling level (0 when the agent
// was started without --auto-downgrade).
type StatsSource interface {
	Counters() (syscalls, intents, framesRead, framesDropped uint64, ringbufUsage float64)
	AdaptiveLevel() int
}

// BaselineController is the narrow interface admin calls for behavioral
// baseline lifecycle operations. kloudlens.Pipeline satisfies it; tests
// inject fakes. A nil BaselineController disables the Baseline* RPCs —
// they return Unavailable-style errors.
type BaselineController interface {
	BaselineReset()
	BaselinePromote(minSamples uint64, imageRef, labelHash string) (*baseline.Profile, error)
	BaselineActivate(profileJSON []byte) (profileID string, deactivated bool, err error)
}

// ConfigController exposes runtime-tunable knobs to AdminService. A nil
// controller disables GetConfig/SetConfig (both return Unavailable-style
// errors so klctl can tell operators the agent build doesn't wire any
// live knobs rather than silently pretend the change took effect).
//
// Implementations are expected to be safe under concurrent RPCs —
// kloudlens keeps its config store behind a mutex.
type ConfigController interface {
	// Get returns every key the controller would accept in Set, with its
	// current normalized value. Keys NOT in the map are rejected by Set.
	Get() map[string]string
	// Set applies one key=value change. The returned string is the
	// normalized form the controller will echo back on subsequent Get
	// calls (for example a duration round-tripped through time.Duration).
	Set(key, value string) (normalized string, err error)
}

// Server implements protobuf.AdminServiceServer. Instances are safe for
// concurrent use — the policy map is guarded by a mutex and the stats
// source is expected to be atomic under the hood.
type Server struct {
	protobuf.UnimplementedAdminServiceServer

	stats     StatsSource
	baseline  BaselineController
	config    ConfigController
	policyOb  PolicyObserver
	corrDisp  CorrelationDispatcher
	histDisp  HistoryDispatcher
	levelDisp EnrichmentLevelDispatcher
	levelSrc  EnrichmentLevelSource
	caps      *types.CapabilityReport
	nodeName  string
	cluster   string
	version   string
	bootAt    time.Time

	mu       sync.RWMutex
	policies map[string]*protobuf.Policy // key = kind|name

	wal *wal.WAL // optional — enables Dump
}

// PolicyObserver receives one call per ApplyPolicy decision. `result` is
// "ok" when the payload passes validation + storage, "rejected" when
// validatePolicy returns an error (bad kind, malformed YAML, enum
// violation, regex compile failure, etc.). kloudlens wires this to the
// kloudlens_policies_applied_total{kind,result} CounterVec so operators
// can watch klctl apply churn + failure rate without tailing logs.
type PolicyObserver interface {
	Observe(kind, result string)
}

// CorrelationDispatcher accepts the `spec.enrichment.correlations` list
// from a HookSubscription and reconfigures the running correlation
// detector. kloudlens's Pipeline satisfies this via
// ApplyEnrichmentCorrelations. When nil, admin stores the policy but
// the heuristic set stays at whatever the pipeline booted with — tests
// and agent builds without a live Detector pass it through unchanged.
type CorrelationDispatcher interface {
	ApplyEnrichmentCorrelations(names []string)
}

// HistoryDispatcher accepts the `spec.enrichment.{historyDepth,historyWindowSecs}`
// values from a HookSubscription and reconfigures the running history store
// at apply time. kloudlens's Pipeline satisfies this via ApplyEnrichmentHistory.
// Without this hook, tightening/loosening the ring from `klctl apply` would
// only rewrite the policy object; the live store would keep its boot-time
// caps until a daemon restart. Non-positive values mean "leave unchanged",
// matching the YAML default semantics (omitted field → 0).
type HistoryDispatcher interface {
	ApplyEnrichmentHistory(depth, windowSec int)
}

// EnrichmentLevelDispatcher accepts the `spec.enrichment.level` value
// ("full" | "minimal" | "none") from a HookSubscription and reconfigures
// the running pipeline's side-layer gates at apply time. kloudlens's
// Pipeline satisfies this via ApplyEnrichmentLevel. Without the hook,
// changing the level via `klctl apply hook.yaml` would only rewrite the
// stored policy — the pipeline would keep running every side layer as if
// level were still "full" (parser default) until a daemon restart.
type EnrichmentLevelDispatcher interface {
	ApplyEnrichmentLevel(level string)
}

// EnrichmentLevelSource is the read-only companion to
// EnrichmentLevelDispatcher: GetStatus calls this to surface the current
// enrichment level in AgentStatus.Info so `klctl status` shows which tier
// the side layers are running at. Two methods because the adaptive
// downgrade controller can force a lower level than the operator asked
// for — exposing only the effective value would leave operators unable
// to tell the difference between "I set minimal" and "pressure demoted
// me from full to minimal", which matters for cost/privacy reviews.
// kloudlens's Pipeline satisfies this via EnrichmentLevel (effective)
// + OperatorEnrichmentLevel (operator intent).
type EnrichmentLevelSource interface {
	EnrichmentLevel() string         // effective (most-restrictive of operator/downgrade)
	OperatorEnrichmentLevel() string // what the operator last asked for
}

// Options configures the admin server.
type Options struct {
	NodeName                  string
	Cluster                   string
	Version                   string
	WAL                       *wal.WAL
	Baseline                  BaselineController
	Config                    ConfigController
	PolicyObserver            PolicyObserver
	CorrelationDispatcher     CorrelationDispatcher
	HistoryDispatcher         HistoryDispatcher
	EnrichmentLevelDispatcher EnrichmentLevelDispatcher
	EnrichmentLevelSource     EnrichmentLevelSource
	// Capabilities is a snapshot of the agent's CapabilityReport (kernel /
	// LSM / tracepoint availability). When non-nil, ApplyPolicy runs the
	// HookSubscription through policy.Resolve against it: onMissing=fail
	// subscriptions get rejected at apply-time on capability-poor nodes
	// instead of silently landing in the policy store, and skip/fallback
	// policies surface the unreachable hooks as ApplyResult.Warnings so
	// klctl apply can show "applied, but these 3 hooks won't attach".
	// Nil disables this check — tests and capability-unaware builds keep
	// the prior behavior.
	Capabilities *types.CapabilityReport
}

// NewServer builds an admin server; `stats` may be nil for tests.
func NewServer(stats StatsSource, opts Options) *Server {
	if opts.Version == "" {
		opts.Version = "dev"
	}
	return &Server{
		stats:     stats,
		baseline:  opts.Baseline,
		config:    opts.Config,
		policyOb:  opts.PolicyObserver,
		corrDisp:  opts.CorrelationDispatcher,
		histDisp:  opts.HistoryDispatcher,
		levelDisp: opts.EnrichmentLevelDispatcher,
		levelSrc:  opts.EnrichmentLevelSource,
		caps:      opts.Capabilities,
		nodeName:  opts.NodeName,
		cluster:   opts.Cluster,
		version:   opts.Version,
		bootAt:    time.Now(),
		policies:  map[string]*protobuf.Policy{},
		wal:       opts.WAL,
	}
}

// GetStatus returns a snapshot of counters + static metadata.
func (s *Server) GetStatus(_ context.Context, _ *protobuf.Empty) (*protobuf.AgentStatus, error) {
	st := &protobuf.AgentStatus{
		NodeName:      s.nodeName,
		Cluster:       s.cluster,
		Version:       s.version,
		SchemaVersion: types.WireSchemaVersion,
		UptimeSec:     uint64(time.Since(s.bootAt).Seconds()),
		Info:          map[string]string{"go": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH},
	}
	if s.stats != nil {
		syss, ints, fr, fd, rb := s.stats.Counters()
		st.SyscallsObserved = syss
		st.IntentsEmitted = ints
		st.FramesRead = fr
		st.FramesDropped = fd
		st.RingbufUsage = rb
		st.AdaptiveLevel = uint32(s.stats.AdaptiveLevel()) // #nosec G115 -- AdaptiveLevel is a small bounded enum value
	}
	if s.levelSrc != nil {
		eff := s.levelSrc.EnrichmentLevel()
		st.Info["enrichment_level"] = eff
		// Only surface operator intent when it diverges from effective —
		// equal values are just noise and would mislead operators into
		// thinking a "forced" demotion is in play.
		if op := s.levelSrc.OperatorEnrichmentLevel(); op != "" && op != eff {
			st.Info["enrichment_level_operator"] = op
		}
	}
	return st, nil
}

// ListPolicies returns all applied policies by kind+name.
func (s *Server) ListPolicies(_ context.Context, _ *protobuf.Empty) (*protobuf.PolicyList, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := &protobuf.PolicyList{}
	keys := make([]string, 0, len(s.policies))
	for k := range s.policies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := s.policies[k]
		out.Items = append(out.Items, &protobuf.PolicySummary{
			Kind:      p.Kind,
			Name:      p.Name,
			NodeScope: s.nodeName,
			Metadata:  map[string]string{"bytes": fmt.Sprintf("%d", len(p.Payload))},
		})
	}
	return out, nil
}

// ApplyPolicy validates the policy (kind-specific shape check) and stores it.
// Parsing errors come back as ApplyResult.Warnings rather than RPC errors
// so klctl can still see partial success.
func (s *Server) ApplyPolicy(_ context.Context, p *protobuf.Policy) (*protobuf.ApplyResult, error) {
	if p.GetKind() == "" || p.GetName() == "" {
		if s.policyOb != nil {
			s.policyOb.Observe(p.GetKind(), "rejected")
		}
		return &protobuf.ApplyResult{Ok: false, Message: "kind and name required"}, nil
	}
	warns, err := validatePolicy(p)
	if err != nil {
		if s.policyOb != nil {
			s.policyOb.Observe(p.GetKind(), "rejected")
		}
		return &protobuf.ApplyResult{Ok: false, Message: err.Error(), Warnings: warns}, nil
	}
	// Capability resolution for HookSubscription — runs only when Options.
	// Capabilities was supplied. onMissing=fail on a capability-poor node
	// turns a ResolutionError into an apply-time rejection; skip/fallback
	// surfaces the unreachable (kind,name) pairs as Warnings so klctl
	// apply shows the operator which hooks will silently stay un-attached.
	if s.caps != nil && p.GetKind() == "HookSubscription" {
		if parsed, perr := policy.Parse(p.Payload); perr == nil {
			resolved, rerr := parsed.Resolve(s.caps)
			var re *policy.ResolutionError
			if errors.As(rerr, &re) {
				if s.policyOb != nil {
					s.policyOb.Observe(p.GetKind(), "rejected")
				}
				return &protobuf.ApplyResult{Ok: false, Message: rerr.Error(), Warnings: warns}, nil
			}
			if resolved != nil {
				for _, m := range resolved.Skipped {
					warns = append(warns, fmt.Sprintf("skipped %s/%s: %s", m.Kind, m.Name, m.Reason))
				}
				for orig, alt := range resolved.Fallback {
					warns = append(warns, fmt.Sprintf("fallback %s → %s", orig, alt))
				}
			}
		}
	}
	s.mu.Lock()
	s.policies[p.GetKind()+"|"+p.GetName()] = p
	s.mu.Unlock()
	if s.policyOb != nil {
		s.policyOb.Observe(p.GetKind(), "ok")
	}
	// HookSubscription → live detector re-dispatch. validatePolicy already
	// exercised policy.Parse(); a second parse here is cheap (small YAML)
	// and avoids leaking the struct through validatePolicy's signature.
	// Errors are swallowed — validatePolicy is the gate; reaching this
	// point means the payload already parsed once.
	if s.corrDisp != nil && p.GetKind() == "HookSubscription" {
		if parsed, perr := policy.Parse(p.Payload); perr == nil {
			s.corrDisp.ApplyEnrichmentCorrelations(parsed.Spec.Enrichment.Correlations)
		}
	}
	// HookSubscription → live history-ring resize. Same reparse pattern as
	// the correlation branch — validatePolicy has already accepted the payload,
	// so the second Parse is expected to succeed; on the unlikely failure
	// path we skip silently rather than surface a late error.
	if s.histDisp != nil && p.GetKind() == "HookSubscription" {
		if parsed, perr := policy.Parse(p.Payload); perr == nil {
			s.histDisp.ApplyEnrichmentHistory(
				parsed.Spec.Enrichment.HistoryDepth,
				parsed.Spec.Enrichment.HistoryWindowSecs,
			)
		}
	}
	// HookSubscription → live enrichment-level swap. Reuses the same parse
	// envelope. validatePolicy already normalized Level to one of
	// full|minimal|none (parser defaults empty → "full"), so no further
	// validation is needed here.
	if s.levelDisp != nil && p.GetKind() == "HookSubscription" {
		if parsed, perr := policy.Parse(p.Payload); perr == nil {
			s.levelDisp.ApplyEnrichmentLevel(parsed.Spec.Enrichment.Level)
		}
	}
	return &protobuf.ApplyResult{Ok: true, Message: "applied", Warnings: warns}, nil
}

// DeletePolicy removes a named policy. Non-existent targets return ok=false
// rather than an error so klctl can `delete --if-exists` cleanly.
func (s *Server) DeletePolicy(_ context.Context, r *protobuf.PolicyRef) (*protobuf.DeleteResult, error) {
	key := r.GetKind() + "|" + r.GetName()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[key]; !ok {
		return &protobuf.DeleteResult{Ok: false, Message: "not found"}, nil
	}
	delete(s.policies, key)
	return &protobuf.DeleteResult{Ok: true, Message: "deleted"}, nil
}

// Diagnose runs a best-effort probe of kernel / LSM / cgroup state.
func (s *Server) Diagnose(_ context.Context, _ *protobuf.Empty) (*protobuf.DiagnoseReport, error) {
	p := hookprobe.DefaultProbe(s.nodeName)
	rep, err := p.Discover()
	if err != nil {
		return &protobuf.DiagnoseReport{Warnings: []string{err.Error()}}, nil
	}
	out := &protobuf.DiagnoseReport{
		KernelVersion:   rep.Kernel.Version,
		BtfAvailable:    rep.Kernel.HasBTF,
		BpfLsmAvailable: hasLSM(rep.Kernel.LSMs, "bpf"),
		CgroupVersion:   rep.Kernel.CgroupVer,
		Probes:          map[string]string{},
	}
	for _, h := range rep.Hooks {
		state := "ok"
		if !h.Available {
			state = "missing"
		}
		if h.FallbackSuggestion != "" {
			state = "fallback"
		}
		out.Probes[h.Kind+"/"+h.Name] = state
		if !h.Available && h.UnavailableReason != "" {
			out.Warnings = append(out.Warnings, h.Kind+"/"+h.Name+": "+h.UnavailableReason)
		}
	}
	return out, nil
}

// GetCapabilities returns the full CapabilityReport.
func (s *Server) GetCapabilities(_ context.Context, _ *protobuf.Empty) (*protobuf.CapabilityReport, error) {
	p := hookprobe.DefaultProbe(s.nodeName)
	rep, err := p.Discover()
	if err != nil {
		return nil, err
	}
	return capabilityReportToProto(rep), nil
}

// Top streams aggregate top-N snapshots every interval_ms tick until the
// client cancels. Synthetic rows backed by pipeline counters give klctl a
// working end-to-end path.
func (s *Server) Top(req *protobuf.TopRequest, stream protobuf.AdminService_TopServer) error {
	d := time.Duration(req.GetIntervalMs()) * time.Millisecond
	if d <= 0 {
		d = time.Second
	}
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-t.C:
			snap := s.topSnapshot(int(req.GetTopN()))
			if err := stream.Send(snap); err != nil {
				return err
			}
		}
	}
}

// Dump replays WAL entries for a container. Requires --wal-dir; otherwise
// returns empty. since_ns / until_ns bound the time window.
func (s *Server) Dump(req *protobuf.DumpRequest, stream protobuf.AdminService_DumpServer) error {
	if s.wal == nil {
		return fmt.Errorf("dump: WAL not enabled on this agent")
	}
	return s.wal.ReadFrom(0, "intent", func(e wal.Entry) error {
		if e.Event.Meta.ContainerID != "" && req.GetContainerId() != "" &&
			e.Event.Meta.ContainerID != req.GetContainerId() {
			return nil
		}
		if req.GetSinceNs() > 0 && uint64(e.TS) < req.GetSinceNs() { // #nosec G115 -- e.TS is a monotonic nanosecond timestamp
			return nil
		}
		if req.GetUntilNs() > 0 && uint64(e.TS) > req.GetUntilNs() { // #nosec G115 -- e.TS is a monotonic nanosecond timestamp
			return nil
		}
		env := &protobuf.EventEnvelope{
			Cursor:  &protobuf.Cursor{NodeId: s.nodeName, Stream: "intent", Seq: e.Seq},
			Payload: intentEnvelopePayload(e.Event),
		}
		return stream.Send(env)
	})
}

// errBaselineUnavailable is returned when no BaselineController is wired. Tests
// rely on errors.Is(); klctl surfaces the string to the user.
var errBaselineUnavailable = errors.New("baseline controller not attached on this agent")

// BaselineReset drops the current learner window and starts a fresh one.
func (s *Server) BaselineReset(_ context.Context, _ *protobuf.Empty) (*protobuf.Empty, error) {
	if s.baseline == nil {
		return nil, errBaselineUnavailable
	}
	s.baseline.BaselineReset()
	return &protobuf.Empty{}, nil
}

// BaselinePromote freezes the learner into a Profile and returns its
// canonical JSON encoding — klctl re-serializes or stores it as-is.
func (s *Server) BaselinePromote(_ context.Context, req *protobuf.PromoteRequest) (*protobuf.PromoteResponse, error) {
	if s.baseline == nil {
		return nil, errBaselineUnavailable
	}
	prof, err := s.baseline.BaselinePromote(req.GetMinSamples(), req.GetImageRef(), req.GetLabelHash())
	if err != nil {
		return nil, err
	}
	b, err := baseline.MarshalProfile(prof)
	if err != nil {
		return nil, fmt.Errorf("marshal profile: %w", err)
	}
	return &protobuf.PromoteResponse{
		ProfileJson: b,
		ProfileId:   prof.ID,
		SampleCount: prof.SampleCount,
		Confidence:  prof.Confidence,
	}, nil
}

// BaselineActivate attaches (or clears) a detector. Empty profile_json clears.
func (s *Server) BaselineActivate(_ context.Context, req *protobuf.ActivateRequest) (*protobuf.ActivateResponse, error) {
	if s.baseline == nil {
		return nil, errBaselineUnavailable
	}
	id, deactivated, err := s.baseline.BaselineActivate(req.GetProfileJson())
	if err != nil {
		return nil, err
	}
	return &protobuf.ActivateResponse{ProfileId: id, Deactivated: deactivated}, nil
}

// errConfigUnavailable surfaces the nil-controller case. Tests rely on
// errors.Is(); klctl surfaces the string to the user.
var errConfigUnavailable = errors.New("config controller not attached on this agent")

// GetConfig dumps every key the controller accepts with its current
// normalized value. Empty map (but ok=nil) is valid: it means the
// controller is attached but exposes no tunables in this build.
func (s *Server) GetConfig(_ context.Context, _ *protobuf.Empty) (*protobuf.ConfigResponse, error) {
	if s.config == nil {
		return nil, errConfigUnavailable
	}
	return &protobuf.ConfigResponse{Entries: s.config.Get()}, nil
}

// SetConfig applies each key=value in req.Entries. Per-key success is
// reported independently: `applied` holds the keys that took effect (with
// their normalized value); `errors` holds rejections keyed by the offending
// key. An entirely empty request is a no-op that still returns the current
// view — so `klctl config set` with no args is a cheap health probe.
func (s *Server) SetConfig(_ context.Context, req *protobuf.SetConfigRequest) (*protobuf.SetConfigResponse, error) {
	if s.config == nil {
		return nil, errConfigUnavailable
	}
	resp := &protobuf.SetConfigResponse{
		Applied: map[string]string{},
		Errors:  map[string]string{},
	}
	for k, v := range req.GetEntries() {
		norm, err := s.config.Set(k, v)
		if err != nil {
			resp.Errors[k] = err.Error()
			continue
		}
		resp.Applied[k] = norm
	}
	return resp, nil
}

func (s *Server) topSnapshot(n int) *protobuf.TopSnapshot {
	now := uint64(time.Now().UnixNano())
	snap := &protobuf.TopSnapshot{TsNs: now}
	if s.stats == nil {
		return snap
	}
	syss, ints, fr, fd, _ := s.stats.Counters()
	rows := []*protobuf.TopRow{
		{Key: "syscalls", Total: syss},
		{Key: "intents", Total: ints},
		{Key: "frames_read", Total: fr},
		{Key: "frames_dropped", Total: fd},
	}
	if n > 0 && n < len(rows) {
		rows = rows[:n]
	}
	snap.Rows = rows
	return snap
}

func validatePolicy(p *protobuf.Policy) (warns []string, err error) {
	switch p.Kind {
	case "HookSubscription", "BaselinePolicy", "BehaviorContract":
		// payload must be valid UTF-8 YAML/JSON — parse a top-level object.
		if len(p.Payload) == 0 {
			return []string{"empty payload"}, nil
		}
		trim := strings.TrimSpace(string(p.Payload))
		if strings.HasPrefix(trim, "{") {
			var v map[string]any
			if err := json.Unmarshal(p.Payload, &v); err != nil {
				return nil, fmt.Errorf("invalid JSON: %w", err)
			}
		}
		// Kind-specific strict parse — surfaces enum violations (pairing,
		// onMissing, enrichment.level) at klctl apply time instead of at
		// some later pipeline consumer that may fallthrough silently.
		// Other kinds still go through the generic shape check above;
		// their type-specific loaders live outside admin.
		if p.Kind == "HookSubscription" {
			if _, perr := policy.Parse(p.Payload); perr != nil {
				return nil, fmt.Errorf("HookSubscription: %w", perr)
			}
		}
		if p.Kind == "BaselinePolicy" {
			if _, perr := baseline.UnmarshalProfile(p.Payload); perr != nil {
				return nil, fmt.Errorf("BaselinePolicy: %w", perr)
			}
		}
		if p.Kind == "BehaviorContract" {
			if _, perr := contract.Parse(p.Payload); perr != nil {
				return nil, fmt.Errorf("BehaviorContract: %w", perr)
			}
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown kind %q (want HookSubscription|BaselinePolicy|BehaviorContract)", p.Kind)
	}
}

func hasLSM(xs []string, want string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, want) {
			return true
		}
	}
	return false
}

func capabilityReportToProto(r *types.CapabilityReport) *protobuf.CapabilityReport {
	out := &protobuf.CapabilityReport{
		NodeId: r.NodeID,
		Kernel: &protobuf.KernelInfo{
			Version:       r.Kernel.Version,
			Lsms:          append([]string(nil), r.Kernel.LSMs...),
			CgroupVersion: r.Kernel.CgroupVer,
			BtfAvailable:  r.Kernel.HasBTF,
		},
		Helpers: map[string]string{},
	}
	for k, v := range r.Helpers {
		out.Helpers[k] = v
	}
	for _, h := range r.Hooks {
		out.Hooks = append(out.Hooks, &protobuf.HookCap{
			Kind:               h.Kind,
			Name:               h.Name,
			Available:          h.Available,
			UnavailableReason:  h.UnavailableReason,
			ArgSchema:          append([]string(nil), h.ArgSchema...),
			FallbackSuggestion: h.FallbackSuggestion,
		})
	}
	return out
}

func intentEnvelopePayload(ev types.IntentEvent) *protobuf.EventEnvelope_Intent {
	return &protobuf.EventEnvelope_Intent{Intent: &protobuf.IntentEvent{
		IntentId:             ev.IntentID,
		Kind:                 ev.Kind,
		StartNs:              ev.StartNS,
		EndNs:                ev.EndNS,
		ContributingEventIds: append([]string(nil), ev.ContributingEventIDs...),
		Attributes:           copyStringMap(ev.Attributes),
		Severity:             uint32(ev.Severity), // #nosec G115 -- Severity is an int32 enum → uint32 proto field
		Confidence:           ev.Confidence,
		Meta: &protobuf.ContainerMeta{
			Cluster:     ev.Meta.Cluster,
			NodeName:    ev.Meta.NodeName,
			Namespace:   ev.Meta.Namespace,
			Pod:         ev.Meta.Pod,
			Container:   ev.Meta.Container,
			ContainerId: ev.Meta.ContainerID,
			Image:       ev.Meta.Image,
			Labels:      copyStringMap(ev.Meta.Labels),
			PidNs:       ev.Meta.PidNS,
			MntNs:       ev.Meta.MntNS,
		},
	}}
}

func copyStringMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
