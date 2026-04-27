// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package admin

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/baseline"
	"github.com/boanlab/kloudlens/pkg/types"
	"github.com/boanlab/kloudlens/protobuf"
)

type fakeBaseline struct {
	resetCalls  int
	promoteArgs struct {
		min       uint64
		imageRef  string
		labelHash string
		called    bool
	}
	promoteRet *baseline.Profile
	promoteErr error

	activateArgs struct {
		payload []byte
		called  bool
	}
	activateID          string
	activateDeactivated bool
	activateErr         error
}

func (f *fakeBaseline) BaselineReset() { f.resetCalls++ }
func (f *fakeBaseline) BaselinePromote(min uint64, imageRef, labelHash string) (*baseline.Profile, error) {
	f.promoteArgs.min = min
	f.promoteArgs.imageRef = imageRef
	f.promoteArgs.labelHash = labelHash
	f.promoteArgs.called = true
	return f.promoteRet, f.promoteErr
}
func (f *fakeBaseline) BaselineActivate(payload []byte) (string, bool, error) {
	f.activateArgs.payload = append([]byte(nil), payload...)
	f.activateArgs.called = true
	return f.activateID, f.activateDeactivated, f.activateErr
}

type fakeStats struct {
	s, i, fr, fd uint64
	rb           float64
	level        int
}

func (f fakeStats) Counters() (uint64, uint64, uint64, uint64, float64) {
	return f.s, f.i, f.fr, f.fd, f.rb
}

func (f fakeStats) AdaptiveLevel() int { return f.level }

func TestStatusReflectsStats(t *testing.T) {
	// level=2 stands in for downgrade.LevelHeavilySampled — we check the raw
	// integer round-trips through AgentStatus.AdaptiveLevel so klctl and the
	// kloudlens_adaptive_level gauge stay consistent. Regression guard
	// against GetStatus silently dropping the field after StatsSource grew.
	srv := NewServer(fakeStats{s: 100, i: 20, fr: 4, fd: 1, rb: 0.5, level: 2},
		Options{NodeName: "n1", Cluster: "c1"})
	got, err := srv.GetStatus(context.Background(), &protobuf.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeName != "n1" || got.SyscallsObserved != 100 || got.RingbufUsage != 0.5 {
		t.Errorf("status = %+v", got)
	}
	if got.AdaptiveLevel != 2 {
		t.Errorf("AdaptiveLevel = %d, want 2", got.AdaptiveLevel)
	}
	// SchemaVersion must always be populated. The klctl ↔ aggregator
	// handshake uses this token to refuse mismatched pairs when the wire
	// layout is bumped, so a silent empty string here would defeat the
	// negotiation check.
	if got.SchemaVersion != types.WireSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", got.SchemaVersion, types.WireSchemaVersion)
	}
	if got.SchemaVersion != "v2" {
		t.Errorf("SchemaVersion must be pinned to %q; got %q — bumping this is a deliberate wire-layout change", "v2", got.SchemaVersion)
	}
}

// TestStatusReflectsVersion guards the Options.Version → AgentStatus.Version
// wiring. Without this, a future refactor could drop either side (the main.go
// Options field or the GetStatus copy) and every other test would still pass
// because they leave Options.Version empty and silently land on the "dev"
// fallback — klctl would then report "dev" for every node.
func TestStatusReflectsVersion(t *testing.T) {
	srv := NewServer(nil, Options{Version: "v1.2.3"})
	got, err := srv.GetStatus(context.Background(), &protobuf.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "v1.2.3" {
		t.Errorf("Version = %q, want %q", got.Version, "v1.2.3")
	}
}

type fakeLevelSource struct {
	eff, op string
}

func (f fakeLevelSource) EnrichmentLevel() string         { return f.eff }
func (f fakeLevelSource) OperatorEnrichmentLevel() string { return f.op }

// TestStatusIncludesEnrichmentLevels covers the three observability
// shapes the new Info keys need to handle:
// 1. eff == op: only "enrichment_level" is surfaced — re-emitting the
// same value under a second key would be noise and would mislead
// operators into thinking a forced demotion is in play.
// 2. eff < op (pressure demoted): both keys appear so the operator can
// see "I set minimal, but the adaptive controller forced none".
// 3. no source wired: neither key appears (back-compat with tests and
// agent builds that don't attach a pipeline).
func TestStatusIncludesEnrichmentLevels(t *testing.T) {
	t.Run("effective equals operator", func(t *testing.T) {
		srv := NewServer(nil, Options{EnrichmentLevelSource: fakeLevelSource{eff: "full", op: "full"}})
		got, err := srv.GetStatus(context.Background(), &protobuf.Empty{})
		if err != nil {
			t.Fatal(err)
		}
		if got.Info["enrichment_level"] != "full" {
			t.Errorf("enrichment_level = %q, want full", got.Info["enrichment_level"])
		}
		if _, present := got.Info["enrichment_level_operator"]; present {
			t.Error("enrichment_level_operator must be omitted when it matches effective")
		}
	})

	t.Run("controller forced demotion", func(t *testing.T) {
		srv := NewServer(nil, Options{EnrichmentLevelSource: fakeLevelSource{eff: "none", op: "minimal"}})
		got, err := srv.GetStatus(context.Background(), &protobuf.Empty{})
		if err != nil {
			t.Fatal(err)
		}
		if got.Info["enrichment_level"] != "none" {
			t.Errorf("enrichment_level = %q, want none", got.Info["enrichment_level"])
		}
		if got.Info["enrichment_level_operator"] != "minimal" {
			t.Errorf("enrichment_level_operator = %q, want minimal", got.Info["enrichment_level_operator"])
		}
	})

	t.Run("no source attached", func(t *testing.T) {
		srv := NewServer(nil, Options{})
		got, err := srv.GetStatus(context.Background(), &protobuf.Empty{})
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"enrichment_level", "enrichment_level_operator"} {
			if _, present := got.Info[k]; present {
				t.Errorf("Info[%q] must be absent without EnrichmentLevelSource", k)
			}
		}
	})
}

func TestApplyListDeletePolicy(t *testing.T) {
	srv := NewServer(nil, Options{NodeName: "n1"})
	// Payload must now pass policy.Parse strict validation — the admin layer
	// rejects malformed HookSubscription at ApplyPolicy time instead of
	// letting enum typos leak into the dispatcher (see TestApplyPolicyRejectsBadEnrichmentLevel).
	res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "hook-1",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: hook-1}\nspec: {syscalls: {include: [openat]}}"),
	})
	if !res.Ok {
		t.Fatalf("apply: %v", res)
	}
	list, _ := srv.ListPolicies(context.Background(), &protobuf.Empty{})
	if len(list.Items) != 1 || list.Items[0].Name != "hook-1" {
		t.Errorf("list = %+v", list)
	}
	del, _ := srv.DeletePolicy(context.Background(), &protobuf.PolicyRef{Kind: "HookSubscription", Name: "hook-1"})
	if !del.Ok {
		t.Errorf("delete: %v", del)
	}
	list2, _ := srv.ListPolicies(context.Background(), &protobuf.Empty{})
	if len(list2.Items) != 0 {
		t.Errorf("after delete list = %+v", list2)
	}
}

// TestApplyPolicyRejectsBadEnrichmentLevel verifies that enum violations
// inside a HookSubscription payload surface at ApplyPolicy time (via
// policy.Parse), not later as a silent fallthrough in the dispatcher.
// Without strict admin-side parsing, `level: full2` would be stored and
// the runtime would map it to the default "full" behavior — defeating
// the operator's attempt to opt down cardinality.
func TestApplyPolicyRejectsBadEnrichmentLevel(t *testing.T) {
	srv := NewServer(nil, Options{NodeName: "n1"})
	res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "bad",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: bad}\nspec: {enrichment: {level: full2}}"),
	})
	if res.Ok {
		t.Fatal("expected apply to fail on unknown enrichment.level")
	}
	if !contains(res.Message, "enrichment.level") {
		t.Errorf("error should name the offending field: %q", res.Message)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestApplyPolicyBaselineProfileStrictParse ensures BaselinePolicy payloads
// go through baseline.UnmarshalProfile at ApplyPolicy time — malformed
// profile JSON used to sit in storage until the next Activate attempt,
// at which point detector attach would fail at runtime with no klctl-side
// signal. Reject at klctl-apply instead.
func TestApplyPolicyBaselineProfileStrictParse(t *testing.T) {
	srv := NewServer(nil, Options{NodeName: "n1"})
	good, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "BaselinePolicy", Name: "ok-profile",
		Payload: []byte(`{"schemaVersion":3,"id":"p1","sampleCount":0,"confidence":0}`),
	})
	if !good.Ok {
		t.Fatalf("valid profile should apply: %v", good.Message)
	}
	bad, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "BaselinePolicy", Name: "broken-profile",
		Payload: []byte(`{"schemaVersion":"three"}`),
	})
	if bad.Ok {
		t.Fatal("BaselinePolicy with wrong field type must be rejected at apply time")
	}
	if !contains(bad.Message, "BaselinePolicy") {
		t.Errorf("error should name the kind: %q", bad.Message)
	}
}

// TestApplyPolicyBehaviorContractStrictParse ensures BehaviorContract
// payloads route through pkg/contract.Parse at ApplyPolicy time so that
// a document with the wrong Kind or an unsupported apiVersion is rejected
// at klctl-apply, rather than silently landing in the policy store and
// surfacing later through gap analysis.
func TestApplyPolicyBehaviorContractStrictParse(t *testing.T) {
	srv := NewServer(nil, Options{NodeName: "n1"})
	good, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "BehaviorContract", Name: "ok-contract",
		Payload: []byte("apiVersion: kloudlens.io/v1\nkind: BehaviorContract\nmetadata: {contractID: c1}\n"),
	})
	if !good.Ok {
		t.Fatalf("valid contract should apply: %v", good.Message)
	}
	wrongKind, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "BehaviorContract", Name: "bad-kind",
		Payload: []byte("apiVersion: kloudlens.io/v1\nkind: HookSubscription\nmetadata: {contractID: c2}\n"),
	})
	if wrongKind.Ok {
		t.Fatal("BehaviorContract with wrong inner kind must be rejected")
	}
	if !contains(wrongKind.Message, "BehaviorContract") {
		t.Errorf("error should name the kind: %q", wrongKind.Message)
	}
	wrongAPI, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "BehaviorContract", Name: "bad-api",
		Payload: []byte("apiVersion: other.example/v1\nkind: BehaviorContract\nmetadata: {contractID: c3}\n"),
	})
	if wrongAPI.Ok {
		t.Fatal("BehaviorContract with foreign apiVersion must be rejected")
	}
}

// TestApplyPolicyObserverFiresForBothPaths verifies the PolicyObserver
// hook is invoked on every ApplyPolicy call, tagged "ok" vs "rejected".
// Ops run alerts like `rate(kloudlens_policies_applied_total{result="rejected"}) > 0`
// and a missed hook on either branch would produce a silent dashboard.
func TestApplyPolicyObserverFiresForBothPaths(t *testing.T) {
	fo := &fakeObserver{}
	srv := NewServer(nil, Options{NodeName: "n1", PolicyObserver: fo})
	// accepted
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "ok-one",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: ok-one}\nspec: {}"),
	}); !res.Ok {
		t.Fatalf("valid apply failed: %v", res.Message)
	}
	// rejected by strict parse
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "bad",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: bad}\nspec: {enrichment: {level: full2}}"),
	}); res.Ok {
		t.Fatal("bad enrichment.level should be rejected")
	}
	// rejected by missing kind/name
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "",
		Payload: []byte("x"),
	}); res.Ok {
		t.Fatal("missing name should be rejected")
	}
	if got := fo.counts["HookSubscription|ok"]; got != 1 {
		t.Errorf("ok counter = %d, want 1", got)
	}
	if got := fo.counts["HookSubscription|rejected"]; got != 2 {
		t.Errorf("rejected counter = %d, want 2 (strict-parse failure + missing-name)", got)
	}
}

type fakeObserver struct {
	counts map[string]int
}

func (f *fakeObserver) Observe(kind, result string) {
	if f.counts == nil {
		f.counts = map[string]int{}
	}
	f.counts[kind+"|"+result]++
}

type fakeCorrDispatcher struct {
	calls [][]string
}

func (f *fakeCorrDispatcher) ApplyEnrichmentCorrelations(names []string) {
	// Store a shallow copy so later mutation by the admin doesn't race.
	cp := append([]string(nil), names...)
	f.calls = append(f.calls, cp)
}

type fakeHistDispatcher struct {
	calls [][2]int // [depth, windowSec]
}

func (f *fakeHistDispatcher) ApplyEnrichmentHistory(depth, windowSec int) {
	f.calls = append(f.calls, [2]int{depth, windowSec})
}

// TestApplyPolicyDispatchesHistoryToPipeline pins the live-history contract
// symmetric with the correlation / eventrole dispatchers: a successful
// ApplyPolicy(HookSubscription) must forward the validated
// spec.enrichment.{historyDepth,historyWindowSecs} to the HistoryDispatcher.
// Without this hook, `klctl apply hook.yaml` with a tightened ring would
// only rewrite the policy object; the live history.Store would keep its
// boot-time caps until a restart. Rejections and non-Hook kinds must not
// fire — matching the guard rails we use for the two sibling dispatchers.
func TestApplyPolicyDispatchesHistoryToPipeline(t *testing.T) {
	fh := &fakeHistDispatcher{}
	srv := NewServer(nil, Options{NodeName: "n1", HistoryDispatcher: fh})

	// 1. Valid HookSubscription with explicit values → one dispatch.
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "sub-1",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: sub-1}\nspec: {enrichment: {historyDepth: 64, historyWindowSecs: 120}}"),
	}); !res.Ok {
		t.Fatalf("valid HookSubscription should apply: %v", res.Message)
	}
	if len(fh.calls) != 1 {
		t.Fatalf("dispatcher should fire once on success, got %d", len(fh.calls))
	}
	// policy.Parse applies defaults (32/30) only when the spec omits the
	// fields entirely; with both values set, the dispatcher must see them
	// verbatim — no silent rewrite via defaults.
	if got := fh.calls[0]; got != [2]int{64, 120} {
		t.Errorf("dispatcher got %v, want [64 120]", got)
	}

	// 2. Rejected HookSubscription (bad enrichment.level) → NO dispatch.
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "bad",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: bad}\nspec: {enrichment: {level: full2}}"),
	}); res.Ok {
		t.Fatal("bad enrichment.level should be rejected")
	}
	if len(fh.calls) != 1 {
		t.Errorf("dispatcher must not fire on rejection, calls=%d", len(fh.calls))
	}

	// 3. Non-HookSubscription kind → NO dispatch.
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "BaselinePolicy", Name: "bp-1",
		Payload: []byte(`{"schemaVersion":3,"id":"bp-1","sampleCount":0,"confidence":0}`),
	}); !res.Ok {
		t.Fatalf("valid BaselinePolicy should apply: %v", res.Message)
	}
	if len(fh.calls) != 1 {
		t.Errorf("non-HookSubscription kind must not dispatch, calls=%d", len(fh.calls))
	}
}

type fakeLevelDispatcher struct {
	calls []string
}

func (f *fakeLevelDispatcher) ApplyEnrichmentLevel(level string) {
	f.calls = append(f.calls, level)
}

// TestApplyPolicyDispatchesEnrichmentLevelToPipeline pins the live-level
// contract in the same shape as the correlation / history dispatchers: a
// successful ApplyPolicy(HookSubscription) must forward the validated
// spec.enrichment.level to the pipeline. Without this hook the level
// would only sit in the stored policy; the pipeline would keep running
// every side layer as if level were "full" until a daemon restart.
// Rejections and non-Hook kinds must not fire the dispatcher.
func TestApplyPolicyDispatchesEnrichmentLevelToPipeline(t *testing.T) {
	fl := &fakeLevelDispatcher{}
	srv := NewServer(nil, Options{NodeName: "n1", EnrichmentLevelDispatcher: fl})

	// 1. Valid HookSubscription with explicit level → one dispatch.
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "lvl-1",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: lvl-1}\nspec: {enrichment: {level: minimal}}"),
	}); !res.Ok {
		t.Fatalf("valid HookSubscription should apply: %v", res.Message)
	}
	if len(fl.calls) != 1 || fl.calls[0] != "minimal" {
		t.Fatalf("dispatcher should receive level=minimal once, got %v", fl.calls)
	}

	// 2. Omitted level → parser defaults to "full", dispatcher sees "full".
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "lvl-default",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: lvl-default}\nspec: {}"),
	}); !res.Ok {
		t.Fatalf("valid default HookSubscription should apply: %v", res.Message)
	}
	if len(fl.calls) != 2 || fl.calls[1] != "full" {
		t.Fatalf("omitted level should dispatch 'full', got %v", fl.calls)
	}

	// 3. Rejected HookSubscription (bad level) → NO dispatch.
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "bad",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: bad}\nspec: {enrichment: {level: extreme}}"),
	}); res.Ok {
		t.Fatal("bad enrichment.level should be rejected")
	}
	if len(fl.calls) != 2 {
		t.Errorf("dispatcher must not fire on rejection, calls=%v", fl.calls)
	}

	// 4. Non-HookSubscription kind → NO dispatch.
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "BaselinePolicy", Name: "bp-1",
		Payload: []byte(`{"schemaVersion":3,"id":"bp-1","sampleCount":0,"confidence":0}`),
	}); !res.Ok {
		t.Fatalf("valid BaselinePolicy should apply: %v", res.Message)
	}
	if len(fl.calls) != 2 {
		t.Errorf("non-HookSubscription kind must not dispatch, calls=%v", fl.calls)
	}
}

// TestApplyPolicyResolveWithCapabilities exercises the three outcomes of
// the capability-aware apply path introduced with admin.Options.Capabilities:
//
//	(1) a matching node admits the policy cleanly,
//	(2) a skip-policy against a capability-poor report yields Warnings,
//	(3) an onMissing=fail policy against the same report is rejected.
//
// The historical behavior (no Capabilities option) is still covered by
// every other ApplyPolicy test — passing nil disables this path entirely.
func TestApplyPolicyResolveWithCapabilities(t *testing.T) {
	// A cap report that knows only about tracepoint/openat. lsm_bpf and
	// kprobe hooks are considered unavailable.
	rep := &types.CapabilityReport{
		Hooks: []types.HookCap{
			{Kind: "syscall_tracepoint", Name: "openat", Available: true},
		},
	}
	srv := NewServer(nil, Options{NodeName: "n1", Capabilities: rep})

	// (1) A subscription that only wants openat — no warnings, applies OK.
	res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "narrow",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: narrow}\nspec: {syscalls: {include: [openat]}, graceful: {onMissing: skip}}"),
	})
	if !res.Ok {
		t.Fatalf("matching subscription should apply: %v", res.Message)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("fully-matched apply should have no warnings, got %v", res.Warnings)
	}

	// (2) skip-policy with one unavailable lsm hook → warnings list it.
	res, _ = srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "skipper",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: skipper}\nspec: {lsm: {include: [bprm_check_security]}, graceful: {onMissing: skip}}"),
	})
	if !res.Ok {
		t.Fatalf("skip-policy should still apply: %v", res.Message)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("missing hook under onMissing=skip should surface as a warning")
	}
	var found bool
	for _, w := range res.Warnings {
		if contains(w, "bprm_check_security") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings should name the skipped hook: %v", res.Warnings)
	}

	// (3) fail-policy with one unavailable lsm hook → apply-time rejection.
	res, _ = srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "strict",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: strict}\nspec: {lsm: {include: [bprm_check_security]}, graceful: {onMissing: fail}}"),
	})
	if res.Ok {
		t.Fatal("onMissing=fail on a capability-poor node must reject at apply time")
	}
	if !contains(res.Message, "bprm_check_security") {
		t.Errorf("rejection should name the missing hook: %q", res.Message)
	}
}

// TestApplyPolicyDispatchesCorrelationsToPipeline wires a fake
// CorrelationDispatcher and confirms ApplyPolicy forwards the validated
// enrichment.correlations list on the HookSubscription success path
// (and ONLY that path — rejections must not dispatch, and non-Hook
// kinds must not invoke the detector hook). This is the live-reconfig
// contract that lets `klctl apply hook.yaml` re-enable/disable
// heuristics without restarting the agent.
func TestApplyPolicyDispatchesCorrelationsToPipeline(t *testing.T) {
	fd := &fakeCorrDispatcher{}
	srv := NewServer(nil, Options{NodeName: "n1", CorrelationDispatcher: fd})

	// 1. Valid HookSubscription with an explicit subset → dispatcher hit.
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "sub-1",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: sub-1}\nspec: {enrichment: {correlations: [exec_after_chmod_x]}}"),
	}); !res.Ok {
		t.Fatalf("valid HookSubscription should apply: %v", res.Message)
	}
	if len(fd.calls) != 1 {
		t.Fatalf("dispatcher should fire once on success, got %d", len(fd.calls))
	}
	if got := fd.calls[0]; len(got) != 1 || got[0] != "exec_after_chmod_x" {
		t.Errorf("dispatcher got %v, want [exec_after_chmod_x]", got)
	}

	// 2. Rejected HookSubscription (bad enrichment.level) → NO dispatch.
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "HookSubscription", Name: "bad",
		Payload: []byte("kind: HookSubscription\nmetadata: {name: bad}\nspec: {enrichment: {level: full2}}"),
	}); res.Ok {
		t.Fatal("bad enrichment.level should be rejected")
	}
	if len(fd.calls) != 1 {
		t.Errorf("dispatcher must not fire on rejection, calls=%d", len(fd.calls))
	}

	// 3. Non-HookSubscription kind → NO dispatch (BaselinePolicy here).
	if res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{
		Kind: "BaselinePolicy", Name: "bp-1",
		Payload: []byte(`{"schemaVersion":3,"id":"bp-1","sampleCount":0,"confidence":0}`),
	}); !res.Ok {
		t.Fatalf("valid BaselinePolicy should apply: %v", res.Message)
	}
	if len(fd.calls) != 1 {
		t.Errorf("non-HookSubscription kind must not dispatch, calls=%d", len(fd.calls))
	}
}

func TestApplyRejectsUnknownKind(t *testing.T) {
	srv := NewServer(nil, Options{NodeName: "n1"})
	res, _ := srv.ApplyPolicy(context.Background(), &protobuf.Policy{Kind: "Foo", Name: "x", Payload: []byte("{}")})
	if res.Ok {
		t.Error("unknown kind should be rejected")
	}
}

func TestDeleteMissing(t *testing.T) {
	srv := NewServer(nil, Options{NodeName: "n1"})
	res, _ := srv.DeletePolicy(context.Background(), &protobuf.PolicyRef{Kind: "HookSubscription", Name: "nope"})
	if res.Ok {
		t.Error("missing delete should return !ok")
	}
}

func TestBaselineRPCsUnavailableWithoutController(t *testing.T) {
	srv := NewServer(nil, Options{NodeName: "n1"})
	if _, err := srv.BaselineReset(context.Background(), &protobuf.Empty{}); err == nil {
		t.Error("reset without controller should error")
	}
	if _, err := srv.BaselinePromote(context.Background(), &protobuf.PromoteRequest{}); err == nil {
		t.Error("promote without controller should error")
	}
	if _, err := srv.BaselineActivate(context.Background(), &protobuf.ActivateRequest{}); err == nil {
		t.Error("activate without controller should error")
	}
}

func TestBaselineResetCallsController(t *testing.T) {
	fb := &fakeBaseline{}
	srv := NewServer(nil, Options{NodeName: "n1", Baseline: fb})
	if _, err := srv.BaselineReset(context.Background(), &protobuf.Empty{}); err != nil {
		t.Fatal(err)
	}
	if fb.resetCalls != 1 {
		t.Errorf("reset calls = %d, want 1", fb.resetCalls)
	}
}

func TestBaselinePromoteRoundTrip(t *testing.T) {
	// Produce a real, marshalable profile via the learner so MarshalProfile works.
	l := baseline.NewLearner(baseline.LearnerConfig{
		CMSEps: 0.01, CMSDelta: 0.01, RarityFreqFloor: 0.02, MarkovProbFloor: 0.10,
	}, timeFixed())
	l.ObserveSyscall("read")
	l.ObserveSyscall("write")
	prof, err := l.Promote(timeFixed().Add(1), "img", "hash", 0)
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBaseline{promoteRet: prof}
	srv := NewServer(nil, Options{NodeName: "n1", Baseline: fb})
	res, err := srv.BaselinePromote(context.Background(),
		&protobuf.PromoteRequest{MinSamples: 1, ImageRef: "img", LabelHash: "hash"})
	if err != nil {
		t.Fatal(err)
	}
	if !fb.promoteArgs.called || fb.promoteArgs.min != 1 ||
		fb.promoteArgs.imageRef != "img" || fb.promoteArgs.labelHash != "hash" {
		t.Errorf("controller not called with expected args: %+v", fb.promoteArgs)
	}
	if res.ProfileId != prof.ID || len(res.ProfileJson) == 0 {
		t.Errorf("unexpected response: id=%s bytes=%d", res.ProfileId, len(res.ProfileJson))
	}
	// Response bytes must round-trip through UnmarshalProfile.
	if _, err := baseline.UnmarshalProfile(res.ProfileJson); err != nil {
		t.Errorf("promoted bytes don't round-trip: %v", err)
	}
}

func TestBaselineActivatePassesBytes(t *testing.T) {
	fb := &fakeBaseline{activateID: "pid-123"}
	srv := NewServer(nil, Options{NodeName: "n1", Baseline: fb})
	res, err := srv.BaselineActivate(context.Background(),
		&protobuf.ActivateRequest{ProfileJson: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	if string(fb.activateArgs.payload) != "hello" {
		t.Errorf("payload = %q", fb.activateArgs.payload)
	}
	if res.ProfileId != "pid-123" || res.Deactivated {
		t.Errorf("res = %+v", res)
	}
}

func TestBaselineDeactivateEmptyBytes(t *testing.T) {
	fb := &fakeBaseline{activateDeactivated: true}
	srv := NewServer(nil, Options{NodeName: "n1", Baseline: fb})
	res, err := srv.BaselineActivate(context.Background(),
		&protobuf.ActivateRequest{ProfileJson: nil})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Deactivated {
		t.Errorf("expected deactivated=true, got %+v", res)
	}
}

func timeFixed() time.Time { return time.Unix(1_700_000_000, 0) }

// fakeConfig is a minimal ConfigController stub. `entries` is the canned
// view returned by Get; `accept` gates which keys Set will store. Every
// accepted write is appended to `setCalls` so tests can assert ordering.
type fakeConfig struct {
	entries  map[string]string
	accept   map[string]bool
	setCalls [][2]string
}

func (f *fakeConfig) Get() map[string]string {
	out := map[string]string{}
	for k, v := range f.entries {
		out[k] = v
	}
	return out
}

func (f *fakeConfig) Set(k, v string) (string, error) {
	f.setCalls = append(f.setCalls, [2]string{k, v})
	if !f.accept[k] {
		return "", fmt.Errorf("unknown key %q", k)
	}
	f.entries[k] = v
	return v, nil
}

func TestGetConfigWithNoController(t *testing.T) {
	srv := NewServer(nil, Options{NodeName: "n1"})
	_, err := srv.GetConfig(context.Background(), &protobuf.Empty{})
	if !errors.Is(err, errConfigUnavailable) {
		t.Fatalf("want errConfigUnavailable, got %v", err)
	}
}

func TestGetConfigEchoesEntries(t *testing.T) {
	fc := &fakeConfig{entries: map[string]string{"stats-interval": "5s"}, accept: map[string]bool{}}
	srv := NewServer(nil, Options{NodeName: "n1", Config: fc})
	resp, err := srv.GetConfig(context.Background(), &protobuf.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.GetEntries()["stats-interval"]; got != "5s" {
		t.Errorf("entries[stats-interval]=%q want 5s", got)
	}
}

func TestSetConfigSplitsAppliedAndErrors(t *testing.T) {
	fc := &fakeConfig{
		entries: map[string]string{"stats-interval": "5s"},
		accept:  map[string]bool{"stats-interval": true},
	}
	srv := NewServer(nil, Options{NodeName: "n1", Config: fc})
	resp, err := srv.SetConfig(context.Background(), &protobuf.SetConfigRequest{
		Entries: map[string]string{
			"stats-interval": "2s",
			"bogus":          "x",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.GetApplied()["stats-interval"]; got != "2s" {
		t.Errorf("applied[stats-interval]=%q want 2s", got)
	}
	if _, ok := resp.GetApplied()["bogus"]; ok {
		t.Errorf("bogus should not appear in applied")
	}
	if msg, ok := resp.GetErrors()["bogus"]; !ok || msg == "" {
		t.Errorf("errors[bogus] missing or blank: %q", msg)
	}
	if len(fc.setCalls) != 2 {
		t.Errorf("want 2 Set calls, got %d", len(fc.setCalls))
	}
}

func TestSetConfigNoEntriesIsNoop(t *testing.T) {
	fc := &fakeConfig{entries: map[string]string{}, accept: map[string]bool{}}
	srv := NewServer(nil, Options{NodeName: "n1", Config: fc})
	resp, err := srv.SetConfig(context.Background(), &protobuf.SetConfigRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetApplied()) != 0 || len(resp.GetErrors()) != 0 {
		t.Errorf("empty request: applied=%v errors=%v", resp.GetApplied(), resp.GetErrors())
	}
	if len(fc.setCalls) != 0 {
		t.Errorf("no keys should reach controller, got %d calls", len(fc.setCalls))
	}
}

func TestSetConfigWithNoController(t *testing.T) {
	srv := NewServer(nil, Options{NodeName: "n1"})
	_, err := srv.SetConfig(context.Background(), &protobuf.SetConfigRequest{
		Entries: map[string]string{"x": "y"},
	})
	if !errors.Is(err, errConfigUnavailable) {
		t.Fatalf("want errConfigUnavailable, got %v", err)
	}
}
