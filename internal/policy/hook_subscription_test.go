// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/boanlab/kloudlens/pkg/types"
)

const sampleYAML = `apiVersion: kloudlens.io/v1
kind: HookSubscription
metadata:
  name: security-standard
spec:
  selector:
    namespaces: ["default", "prod-*"]
    excludeNamespaces: ["kube-system"]
    labels:
      tier: frontend
  pairing: enter_exit
  syscalls:
    include: [execve, openat, connect]
    exclude: []
  lsm:
    include: [bprm_check_security, file_open]
  decode:
    resolvePath: true
    resolveFd: true
    dumpArgv: truncate(256)
  sampling:
    openat: 1/10
  priority:
    critical: [execve, connect, bprm_check_security]
    normal: "*"
  graceful:
    onMissing: fallback
    fallback:
      bprm_check_security: kprobe:security_bprm_check
  enrichment:
    level: full
    historyDepth: 32
    historyWindowSecs: 30
    correlations: [file_written_then_executed]
`

func TestParseDefaultsAndFields(t *testing.T) {
	h, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if h.Metadata.Name != "security-standard" {
		t.Fatalf("name=%s", h.Metadata.Name)
	}
	if h.Spec.Pairing != "enter_exit" {
		t.Fatalf("pairing=%s", h.Spec.Pairing)
	}
	if !h.Spec.Decode.ResolvePath {
		t.Fatal("resolvePath should be true")
	}
	if h.Spec.Graceful.OnMissing != "fallback" {
		t.Fatalf("onMissing=%s", h.Spec.Graceful.OnMissing)
	}
	if len(h.Spec.Enrichment.Correlations) != 1 {
		t.Fatalf("correlations=%+v", h.Spec.Enrichment.Correlations)
	}
}

func TestParseRequiresKindAndName(t *testing.T) {
	_, err := Parse([]byte(`metadata: {name: x}`))
	if err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("expected kind error, got %v", err)
	}
	_, err = Parse([]byte("kind: HookSubscription\nmetadata: {}"))
	if err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("expected name error, got %v", err)
	}
}

func TestParseRejectsUnknownPairing(t *testing.T) {
	raw := "kind: HookSubscription\nmetadata: {name: t}\nspec: {pairing: invalid}"
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("expected pairing error")
	}
}

// TestParseRejectsUnknownEnrichmentLevel locks in parse-time validation
// for the enrichment.level enum. Without this guard, a typo like
// "full2" silently passes — runtime then treats the subscription as
// default "full" (because the dispatcher falls through on anything
// non-matching), defeating the operator's attempt to opt down to
// "minimal" for high-cardinality pods.
func TestParseRejectsUnknownEnrichmentLevel(t *testing.T) {
	raw := "kind: HookSubscription\nmetadata: {name: t}\nspec: {enrichment: {level: full2}}"
	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("expected enrichment.level error, got nil")
	}
	if !strings.Contains(err.Error(), "enrichment.level") {
		t.Errorf("error did not mention field: %v", err)
	}
	for _, ok := range []string{"full", "minimal", "none"} {
		raw := "kind: HookSubscription\nmetadata: {name: t}\nspec: {enrichment: {level: " + ok + "}}"
		if _, err := Parse([]byte(raw)); err != nil {
			t.Errorf("level=%q must parse: %v", ok, err)
		}
	}
}

// TestParseRejectsUnknownCorrelation locks in the parse-time guard for
// enrichment.correlations. A silent typo like "file_writ_then_exec"
// would disable the heuristic the operator thought they were enabling;
// rejecting at parse time makes every authored policy YAML fail fast
// rather than silently mis-configuring the detector.
func TestParseRejectsUnknownCorrelation(t *testing.T) {
	raw := "kind: HookSubscription\nmetadata: {name: t}\nspec: {enrichment: {correlations: [file_writ_then_exec]}}"
	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("expected correlation error, got nil")
	}
	if !strings.Contains(err.Error(), "correlations") {
		t.Errorf("error should name the field: %v", err)
	}
	// All 5 known kinds must pass.
	for _, k := range []string{
		"file_written_then_executed", "connect_after_dns",
		"exec_after_chmod_x", "read_sensitive_before_send",
		"privilege_escalation_window",
	} {
		ok := "kind: HookSubscription\nmetadata: {name: t}\nspec: {enrichment: {correlations: [" + k + "]}}"
		if _, err := Parse([]byte(ok)); err != nil {
			t.Errorf("kind %q must parse: %v", k, err)
		}
	}
}

func TestSelectorMatch(t *testing.T) {
	h, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	// matches default, label matches
	if !h.MatchPod(PodRef{Namespace: "default", Labels: map[string]string{"tier": "frontend"}}) {
		t.Fatal("expected default/frontend to match")
	}
	// matches prod-web via glob
	if !h.MatchPod(PodRef{Namespace: "prod-web", Labels: map[string]string{"tier": "frontend"}}) {
		t.Fatal("expected prod-web/frontend to match")
	}
	// label mismatch
	if h.MatchPod(PodRef{Namespace: "default", Labels: map[string]string{"tier": "backend"}}) {
		t.Fatal("label mismatch should not match")
	}
	// excluded namespace
	if h.MatchPod(PodRef{Namespace: "kube-system", Labels: map[string]string{"tier": "frontend"}}) {
		t.Fatal("kube-system should be excluded")
	}
	// namespace not in include list
	if h.MatchPod(PodRef{Namespace: "staging", Labels: map[string]string{"tier": "frontend"}}) {
		t.Fatal("staging should not match")
	}
}

func TestResolveFallback(t *testing.T) {
	h, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	r := &types.CapabilityReport{Hooks: []types.HookCap{
		{Kind: "syscall_tracepoint", Name: "execve", Available: true},
		{Kind: "syscall_tracepoint", Name: "openat", Available: true},
		{Kind: "syscall_tracepoint", Name: "connect", Available: true},
		{Kind: "lsm_bpf", Name: "bprm_check_security", Available: false, UnavailableReason: "lsm=bpf missing"},
		{Kind: "lsm_bpf", Name: "file_open", Available: false, UnavailableReason: "lsm=bpf missing"},
		{Kind: "kprobe", Name: "security_bprm_check", Available: true},
	}}
	res, err := h.Resolve(r)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Expect execve/openat/connect attached, bprm_check_security fallbacked to
	// kprobe:security_bprm_check, file_open skipped (no fallback mapping).
	var sawFallback, sawFileOpen bool
	for _, a := range res.Attach {
		if a.Kind == "kprobe" && a.Name == "security_bprm_check" {
			sawFallback = true
			if a.Priority != "critical" {
				t.Fatalf("fallback should keep critical priority, got %s", a.Priority)
			}
		}
	}
	for _, s := range res.Skipped {
		if s.Name == "file_open" {
			sawFileOpen = true
		}
	}
	if !sawFallback {
		t.Fatalf("expected security_bprm_check fallback in attach, got %+v", res.Attach)
	}
	if !sawFileOpen {
		t.Fatalf("expected file_open to be skipped, got skipped=%+v", res.Skipped)
	}
	if res.Fallback["lsm_bpf:bprm_check_security"] != "kprobe:security_bprm_check" {
		t.Fatalf("fallback map: %+v", res.Fallback)
	}
}

// TestResolveFallbackBranches exercises the three failure modes inside the
// fallback branch of Resolve: (a) no mapping entry at all, (b) malformed
// alt string (missing "kind:name" colon), (c) alt mapping exists but the
// alt hook itself is unavailable. Each must land in Skipped with a
// distinguishable Reason so operators can debug from `klctl caps` output
// without source-diving.
func TestResolveFallbackBranches(t *testing.T) {
	h, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite fallback map: one mapping is malformed (no colon), one points
	// at a hook the report says is unavailable.
	h.Spec.Graceful.Fallback = map[string]string{
		"bprm_check_security": "malformed-no-colon",
		"file_open":           "kprobe:security_file_open",
	}
	r := &types.CapabilityReport{Hooks: []types.HookCap{
		{Kind: "syscall_tracepoint", Name: "execve", Available: true},
		{Kind: "syscall_tracepoint", Name: "openat", Available: true},
		{Kind: "syscall_tracepoint", Name: "connect", Available: true},
		{Kind: "lsm_bpf", Name: "bprm_check_security", Available: false, UnavailableReason: "lsm=bpf missing"},
		{Kind: "lsm_bpf", Name: "file_open", Available: false, UnavailableReason: "lsm=bpf missing"},
		{Kind: "kprobe", Name: "security_file_open", Available: false, UnavailableReason: "symbol not found"},
	}}
	res, err := h.Resolve(r)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var malformed, alsoUnavail bool
	for _, s := range res.Skipped {
		if s.Name == "bprm_check_security" && stringContains(s.Reason, "malformed fallback") {
			malformed = true
		}
		if s.Name == "file_open" && stringContains(s.Reason, "also unavailable") {
			alsoUnavail = true
		}
	}
	if !malformed {
		t.Errorf("bprm_check_security should be skipped with malformed-fallback reason: %+v", res.Skipped)
	}
	if !alsoUnavail {
		t.Errorf("file_open should be skipped when alt hook is also unavailable: %+v", res.Skipped)
	}
	// No fallback should have been recorded — all three fell through.
	if len(res.Fallback) != 0 {
		t.Errorf("no successful fallback should have been recorded: %+v", res.Fallback)
	}
}

func TestResolveFailOnMissing(t *testing.T) {
	h, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	h.Spec.Graceful.OnMissing = "fail"
	h.Spec.Graceful.Fallback = nil
	r := &types.CapabilityReport{Hooks: []types.HookCap{
		{Kind: "syscall_tracepoint", Name: "execve", Available: true},
	}}
	_, err = h.Resolve(r)
	if err == nil {
		t.Fatal("expected error when hooks missing under fail policy")
	}
	// ResolutionError must be retrievable via errors.As — callers (admin,
	// klctl) switch on this type to render a structured missing-hooks list
	// instead of dumping the raw message. Regression guard against someone
	// wrapping the error in a way that strips the concrete type.
	var re *ResolutionError
	if !errors.As(err, &re) {
		t.Fatalf("expected *ResolutionError, got %T: %v", err, err)
	}
	if !stringContains(err.Error(), "openat") {
		t.Fatalf("error should list missing hooks: %v", err)
	}
	var sawOpenat bool
	for _, m := range re.Missing {
		if m.Name == "openat" {
			sawOpenat = true
			break
		}
	}
	if !sawOpenat {
		t.Fatalf("Missing list should include openat: %+v", re.Missing)
	}
}

func stringContains(s, sub string) bool { return strings.Contains(s, sub) }

func TestPresetsParseAndCoverCriticalHooks(t *testing.T) {
	for _, name := range PresetNames() {
		p := Preset(name)
		if p == nil {
			t.Fatalf("preset %s not found", name)
		}
		if p.Metadata.Name != name {
			t.Fatalf("preset name mismatch: %s vs %s", p.Metadata.Name, name)
		}
	}
	std := Preset("security-standard")
	// execve MUST be in security-standard
	found := false
	for _, s := range std.Spec.Syscalls.Include {
		if s == "execve" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("security-standard missing execve")
	}
}
