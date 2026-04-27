// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/internal/downgrade"
)

// TestConfigWALGCEveryRoundTrip locks in that `klctl config set
// wal-gc-every=…` (a) parses durations the same way stats-interval does
// (so operators don't trip on one being strict and the other loose),
// (b) pushes the new duration to the janitor's reconfigure channel, and
// (c) round-trips through Get with normalized form. Without the key
// surfacing in Get, klctl's whitelist introspection would hide the knob
// from operators who don't already know it exists.
func TestConfigWALGCEveryRoundTrip(t *testing.T) {
	ch := make(chan time.Duration, 1)
	cc := &configController{
		statsInterval: 30 * time.Second,
		walGCEvery:    30 * time.Second,
		walGCCh:       ch,
	}

	// Key is listed both in Get and in acceptedKeys when the channel
	// is wired.
	if got, ok := cc.Get()["wal-gc-every"]; !ok || got != "30s" {
		t.Fatalf("initial Get: got %q ok=%v, want 30s", got, ok)
	}

	norm, err := cc.Set("wal-gc-every", "2m")
	if err != nil {
		t.Fatalf("Set 2m: %v", err)
	}
	if norm != "2m0s" {
		t.Errorf("normalized = %q, want 2m0s", norm)
	}
	select {
	case d := <-ch:
		if d != 2*time.Minute {
			t.Errorf("channel got %v, want 2m", d)
		}
	default:
		t.Fatal("Set did not push new duration to channel")
	}
	if got := cc.Get()["wal-gc-every"]; got != "2m0s" {
		t.Errorf("after Set: Get = %q, want 2m0s", got)
	}

	// "off" is the documented pause synonym — same contract as
	// stats-interval so operators don't have to remember two dialects.
	if _, err := cc.Set("wal-gc-every", "off"); err != nil {
		t.Fatalf("Set off: %v", err)
	}
	select {
	case d := <-ch:
		if d != 0 {
			t.Errorf("off channel got %v, want 0", d)
		}
	default:
		t.Fatal("off did not push 0 to channel")
	}
}

// TestConfigWALGCEveryRejectsWhenNoWAL covers the --wal-dir=unset deploy
// shape: the knob is advertised only when the channel is wired, so Set
// must refuse the key with an actionable error instead of silently
// succeeding against nothing.
func TestConfigWALGCEveryRejectsWhenNoWAL(t *testing.T) {
	cc := &configController{statsInterval: 30 * time.Second}
	if _, ok := cc.Get()["wal-gc-every"]; ok {
		t.Error("wal-gc-every should not appear in Get without a channel")
	}
	_, err := cc.Set("wal-gc-every", "1m")
	if err == nil {
		t.Fatal("expected error when WAL is disabled")
	}
	if !strings.Contains(err.Error(), "wal-dir") {
		t.Errorf("error did not mention --wal-dir: %v", err)
	}
}

// TestConfigWALGCEveryRejectsBadDuration guards the same parser error
// surface the stats-interval key already exposes — an operator fat-
// fingering the value gets a named error, not a silent parse of "0".
func TestConfigWALGCEveryRejectsBadDuration(t *testing.T) {
	ch := make(chan time.Duration, 1)
	cc := &configController{
		statsInterval: 30 * time.Second,
		walGCCh:       ch,
	}
	if _, err := cc.Set("wal-gc-every", "garbage"); err == nil {
		t.Error("expected parse error")
	}
	if _, err := cc.Set("wal-gc-every", "-5s"); err == nil {
		t.Error("expected negative-duration error")
	}
	// Neither error path should have leaked a spurious push to the channel.
	select {
	case d := <-ch:
		t.Errorf("unexpected channel send on error path: %v", d)
	default:
	}
}

// TestConfigDowngradeThresholdsRoundTrip exercises the happy path: a
// full four-key update replaces every controller threshold and the
// normalized echo format round-trips through Get unchanged.
func TestConfigDowngradeThresholdsRoundTrip(t *testing.T) {
	ctrl := downgrade.New(downgrade.DefaultThresholds(), nil)
	cc := &configController{
		statsInterval: 30 * time.Second,
		downgradeCtrl: ctrl,
	}

	// Initial Get echoes defaults in canonical order.
	got := cc.Get()["downgrade-thresholds"]
	want := "sampled=0.60,heavy=0.80,critical=0.95,recover=0.40"
	if got != want {
		t.Fatalf("initial Get = %q, want %q", got, want)
	}

	norm, err := cc.Set("downgrade-thresholds", "sampled=0.50,heavy=0.75,critical=0.90,recover=0.30")
	if err != nil {
		t.Fatalf("Set full: %v", err)
	}
	if norm != "sampled=0.50,heavy=0.75,critical=0.90,recover=0.30" {
		t.Errorf("normalized = %q", norm)
	}
	thr := ctrl.Thresholds()
	if thr.SampledUp != 0.50 || thr.HeavilySampledUp != 0.75 || thr.CriticalOnlyUp != 0.90 || thr.RecoveryDown != 0.30 {
		t.Errorf("controller thresholds = %+v, want all four updated", thr)
	}
}

// TestConfigDowngradeThresholdsPartialUpdate confirms the caller-friendly
// short form: specifying only the key the operator wants to change and
// leaving the rest untouched. Without partial support, operators would
// have to re-type all four values every time they bumped one.
func TestConfigDowngradeThresholdsPartialUpdate(t *testing.T) {
	ctrl := downgrade.New(downgrade.DefaultThresholds(), nil)
	cc := &configController{downgradeCtrl: ctrl}

	if _, err := cc.Set("downgrade-thresholds", "critical=0.98"); err != nil {
		t.Fatalf("Set partial: %v", err)
	}
	thr := ctrl.Thresholds()
	if thr.CriticalOnlyUp != 0.98 {
		t.Errorf("critical = %v, want 0.98", thr.CriticalOnlyUp)
	}
	// Other three keys untouched.
	if thr.SampledUp != 0.60 || thr.HeavilySampledUp != 0.80 || thr.RecoveryDown != 0.40 {
		t.Errorf("unspecified keys mutated: %+v", thr)
	}
}

// TestConfigDowngradeThresholdsValidation walks the rejection paths the
// controller depends on. Each error must name the offending key so
// operators see a one-line actionable message instead of a silent
// clamp that hides a mis-typed value for a shift.
func TestConfigDowngradeThresholdsValidation(t *testing.T) {
	ctrl := downgrade.New(downgrade.DefaultThresholds(), nil)
	cc := &configController{downgradeCtrl: ctrl}

	cases := []struct {
		name string
		in   string
		want string // substring expected in error
	}{
		{"out of range", "sampled=1.2", "out of [0,1]"},
		{"negative", "heavy=-0.1", "out of [0,1]"},
		{"unknown key", "foo=0.5", "unknown key"},
		{"bad pair", "sampled", "bad pair"},
		{"parse fail", "sampled=x", "parse"},
		{"empty", "", "empty input"},
		{"ordering broken", "sampled=0.80,heavy=0.70,critical=0.90", "ordering violated"},
		{"recover above sampled", "sampled=0.40,heavy=0.60,critical=0.80,recover=0.50", "must be ≤ sampled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cc.Set("downgrade-thresholds", tc.in)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q, want to contain %q", err, tc.want)
			}
		})
	}
	// The controller must be unchanged after every rejected Set.
	if thr := ctrl.Thresholds(); thr != downgrade.DefaultThresholds() {
		t.Errorf("controller mutated on error path: %+v", thr)
	}
}

// fakeEnrichLevel is the test double for enrichmentLevelReconfigurer.
// It records the last Apply call so tests can assert the normalized form
// reached the pipeline, and lets Get read back whatever the test seeded.
type fakeEnrichLevel struct {
	level   string
	applied []string
}

func (f *fakeEnrichLevel) EnrichmentLevel() string { return f.level }
func (f *fakeEnrichLevel) ApplyEnrichmentLevel(l string) {
	f.level = l
	f.applied = append(f.applied, l)
}

// TestConfigEnrichmentLevelRoundTrip locks in that all three documented
// values reach the pipeline in normalized (lowercased, trimmed) form and
// that Get echoes the pipeline's current state rather than a local
// shadow — the pipeline is the source of truth since ApplyPolicy is a
// second entry point that can change the level without going through
// configController.
func TestConfigEnrichmentLevelRoundTrip(t *testing.T) {
	fake := &fakeEnrichLevel{level: "full"}
	cc := &configController{enrichLevel: fake}

	if got := cc.Get()["enrichment-level"]; got != "full" {
		t.Fatalf("initial Get = %q, want full", got)
	}

	for _, in := range []string{"minimal", " NONE ", "Full"} {
		norm, err := cc.Set("enrichment-level", in)
		if err != nil {
			t.Fatalf("Set %q: %v", in, err)
		}
		want := strings.ToLower(strings.TrimSpace(in))
		if norm != want {
			t.Errorf("Set %q normalized = %q, want %q", in, norm, want)
		}
		if fake.level != want {
			t.Errorf("pipeline level = %q, want %q", fake.level, want)
		}
		if got := cc.Get()["enrichment-level"]; got != want {
			t.Errorf("Get after Set(%q) = %q, want %q", in, got, want)
		}
	}

	if len(fake.applied) != 3 {
		t.Errorf("ApplyEnrichmentLevel calls = %d, want 3", len(fake.applied))
	}
}

// TestConfigEnrichmentLevelRejectsBogus confirms the CLI boundary snaps
// invalid values into an error instead of silently falling back to "full"
// the way ApplyPolicy's dispatcher does. A human at klctl has typed
// something — tell them, don't paper over it.
func TestConfigEnrichmentLevelRejectsBogus(t *testing.T) {
	fake := &fakeEnrichLevel{level: "full"}
	cc := &configController{enrichLevel: fake}

	_, err := cc.Set("enrichment-level", "verbose")
	if err == nil {
		t.Fatal("expected error for unknown level")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("error did not mention invalid: %v", err)
	}
	if fake.level != "full" {
		t.Errorf("level mutated on error path: %q", fake.level)
	}
	if len(fake.applied) != 0 {
		t.Errorf("ApplyEnrichmentLevel called on error path: %v", fake.applied)
	}
}

// TestConfigEnrichmentLevelHiddenWithoutPipeline mirrors the other
// conditional keys: a controller with no pipeline pointer does not
// advertise the key via Get and refuses Set with an actionable error.
// The nil case is only realistic in tests — production main.go always()
// wires the pipeline — but the guard keeps the test surface honest.
func TestConfigEnrichmentLevelHiddenWithoutPipeline(t *testing.T) {
	cc := &configController{statsInterval: 30 * time.Second}
	if _, ok := cc.Get()["enrichment-level"]; ok {
		t.Error("enrichment-level should not appear without pipeline")
	}
	_, err := cc.Set("enrichment-level", "minimal")
	if err == nil {
		t.Fatal("expected error when pipeline is absent")
	}
}

// TestConfigDowngradeThresholdsRejectsWhenNoController mirrors the
// wal-gc-every gate: a daemon without --auto-downgrade does not
// advertise the key via Get and Set must refuse with an actionable
// error rather than silently writing into a nil controller.
func TestConfigDowngradeThresholdsRejectsWhenNoController(t *testing.T) {
	cc := &configController{statsInterval: 30 * time.Second}
	if _, ok := cc.Get()["downgrade-thresholds"]; ok {
		t.Error("downgrade-thresholds should not appear without controller")
	}
	_, err := cc.Set("downgrade-thresholds", "sampled=0.50")
	if err == nil {
		t.Fatal("expected error when controller is absent")
	}
	if !strings.Contains(err.Error(), "auto-downgrade") {
		t.Errorf("error did not mention --auto-downgrade: %v", err)
	}
}
