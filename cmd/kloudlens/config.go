// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/boanlab/kloudlens/internal/downgrade"
)

// configController exposes a small whitelist of runtime-tunable knobs to
// the admin service. It implements admin.ConfigController. Every write
// is guarded by mu so klctl config set is safe under concurrent calls.
//
// Current keys:
// - stats-interval: duration fed to the stats goroutine's re-cadence
// channel. "0" or "off" disables the periodic print (the goroutine
// still runs, it just stops firing).
// - wal-gc-every: duration pushed to the WAL janitor's reconfigure
// channel. "0" or "off" parks the janitor (WAL retention caps stop
// being enforced until re-armed). Only available when the daemon
// was started with --wal-dir.
// - downgrade-thresholds: CSV of "key=float" pairs (any subset of
// sampled/heavy/critical/recover) that rewrites the adaptive
// controller's escalation/recovery fractions live. Only available
// when --auto-downgrade was passed at startup; partial updates
// leave unspecified keys at their current value.
// - enrichment-level: one of full|minimal|none, mirrors the
// spec.enrichment.level field on HookSubscription. Routes through
// the same Pipeline.ApplyEnrichmentLevel as ApplyPolicy, so the two
// entry points (klctl apply -f hook.yaml vs klctl config set
// enrichment-level=minimal) land on the same runtime gate.
type configController struct {
	mu sync.Mutex

	statsInterval   time.Duration
	statsIntervalCh chan<- time.Duration // closed-over by main's stats goroutine

	walGCEvery time.Duration
	walGCCh    chan<- time.Duration // nil when --wal-dir was not set

	downgradeCtrl *downgrade.Controller // nil when --auto-downgrade was not passed

	enrichLevel enrichmentLevelReconfigurer // nil when no pipeline is attached (tests)
}

// enrichmentLevelReconfigurer is the narrow interface configController
// needs from the running pipeline to both echo the current level in
// Get and swap it in Set. kloudlens's Pipeline satisfies it via
// EnrichmentLevel / ApplyEnrichmentLevel. A nil value hides the
// enrichment-level key from the whitelist — tests that don't wire a
// pipeline keep the old 4-key surface.
type enrichmentLevelReconfigurer interface {
	EnrichmentLevel() string
	ApplyEnrichmentLevel(level string)
}

// Get returns every accepted key with its current normalized value.
// Trigger-style keys echo an empty string — there is no "current" trigger
// value, but listing the key still tells the operator it is settable.
func (c *configController) Get() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]string{
		"stats-interval": c.statsInterval.String(),
	}
	if c.walGCCh != nil {
		out["wal-gc-every"] = c.walGCEvery.String()
	}
	if c.downgradeCtrl != nil {
		out["downgrade-thresholds"] = formatThresholds(c.downgradeCtrl.Thresholds())
	}
	if c.enrichLevel != nil {
		out["enrichment-level"] = c.enrichLevel.EnrichmentLevel()
	}
	return out
}

// Set applies one key=value change. Unknown keys are rejected — the
// controller is the source of truth for what is mutable at runtime.
func (c *configController) Set(key, value string) (string, error) {
	switch key {
	case "stats-interval":
		return c.setStatsInterval(value)
	case "wal-gc-every":
		return c.setWALGCEvery(value)
	case "downgrade-thresholds":
		return c.setDowngradeThresholds(value)
	case "enrichment-level":
		return c.setEnrichmentLevel(value)
	default:
		return "", fmt.Errorf("unknown config key %q (accepted: %s)", key, strings.Join(c.acceptedKeys(), ", "))
	}
}

func (c *configController) acceptedKeys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := []string{"stats-interval"}
	if c.walGCCh != nil {
		keys = append(keys, "wal-gc-every")
	}
	if c.downgradeCtrl != nil {
		keys = append(keys, "downgrade-thresholds")
	}
	if c.enrichLevel != nil {
		keys = append(keys, "enrichment-level")
	}
	sort.Strings(keys)
	return keys
}

func (c *configController) setStatsInterval(raw string) (string, error) {
	var d time.Duration
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "0", "off", "disable", "disabled":
		d = 0
	default:
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return "", fmt.Errorf("stats-interval: %w", err)
		}
		if parsed < 0 {
			return "", fmt.Errorf("stats-interval: negative duration %q", raw)
		}
		d = parsed
	}
	c.mu.Lock()
	c.statsInterval = d
	ch := c.statsIntervalCh
	c.mu.Unlock()
	if ch != nil {
		ch <- d
	}
	return d.String(), nil
}

func (c *configController) setWALGCEvery(raw string) (string, error) {
	c.mu.Lock()
	ch := c.walGCCh
	c.mu.Unlock()
	if ch == nil {
		return "", fmt.Errorf("wal-gc-every: no --wal-dir was set at startup")
	}
	var d time.Duration
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "0", "off", "disable", "disabled":
		d = 0
	default:
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return "", fmt.Errorf("wal-gc-every: %w", err)
		}
		if parsed < 0 {
			return "", fmt.Errorf("wal-gc-every: negative duration %q", raw)
		}
		d = parsed
	}
	c.mu.Lock()
	c.walGCEvery = d
	c.mu.Unlock()
	ch <- d
	return d.String(), nil
}

// setDowngradeThresholds applies a CSV of "key=float" pairs to the
// attached downgrade.Controller. Accepted keys: sampled, heavy,
// critical, recover (the short forms of SampledUp / HeavilySampledUp /
// CriticalOnlyUp / RecoveryDown). Missing keys inherit the controller's
// current values — an operator bumping only `critical=0.98` does not
// have to re-type the other three.
//
// Validation mirrors the invariants the controller itself relies on:
// every value in [0,1], escalation ordering (sampled < heavy < critical),
// and RecoveryDown ≤ SampledUp (otherwise the hysteresis gate sits above
// the first escalation rung and the controller can't de-escalate from
// LevelSampled back to Normal). Errors name the offending key so klctl
// users see a one-line "why".
func (c *configController) setDowngradeThresholds(raw string) (string, error) {
	c.mu.Lock()
	ctrl := c.downgradeCtrl
	c.mu.Unlock()
	if ctrl == nil {
		return "", fmt.Errorf("downgrade-thresholds: --auto-downgrade was not enabled at startup")
	}
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("downgrade-thresholds: empty input; expected sampled=...,heavy=...,critical=...,recover=...")
	}
	cur := ctrl.Thresholds()
	for _, part := range strings.Split(raw, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return "", fmt.Errorf("downgrade-thresholds: bad pair %q (want key=value)", part)
		}
		k := strings.TrimSpace(kv[0])
		v, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64)
		if err != nil {
			return "", fmt.Errorf("downgrade-thresholds: parse %s: %w", k, err)
		}
		if v < 0 || v > 1 {
			return "", fmt.Errorf("downgrade-thresholds: %s=%v out of [0,1]", k, v)
		}
		switch k {
		case "sampled":
			cur.SampledUp = v
		case "heavy":
			cur.HeavilySampledUp = v
		case "critical":
			cur.CriticalOnlyUp = v
		case "recover":
			cur.RecoveryDown = v
		default:
			return "", fmt.Errorf("downgrade-thresholds: unknown key %q (accepted: sampled, heavy, critical, recover)", k)
		}
	}
	if !(cur.SampledUp < cur.HeavilySampledUp && cur.HeavilySampledUp < cur.CriticalOnlyUp) {
		return "", fmt.Errorf("downgrade-thresholds: ordering violated, need sampled < heavy < critical (got %.2f < %.2f < %.2f)",
			cur.SampledUp, cur.HeavilySampledUp, cur.CriticalOnlyUp)
	}
	if cur.RecoveryDown > cur.SampledUp {
		return "", fmt.Errorf("downgrade-thresholds: recover=%.2f must be ≤ sampled=%.2f so the controller can de-escalate",
			cur.RecoveryDown, cur.SampledUp)
	}
	ctrl.SetThresholds(cur)
	return formatThresholds(cur), nil
}

// setEnrichmentLevel validates and forwards the level string to the
// attached pipeline. Accepted values are full|minimal|none, matching the
// HookSubscription spec.enrichment.level enum. Unknown values are
// rejected at this boundary (ApplyPolicy's dispatcher is the other entry
// point and snaps unknowns to "full" to stay fail-safe under a bad
// manifest — here we have a human at the keyboard, so surface the typo).
func (c *configController) setEnrichmentLevel(raw string) (string, error) {
	c.mu.Lock()
	target := c.enrichLevel
	c.mu.Unlock()
	if target == nil {
		return "", fmt.Errorf("enrichment-level: no pipeline attached")
	}
	norm := strings.ToLower(strings.TrimSpace(raw))
	switch norm {
	case "full", "minimal", "none":
	default:
		return "", fmt.Errorf("enrichment-level: invalid %q (accepted: full, minimal, none)", raw)
	}
	target.ApplyEnrichmentLevel(norm)
	return norm, nil
}

// formatThresholds is the canonical one-line echo form used by both
// Get and Set. The order is fixed (sampled, heavy, critical, recover)
// so a round-tripped value diffs cleanly.
func formatThresholds(t downgrade.Thresholds) string {
	return fmt.Sprintf("sampled=%.2f,heavy=%.2f,critical=%.2f,recover=%.2f",
		t.SampledUp, t.HeavilySampledUp, t.CriticalOnlyUp, t.RecoveryDown)
}
