// SPDX-License-Identifier: Apache-2.0

package downgrade

import (
	"sync/atomic"
	"testing"
)

func TestEscalationPathThroughLevels(t *testing.T) {
	var transitions []Transition
	c := New(DefaultThresholds(), func(tr Transition) { transitions = append(transitions, tr) })

	steps := []struct {
		usage float64
		want  Level
	}{
		{0.10, LevelNormal},
		{0.55, LevelNormal},
		{0.61, LevelSampled},
		{0.70, LevelSampled},
		{0.81, LevelHeavilySampled},
		{0.90, LevelHeavilySampled},
		{0.96, LevelCriticalOnly},
		{0.99, LevelCriticalOnly},
	}
	for i, s := range steps {
		c.Observe(s.usage)
		if got := c.Level(); got != s.want {
			t.Fatalf("step %d usage=%.2f: want %s got %s", i, s.usage, s.want, got)
		}
	}
	// Should have moved through 3 transitions (normal→sampled, sampled→heavily, heavily→critical)
	if len(transitions) != 3 {
		t.Fatalf("expected 3 transitions, got %d: %+v", len(transitions), transitions)
	}
}

func TestHysteresisDownstepsOneAtATime(t *testing.T) {
	c := New(DefaultThresholds(), nil)
	c.Observe(0.96) // critical only
	c.Observe(0.30) // below recovery → step down to heavily_sampled
	if got := c.Level(); got != LevelHeavilySampled {
		t.Fatalf("want heavily_sampled, got %s", got)
	}
	c.Observe(0.30)
	if got := c.Level(); got != LevelSampled {
		t.Fatalf("want sampled, got %s", got)
	}
	c.Observe(0.30)
	if got := c.Level(); got != LevelNormal {
		t.Fatalf("want normal, got %s", got)
	}
	// Further observations at low usage keep normal.
	c.Observe(0.05)
	if got := c.Level(); got != LevelNormal {
		t.Fatalf("stay normal, got %s", got)
	}
}

func TestUsageBelowSampledUpDoesNotDemotePrematurely(t *testing.T) {
	c := New(DefaultThresholds(), nil)
	c.Observe(0.61) // escalate to sampled
	// usage sits between recovery (0.40) and sampled_up (0.60) — should stay sampled (no flapping).
	c.Observe(0.50)
	if c.Level() != LevelSampled {
		t.Fatalf("hysteresis broken: %s", c.Level())
	}
	c.Observe(0.55)
	if c.Level() != LevelSampled {
		t.Fatalf("hysteresis broken: %s", c.Level())
	}
}

func TestSamplingRateAndDecodeEnabled(t *testing.T) {
	c := New(DefaultThresholds(), nil)
	if c.SamplingRate() != 1 {
		t.Fatalf("normal rate: %d", c.SamplingRate())
	}
	c.Observe(0.61)
	if c.SamplingRate() != 2 {
		t.Fatalf("sampled rate: %d", c.SamplingRate())
	}
	c.Observe(0.81)
	if c.SamplingRate() != 10 {
		t.Fatalf("heavily rate: %d", c.SamplingRate())
	}
	if c.DecodeEnabled() {
		t.Fatal("decode should be off at heavily_sampled")
	}
	c.Observe(0.96)
	if c.SamplingRate() != 0 {
		t.Fatal("critical only should detach (rate=0)")
	}
}

func TestClampedInputs(t *testing.T) {
	c := New(DefaultThresholds(), nil)
	c.Observe(-1.0)
	if c.LastUsage() != 0 {
		t.Fatalf("negative usage should clamp to 0, got %v", c.LastUsage())
	}
	c.Observe(2.0)
	if c.LastUsage() != 1 {
		t.Fatalf("over-1 usage should clamp to 1, got %v", c.LastUsage())
	}
	if c.Level() != LevelCriticalOnly {
		t.Fatalf("clamped 1.0 should be critical_only, got %s", c.Level())
	}
}

func TestTransitionCallbackFires(t *testing.T) {
	var n atomic.Uint32
	c := New(DefaultThresholds(), func(Transition) { n.Add(1) })
	c.Observe(0.61)
	c.Observe(0.62) // no transition
	c.Observe(0.81)
	c.Observe(0.96)
	if n.Load() != 3 {
		t.Fatalf("expected 3 callbacks, got %d", n.Load())
	}
}

func TestCustomThresholds(t *testing.T) {
	thr := Thresholds{SampledUp: 0.50, HeavilySampledUp: 0.70, CriticalOnlyUp: 0.85, RecoveryDown: 0.30}
	c := New(thr, nil)
	c.Observe(0.52)
	if c.Level() != LevelSampled {
		t.Fatalf("level: %s", c.Level())
	}
}

// TestSetThresholdsLiveReconfigure locks in that runtime threshold
// changes take effect on the next Observe. The test exercises two
// directions: loosening (a usage that used to escalate no longer does)
// and tightening (a usage that used to stay flat now escalates).
// Operators use SetThresholds to retune the controller against a known
// workload without restarting the daemon.
func TestSetThresholdsLiveReconfigure(t *testing.T) {
	c := New(DefaultThresholds(), nil)

	// Loosen: raise Sampled floor to 0.70. A 0.65 usage that would have
	// crossed the default 0.60 floor must now stay LevelNormal.
	c.SetThresholds(Thresholds{SampledUp: 0.70, HeavilySampledUp: 0.85, CriticalOnlyUp: 0.98, RecoveryDown: 0.40})
	if got := c.Thresholds().SampledUp; got != 0.70 {
		t.Errorf("Thresholds.SampledUp = %v, want 0.70", got)
	}
	c.Observe(0.65)
	if got := c.Level(); got != LevelNormal {
		t.Fatalf("loosened: Level = %s, want Normal (0.65 < sampled=0.70)", got)
	}

	// Tighten: drop Critical floor to 0.80. The same 0.85 usage that
	// would merely be HeavilySampled under defaults now vaults straight
	// to CriticalOnly.
	c.SetThresholds(Thresholds{SampledUp: 0.30, HeavilySampledUp: 0.50, CriticalOnlyUp: 0.80, RecoveryDown: 0.20})
	c.Observe(0.85)
	if got := c.Level(); got != LevelCriticalOnly {
		t.Fatalf("tightened: Level = %s, want CriticalOnly (0.85 ≥ critical=0.80)", got)
	}
}
