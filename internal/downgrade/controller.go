// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package downgrade implements the adaptive downgrade controller from
// It watches ring buffer usage and moves the agent through
// four levels: Normal → Sampled → HeavilySampled → CriticalOnly, emitting
// an audit hook on every transition.
//
// The thresholds in the plan (60%, 80%, 95%) are used for escalation.
// De-escalation uses a 40% hysteresis threshold to avoid flapping.
package downgrade

import (
	"fmt"
	"sync"
)

// Level describes the agent throttling state.
type Level int

const (
	LevelNormal         Level = 0
	LevelSampled        Level = 1 // non-critical sampled 1/2
	LevelHeavilySampled Level = 2 // non-critical 1/10, arg decode off
	LevelCriticalOnly   Level = 3 // non-critical detached, critical preserved
)

func (l Level) String() string {
	switch l {
	case LevelNormal:
		return "normal"
	case LevelSampled:
		return "sampled"
	case LevelHeavilySampled:
		return "heavily_sampled"
	case LevelCriticalOnly:
		return "critical_only"
	default:
		return fmt.Sprintf("level(%d)", int(l))
	}
}

// Thresholds are in [0,1]. Each Up threshold is the usage fraction at which
// the controller promotes to that level; Down is the hysteresis fraction
// below which it demotes.
type Thresholds struct {
	SampledUp        float64 // default 0.60
	HeavilySampledUp float64 // default 0.80
	CriticalOnlyUp   float64 // default 0.95
	RecoveryDown     float64 // default 0.40
}

// DefaultThresholds matches
func DefaultThresholds() Thresholds {
	return Thresholds{0.60, 0.80, 0.95, 0.40}
}

// Transition is emitted when the controller changes Level.
type Transition struct {
	From   Level
	To     Level
	Reason string // descriptive, e.g. "usage=0.83 > heavily_sampled_up=0.80"
	Usage  float64
}

// Controller is goroutine-safe. Observe(u) feeds new usage; subsequent
// Level reads the latest computed level.
type Controller struct {
	mu         sync.RWMutex
	level      Level
	thresholds Thresholds
	onChange   func(Transition)
	lastUsage  float64
}

// New returns a controller initialized at LevelNormal.
func New(thr Thresholds, onChange func(Transition)) *Controller {
	if thr.SampledUp == 0 && thr.HeavilySampledUp == 0 && thr.CriticalOnlyUp == 0 && thr.RecoveryDown == 0 {
		thr = DefaultThresholds()
	}
	return &Controller{
		thresholds: thr,
		onChange:   onChange,
	}
}

// Level returns the current throttling level.
func (c *Controller) Level() Level {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.level
}

// LastUsage returns the most recent observed usage fraction.
func (c *Controller) LastUsage() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastUsage
}

// Thresholds returns a copy of the current thresholds. Used by the runtime
// config controller to echo the current values back on `klctl config get`.
func (c *Controller) Thresholds() Thresholds {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.thresholds
}

// SetThresholds atomically replaces the controller's thresholds. The next
// Observe call uses the new values — there is no retroactive re-evaluation
// against the last usage reading, so operators raising the Critical floor
// while the controller is already in CriticalOnly still have to wait for a
// usage drop below RecoveryDown to demote.
//
// Validation is the caller's responsibility; any Thresholds struct is
// accepted so tests can exercise degenerate cases.
func (c *Controller) SetThresholds(t Thresholds) {
	c.mu.Lock()
	c.thresholds = t
	c.mu.Unlock()
}

// Observe feeds a new usage reading (0.0 – 1.0). Returns whether a transition
// occurred and, if so, its details.
func (c *Controller) Observe(usage float64) (bool, Transition) {
	if usage < 0 {
		usage = 0
	}
	if usage > 1 {
		usage = 1
	}
	c.mu.Lock()
	c.lastUsage = usage
	prev := c.level
	next := c.computeNext(prev, usage)
	if next == prev {
		c.mu.Unlock()
		return false, Transition{}
	}
	c.level = next
	c.mu.Unlock()

	tr := Transition{
		From:   prev,
		To:     next,
		Usage:  usage,
		Reason: c.reason(prev, next, usage),
	}
	if c.onChange != nil {
		c.onChange(tr)
	}
	return true, tr
}

func (c *Controller) computeNext(prev Level, usage float64) Level {
	t := c.thresholds
	// Escalation takes priority over de-escalation: check from highest down.
	switch {
	case usage >= t.CriticalOnlyUp:
		return LevelCriticalOnly
	case usage >= t.HeavilySampledUp:
		if prev < LevelHeavilySampled {
			return LevelHeavilySampled
		}
		return prev // keep higher level
	case usage >= t.SampledUp:
		if prev < LevelSampled {
			return LevelSampled
		}
		return prev
	}
	// De-escalation: usage below RecoveryDown steps down one at a time.
	if usage < t.RecoveryDown && prev > LevelNormal {
		return prev - 1
	}
	return prev
}

func (c *Controller) reason(prev, next Level, usage float64) string {
	t := c.thresholds
	if next > prev {
		var thresh float64
		switch next {
		case LevelSampled:
			thresh = t.SampledUp
		case LevelHeavilySampled:
			thresh = t.HeavilySampledUp
		case LevelCriticalOnly:
			thresh = t.CriticalOnlyUp
		}
		return fmt.Sprintf("usage=%.2f >= %s_up=%.2f", usage, next, thresh)
	}
	return fmt.Sprintf("usage=%.2f < recovery_down=%.2f (hysteresis)", usage, t.RecoveryDown)
}

// SamplingRate returns the non-critical sampling denominator for the current level.
// 1/n means keep 1 out of every n events.
func (c *Controller) SamplingRate() int {
	switch c.Level() {
	case LevelSampled:
		return 2
	case LevelHeavilySampled:
		return 10
	case LevelCriticalOnly:
		return 0 // detach
	default:
		return 1
	}
}

// DecodeEnabled returns whether full argument decoding is currently on.
func (c *Controller) DecodeEnabled() bool {
	return c.Level() < LevelHeavilySampled
}
