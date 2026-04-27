// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package baseline

import "sync"

// MarkovModel is a first-order transition model over discrete states, used
// for the `markov_anomaly` deviation. States are string keys —
// typically syscall names.
type MarkovModel struct {
	mu         sync.RWMutex
	transCount map[string]map[string]uint64
	stateTotal map[string]uint64
}

// NewMarkovModel returns an empty model.
func NewMarkovModel() *MarkovModel {
	return &MarkovModel{
		transCount: map[string]map[string]uint64{},
		stateTotal: map[string]uint64{},
	}
}

// Observe records a transition from→to.
func (m *MarkovModel) Observe(from, to string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.transCount[from]
	if !ok {
		row = map[string]uint64{}
		m.transCount[from] = row
	}
	row[to]++
	m.stateTotal[from]++
}

// Probability returns P(to|from). Returns 0 for unseen transitions.
func (m *MarkovModel) Probability(from, to string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	total, ok := m.stateTotal[from]
	if !ok || total == 0 {
		return 0
	}
	c := m.transCount[from][to]
	return float64(c) / float64(total)
}

// Known reports whether from has been observed at least once. Used to avoid
// flagging anomalies on states that were never trained.
func (m *MarkovModel) Known(from string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stateTotal[from] > 0
}

// States returns the set of from-states seen, for diagnostic use.
func (m *MarkovModel) States() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.stateTotal))
	for s := range m.stateTotal {
		out = append(out, s)
	}
	return out
}

// Merge folds `other` into m by summing transition and state counts. Any
// from-state unique to `other` is added; shared states have their row
// counts summed. No-op when other is nil or empty.
func (m *MarkovModel) Merge(other *MarkovModel) {
	if other == nil {
		return
	}
	other.mu.RLock()
	defer other.mu.RUnlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	for from, row := range other.transCount {
		dst, ok := m.transCount[from]
		if !ok {
			dst = map[string]uint64{}
			m.transCount[from] = dst
		}
		for to, n := range row {
			dst[to] += n
		}
	}
	for from, n := range other.stateTotal {
		m.stateTotal[from] += n
	}
}
