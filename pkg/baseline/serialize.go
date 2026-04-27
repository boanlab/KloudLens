// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package baseline

import (
	"encoding/json"
	"slices"
	"time"
)

// profileWire is the on-disk JSON form. CMS/Markov are intentionally dropped —
// downstream consumers (contract.FromProfile(), gap analysis, YAML export) only
// need the allow-sets + identity. Reconstructed profiles get empty sketches so
// they remain safe to pass into the Detector even though rare_syscall /
// markov_anomaly won't fire.
type profileWire struct {
	SchemaVersion    int       `json:"schemaVersion"`
	ID               string    `json:"id"`
	LearnStart       time.Time `json:"learnStart"`
	LearnEnd         time.Time `json:"learnEnd"`
	SampleCount      uint64    `json:"sampleCount"`
	Confidence       float64   `json:"confidence"`
	ExecBinaries     []string  `json:"execBinaries,omitempty"`
	FilePaths        []string  `json:"filePaths,omitempty"`
	FilePathsWrite   []string  `json:"filePathsWrite,omitempty"` // schemaVersion ≥ 3
	EgressPeers      []string  `json:"egressPeers,omitempty"`
	Capabilities     []string  `json:"capabilities,omitempty"`
	UIDs             []uint32  `json:"uids,omitempty"`
	SyscallAllowlist []string  `json:"syscallAllowlist,omitempty"`
	RarityFreqFloor  float64   `json:"rarityFreqFloor"`
	MarkovProbFloor  float64   `json:"markovProbFloor"`
}

// schemaVersion 3 adds direction-tagged file paths (FilePathsWrite subset).
// v2 profiles decode cleanly: FilePathsWrite is empty, so every path reads as
// read-only — matching v2's implicit semantics.
const profileSchemaVersion = 3

// MarshalProfile writes p as newline-free JSON.
func MarshalProfile(p *Profile) ([]byte, error) {
	w := profileWire{
		SchemaVersion:    profileSchemaVersion,
		ID:               p.ID,
		LearnStart:       p.LearnStart,
		LearnEnd:         p.LearnEnd,
		SampleCount:      p.SampleCount,
		Confidence:       p.Confidence,
		ExecBinaries:     keysSorted(p.ExecBinaries),
		FilePaths:        keysSorted(p.FilePaths),
		FilePathsWrite:   keysSorted(p.FilePathsWrite),
		EgressPeers:      keysSorted(p.EgressPeers),
		Capabilities:     keysSorted(p.Capabilities),
		SyscallAllowlist: keysSorted(p.SyscallAllowlist),
		RarityFreqFloor:  p.RarityFreqFloor,
		MarkovProbFloor:  p.MarkovProbFloor,
	}
	w.UIDs = make([]uint32, 0, len(p.UIDs))
	for u := range p.UIDs {
		w.UIDs = append(w.UIDs, u)
	}
	slices.Sort(w.UIDs)
	return json.MarshalIndent(w, "", " ")
}

// UnmarshalProfile rebuilds a Profile from JSON. CMS and Markov are empty
// (non-nil) stubs so callers that poke into those fields don't deref nil.
func UnmarshalProfile(data []byte) (*Profile, error) {
	var w profileWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, err
	}
	p := &Profile{
		ID:               w.ID,
		LearnStart:       w.LearnStart,
		LearnEnd:         w.LearnEnd,
		SampleCount:      w.SampleCount,
		Confidence:       w.Confidence,
		ExecBinaries:     toStringSet(w.ExecBinaries),
		FilePaths:        toStringSet(w.FilePaths),
		FilePathsWrite:   toStringSet(w.FilePathsWrite),
		EgressPeers:      toStringSet(w.EgressPeers),
		Capabilities:     toStringSet(w.Capabilities),
		UIDs:             map[uint32]struct{}{},
		SyscallAllowlist: toStringSet(w.SyscallAllowlist),
		SyscallCMS:       NewCountMinSketch(0.001, 0.001),
		Markov:           NewMarkovModel(),
		RarityFreqFloor:  w.RarityFreqFloor,
		MarkovProbFloor:  w.MarkovProbFloor,
	}
	for _, u := range w.UIDs {
		p.UIDs[u] = struct{}{}
	}
	return p, nil
}

func toStringSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}
