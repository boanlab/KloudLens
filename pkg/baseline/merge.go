// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

// ErrNoProfiles is returned by MergeProfiles when given an empty slice.
var ErrNoProfiles = errors.New("baseline: no profiles to merge")

// ErrThresholdMismatch is returned when profiles disagree on their rarity
// or Markov floors. Merging across incompatible thresholds would silently
// shift detection behavior, so we refuse rather than pick one.
var ErrThresholdMismatch = errors.New("baseline: profiles have mismatched rarity/markov thresholds")

// MergeProfiles folds N profiles into a single cluster-wide profile.
// Allow-sets are unioned, SampleCount is summed, CMS and Markov are merged
// in place (requires compatible CMS dims/seeds), Learn() window becomes
// [min(starts), max(ends)], Confidence is sample-weighted mean, and the
// merged ID is a deterministic hash of the sorted source IDs so the same
// inputs always produce the same output regardless of order.
//
// Profiles must agree on RarityFreqFloor and MarkovProbFloor — CMS seeds
// match automatically when they were all built by NewCountMinSketch with
// the same (eps, delta), which the Learner enforces.
func MergeProfiles(profiles []*Profile) (*Profile, error) {
	if len(profiles) == 0 {
		return nil, ErrNoProfiles
	}
	if len(profiles) == 1 {
		// Return a deep-enough copy so the caller can't mutate the input.
		return cloneProfile(profiles[0]), nil
	}
	// Validate thresholds up front.
	first := profiles[0]
	for _, p := range profiles[1:] {
		if p.RarityFreqFloor != first.RarityFreqFloor || p.MarkovProbFloor != first.MarkovProbFloor {
			return nil, ErrThresholdMismatch
		}
	}

	merged := cloneProfile(first)
	merged.ID = ""
	for _, p := range profiles[1:] {
		if err := mergeInto(merged, p); err != nil {
			return nil, err
		}
	}
	merged.ID = clusterMergedID(profiles)
	return merged, nil
}

// mergeInto folds src into dst. Caller must have already verified thresholds.
func mergeInto(dst, src *Profile) error {
	if src == nil {
		return nil
	}
	unionStringSet(dst.ExecBinaries, src.ExecBinaries)
	unionStringSet(dst.FilePaths, src.FilePaths)
	unionStringSet(dst.FilePathsWrite, src.FilePathsWrite)
	unionStringSet(dst.EgressPeers, src.EgressPeers)
	unionStringSet(dst.Capabilities, src.Capabilities)
	unionStringSet(dst.SyscallAllowlist, src.SyscallAllowlist)
	for u := range src.UIDs {
		dst.UIDs[u] = struct{}{}
	}
	if dst.SyscallCMS != nil && src.SyscallCMS != nil {
		if err := dst.SyscallCMS.Merge(src.SyscallCMS); err != nil {
			return fmt.Errorf("merge CMS from %q: %w", src.ID, err)
		}
	}
	if dst.Markov != nil && src.Markov != nil {
		dst.Markov.Merge(src.Markov)
	}

	// Confidence is sample-weighted mean so a 100-sample profile with
	// confidence 1.0 doesn't get averaged down by a 10-sample 0.1 profile.
	totalSamples := dst.SampleCount + src.SampleCount
	if totalSamples > 0 {
		dst.Confidence = (dst.Confidence*float64(dst.SampleCount) +
			src.Confidence*float64(src.SampleCount)) / float64(totalSamples)
	}
	dst.SampleCount = totalSamples

	if src.LearnStart.Before(dst.LearnStart) || dst.LearnStart.IsZero() {
		dst.LearnStart = src.LearnStart
	}
	if src.LearnEnd.After(dst.LearnEnd) {
		dst.LearnEnd = src.LearnEnd
	}
	return nil
}

// clusterMergedID is a deterministic id for the union: SHA-256 over the
// sorted source IDs, prefixed so it's visibly distinguishable from a
// single-profile ID.
func clusterMergedID(profiles []*Profile) string {
	ids := make([]string, 0, len(profiles))
	for _, p := range profiles {
		ids = append(ids, p.ID)
	}
	sort.Strings(ids)
	h := sha256.New()
	for _, id := range ids {
		_, _ = h.Write([]byte(id))
		_, _ = h.Write([]byte{0})
	}
	return "merged:" + hex.EncodeToString(h.Sum(nil))[:32]
}

// DriftReport summarizes how one node's profile differs from the merged
// cluster baseline (plan drift signals). All fields are ordered for
// stable output — same inputs always produce identical JSON.
type DriftReport struct {
	// Items the local profile has but the cluster baseline does not.
	// In practice the local profile's allow-sets are always a subset of
	// the merged superset, so these fields exist primarily for symmetry
	// when a caller passes a non-merged "other" profile.
	OnlyInLocal DriftItems `json:"only_in_local"`
	// Items the cluster baseline has but this local profile does not —
	// candidates for "this node hasn't seen X yet" lag analysis.
	OnlyInCluster DriftItems `json:"only_in_cluster"`
	// Syscalls where local relative frequency differs from cluster by
	// more than the tolerance passed to Drift. Key is syscall name; value
	// is signed delta (local − cluster).
	SyscallFreqDelta map[string]float64 `json:"syscall_freq_delta,omitempty"`
}

// DriftItems buckets drift findings by allow-set category.
type DriftItems struct {
	ExecBinaries     []string `json:"exec_binaries,omitempty"`
	FilePaths        []string `json:"file_paths,omitempty"`
	EgressPeers      []string `json:"egress_peers,omitempty"`
	Capabilities     []string `json:"capabilities,omitempty"`
	SyscallAllowlist []string `json:"syscall_allowlist,omitempty"`
}

// Drift computes the set-difference drift between `local` and `cluster`.
// `freqTolerance` is the absolute |local_freq − cluster_freq| threshold
// above which a syscall shows up in SyscallFreqDelta (0 = report every
// non-zero delta). Pass the same CMS-backed merged profile you got out
// of MergeProfiles as `cluster`.
func Drift(local, cluster *Profile, freqTolerance float64) DriftReport {
	rep := DriftReport{
		OnlyInLocal:      diffItems(local, cluster),
		OnlyInCluster:    diffItems(cluster, local),
		SyscallFreqDelta: map[string]float64{},
	}
	if local.SyscallCMS == nil || cluster.SyscallCMS == nil {
		if len(rep.SyscallFreqDelta) == 0 {
			rep.SyscallFreqDelta = nil
		}
		return rep
	}
	seen := map[string]struct{}{}
	for k := range local.SyscallAllowlist {
		seen[k] = struct{}{}
	}
	for k := range cluster.SyscallAllowlist {
		seen[k] = struct{}{}
	}
	for k := range seen {
		lf := local.SyscallCMS.RelativeFrequency(k)
		cf := cluster.SyscallCMS.RelativeFrequency(k)
		delta := lf - cf
		abs := delta
		if abs < 0 {
			abs = -abs
		}
		if abs > freqTolerance {
			rep.SyscallFreqDelta[k] = delta
		}
	}
	if len(rep.SyscallFreqDelta) == 0 {
		rep.SyscallFreqDelta = nil
	}
	return rep
}

// diffItems returns items present in `a` but missing from `b`. Output is
// sorted so DriftReport JSON is stable across runs.
func diffItems(a, b *Profile) DriftItems {
	return DriftItems{
		ExecBinaries:     sortedMissing(a.ExecBinaries, b.ExecBinaries),
		FilePaths:        sortedMissing(a.FilePaths, b.FilePaths),
		EgressPeers:      sortedMissing(a.EgressPeers, b.EgressPeers),
		Capabilities:     sortedMissing(a.Capabilities, b.Capabilities),
		SyscallAllowlist: sortedMissing(a.SyscallAllowlist, b.SyscallAllowlist),
	}
}

func sortedMissing(src, have map[string]struct{}) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, 0, len(src))
	for k := range src {
		if _, ok := have[k]; !ok {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func unionStringSet(dst, src map[string]struct{}) {
	for k := range src {
		dst[k] = struct{}{}
	}
}

// cloneProfile returns a deep copy sufficient to prevent the caller from
// seeing subsequent mutations on the input. CMS + Markov are copied; the
// Profile's own reference types (maps) are rebuilt.
func cloneProfile(p *Profile) *Profile {
	out := &Profile{
		ID:               p.ID,
		LearnStart:       p.LearnStart,
		LearnEnd:         p.LearnEnd,
		SampleCount:      p.SampleCount,
		Confidence:       p.Confidence,
		RarityFreqFloor:  p.RarityFreqFloor,
		MarkovProbFloor:  p.MarkovProbFloor,
		ExecBinaries:     copyStringSet(p.ExecBinaries),
		FilePaths:        copyStringSet(p.FilePaths),
		FilePathsWrite:   copyStringSet(p.FilePathsWrite),
		EgressPeers:      copyStringSet(p.EgressPeers),
		Capabilities:     copyStringSet(p.Capabilities),
		UIDs:             make(map[uint32]struct{}, len(p.UIDs)),
		SyscallAllowlist: copyStringSet(p.SyscallAllowlist),
	}
	for u := range p.UIDs {
		out.UIDs[u] = struct{}{}
	}
	out.SyscallCMS = cloneCMS(p.SyscallCMS)
	out.Markov = cloneMarkov(p.Markov)
	return out
}

func copyStringSet(src map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(src))
	for k := range src {
		out[k] = struct{}{}
	}
	return out
}

func cloneCMS(c *CountMinSketch) *CountMinSketch {
	if c == nil {
		return nil
	}
	out := newSketch(c.width, c.depth)
	copy(out.seeds, c.seeds)
	for i := range c.rows {
		copy(out.rows[i], c.rows[i])
	}
	out.total = c.total
	return out
}

func cloneMarkov(m *MarkovModel) *MarkovModel {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := NewMarkovModel()
	for from, row := range m.transCount {
		dst := make(map[string]uint64, len(row))
		for to, n := range row {
			dst[to] = n
		}
		out.transCount[from] = dst
	}
	for from, n := range m.stateTotal {
		out.stateTotal[from] = n
	}
	return out
}

// CompatibleCMS returns nil if the two sketches can be merged, or a
// descriptive error otherwise. Exposed so klctl can fail fast with a
// friendly message before the Merge call.
func (c *CountMinSketch) CompatibleCMS(other *CountMinSketch) error {
	if c == nil || other == nil {
		return errors.New("baseline: nil CMS")
	}
	if c.width != other.width || c.depth != other.depth {
		return fmt.Errorf("baseline: CMS dims differ (%dx%d vs %dx%d)",
			c.width, c.depth, other.width, other.depth)
	}
	for i := range c.seeds {
		if c.seeds[i] != other.seeds[i] {
			return errors.New("baseline: CMS seeds differ")
		}
	}
	return nil
}
