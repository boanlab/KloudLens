// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package baseline implements the Behavioral Baseline engine. A Profile
// captures allowed syscalls, file paths (globbed), egress peers, creds and a
// Markov model of syscall transitions. The Profile is the source of truth
// for deviation-only emission: once promoted, the runtime only reports
// events that do *not* match it.
//
// A Profile is built incrementally by a Learner during a training window.
// After promotion, a Detector scores new events against the frozen profile
// and emits DeviationEvents.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

// Profile holds a frozen set of allowed behavior plus a CMS+Markov model.
type Profile struct {
	ID          string
	LearnStart  time.Time
	LearnEnd    time.Time
	SampleCount uint64
	Confidence  float64

	// Allow-sets (O(1) lookup for new_* checks).
	ExecBinaries     map[string]struct{}
	FilePaths        map[string]struct{} // union: every path seen in either direction — Detector uses this
	FilePathsWrite   map[string]struct{} // direction tag: paths observed via write-style ops (subset of FilePaths)
	EgressPeers      map[string]struct{} // "ip:port"
	Capabilities     map[string]struct{}
	UIDs             map[uint32]struct{}
	SyscallAllowlist map[string]struct{} // concrete syscall names (bounded by LearnerConfig.SyscallAllowlistCap)

	// Rarity + transition models.
	SyscallCMS *CountMinSketch
	Markov     *MarkovModel

	// Thresholds persisted with the profile.
	RarityFreqFloor float64 // below this relative frequency → rare_syscall
	MarkovProbFloor float64 // below this P(to|from) → markov_anomaly
}

// DeviationKind constants match
const (
	DevNewExec          = "new_exec"
	DevNewConnectTarget = "new_connect_target"
	DevNewFilePath      = "new_file_path"
	DevRareSyscall      = "rare_syscall"
	DevMarkovAnomaly    = "markov_anomaly"
)

// Learner accumulates observations into a Profile-in-progress. Safe for
// concurrent use.
type Learner struct {
	mu sync.Mutex
	p  *Profile

	started             time.Time
	prevCall            string
	syscallAllowlistCap int // -1 = unlimited; 0 never reached here (withDefaults normalizes)

	// cfg is retained so Reset can rebuild the internal Profile with the
	// same CMS epsilon/delta and rarity/Markov floors it was constructed
	// with — preserves the operator's tuning across a mid-life reset.
	cfg LearnerConfig
}

// LearnerConfig configures rarity/Markov floors stored on the resulting
// Profile after promotion.
type LearnerConfig struct {
	RarityFreqFloor     float64 // default 1e-4
	MarkovProbFloor     float64 // default 0.01
	CMSEps              float64 // default 0.001
	CMSDelta            float64 // default 0.001
	SyscallAllowlistCap int     // default 1024; 0 = use default, negative = unlimited
}

func (c *LearnerConfig) withDefaults() {
	if c.RarityFreqFloor == 0 {
		c.RarityFreqFloor = 1e-4
	}
	if c.MarkovProbFloor == 0 {
		c.MarkovProbFloor = 0.01
	}
	if c.CMSEps == 0 {
		c.CMSEps = 0.001
	}
	if c.CMSDelta == 0 {
		c.CMSDelta = 0.001
	}
	if c.SyscallAllowlistCap == 0 {
		c.SyscallAllowlistCap = 1024
	}
}

// NewLearner starts a fresh learning window at `start`.
func NewLearner(cfg LearnerConfig, start time.Time) *Learner {
	cfg.withDefaults()
	l := &Learner{
		cfg:                 cfg,
		syscallAllowlistCap: cfg.SyscallAllowlistCap,
	}
	l.initProfile(start)
	return l
}

// initProfile (re)builds the internal Profile without touching cfg. Shared
// by NewLearner + Reset so both paths produce identically-shaped zero state.
func (l *Learner) initProfile(start time.Time) {
	l.started = start
	l.prevCall = ""
	l.p = &Profile{
		LearnStart:       start,
		ExecBinaries:     map[string]struct{}{},
		FilePaths:        map[string]struct{}{},
		FilePathsWrite:   map[string]struct{}{},
		EgressPeers:      map[string]struct{}{},
		Capabilities:     map[string]struct{}{},
		UIDs:             map[uint32]struct{}{},
		SyscallAllowlist: map[string]struct{}{},
		SyscallCMS:       NewCountMinSketch(l.cfg.CMSEps, l.cfg.CMSDelta),
		Markov:           NewMarkovModel(),
		RarityFreqFloor:  l.cfg.RarityFreqFloor,
		MarkovProbFloor:  l.cfg.MarkovProbFloor,
	}
}

// Reset discards all observed state and starts a fresh learning window at
// `start`. Used by the BaselineReset admin RPC so klctl can restart the
// learner without bouncing the agent.
func (l *Learner) Reset(start time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.initProfile(start)
}

// ObserveSyscall records a syscall for frequency and Markov edges.
// `prev` is optional — empty means "no predecessor". The name is also added
// to the SyscallAllowlist until LearnerConfig.SyscallAllowlistCap is reached
// (preserves a concrete set for seccomp-style export alongside CMS).
func (l *Learner) ObserveSyscall(name string) {
	if name == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.p == nil {
		return
	}
	l.p.SyscallCMS.Add(name)
	if l.prevCall != "" {
		l.p.Markov.Observe(l.prevCall, name)
	}
	l.prevCall = name
	l.p.SampleCount++
	if _, already := l.p.SyscallAllowlist[name]; !already {
		if l.syscallAllowlistCap < 0 || len(l.p.SyscallAllowlist) < l.syscallAllowlistCap {
			l.p.SyscallAllowlist[name] = struct{}{}
		}
	}
}

// SnapshotSyscallAllowlist returns a copy of the current allowlist. Callers
// should treat the return value as read-only; it's useful for tests and for
// diagnostic dumps before Promote. Returns an empty map if the Learner has
// already been promoted.
func (l *Learner) SnapshotSyscallAllowlist() map[string]struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.p == nil {
		return map[string]struct{}{}
	}
	out := make(map[string]struct{}, len(l.p.SyscallAllowlist))
	for k := range l.p.SyscallAllowlist {
		out[k] = struct{}{}
	}
	return out
}

// SnapshotFileAllowlist returns a copy of the current file-path allow-set.
// Callers should treat the return value as read-only. Returns an empty map
// if the Learner has already been promoted.
func (l *Learner) SnapshotFileAllowlist() map[string]struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.p == nil {
		return map[string]struct{}{}
	}
	out := make(map[string]struct{}, len(l.p.FilePaths))
	for k := range l.p.FilePaths {
		out[k] = struct{}{}
	}
	return out
}

// ObserveExec adds an exec target to the allow-set.
func (l *Learner) ObserveExec(binary string) {
	if binary == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.p == nil {
		return
	}
	l.p.ExecBinaries[binary] = struct{}{}
}

// ObserveFilePath adds a file path (exact or glob) to the read-direction
// allow-set. Callers that don't know the direction should use this — an
// untagged observation is treated as read, which is the conservative default
// for enforcement (read perm doesn't imply write).
func (l *Learner) ObserveFilePath(pathOrGlob string) {
	if pathOrGlob == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.p == nil {
		return
	}
	l.p.FilePaths[pathOrGlob] = struct{}{}
}

// ObserveFilePathWrite records a path observed via a write-style operation
// (mkdir/unlink/rename/chmod/chown/link/symlink/rmdir/etc.). It lands in the
// union set (for Detector) *and* the Write subset (for Contract export). A
// path seen as both read and write ends up flagged write — at enforcement
// time "can write" subsumes "can read".
func (l *Learner) ObserveFilePathWrite(pathOrGlob string) {
	if pathOrGlob == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.p == nil {
		return
	}
	l.p.FilePaths[pathOrGlob] = struct{}{}
	l.p.FilePathsWrite[pathOrGlob] = struct{}{}
}

// ObserveEgressPeer adds "ip:port" to the allow-set.
func (l *Learner) ObserveEgressPeer(peer string) {
	if peer == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.p == nil {
		return
	}
	l.p.EgressPeers[peer] = struct{}{}
}

// ObserveCapability adds a capability name.
func (l *Learner) ObserveCapability(cap string) {
	if cap == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.p == nil {
		return
	}
	l.p.Capabilities[cap] = struct{}{}
}

// ObserveUID records a uid actually used by the workload.
func (l *Learner) ObserveUID(uid uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.p == nil {
		return
	}
	l.p.UIDs[uid] = struct{}{}
}

// Promote freezes the profile. imageRef+labelHash seed the deterministic
// profileID. minSampleCount guards against under-trained profiles — if the
// window had too few samples, Promote returns (nil, ErrInsufficientSamples()).
func (l *Learner) Promote(end time.Time, imageRef, labelHash string, minSampleCount uint64) (*Profile, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.p.SampleCount < minSampleCount {
		return nil, ErrInsufficientSamples
	}
	l.p.LearnEnd = end
	l.p.ID = profileID(imageRef, labelHash)
	// Confidence: crude — saturates at 1.0 as sample count grows.
	if minSampleCount > 0 {
		l.p.Confidence = float64(l.p.SampleCount) / float64(minSampleCount*10)
		if l.p.Confidence > 1 {
			l.p.Confidence = 1
		}
	}
	out := l.p
	// Mark the Learner spent. Subsequent Observe*/Snapshot* calls become
	// no-ops — necessary because the agent's eBPF pump goroutine keeps
	// emitting events after BaselinePromote returns; without the nil-p
	// guards in those methods the next Observe would race-deref l.p.
	l.p = nil
	return out, nil
}

// ErrInsufficientSamples is returned from Promote when the window was too short.
var ErrInsufficientSamples = &profileError{"baseline: insufficient samples to promote profile"}

type profileError struct{ msg string }

func (e *profileError) Error() string { return e.msg }

func profileID(imageRef, labelHash string) string {
	h := sha256.New
	_, _ = h().Write([]byte(imageRef))
	_, _ = h().Write([]byte{0})
	_, _ = h().Write([]byte(labelHash))
	return hex.EncodeToString(h().Sum(nil))
}

// MatchFilePath returns true if p matches any file entry (exact or glob).
func (p *Profile) MatchFilePath(query string) bool {
	if query == "" {
		return true
	}
	if _, ok := p.FilePaths[query]; ok {
		return true
	}
	for pattern := range p.FilePaths {
		if strings.ContainsAny(pattern, "*?[") {
			if matched, err := path.Match(pattern, query); err == nil && matched {
				return true
			}
		}
	}
	return false
}

// Detector scores live observations against a frozen Profile. It tracks
// Markov state per pid so cross-process transitions don't pollute each other.
type Detector struct {
	mu       sync.Mutex
	profile  *Profile
	lastCall map[int32]string // pid -> last syscall name

	// Already-reported new_* deduplication per profile lifetime.
	reportedExecs map[string]struct{}
	reportedPeers map[string]struct{}
	reportedPaths map[string]struct{}
}

// NewDetector attaches a detector to a promoted profile.
func NewDetector(p *Profile) *Detector {
	return &Detector{
		profile:       p,
		lastCall:      map[int32]string{},
		reportedExecs: map[string]struct{}{},
		reportedPeers: map[string]struct{}{},
		reportedPaths: map[string]struct{}{},
	}
}

// ObserveSyscall updates per-pid state and returns a rare_syscall /
// markov_anomaly deviation when applicable. Returns nil when nothing fires.
func (d *Detector) ObserveSyscall(pid int32, name string, meta types.ContainerMeta) []types.DeviationEvent {
	if name == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []types.DeviationEvent

	prev := d.lastCall[pid]
	d.lastCall[pid] = name

	freq := d.profile.SyscallCMS.RelativeFrequency(name)
	if freq < d.profile.RarityFreqFloor {
		// The CMS can report 0 for unseen keys — we surface that as max rarity.
		score := 1.0 - freq/d.profile.RarityFreqFloor
		if score > 1 {
			score = 1
		}
		out = append(out, types.DeviationEvent{
			DeviationID:    "",
			ProfileID:      d.profile.ID,
			Kind:           DevRareSyscall,
			DeviationScore: score,
			Evidence:       "syscall=" + name,
			Meta:           meta,
		})
	}
	if prev != "" && d.profile.Markov.Known(prev) {
		p := d.profile.Markov.Probability(prev, name)
		if p < d.profile.MarkovProbFloor {
			out = append(out, types.DeviationEvent{
				ProfileID:      d.profile.ID,
				Kind:           DevMarkovAnomaly,
				DeviationScore: 1.0 - p,
				Evidence:       prev + "->" + name,
				Meta:           meta,
			})
		}
	}
	return out
}

// CheckExec returns a new_exec deviation if binary isn't in the allow-set.
func (d *Detector) CheckExec(binary string, meta types.ContainerMeta) *types.DeviationEvent {
	if binary == "" {
		return nil
	}
	if _, ok := d.profile.ExecBinaries[binary]; ok {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, seen := d.reportedExecs[binary]; seen {
		return nil
	}
	d.reportedExecs[binary] = struct{}{}
	return &types.DeviationEvent{
		ProfileID:      d.profile.ID,
		Kind:           DevNewExec,
		DeviationScore: 1.0,
		Evidence:       "binary=" + binary,
		Meta:           meta,
	}
}

// CheckConnect returns new_connect_target when peer is unseen.
func (d *Detector) CheckConnect(peer string, meta types.ContainerMeta) *types.DeviationEvent {
	if peer == "" {
		return nil
	}
	if _, ok := d.profile.EgressPeers[peer]; ok {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, seen := d.reportedPeers[peer]; seen {
		return nil
	}
	d.reportedPeers[peer] = struct{}{}
	return &types.DeviationEvent{
		ProfileID:      d.profile.ID,
		Kind:           DevNewConnectTarget,
		DeviationScore: 1.0,
		Evidence:       "peer=" + peer,
		Meta:           meta,
	}
}

// CheckFilePath returns new_file_path when path doesn't match the allow-set.
func (d *Detector) CheckFilePath(queryPath string, meta types.ContainerMeta) *types.DeviationEvent {
	if queryPath == "" {
		return nil
	}
	if d.profile.MatchFilePath(queryPath) {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, seen := d.reportedPaths[queryPath]; seen {
		return nil
	}
	d.reportedPaths[queryPath] = struct{}{}
	return &types.DeviationEvent{
		ProfileID:      d.profile.ID,
		Kind:           DevNewFilePath,
		DeviationScore: 1.0,
		Evidence:       "path=" + queryPath,
		Meta:           meta,
	}
}

// SortedAllowSet returns the allow-sets in deterministic order, for
// export/diff of a Contract. `paths` is the full union of observed
// paths; `writePaths` is the subset observed via write-style ops — callers
// that care about direction (FromProfile → Spec.File.Read vs Write) derive
// read = paths \ writePaths.
func (p *Profile) SortedAllowSet() (execs, paths, writePaths, peers, caps, syscalls []string, uids []uint32) {
	execs = keysSorted(p.ExecBinaries)
	paths = keysSorted(p.FilePaths)
	writePaths = keysSorted(p.FilePathsWrite)
	peers = keysSorted(p.EgressPeers)
	caps = keysSorted(p.Capabilities)
	syscalls = keysSorted(p.SyscallAllowlist)
	uids = make([]uint32, 0, len(p.UIDs))
	for u := range p.UIDs {
		uids = append(uids, u)
	}
	slices.Sort(uids)
	return
}

func keysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
