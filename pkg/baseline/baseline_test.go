// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

func TestCMSNoFalseNegatives(t *testing.T) {
	c := NewCountMinSketchDims(256, 4)
	inputs := []string{"a", "b", "c", "a", "a", "d", "b"}
	for _, s := range inputs {
		c.Add(s)
	}
	if e := c.Estimate("a"); e < 3 {
		t.Fatalf("CMS under-counted a: %d", e)
	}
	if e := c.Estimate("b"); e < 2 {
		t.Fatalf("CMS under-counted b: %d", e)
	}
	// "missing" must be either 0 or a small collision artifact, never
	// greater than total (can't overcount).
	if e := c.Estimate("missing"); uint64(e) > c.Total() {
		t.Fatalf("missing over-estimate: %d", e)
	}
	if c.Total() != uint64(len(inputs)) {
		t.Fatalf("total: %d", c.Total())
	}
}

func TestCMSRelativeFrequency(t *testing.T) {
	c := NewCountMinSketchDims(1024, 5)
	for range 100 {
		c.Add("common")
	}
	for range 2 {
		c.Add("rare")
	}
	f := c.RelativeFrequency("rare")
	if f > 0.1 {
		t.Fatalf("rare freq too high: %v", f)
	}
	if c.RelativeFrequency("unseen") != 0 {
		t.Fatalf("unseen should be 0")
	}
}

func TestMarkovBasicProbability(t *testing.T) {
	m := NewMarkovModel()
	m.Observe("openat", "read")
	m.Observe("openat", "read")
	m.Observe("openat", "close")
	m.Observe("read", "close")

	if p := m.Probability("openat", "read"); p < 0.66 || p > 0.67 {
		t.Fatalf("P(read|openat)=%v want ≈0.666", p)
	}
	if p := m.Probability("openat", "close"); p < 0.33 || p > 0.34 {
		t.Fatalf("P(close|openat)=%v want ≈0.333", p)
	}
	if p := m.Probability("never", "seen"); p != 0 {
		t.Fatalf("unseen: %v", p)
	}
	if !m.Known("openat") || m.Known("never") {
		t.Fatal("Known wrong")
	}
}

func TestLearnerPromoteInsufficient(t *testing.T) {
	l := NewLearner(LearnerConfig{}, time.Unix(0, 0))
	l.ObserveSyscall("openat")
	if _, err := l.Promote(time.Unix(10, 0), "image:latest", "lh", 10); err != ErrInsufficientSamples {
		t.Fatalf("expected ErrInsufficientSamples, got %v", err)
	}
}

// TestLearnerObserveAfterPromoteIsSafe regresses a nil-deref where the eBPF
// pump goroutine kept calling Observe* on a Learner whose internal Profile
// had already been frozen by BaselinePromote. Every observation method must
// silently drop post-promote — the only crash signal would be an unrecovered
// runtime.Error inside one of them.
func TestLearnerObserveAfterPromoteIsSafe(t *testing.T) {
	l := NewLearner(LearnerConfig{}, time.Unix(0, 0))
	for range 20 {
		l.ObserveSyscall("openat")
	}
	if _, err := l.Promote(time.Unix(60, 0), "img", "lh", 10); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	// After Promote, l.p is nil. Each of these used to panic with a
	// nil-pointer deref on the field access (e.g. l.p.FilePaths).
	l.ObserveSyscall("read")
	l.ObserveExec("/bin/sh")
	l.ObserveFilePath("/etc/hosts")
	l.ObserveFilePathWrite("/var/log/app.log")
	l.ObserveEgressPeer("10.0.0.1:443")
	l.ObserveCapability("CAP_NET_ADMIN")
	l.ObserveUID(1000)

	// Snapshots return the empty set — they must not panic either.
	if got := l.SnapshotSyscallAllowlist(); len(got) != 0 {
		t.Errorf("SnapshotSyscallAllowlist post-promote = %v, want empty", got)
	}
	if got := l.SnapshotFileAllowlist(); len(got) != 0 {
		t.Errorf("SnapshotFileAllowlist post-promote = %v, want empty", got)
	}
}

func TestLearnerPromoteProducesDeterministicID(t *testing.T) {
	l1 := NewLearner(LearnerConfig{}, time.Unix(0, 0))
	l2 := NewLearner(LearnerConfig{}, time.Unix(0, 0))
	for range 20 {
		l1.ObserveSyscall("openat")
		l2.ObserveSyscall("openat")
	}
	p1, err := l1.Promote(time.Unix(60, 0), "ghcr.io/app:v1", "lh-abc", 5)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := l2.Promote(time.Unix(60, 0), "ghcr.io/app:v1", "lh-abc", 5)
	if err != nil {
		t.Fatal(err)
	}
	if p1.ID != p2.ID || p1.ID == "" {
		t.Fatalf("IDs not deterministic: %q vs %q", p1.ID, p2.ID)
	}
}

func TestDetectorNewExec(t *testing.T) {
	l := NewLearner(LearnerConfig{}, time.Unix(0, 0))
	l.ObserveExec("/usr/bin/python3")
	for range 50 {
		l.ObserveSyscall("openat")
	}
	p, err := l.Promote(time.Unix(60, 0), "img", "lh", 10)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDetector(p)
	if ev := d.CheckExec("/usr/bin/python3", types.ContainerMeta{}); ev != nil {
		t.Fatalf("expected no deviation for known exec, got %+v", ev)
	}
	ev := d.CheckExec("/bin/sh", types.ContainerMeta{})
	if ev == nil || ev.Kind != DevNewExec {
		t.Fatalf("expected new_exec, got %+v", ev)
	}
	// Dedup: reporting the same binary twice returns nil the second time.
	if ev := d.CheckExec("/bin/sh", types.ContainerMeta{}); ev != nil {
		t.Fatalf("dedup broken: %+v", ev)
	}
}

func TestDetectorNewConnectTarget(t *testing.T) {
	l := NewLearner(LearnerConfig{}, time.Unix(0, 0))
	l.ObserveEgressPeer("10.0.0.5:5432")
	for range 50 {
		l.ObserveSyscall("openat")
	}
	p, _ := l.Promote(time.Unix(60, 0), "img", "lh", 10)
	d := NewDetector(p)

	if d.CheckConnect("10.0.0.5:5432", types.ContainerMeta{}) != nil {
		t.Fatal("known peer flagged")
	}
	ev := d.CheckConnect("1.2.3.4:443", types.ContainerMeta{})
	if ev == nil || ev.Kind != DevNewConnectTarget {
		t.Fatalf("expected new_connect_target, got %+v", ev)
	}
}

func TestDetectorFilePathGlob(t *testing.T) {
	l := NewLearner(LearnerConfig{}, time.Unix(0, 0))
	l.ObserveFilePath("/etc/passwd")
	l.ObserveFilePath("/var/log/app/*.log")
	for range 50 {
		l.ObserveSyscall("openat")
	}
	p, _ := l.Promote(time.Unix(60, 0), "img", "lh", 10)
	d := NewDetector(p)

	if d.CheckFilePath("/etc/passwd", types.ContainerMeta{}) != nil {
		t.Fatal("exact path false positive")
	}
	if d.CheckFilePath("/var/log/app/access.log", types.ContainerMeta{}) != nil {
		t.Fatal("glob didn't match")
	}
	ev := d.CheckFilePath("/tmp/payload.sh", types.ContainerMeta{})
	if ev == nil || ev.Kind != DevNewFilePath {
		t.Fatalf("expected new_file_path, got %+v", ev)
	}
}

func TestDetectorRareSyscallAndMarkov(t *testing.T) {
	l := NewLearner(LearnerConfig{
		RarityFreqFloor: 0.05, // anything below 5% is rare
		MarkovProbFloor: 0.10,
		CMSEps:          0.01,
		CMSDelta:        0.01,
	}, time.Unix(0, 0))

	// Workload is openat → read → close repeated many times.
	for range 200 {
		l.ObserveSyscall("openat")
		l.ObserveSyscall("read")
		l.ObserveSyscall("close")
	}
	p, err := l.Promote(time.Unix(60, 0), "img", "lh", 100)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDetector(p)
	// Warm up detector state: seed previous call with "openat" so the Markov
	// check has a known from-state.
	d.ObserveSyscall(1, "openat", types.ContainerMeta{})

	// ptrace was never observed — should fire rare_syscall AND markov_anomaly.
	devs := d.ObserveSyscall(1, "ptrace", types.ContainerMeta{})
	sawRare, sawMarkov := false, false
	for _, dv := range devs {
		if dv.Kind == DevRareSyscall {
			sawRare = true
		}
		if dv.Kind == DevMarkovAnomaly {
			sawMarkov = true
		}
	}
	if !sawRare {
		t.Fatalf("expected rare_syscall, got %+v", devs)
	}
	if !sawMarkov {
		t.Fatalf("expected markov_anomaly (openat→ptrace unseen), got %+v", devs)
	}

	// read following openat is normal — no deviations.
	d2 := NewDetector(p)
	d2.ObserveSyscall(2, "openat", types.ContainerMeta{})
	devs = d2.ObserveSyscall(2, "read", types.ContainerMeta{})
	for _, dv := range devs {
		if dv.Kind == DevMarkovAnomaly {
			t.Fatalf("normal transition flagged: %+v", dv)
		}
	}
}

func TestProfileSortedAllowSetDeterministic(t *testing.T) {
	l := NewLearner(LearnerConfig{}, time.Unix(0, 0))
	l.ObserveExec("/b")
	l.ObserveExec("/a")
	l.ObserveFilePath("/z")
	l.ObserveFilePath("/y")
	l.ObserveEgressPeer("2.2.2.2:80")
	l.ObserveEgressPeer("1.1.1.1:80")
	l.ObserveCapability("NET_BIND_SERVICE")
	l.ObserveUID(1000)
	l.ObserveUID(0)
	for range 20 {
		l.ObserveSyscall("openat")
	}
	p, _ := l.Promote(time.Unix(60, 0), "img", "lh", 10)

	execs, paths, _, peers, caps, syscalls, uids := p.SortedAllowSet()
	if execs[0] != "/a" || execs[1] != "/b" {
		t.Fatalf("execs not sorted: %v", execs)
	}
	if paths[0] != "/y" {
		t.Fatalf("paths not sorted: %v", paths)
	}
	if peers[0] != "1.1.1.1:80" {
		t.Fatalf("peers not sorted: %v", peers)
	}
	if len(caps) != 1 {
		t.Fatalf("caps: %v", caps)
	}
	if uids[0] != 0 || uids[1] != 1000 {
		t.Fatalf("uids: %v", uids)
	}
	if len(syscalls) == 0 || syscalls[0] != "openat" {
		t.Fatalf("syscalls missing/unsorted: %v", syscalls)
	}
}

func TestObserveFilePathWriteTagsWriteDirection(t *testing.T) {
	l := NewLearner(LearnerConfig{}, time.Unix(0, 0))
	l.ObserveFilePath("/etc/hosts")        // read-only
	l.ObserveFilePathWrite("/var/log/app") // write-direction
	l.ObserveFilePath("/var/log/app")      // same path also seen as read
	for range 20 {
		l.ObserveSyscall("openat")
	}
	p, err := l.Promote(time.Unix(60, 0), "img", "lh", 10)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	// Both paths appear in the detection union.
	if _, ok := p.FilePaths["/etc/hosts"]; !ok {
		t.Errorf("read path missing from union: %+v", p.FilePaths)
	}
	if _, ok := p.FilePaths["/var/log/app"]; !ok {
		t.Errorf("write path missing from union: %+v", p.FilePaths)
	}
	// Only the write-observed path is tagged.
	if _, ok := p.FilePathsWrite["/var/log/app"]; !ok {
		t.Errorf("write tag missing: %+v", p.FilePathsWrite)
	}
	if _, ok := p.FilePathsWrite["/etc/hosts"]; ok {
		t.Errorf("read-only path must not be tagged write: %+v", p.FilePathsWrite)
	}
	// SortedAllowSet exposes both.
	_, paths, writePaths, _, _, _, _ := p.SortedAllowSet()
	if len(paths) != 2 {
		t.Errorf("union size: got %d, want 2", len(paths))
	}
	if len(writePaths) != 1 || writePaths[0] != "/var/log/app" {
		t.Errorf("writePaths: got %v, want [/var/log/app]", writePaths)
	}
}
