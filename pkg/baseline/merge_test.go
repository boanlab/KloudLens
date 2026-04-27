// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package baseline

import (
	"testing"
	"time"
)

func buildLearner(start time.Time) *Learner {
	return NewLearner(LearnerConfig{
		CMSEps:          0.01,
		CMSDelta:        0.01,
		RarityFreqFloor: 0.02,
		MarkovProbFloor: 0.10,
	}, start)
}

func TestMergeProfilesSingleReturnsClone(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	l := buildLearner(start)
	l.ObserveExec("/bin/sh")
	l.ObserveSyscall("read")
	p, err := l.Promote(start.Add(time.Second), "img", "h", 0)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeProfiles([]*Profile{p})
	if err != nil {
		t.Fatal(err)
	}
	if merged == p {
		t.Fatal("MergeProfiles of 1 should return a clone, not the same pointer")
	}
	// Mutating clone must not affect original.
	merged.ExecBinaries["/bin/bash"] = struct{}{}
	if _, ok := p.ExecBinaries["/bin/bash"]; ok {
		t.Error("clone is shallow — mutation leaked back")
	}
}

func TestMergeProfilesEmptyReturnsError(t *testing.T) {
	if _, err := MergeProfiles(nil); err != ErrNoProfiles {
		t.Errorf("got %v, want ErrNoProfiles", err)
	}
}

func TestMergeProfilesUnionsAllowSetsAndSumsSamples(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	l1 := buildLearner(start)
	l1.ObserveExec("/bin/sh")
	l1.ObserveFilePath("/etc/hosts")
	l1.ObserveEgressPeer("10.0.0.1:443")
	l1.ObserveCapability("CAP_NET_BIND_SERVICE")
	l1.ObserveUID(1000)
	for i := 0; i < 10; i++ {
		l1.ObserveSyscall("read")
	}
	p1, err := l1.Promote(start.Add(10*time.Second), "img-a", "hash-a", 1)
	if err != nil {
		t.Fatal(err)
	}

	l2 := buildLearner(start.Add(5 * time.Second))
	l2.ObserveExec("/bin/bash")
	l2.ObserveFilePath("/etc/hosts") // overlap
	l2.ObserveEgressPeer("10.0.0.2:80")
	l2.ObserveCapability("CAP_CHOWN")
	l2.ObserveUID(1001)
	for i := 0; i < 20; i++ {
		l2.ObserveSyscall("write")
	}
	p2, err := l2.Promote(start.Add(30*time.Second), "img-b", "hash-b", 1)
	if err != nil {
		t.Fatal(err)
	}

	merged, err := MergeProfiles([]*Profile{p1, p2})
	if err != nil {
		t.Fatal(err)
	}

	// Allow-sets are unions.
	for _, want := range []string{"/bin/sh", "/bin/bash"} {
		if _, ok := merged.ExecBinaries[want]; !ok {
			t.Errorf("merged ExecBinaries missing %q", want)
		}
	}
	if _, ok := merged.FilePaths["/etc/hosts"]; !ok {
		t.Error("merged FilePaths missing /etc/hosts")
	}
	for _, want := range []string{"10.0.0.1:443", "10.0.0.2:80"} {
		if _, ok := merged.EgressPeers[want]; !ok {
			t.Errorf("merged EgressPeers missing %q", want)
		}
	}
	for _, want := range []string{"CAP_NET_BIND_SERVICE", "CAP_CHOWN"} {
		if _, ok := merged.Capabilities[want]; !ok {
			t.Errorf("merged Capabilities missing %q", want)
		}
	}
	for _, want := range []uint32{1000, 1001} {
		if _, ok := merged.UIDs[want]; !ok {
			t.Errorf("merged UIDs missing %d", want)
		}
	}
	for _, want := range []string{"read", "write"} {
		if _, ok := merged.SyscallAllowlist[want]; !ok {
			t.Errorf("merged SyscallAllowlist missing %q", want)
		}
	}

	// SampleCount is summed exactly.
	if got, want := merged.SampleCount, p1.SampleCount+p2.SampleCount; got != want {
		t.Errorf("SampleCount = %d, want %d", got, want)
	}
	// CMS.Total is summed too (structural: we merged via CMS.Merge).
	if got, want := merged.SyscallCMS.Total(), p1.SyscallCMS.Total()+p2.SyscallCMS.Total(); got != want {
		t.Errorf("CMS.Total = %d, want %d", got, want)
	}
	// CMS estimates are at least the local counts.
	if est := merged.SyscallCMS.Estimate("read"); est < 10 {
		t.Errorf("merged CMS read estimate = %d, want ≥10", est)
	}
	// Learn window widens.
	if !merged.LearnStart.Equal(start) {
		t.Errorf("LearnStart = %v, want %v", merged.LearnStart, start)
	}
	if !merged.LearnEnd.Equal(start.Add(30 * time.Second)) {
		t.Errorf("LearnEnd = %v, want %v", merged.LearnEnd, start.Add(30*time.Second))
	}
	// Merged ID is the cluster prefix and deterministic under reorder.
	if len(merged.ID) == 0 || merged.ID[:7] != "merged:" {
		t.Errorf("merged ID = %q, want merged: prefix", merged.ID)
	}
	reordered, err := MergeProfiles([]*Profile{p2, p1})
	if err != nil {
		t.Fatal(err)
	}
	if reordered.ID != merged.ID {
		t.Errorf("merged ID not order-invariant: %q vs %q", merged.ID, reordered.ID)
	}
}

func TestMergeProfilesRejectsThresholdMismatch(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	l1 := NewLearner(LearnerConfig{
		CMSEps: 0.01, CMSDelta: 0.01, RarityFreqFloor: 0.02, MarkovProbFloor: 0.10,
	}, start)
	l1.ObserveSyscall("read")
	p1, err := l1.Promote(start.Add(time.Second), "a", "h", 0)
	if err != nil {
		t.Fatal(err)
	}
	l2 := NewLearner(LearnerConfig{
		CMSEps: 0.01, CMSDelta: 0.01, RarityFreqFloor: 0.05, MarkovProbFloor: 0.10, // different rarity floor
	}, start)
	l2.ObserveSyscall("read")
	p2, err := l2.Promote(start.Add(time.Second), "b", "h", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeProfiles([]*Profile{p1, p2}); err != ErrThresholdMismatch {
		t.Errorf("got %v, want ErrThresholdMismatch", err)
	}
}

func TestMergeProfilesConfidenceIsSampleWeighted(t *testing.T) {
	// Two synthetic profiles so we can control Confidence directly.
	p1 := &Profile{
		SampleCount: 100, Confidence: 1.0,
		ExecBinaries: map[string]struct{}{}, FilePaths: map[string]struct{}{},
		FilePathsWrite: map[string]struct{}{}, EgressPeers: map[string]struct{}{},
		Capabilities: map[string]struct{}{}, UIDs: map[uint32]struct{}{},
		SyscallAllowlist: map[string]struct{}{},
		SyscallCMS:       NewCountMinSketch(0.01, 0.01),
		Markov:           NewMarkovModel(),
		RarityFreqFloor:  0.02, MarkovProbFloor: 0.10,
	}
	p2 := &Profile{
		SampleCount: 10, Confidence: 0.1,
		ExecBinaries: map[string]struct{}{}, FilePaths: map[string]struct{}{},
		FilePathsWrite: map[string]struct{}{}, EgressPeers: map[string]struct{}{},
		Capabilities: map[string]struct{}{}, UIDs: map[uint32]struct{}{},
		SyscallAllowlist: map[string]struct{}{},
		SyscallCMS:       NewCountMinSketch(0.01, 0.01),
		Markov:           NewMarkovModel(),
		RarityFreqFloor:  0.02, MarkovProbFloor: 0.10,
	}
	merged, err := MergeProfiles([]*Profile{p1, p2})
	if err != nil {
		t.Fatal(err)
	}
	// Weighted mean = (1.0*100 + 0.1*10) / 110 ≈ 0.919
	want := (1.0*100 + 0.1*10) / 110.0
	if got := merged.Confidence; got < want-1e-9 || got > want+1e-9 {
		t.Errorf("Confidence = %v, want %v", got, want)
	}
}

func TestDriftSetDifferences(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	// Local: knows only /bin/sh + read. Cluster: has bash, ls, write.
	l := buildLearner(start)
	l.ObserveExec("/bin/sh")
	l.ObserveSyscall("read")
	local, err := l.Promote(start.Add(time.Second), "a", "h", 0)
	if err != nil {
		t.Fatal(err)
	}
	l2 := buildLearner(start)
	l2.ObserveExec("/bin/sh")
	l2.ObserveExec("/bin/bash")
	l2.ObserveExec("/bin/ls")
	l2.ObserveSyscall("read")
	l2.ObserveSyscall("write")
	other, err := l2.Promote(start.Add(time.Second), "b", "h", 0)
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := MergeProfiles([]*Profile{local, other})
	if err != nil {
		t.Fatal(err)
	}
	d := Drift(local, cluster, 0)
	if len(d.OnlyInLocal.ExecBinaries) != 0 {
		t.Errorf("OnlyInLocal.ExecBinaries = %v, want empty (local's set is a subset)",
			d.OnlyInLocal.ExecBinaries)
	}
	// /bin/bash and /bin/ls are in cluster but not local.
	missing := d.OnlyInCluster.ExecBinaries
	if len(missing) != 2 || missing[0] != "/bin/bash" || missing[1] != "/bin/ls" {
		t.Errorf("OnlyInCluster.ExecBinaries = %v, want [/bin/bash /bin/ls]", missing)
	}
	// Syscall "write" missing from local allowlist.
	if len(d.OnlyInCluster.SyscallAllowlist) != 1 || d.OnlyInCluster.SyscallAllowlist[0] != "write" {
		t.Errorf("OnlyInCluster.SyscallAllowlist = %v, want [write]", d.OnlyInCluster.SyscallAllowlist)
	}
}

func TestDriftSyscallFreqDeltaRespectsTolerance(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	// Local heavily reads; other heavily writes. Cluster is a mix.
	l := buildLearner(start)
	for i := 0; i < 100; i++ {
		l.ObserveSyscall("read")
	}
	for i := 0; i < 2; i++ {
		l.ObserveSyscall("write")
	}
	local, err := l.Promote(start.Add(time.Second), "a", "h", 0)
	if err != nil {
		t.Fatal(err)
	}
	o := buildLearner(start)
	for i := 0; i < 2; i++ {
		o.ObserveSyscall("read")
	}
	for i := 0; i < 100; i++ {
		o.ObserveSyscall("write")
	}
	other, err := o.Promote(start.Add(time.Second), "b", "h", 0)
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := MergeProfiles([]*Profile{local, other})
	if err != nil {
		t.Fatal(err)
	}
	// Tolerance 0 reports every non-zero delta.
	d0 := Drift(local, cluster, 0)
	if len(d0.SyscallFreqDelta) != 2 {
		t.Errorf("freq delta count (tol=0) = %d, want 2", len(d0.SyscallFreqDelta))
	}
	// Tolerance 0.9 is larger than any realistic delta → map empty/nil.
	d9 := Drift(local, cluster, 0.9)
	if len(d9.SyscallFreqDelta) != 0 {
		t.Errorf("freq delta count (tol=0.9) = %d, want 0", len(d9.SyscallFreqDelta))
	}
	// Local reads more than cluster → read delta positive.
	if d0.SyscallFreqDelta["read"] <= 0 {
		t.Errorf("read delta = %v, want >0", d0.SyscallFreqDelta["read"])
	}
	// Local writes less than cluster → write delta negative.
	if d0.SyscallFreqDelta["write"] >= 0 {
		t.Errorf("write delta = %v, want <0", d0.SyscallFreqDelta["write"])
	}
}

func TestCMSMergeRejectsMismatchedDims(t *testing.T) {
	a := NewCountMinSketchDims(100, 4)
	b := NewCountMinSketchDims(200, 4)
	if err := a.Merge(b); err == nil {
		t.Error("expected dim mismatch error")
	}
}

func TestMarkovMergeSumsCounts(t *testing.T) {
	a := NewMarkovModel()
	b := NewMarkovModel()
	a.Observe("read", "write")
	a.Observe("read", "write")
	b.Observe("read", "write")
	b.Observe("read", "close")
	a.Merge(b)
	// a should now have read: write=3, close=1.
	if a.Probability("read", "write") < 0.74 || a.Probability("read", "write") > 0.76 {
		t.Errorf("P(write|read) = %v, want ~0.75", a.Probability("read", "write"))
	}
	if a.Probability("read", "close") < 0.24 || a.Probability("read", "close") > 0.26 {
		t.Errorf("P(close|read) = %v, want ~0.25", a.Probability("read", "close"))
	}
}
