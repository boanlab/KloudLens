// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"testing"
	"time"
)

func TestProfileJSONRoundTrip(t *testing.T) {
	start := time.Date(2026, 4, 19, 10, 0, 0, 0, time.UTC)
	l := NewLearner(LearnerConfig{RarityFreqFloor: 0.02, MarkovProbFloor: 0.1}, start)
	l.ObserveExec("/usr/bin/curl")
	l.ObserveExec("/bin/sh")
	l.ObserveFilePath("/etc/hosts")
	l.ObserveFilePath("/var/log/*.log")
	l.ObserveEgressPeer("10.0.0.1:443")
	l.ObserveCapability("CAP_NET_BIND_SERVICE")
	l.ObserveUID(1000)
	// push sample count above the min so Promote succeeds
	for range 20 {
		l.ObserveSyscall("execve")
	}

	p, err := l.Promote(start.Add(10*time.Second), "demo:latest", "hash123", 10)
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}

	data, err := MarshalProfile(p)
	if err != nil {
		t.Fatalf("MarshalProfile: %v", err)
	}
	got, err := UnmarshalProfile(data)
	if err != nil {
		t.Fatalf("UnmarshalProfile: %v", err)
	}
	if got.ID != p.ID {
		t.Errorf("ID mismatch: %q vs %q", got.ID, p.ID)
	}
	if got.SampleCount != p.SampleCount {
		t.Errorf("SampleCount: %d vs %d", got.SampleCount, p.SampleCount)
	}
	for _, bin := range []string{"/usr/bin/curl", "/bin/sh"} {
		if _, ok := got.ExecBinaries[bin]; !ok {
			t.Errorf("exec %q missing after round-trip", bin)
		}
	}
	if _, ok := got.FilePaths["/var/log/*.log"]; !ok {
		t.Errorf("glob path missing after round-trip")
	}
	if !got.MatchFilePath("/var/log/kern.log") {
		t.Errorf("glob matcher broken after round-trip")
	}
	if _, ok := got.EgressPeers["10.0.0.1:443"]; !ok {
		t.Errorf("egress missing")
	}
	if _, ok := got.UIDs[1000]; !ok {
		t.Errorf("uid missing")
	}
	// CMS/Markov should be non-nil stubs so Detector doesn't panic.
	if got.SyscallCMS == nil || got.Markov == nil {
		t.Errorf("CMS/Markov should be non-nil placeholders after decode")
	}
}

func TestProfileJSONPreservesWriteTags(t *testing.T) {
	start := time.Date(2026, 4, 19, 10, 0, 0, 0, time.UTC)
	l := NewLearner(LearnerConfig{}, start)
	l.ObserveFilePath("/etc/hosts")
	l.ObserveFilePathWrite("/var/log/app.log")
	for range 20 {
		l.ObserveSyscall("openat")
	}
	p, err := l.Promote(start.Add(10*time.Second), "img", "lh", 10)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	data, err := MarshalProfile(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := UnmarshalProfile(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := got.FilePathsWrite["/var/log/app.log"]; !ok {
		t.Errorf("write tag lost: %+v", got.FilePathsWrite)
	}
	if _, ok := got.FilePathsWrite["/etc/hosts"]; ok {
		t.Errorf("read-only path leaked into write tag: %+v", got.FilePathsWrite)
	}
}

func TestProfileJSONLegacyV2DecodesAsReadOnly(t *testing.T) {
	// A schemaVersion=2 profile (no filePathsWrite field) must decode as if
	// every path were read-only — matching v2's semantics where filePaths
	// is the only path list.
	legacy := []byte(`{
 "schemaVersion": 2,
 "id": "legacy",
 "learnStart": "2026-04-19T10:00:00Z",
 "learnEnd": "2026-04-19T10:00:10Z",
 "sampleCount": 20,
 "confidence": 1.0,
 "filePaths": ["/etc/hosts", "/var/log/app.log"]
}`)
	p, err := UnmarshalProfile(legacy)
	if err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if len(p.FilePaths) != 2 {
		t.Errorf("legacy file paths lost: %+v", p.FilePaths)
	}
	if len(p.FilePathsWrite) != 0 {
		t.Errorf("legacy should have empty write tags, got %+v", p.FilePathsWrite)
	}
}
