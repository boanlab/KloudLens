// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"slices"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/boanlab/kloudlens/pkg/baseline"
	"github.com/boanlab/kloudlens/pkg/types"
)

func trainedProfile(t *testing.T) *baseline.Profile {
	t.Helper()
	l := baseline.NewLearner(baseline.LearnerConfig{}, time.Unix(0, 0))
	l.ObserveExec("/usr/bin/python3")
	l.ObserveFilePath("/etc/passwd")
	l.ObserveFilePath("/var/log/app/*.log")
	l.ObserveEgressPeer("10.0.0.5:5432")
	l.ObserveCapability("NET_BIND_SERVICE")
	l.ObserveUID(1000)
	for range 200 {
		l.ObserveSyscall("openat")
	}
	p, err := l.Promote(time.Unix(60, 0), "ghcr.io/x/app:v1", "lh", 10)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	return p
}

func TestFromProfileRejectsLowConfidence(t *testing.T) {
	l := baseline.NewLearner(baseline.LearnerConfig{}, time.Unix(0, 0))
	l.ObserveSyscall("openat")
	p, err := l.Promote(time.Unix(1, 0), "img", "lh", 1)
	if err != nil {
		t.Fatal(err)
	}
	// Confidence is sampleCount / (minSampleCount*10) = 1/10 = 0.1.
	if _, err := FromProfile(p, 0.5); err != ErrInsufficientConfidence {
		t.Fatalf("expected ErrInsufficientConfidence, got %v", err)
	}
}

func TestFromProfileBuildsContract(t *testing.T) {
	p := trainedProfile(t)
	c, err := FromProfile(p, 0)
	if err != nil {
		t.Fatalf("from profile: %v", err)
	}
	if c.APIVersion != APIVersion || c.Kind != Kind {
		t.Fatalf("header: %+v", c)
	}
	if c.Metadata.ContractID == "" || c.Metadata.DerivedFrom.ProfileID != c.Metadata.ContractID {
		t.Fatalf("ID mismatch: %+v", c.Metadata)
	}
	if len(c.Spec.Process.Exec) != 1 || c.Spec.Process.Exec[0].Binary != "/usr/bin/python3" {
		t.Fatalf("exec: %+v", c.Spec.Process.Exec)
	}
	// File list: exact "/etc/passwd" is Path, glob is PathGlob.
	sawExact, sawGlob := false, false
	for _, r := range c.Spec.File.Read {
		if r.Path == "/etc/passwd" {
			sawExact = true
		}
		if r.PathGlob == "/var/log/app/*.log" {
			sawGlob = true
		}
	}
	if !sawExact || !sawGlob {
		t.Fatalf("file rules: %+v", c.Spec.File.Read)
	}
}

func TestFromProfileFansOutReadAndWritePaths(t *testing.T) {
	// A path observed via a write-style op must land in Spec.File.Write(); a
	// read-only path must land in Spec.File.Read(); nothing duplicates across
	// the two lists. This closes Pkg 10's read-only fallback.
	l := baseline.NewLearner(baseline.LearnerConfig{}, time.Unix(0, 0))
	l.ObserveFilePath("/etc/hosts")
	l.ObserveFilePathWrite("/var/log/app.log")
	l.ObserveFilePathWrite("/tmp/state") // write-only — shouldn't appear in Read
	for range 20 {
		l.ObserveSyscall("openat")
	}
	p, err := l.Promote(time.Unix(60, 0), "img", "lh", 10)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	c, err := FromProfile(p, 0)
	if err != nil {
		t.Fatalf("from profile: %v", err)
	}

	readPaths := map[string]bool{}
	for _, r := range c.Spec.File.Read {
		key := r.Path
		if key == "" {
			key = r.PathGlob
		}
		readPaths[key] = true
	}
	writePaths := map[string]bool{}
	for _, r := range c.Spec.File.Write {
		key := r.Path
		if key == "" {
			key = r.PathGlob
		}
		writePaths[key] = true
	}

	if !readPaths["/etc/hosts"] {
		t.Errorf("/etc/hosts missing from Read: %+v", c.Spec.File.Read)
	}
	if !writePaths["/var/log/app.log"] || !writePaths["/tmp/state"] {
		t.Errorf("write paths missing from Write: %+v", c.Spec.File.Write)
	}
	// Write-tagged paths must not duplicate into Read.
	for _, p := range []string{"/var/log/app.log", "/tmp/state"} {
		if readPaths[p] {
			t.Errorf("write-tagged %q leaked into Read: %+v", p, c.Spec.File.Read)
		}
	}
	// AllowsFileWrite works end-to-end.
	if !c.AllowsFileWrite("/tmp/state") {
		t.Errorf("AllowsFileWrite should permit /tmp/state")
	}
	if c.AllowsFileWrite("/etc/hosts") {
		t.Errorf("AllowsFileWrite should deny read-only /etc/hosts")
	}
}

func TestContractYAMLDeterministic(t *testing.T) {
	p := trainedProfile(t)
	a, _ := FromProfile(p, 0)
	b, _ := FromProfile(p, 0)
	// Intentionally inject entries in reverse order in `a` to ensure Sort
	// normalizes.
	a.Spec.Process.Exec = append([]ExecRule{{Binary: "/z/rev"}}, a.Spec.Process.Exec...)
	b.Spec.Process.Exec = append(b.Spec.Process.Exec, ExecRule{Binary: "/z/rev"})
	a.Sort()
	b.Sort()

	ya, err := yaml.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	yb, err := yaml.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ya) != string(yb) {
		t.Fatalf("non-deterministic yaml:\n=== a ===\n%s\n=== b ===\n%s", ya, yb)
	}
}

func TestContractAllowsQueries(t *testing.T) {
	p := trainedProfile(t)
	c, _ := FromProfile(p, 0)
	if !c.AllowsExec("/usr/bin/python3") {
		t.Fatal("AllowsExec exact")
	}
	if c.AllowsExec("/bin/sh") {
		t.Fatal("AllowsExec should deny")
	}
	if !c.AllowsFileRead("/etc/passwd") {
		t.Fatal("AllowsFileRead exact")
	}
	if !c.AllowsFileRead("/var/log/app/access.log") {
		t.Fatal("AllowsFileRead glob")
	}
	if c.AllowsFileRead("/etc/shadow") {
		t.Fatal("AllowsFileRead should deny")
	}
	if !c.AllowsEgress("10.0.0.5:5432") {
		t.Fatal("AllowsEgress exact")
	}
}

func TestGapUnusedAndObservedButDenied(t *testing.T) {
	observed := &Contract{
		Spec: Spec{
			Process:      ProcessSpec{Exec: []ExecRule{{Binary: "/bin/curl"}, {Binary: "/bin/cat"}}},
			Network:      NetworkSpec{Egress: []EgressRule{{Peer: "1.2.3.4:443"}}},
			File:         FileSpec{Read: []FileRule{{Path: "/etc/passwd"}}},
			Capabilities: []string{"NET_ADMIN"},
		},
	}
	policy := &Contract{
		Spec: Spec{
			Process:      ProcessSpec{Exec: []ExecRule{{Binary: "/bin/curl"}, {Binary: "/bin/rarely-used"}}},
			Network:      NetworkSpec{Egress: []EgressRule{{Peer: "10.0.0.5:80"}}},
			File:         FileSpec{Read: []FileRule{{PathGlob: "/var/log/*"}}},
			Capabilities: []string{"SYS_PTRACE"},
		},
	}

	r := Gap(observed, policy)

	// observed_but_denied: /bin/cat, /etc/passwd, 1.2.3.4:443, NET_ADMIN()
	obSubjects := findingSubjects(r.ObservedButDenied)
	for _, want := range []string{"/bin/cat", "/etc/passwd", "1.2.3.4:443", "NET_ADMIN"} {
		if !containsStr(obSubjects, want) {
			t.Fatalf("missing observed_but_denied %q: %v", want, obSubjects)
		}
	}
	// unused_allowance: /bin/rarely-used, /var/log/*, 10.0.0.5:80, SYS_PTRACE()
	unSubjects := findingSubjects(r.UnusedAllowance)
	for _, want := range []string{"/bin/rarely-used", "/var/log/*", "10.0.0.5:80", "SYS_PTRACE"} {
		if !containsStr(unSubjects, want) {
			t.Fatalf("missing unused_allowance %q: %v", want, unSubjects)
		}
	}

	// /bin/curl is in both → no finding either way.
	for _, f := range r.ObservedButDenied {
		if f.Subject == "/bin/curl" {
			t.Fatalf("shared item shouldn't be denied: %+v", f)
		}
	}
	for _, f := range r.UnusedAllowance {
		if f.Subject == "/bin/curl" {
			t.Fatalf("shared item shouldn't be unused: %+v", f)
		}
	}

	// Drift score in (0, 1) — sets diverge but overlap on /bin/curl.
	if r.DriftScore <= 0 || r.DriftScore >= 1 {
		t.Fatalf("drift score out of expected range: %v", r.DriftScore)
	}
	// Coverage: 1/4 observed items are permitted (/bin/curl).
	if r.CoveragePercent < 20 || r.CoveragePercent > 30 {
		t.Fatalf("coverage: %v (expected ~25%%)", r.CoveragePercent)
	}
}

func TestGapPolicyGlobCoversObservedLiterals(t *testing.T) {
	observed := &Contract{
		Spec: Spec{File: FileSpec{Read: []FileRule{{Path: "/var/log/app/a.log"}, {Path: "/var/log/app/b.log"}}}},
	}
	policy := &Contract{
		Spec: Spec{File: FileSpec{Read: []FileRule{{PathGlob: "/var/log/app/*.log"}}}},
	}
	r := Gap(observed, policy)
	if len(r.ObservedButDenied) != 0 {
		t.Fatalf("policy glob should cover literals: %+v", r.ObservedButDenied)
	}
	if len(r.UnusedAllowance) != 0 {
		t.Fatalf("policy glob should not be unused: %+v", r.UnusedAllowance)
	}
}

func TestGapIncludesSyscallsCategory(t *testing.T) {
	// Syscalls participate in both findings directions and in drift/coverage.
	observed := &Contract{
		Spec: Spec{Syscalls: []string{"execve", "openat", "read"}},
	}
	policy := &Contract{
		Spec: Spec{Syscalls: []string{"openat", "write"}},
	}
	r := Gap(observed, policy)

	denied := findingSubjects(r.ObservedButDenied)
	for _, want := range []string{"execve", "read"} {
		if !containsStr(denied, want) {
			t.Errorf("missing syscall %q in observed_but_denied: %v", want, denied)
		}
	}
	unused := findingSubjects(r.UnusedAllowance)
	if !containsStr(unused, "write") {
		t.Errorf("missing syscall %q in unused_allowance: %v", "write", unused)
	}
	// Every syscall finding should carry category=syscalls.
	for _, f := range r.ObservedButDenied {
		if f.Category != "syscalls" {
			continue
		}
		if f.Subject == "" {
			t.Errorf("syscall finding missing subject: %+v", f)
		}
	}
	if r.TotalObserved != 3 {
		t.Errorf("TotalObserved: got %d, want 3", r.TotalObserved)
	}
	// 1 of 3 observed syscalls permitted (openat) → ~33% coverage.
	if r.CoveragePercent < 30 || r.CoveragePercent > 36 {
		t.Errorf("coverage: got %.1f, want ~33%%", r.CoveragePercent)
	}
	if r.DriftScore <= 0 {
		t.Errorf("drift should be nonzero, got %.3f", r.DriftScore)
	}
}

func TestGapWithSyscallsOnlyScope(t *testing.T) {
	// Simulate a seccomp-style policy that expresses only syscalls: the
	// observed Contract has file/exec/network activity that the policy can't
	// possibly allow. With Syscalls-only scope, none of those other
	// categories should generate findings or affect drift/coverage.
	observed := &Contract{
		Spec: Spec{
			Process:  ProcessSpec{Exec: []ExecRule{{Binary: "/bin/sh"}}},
			File:     FileSpec{Read: []FileRule{{Path: "/etc/hosts"}}},
			Network:  NetworkSpec{Egress: []EgressRule{{Peer: "1.2.3.4:80"}}},
			Syscalls: []string{"execve", "openat"},
		},
	}
	policy := &Contract{
		Spec: Spec{Syscalls: []string{"execve", "openat", "read"}},
	}

	full := Gap(observed, policy)
	// Full-scope: exec/file/net are all "denied" because policy has none.
	if len(full.ObservedButDenied) < 3 {
		t.Fatalf("full-scope should flag exec/file/net: %+v", full.ObservedButDenied)
	}
	if full.CoveragePercent > 60 {
		t.Fatalf("full-scope coverage should be low, got %.1f", full.CoveragePercent)
	}

	scoped := GapWith(observed, policy, GapOptions{
		Categories: GapCategories{Syscalls: true},
	})
	// Scoped: observed syscalls fully covered, nothing else compared.
	for _, f := range scoped.ObservedButDenied {
		if f.Category != "syscalls" {
			t.Errorf("scoped report leaked non-syscall finding: %+v", f)
		}
	}
	if len(scoped.ObservedButDenied) != 0 {
		t.Errorf("scoped syscalls-only should have no denials (observed ⊂ policy): %+v", scoped.ObservedButDenied)
	}
	if scoped.CoveragePercent != 100 {
		t.Errorf("scoped coverage: got %.1f, want 100", scoped.CoveragePercent)
	}
	// "read" is in policy but not observed → one unused_allowance entry.
	unused := findingSubjects(scoped.UnusedAllowance)
	if !containsStr(unused, "read") {
		t.Errorf("scoped unused missing 'read': %v", unused)
	}
	for _, f := range scoped.UnusedAllowance {
		if f.Category != "syscalls" {
			t.Errorf("scoped unused leaked non-syscall finding: %+v", f)
		}
	}
}

func TestGapWithEmptyCategoriesProducesEmptyReport(t *testing.T) {
	observed := &Contract{
		Spec: Spec{
			Process:  ProcessSpec{Exec: []ExecRule{{Binary: "/bin/sh"}}},
			Syscalls: []string{"execve"},
		},
	}
	policy := &Contract{Spec: Spec{Syscalls: []string{"read"}}}
	r := GapWith(observed, policy, GapOptions{Categories: GapCategories{}})
	if len(r.ObservedButDenied) != 0 || len(r.UnusedAllowance) != 0 {
		t.Fatalf("zero-scope should produce no findings: %+v", r)
	}
	if r.TotalObserved != 0 || r.DriftScore != 0 {
		t.Errorf("zero-scope drift/total should be 0: %+v", r)
	}
}

func TestReplayDecidesAllowDeny(t *testing.T) {
	c := &Contract{
		Spec: Spec{
			Process: ProcessSpec{Exec: []ExecRule{{Binary: "/usr/bin/python3"}}},
			File:    FileSpec{Read: []FileRule{{PathGlob: "/var/log/*"}}},
			Network: NetworkSpec{Egress: []EgressRule{{Peer: "10.0.0.5:5432"}}},
		},
	}
	events := []types.IntentEvent{
		{IntentID: "i1", Kind: "Exec", Attributes: map[string]string{"binary": "/usr/bin/python3"}},
		{IntentID: "i2", Kind: "Exec", Attributes: map[string]string{"binary": "/bin/sh"}},
		{IntentID: "i3", Kind: "FileRead", Attributes: map[string]string{"path": "/var/log/app.log"}},
		{IntentID: "i4", Kind: "FileRead", Attributes: map[string]string{"path": "/etc/shadow"}},
		{IntentID: "i5", Kind: "NetworkExchange", Attributes: map[string]string{"peer": "10.0.0.5:5432"}},
		{IntentID: "i6", Kind: "NetworkExchange", Attributes: map[string]string{"peer": "1.2.3.4:443"}},
		{IntentID: "i7", Kind: "FileWrite", Attributes: map[string]string{"path": "/tmp/x"}},
	}
	rs := Replay(c, events, 10)
	if rs.Total != 7 || rs.Denied != 4 || rs.Allowed != 3 {
		t.Fatalf("replay: %+v", rs)
	}
	deniedIDs := map[string]bool{}
	for _, s := range rs.Samples {
		deniedIDs[s.IntentID] = true
	}
	for _, id := range []string{"i2", "i4", "i6", "i7"} {
		if !deniedIDs[id] {
			t.Fatalf("expected %s denied, samples=%+v", id, rs.Samples)
		}
	}
}

func TestReplayIgnoresOutOfScope(t *testing.T) {
	c := &Contract{Spec: Spec{Process: ProcessSpec{Exec: []ExecRule{{Binary: "/x"}}}}}
	ev := types.IntentEvent{IntentID: "z", Kind: "MountShare", Attributes: map[string]string{}}
	if d := Decide(c, ev); !d.Allow {
		t.Fatalf("out-of-scope should allow: %+v", d)
	}
}

func findingSubjects(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Subject)
	}
	return out
}

func containsStr(ss []string, s string) bool {
	return slices.Contains(ss, s)
}
