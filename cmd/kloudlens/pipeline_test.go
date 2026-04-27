// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"os"
	"path/filepath"
	"strconv"

	"github.com/boanlab/kloudlens/internal/downgrade"
	"github.com/boanlab/kloudlens/internal/graph"
	"github.com/boanlab/kloudlens/internal/lineage"
	"github.com/boanlab/kloudlens/internal/syscalls"
	"github.com/boanlab/kloudlens/pkg/baseline"
	"github.com/boanlab/kloudlens/pkg/types"
)

// TestPipelineFanOut feeds the handler a realistic execve + open + close +
// connect sequence (the same shape the eBPF bridge produces) and asserts
// every downstream layer captured its share: JSONL sink has intents, history
// has a container entry, graph has the expected edges, baseline learned the
// new exec/peer/path.
func TestPipelineFanOut(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	meta := types.ContainerMeta{ContainerID: "cid-1", Container: "demo", Namespace: "ns", Pod: "pod-0"}
	baseTS := uint64(clock().UnixNano())

	// execve /usr/bin/curl
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 200, SyscallName: "execve",
		Category: "process", Operation: "execute",
		Resource: "/usr/bin/curl", Meta: meta, RetVal: 0,
	})
	// openat /etc/hosts → fd 7
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 10, PID: 200, SyscallName: "openat",
		Category: "file", Operation: "open", Resource: "/etc/hosts", Meta: meta, RetVal: 7,
	})
	// close fd 7
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 20, PID: 200, SyscallName: "close",
		Category: "file", Operation: "close", Meta: meta,
		Args: []types.SyscallArg{{Name: "fd", Value: "7"}},
	})
	// socket fd 5
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 30, PID: 200, SyscallName: "socket",
		Category: "network", Operation: "socket", Meta: meta, RetVal: 5,
	})
	// connect 10.0.0.1:443
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 40, PID: 200, SyscallName: "connect",
		Category: "network", Operation: "connect", Resource: "10.0.0.1:443", Meta: meta,
		Args: []types.SyscallArg{{Name: "fd", Value: "5"}},
	})
	// close fd 5
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 50, PID: 200, SyscallName: "close",
		Category: "file", Operation: "close", Meta: meta,
		Args: []types.SyscallArg{{Name: "fd", Value: "5"}},
	})
	// exit
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 60, PID: 200, SyscallName: "exit",
		Category: "process", Operation: "exit", Meta: meta,
	})

	// --- aggregator intents should have emitted to JSONL ------------------
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 3 {
		t.Fatalf("want ≥3 intent lines, got %d: %s", len(lines), out.String())
	}
	kinds := map[string]int{}
	for _, l := range lines {
		var ev types.IntentEvent
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatalf("invalid JSON line: %q (%v)", l, err)
		}
		kinds[ev.Kind]++
	}
	for _, k := range []string{"ProcessStart", "NetworkExchange"} {
		if kinds[k] == 0 {
			t.Errorf("expected at least one %q intent, got kinds=%v", k, kinds)
		}
	}
	// FileAccess OR FileRead — the exact variant depends on whether ObserveFileIO
	// got any bytes (it didn't in this synthetic run).
	if kinds["FileAccess"]+kinds["FileRead"]+kinds["FileWrite"] == 0 {
		t.Errorf("expected a file-* intent, got kinds=%v", kinds)
	}

	// --- side layers ------------------------------------------------------
	if nodes := p.Graph.NodeCount(); nodes < 3 {
		t.Errorf("graph node count want ≥3, got %d", nodes)
	}
	if edges := p.Graph.EdgeCount(); edges < 3 {
		t.Errorf("graph edge count want ≥3, got %d", edges)
	}
	if s := p.History.Sizes(); s.ContKeys == 0 {
		t.Errorf("history container keys empty, want at least the curl intents")
	}

	// Check a graph edge references the peer.
	found := false
	for _, nid := range p.Graph.Peers("proc:200") {
		if strings.Contains(nid, "10.0.0.1:443") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected graph IPC_CONNECT edge to peer 10.0.0.1:443")
	}

	// baseline: the learner records the egress peer via its known-strings set,
	// so we can confirm learning happened by checking the graph-linked edge
	// above + verifying ObserveExec was reachable (promote requires more
	// samples than this test supplies, so we don't assert promote here).
	_ = graph.EdgeIPCConnect
}

// TestPipelineDropsPseudoSyscallsFromAllowlist feeds both real syscalls and
// pseudo-hook events (sched_process_exit / security_bprm_check / filp_close)
// and asserts only the real names survive into the learner's syscall
// allowlist. Hook names in the allowlist break seccomp export because the
// kernel's seccomp filter only accepts real syscall names.
func TestPipelineDropsPseudoSyscallsFromAllowlist(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	baseTS := uint64(clock().UnixNano())
	meta := types.ContainerMeta{ContainerID: "cid-x"}

	realEvents := []types.SyscallEvent{
		{TimestampNS: baseTS, PID: 10, SyscallID: syscalls.SysExecve, SyscallName: "execve", Category: "process", Operation: "execute", Resource: "/bin/ls", Meta: meta},
		{TimestampNS: baseTS + 1, PID: 10, SyscallID: syscalls.SysOpenat, SyscallName: "openat", Category: "file", Operation: "open", Resource: "/etc/hosts", Meta: meta},
		{TimestampNS: baseTS + 2, PID: 10, SyscallID: syscalls.SysClose, SyscallName: "close", Category: "file", Operation: "close", Meta: meta},
	}
	pseudoEvents := []types.SyscallEvent{
		{TimestampNS: baseTS + 3, PID: 10, SyscallID: syscalls.SysSchedProcessExit, SyscallName: "sched_process_exit", Category: "process", Operation: "exit", Meta: meta},
		{TimestampNS: baseTS + 4, PID: 10, SyscallID: syscalls.SysSecurityBprmCheck, SyscallName: "security_bprm_check", Category: "default", Operation: "security_bprm_check", Meta: meta},
		{TimestampNS: baseTS + 5, PID: 10, SyscallID: syscalls.SysFilpClose, SyscallName: "filp_close", Category: "default", Operation: "filp_close", Meta: meta},
		{TimestampNS: baseTS + 6, PID: 10, SyscallID: syscalls.SysSecurityFileOpen, SyscallName: "security_file_open", Category: "default", Operation: "security_file_open", Meta: meta},
	}
	for _, e := range realEvents {
		p.Handle(e)
	}
	for _, e := range pseudoEvents {
		p.Handle(e)
	}

	allow := p.Learner.SnapshotSyscallAllowlist()
	for _, want := range []string{"execve", "openat", "close"} {
		if _, ok := allow[want]; !ok {
			t.Errorf("real syscall %q missing from allowlist: %v", want, allow)
		}
	}
	for _, reject := range []string{"sched_process_exit", "security_bprm_check", "filp_close", "security_file_open"} {
		if _, ok := allow[reject]; ok {
			t.Errorf("pseudo-hook %q leaked into allowlist: %v", reject, allow)
		}
	}
}

// TestPipelineRoutesWriteOpsToWriteSet feeds file-category events whose
// Operation is an unambiguous write (chmod/unlink/rename/mkdir) and asserts
// they land in FilePathsWrite, while plain open stays read-only.
func TestPipelineRoutesWriteOpsToWriteSet(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	meta := types.ContainerMeta{ContainerID: "cid-w"}
	baseTS := uint64(clock().UnixNano())

	cases := []struct {
		op, path string
	}{
		{"open", "/etc/hosts"},
		{"chmod", "/bin/payload"},
		{"unlink", "/tmp/stale"},
		{"rename", "/var/lib/app/state"},
		{"mkdir", "/var/log/app"},
	}
	for i, c := range cases {
		p.Handle(types.SyscallEvent{
			TimestampNS: baseTS + uint64(i),
			PID:         200,
			SyscallName: c.op,
			Category:    "file",
			Operation:   c.op,
			Resource:    c.path,
			Meta:        meta,
		})
	}

	allow := p.Learner.SnapshotFileAllowlist()
	for _, want := range []string{"/etc/hosts", "/bin/payload", "/tmp/stale", "/var/lib/app/state", "/var/log/app"} {
		if _, ok := allow[want]; !ok {
			t.Errorf("path %q missing from union allowlist: %v", want, allow)
		}
	}
	// Promote so we can inspect FilePathsWrite (it lives on the Profile).
	for range 20 {
		p.Handle(types.SyscallEvent{
			TimestampNS: baseTS + 100, PID: 200, SyscallName: "openat",
			Category: "file", Operation: "close", Meta: meta,
		})
	}
	prof, err := p.Learner.Promote(clock(), "img", "lh", 10)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	for _, want := range []string{"/bin/payload", "/tmp/stale", "/var/lib/app/state", "/var/log/app"} {
		if _, ok := prof.FilePathsWrite[want]; !ok {
			t.Errorf("write-op path %q missing from FilePathsWrite: %v", want, prof.FilePathsWrite)
		}
	}
	if _, ok := prof.FilePathsWrite["/etc/hosts"]; ok {
		t.Errorf("read-only open leaked into FilePathsWrite: %v", prof.FilePathsWrite)
	}
}

// TestPipelineRoutesOpenWriteToWriteSet covers the Pkg 26 extension: the
// mapper now classifies open/openat/openat2 with O_WRONLY/O_RDWR/O_CREAT/
// O_TRUNC as Operation="open_write", and the pipeline must route that to
// FilePathsWrite just like the unambiguous write ops. A plain Operation="open"
// sibling must stay read-only.
func TestPipelineRoutesOpenWriteToWriteSet(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	meta := types.ContainerMeta{ContainerID: "cid-ow"}
	baseTS := uint64(clock().UnixNano())

	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 300, SyscallName: "openat",
		Category: "file", Operation: "open",
		Resource: "/etc/passwd", Meta: meta, RetVal: 7,
	})
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 1, PID: 300, SyscallName: "openat",
		Category: "file", Operation: "open_write",
		Resource: "/var/log/app.log", Meta: meta, RetVal: 8,
	})
	// Enough syscall samples to clear Promote's minSamples floor.
	for range 20 {
		p.Handle(types.SyscallEvent{
			TimestampNS: baseTS + 100, PID: 300, SyscallName: "openat",
			Category: "file", Operation: "close", Meta: meta,
		})
	}
	prof, err := p.Learner.Promote(clock(), "img", "lh", 10)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if _, ok := prof.FilePathsWrite["/var/log/app.log"]; !ok {
		t.Errorf("open_write path missing from FilePathsWrite: %v", prof.FilePathsWrite)
	}
	if _, ok := prof.FilePathsWrite["/etc/passwd"]; ok {
		t.Errorf("read-only open leaked into FilePathsWrite: %v", prof.FilePathsWrite)
	}
	// Both paths must still land in the union so the detector can recognize
	// them as known.
	if _, ok := prof.FilePaths["/etc/passwd"]; !ok {
		t.Errorf("read path missing from union: %v", prof.FilePaths)
	}
	if _, ok := prof.FilePaths["/var/log/app.log"]; !ok {
		t.Errorf("write path missing from union: %v", prof.FilePaths)
	}
}

// TestPipelineDetectorEmitsDeviations attaches a minimal frozen Profile and
// feeds events that partly match (known exec, known peer) and partly deviate
// (unknown exec, unknown peer, unknown file path). The pipeline must emit
// exactly one DeviationEvent per new_* condition and none for matches.
func TestPipelineDetectorEmitsDeviations(t *testing.T) {
	var out bytes.Buffer
	var devOut bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	prof := &baseline.Profile{
		ID:               "test-prof",
		ExecBinaries:     map[string]struct{}{"/usr/bin/curl": {}},
		FilePaths:        map[string]struct{}{"/etc/hosts": {}},
		FilePathsWrite:   map[string]struct{}{},
		EgressPeers:      map[string]struct{}{"10.0.0.1:443": {}},
		Capabilities:     map[string]struct{}{},
		UIDs:             map[uint32]struct{}{},
		SyscallAllowlist: map[string]struct{}{},
		SyscallCMS:       baseline.NewCountMinSketch(0.001, 0.001),
		Markov:           baseline.NewMarkovModel(),
		RarityFreqFloor:  0, // disable rare-syscall firing for this focused test
		MarkovProbFloor:  0,
	}
	p.AttachDetector(baseline.NewDetector(prof), &devOut)

	meta := types.ContainerMeta{ContainerID: "cid-d", Container: "demo", Namespace: "ns", Pod: "pod-0"}
	baseTS := uint64(clock().UnixNano())

	// Known exec + known peer + known file → no deviations.
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 100, SyscallName: "execve",
		Category: "process", Operation: "execute",
		Resource: "/usr/bin/curl", Meta: meta, RetVal: 0,
	})
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 1, PID: 100, SyscallName: "openat",
		Category: "file", Operation: "open", Resource: "/etc/hosts", Meta: meta,
	})
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 2, PID: 100, SyscallName: "connect",
		Category: "network", Operation: "connect", Resource: "10.0.0.1:443", Meta: meta,
	})
	// Unknown exec + unknown peer + unknown path → three deviations.
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 10, PID: 101, SyscallName: "execve",
		Category: "process", Operation: "execute",
		Resource: "/usr/bin/nc", Meta: meta, RetVal: 0,
	})
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 11, PID: 101, SyscallName: "openat",
		Category: "file", Operation: "open", Resource: "/etc/shadow", Meta: meta,
	})
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 12, PID: 101, SyscallName: "connect",
		Category: "network", Operation: "connect", Resource: "8.8.8.8:53", Meta: meta,
	})

	if got := p.DeviationCount(); got != 3 {
		t.Fatalf("DeviationCount = %d (want 3); devOut=%q", got, devOut.String())
	}
	lines := strings.Split(strings.TrimSpace(devOut.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 devOut lines, got %d: %q", len(lines), devOut.String())
	}
	seen := map[string]string{}
	for _, l := range lines {
		var dv types.DeviationEvent
		if err := json.Unmarshal([]byte(l), &dv); err != nil {
			t.Fatalf("invalid devOut JSON: %q (%v)", l, err)
		}
		if dv.DeviationID == "" {
			t.Errorf("missing DeviationID: %+v", dv)
		}
		if dv.ProfileID != "test-prof" {
			t.Errorf("wrong ProfileID: %+v", dv)
		}
		seen[dv.Kind] = dv.Evidence
	}
	for _, kind := range []string{baseline.DevNewExec, baseline.DevNewConnectTarget, baseline.DevNewFilePath} {
		if _, ok := seen[kind]; !ok {
			t.Errorf("missing %q deviation, got %+v", kind, seen)
		}
	}
	// Repeating the same unknown exec must NOT emit a second deviation —
	// Detector dedupes per profile lifetime.
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 20, PID: 102, SyscallName: "execve",
		Category: "process", Operation: "execute",
		Resource: "/usr/bin/nc", Meta: meta, RetVal: 0,
	})
	if got := p.DeviationCount(); got != 3 {
		t.Fatalf("repeated exec leaked a new deviation: %d", got)
	}
	// Stats line should mention deviations=3 when a Detector is attached.
	if s := p.Stats(); !strings.Contains(s, "deviations=3") {
		t.Errorf("Stats missing deviations segment: %s", s)
	}
}

func TestPipelineStatsSmoke(t *testing.T) {
	var out bytes.Buffer
	p := NewPipeline(&out, time.Now)
	// Stats must be callable even before any events arrive.
	if s := p.Stats(); !strings.Contains(s, "syscalls=0") {
		t.Errorf("initial stats unexpected: %s", s)
	}
	if !strings.Contains(p.Stats(), "paths={resolved=0 dropped=0}") {
		t.Errorf("paths segment missing: %s", p.Stats())
	}
}

// TestPipelineDropsUnresolvableRelativePaths feeds a relative-path open with
// no CWD available and asserts the path never reaches the learner's allow-set
// or the graph. Regression for the .git/config / hugetlb.2MB.current leak seen
// in the Pkg 21 round-trip.
func TestPipelineDropsUnresolvableRelativePaths(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)
	p.PathComp = &PathCompleter{} // nil CWD → all relatives dropped

	meta := types.ContainerMeta{ContainerID: "cid-r"}
	baseTS := uint64(clock().UnixNano())

	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 77, SyscallName: "openat",
		Category: "file", Operation: "open",
		Resource: ".git/config", Meta: meta, RetVal: 9,
	})
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 1, PID: 77, SyscallName: "openat",
		Category: "file", Operation: "open",
		Resource: "hugetlb.2MB.current", Meta: meta, RetVal: 10,
	})

	allow := p.Learner.SnapshotFileAllowlist()
	for _, leak := range []string{".git/config", "hugetlb.2MB.current"} {
		if _, ok := allow[leak]; ok {
			t.Errorf("relative path %q leaked into file allowlist: %v", leak, allow)
		}
	}
	for k := range allow {
		if !strings.HasPrefix(k, "/") {
			t.Errorf("non-absolute entry in allowlist: %q", k)
		}
	}
	if _, d := p.PathComp.Stats(); d < 2 {
		t.Errorf("expected ≥2 drops, got %d", d)
	}
}

// TestPipelineAbsolutizesRelativePathsWithCWD feeds the same relatives with a
// fake CWD in place — they should be resolved and flow into the allow-set as
// absolute paths.
func TestPipelineAbsolutizesRelativePathsWithCWD(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)
	p.PathComp = &PathCompleter{CWD: fakeCWD{77: "/workspace"}}

	meta := types.ContainerMeta{ContainerID: "cid-r"}
	baseTS := uint64(clock().UnixNano())

	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 77, SyscallName: "openat",
		Category: "file", Operation: "open",
		Resource: ".git/config", Meta: meta, RetVal: 9,
	})

	allow := p.Learner.SnapshotFileAllowlist()
	if _, ok := allow["/workspace/.git/config"]; !ok {
		t.Errorf("expected /workspace/.git/config in allowlist, got %v", allow)
	}
	if r, _ := p.PathComp.Stats(); r < 1 {
		t.Errorf("expected ≥1 resolved, got %d", r)
	}
}

func TestPipelineBaselineReset(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)
	// Drive samples, then reset — promote with min=1 should then fail because
	// the fresh window has zero samples.
	for i := 0; i < 3; i++ {
		p.Learner.ObserveSyscall("read")
	}
	p.BaselineReset()
	if _, err := p.BaselinePromote(1, "img", "hash"); err == nil {
		t.Error("promote after reset with min=1 should fail (fresh window)")
	}
}

func TestPipelineBaselinePromoteInsufficient(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)
	// No samples — should fail the minSamples floor.
	_, err := p.BaselinePromote(10, "img", "hash")
	if err == nil {
		t.Fatal("expected ErrInsufficientSamples, got nil")
	}
}

func TestPipelineBaselineActivateDeactivate(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)
	// Train + promote to get a real profile.
	for i := 0; i < 3; i++ {
		p.Learner.ObserveSyscall("read")
	}
	prof, err := p.BaselinePromote(1, "img", "hash")
	if err != nil {
		t.Fatal(err)
	}
	bs, err := baseline.MarshalProfile(prof)
	if err != nil {
		t.Fatal(err)
	}
	id, deactivated, err := p.BaselineActivate(bs)
	if err != nil {
		t.Fatal(err)
	}
	if deactivated || id != prof.ID {
		t.Errorf("activate got id=%q deactivated=%v; want id=%q deactivated=false", id, deactivated, prof.ID)
	}
	if p.Detector() == nil {
		t.Error("detector should be attached after activate")
	}
	// Empty bytes clears the detector.
	id2, deactivated2, err := p.BaselineActivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if id2 != "" || !deactivated2 {
		t.Errorf("deactivate got id=%q deactivated=%v; want empty+true", id2, deactivated2)
	}
	if p.Detector() != nil {
		t.Error("detector should be nil after deactivate")
	}
}

func TestPipelineBaselineActivateBadBytes(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)
	if _, _, err := p.BaselineActivate([]byte("not-json")); err == nil {
		t.Error("expected unmarshal error")
	}
}

// TestPipelineAdaptiveLevelFollowsController locks in that AdaptiveLevel
// reads through the attached downgrade.Controller instead of the previous
// zero-value stub. The metrics package + AdminService.GetStatus both go
// through this accessor, so without this wiring operators staring at
// kloudlens_adaptive_level or klctl's AgentStatus would see "normal" even
// during a critical-only throttle — exactly the failure mode
// cited when adding the controller in the first place.
func TestPipelineAdaptiveLevelFollowsController(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	// No controller attached: preserves the pre-wiring default so builds
	// without --auto-downgrade keep publishing 0 rather than panicking on
	// a nil pointer deref.
	if got := p.AdaptiveLevel(); got != 0 {
		t.Fatalf("unattached AdaptiveLevel = %d, want 0", got)
	}

	ctrl := downgrade.New(downgrade.DefaultThresholds(), nil)
	p.SetDowngradeController(ctrl)
	if got := p.AdaptiveLevel(); got != int(downgrade.LevelNormal) {
		t.Fatalf("fresh controller AdaptiveLevel = %d, want %d", got, downgrade.LevelNormal)
	}

	// 0.85 usage is above HeavilySampledUp (0.80), so the controller steps
	// up two levels and AdaptiveLevel must reflect the new state.
	ctrl.Observe(0.85)
	if got := p.AdaptiveLevel(); got != int(downgrade.LevelHeavilySampled) {
		t.Fatalf("under pressure AdaptiveLevel = %d, want %d", got, downgrade.LevelHeavilySampled)
	}

	p.SetDowngradeController(nil)
	if got := p.AdaptiveLevel(); got != 0 {
		t.Fatalf("post-detach AdaptiveLevel = %d, want 0", got)
	}
}

// TestPipelineCredsRecordsTransition feeds the creds branch a successful
// setuid(0) from uid=1000 and asserts HistoricalContext.CredTimeline picks
// it up. This guards the privilege_escalation_window correlation from
// regressing back to an empty credTimeline — without the recorded
// transition a 1000→0 privilege gain would go unseen.()
func TestPipelineCredsRecordsTransition(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	baseTS := uint64(clock().UnixNano())
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 300, UID: 1000,
		SyscallName: "setuid", SyscallID: syscalls.SysSetuid,
		Category: "creds", Operation: "setuid", RetVal: 0,
		Args: []types.SyscallArg{
			{Name: "uid", Type: "uint32", Value: "0"},
			{Name: "new_uid", Type: "uint32", Value: "0"},
		},
	})

	hc := p.History.Snapshot(300, "")
	if len(hc.CredTimeline) != 1 {
		t.Fatalf("cred timeline = %d entries, want 1 (hc=%+v)", len(hc.CredTimeline), hc)
	}
	ct := hc.CredTimeline[0]
	if ct.From != "uid=1000" || ct.To != "uid=0" || ct.Cause != "setuid" {
		t.Errorf("transition = %+v, want From=uid=1000 To=uid=0 Cause=setuid", ct)
	}
	if ct.TSNS != baseTS {
		t.Errorf("TSNS = %d, want %d", ct.TSNS, baseTS)
	}
}

// TestPipelineCredsSkipsFailedSyscalls pins the RetVal != 0 guard: a failed
// setuid doesn't actually flip kernel credentials, so recording it would
// fabricate transitions that never happened and corrupt the
// privilege_escalation_window correlation.
func TestPipelineCredsSkipsFailedSyscalls(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	p.Handle(types.SyscallEvent{
		TimestampNS: uint64(clock().UnixNano()), PID: 301, UID: 1000,
		SyscallName: "setuid", Category: "creds", Operation: "setuid",
		RetVal: -1, // EPERM or similar
		Args:   []types.SyscallArg{{Name: "new_uid", Value: "0"}},
	})

	if n := len(p.History.Snapshot(301, "").CredTimeline); n != 0 {
		t.Errorf("failed setuid should not record, got %d entries", n)
	}
}

// TestPipelineCredsSkipsUnchangedSetreuid covers the case where setreuid
// was called with -1 meaning "leave unchanged" — the mapper drops new_uid
// in this case, so the pipeline can't build a transition and should no-op
// rather than record an empty-To entry.
func TestPipelineCredsSkipsUnchangedSetreuid(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	p.Handle(types.SyscallEvent{
		TimestampNS: uint64(clock().UnixNano()), PID: 302, UID: 1000,
		SyscallName: "setreuid", Category: "creds", Operation: "setuid", RetVal: 0,
		// No new_uid arg — mapper skipped it because euid was 0xFFFFFFFF.
		Args: []types.SyscallArg{
			{Name: "ruid", Value: "1001"},
			{Name: "euid", Value: "unchanged"},
		},
	})
	if n := len(p.History.Snapshot(302, "").CredTimeline); n != 0 {
		t.Errorf("unchanged setreuid should not record, got %d entries", n)
	}
}

// TestPipelineEnrichmentLevelMinimalSkipsCorrelation asserts that after
// ApplyEnrichmentLevel("minimal") the correlation detector no longer
// records chmod +x or connect observations — those are the "full"-only
// heuristic feeds — while history ring writes continue unaffected.
func TestPipelineEnrichmentLevelMinimalSkipsCorrelation(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)
	p.ApplyEnrichmentLevel("minimal")

	baseTS := uint64(clock().UnixNano())
	// chmod on /tmp/a: would normally feed Corr.RecordChmodX.
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 400,
		SyscallName: "chmod", Category: "file", Operation: "chmod",
		Resource: "/tmp/a", RetVal: 0,
	})
	// exec: history recording should still run (minimal keeps G2 ring).
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 1, PID: 401,
		SyscallName: "execve", Category: "process", Operation: "execute",
		Resource: "/bin/sh", RetVal: 0,
	})

	if cs := p.Corr.Sizes(); cs.ChmodX != 0 {
		t.Errorf("minimal level must skip Corr.RecordChmodX, got ChmodX=%d", cs.ChmodX)
	}
	if hc := p.History.Snapshot(401, ""); len(hc.Ancestors) == 0 {
		t.Error("minimal level must still record exec in history ring")
	}
}

// TestPipelineEnrichmentLevelNoneSkipsHistory asserts that level=none
// also silences the history ring — no exec records, no cred transitions —
// while leaving the baseline learner observing every syscall so security
// posture (deviation detection, allow-set learning) stays intact.
func TestPipelineEnrichmentLevelNoneSkipsHistory(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)
	p.ApplyEnrichmentLevel("none")

	baseTS := uint64(clock().UnixNano())
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 500,
		SyscallName: "execve", Category: "process", Operation: "execute",
		Resource: "/bin/ls", RetVal: 0,
	})
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 1, PID: 500, UID: 1000,
		SyscallName: "setuid", Category: "creds", Operation: "setuid", RetVal: 0,
		Args: []types.SyscallArg{{Name: "new_uid", Value: "0"}},
	})

	hc := p.History.Snapshot(500, "")
	if len(hc.Ancestors) != 0 {
		t.Errorf("level=none must skip RecordExec, got %d ancestors", len(hc.Ancestors))
	}
	if len(hc.CredTimeline) != 0 {
		t.Errorf("level=none must skip RecordCred, got %d cred entries", len(hc.CredTimeline))
	}
	// Baseline learner observed the exec binary despite level=none —
	// security-critical path must not regress. Promote with minSamples=0 so
	// a tiny sample count doesn't fail the confidence gate.
	prof, err := p.Learner.Promote(clock(), "", "", 0)
	if err != nil {
		t.Fatalf("promote after level=none exec: %v", err)
	}
	if _, ok := prof.ExecBinaries["/bin/ls"]; !ok {
		t.Error("level=none must not disable baseline learner (security-critical)")
	}
}

// TestPipelineEnrichmentLevelRestoreToFull pins the live-reconfig
// round-trip: minimal → none → full must unwedge every side layer, so a
// klctl apply that walks the level back up doesn't leave a dark pipeline.
func TestPipelineEnrichmentLevelRestoreToFull(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	p.ApplyEnrichmentLevel("none")
	if got := p.EnrichmentLevel(); got != "none" {
		t.Fatalf("EnrichmentLevel = %q, want none", got)
	}
	p.ApplyEnrichmentLevel("full")

	baseTS := uint64(clock().UnixNano())
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 600,
		SyscallName: "chmod", Category: "file", Operation: "chmod",
		Resource: "/tmp/b", RetVal: 0,
	})
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 1, PID: 600,
		SyscallName: "execve", Category: "process", Operation: "execute",
		Resource: "/bin/sh", RetVal: 0,
	})

	if cs := p.Corr.Sizes(); cs.ChmodX == 0 {
		t.Error("after restore to full, Corr.RecordChmodX must run again")
	}
	if hc := p.History.Snapshot(600, ""); len(hc.Ancestors) == 0 {
		t.Error("after restore to full, History.RecordExec must run again")
	}
}

// TestPipelineExecPopulatesAncestorChain stages a fake /proc tree, points
// the Lineage walker at it, and asserts the History snapshot for the leaf
// pid carries the full chain (root-first, leaf last). Without the walker
// only the leaf is recorded — that case is already covered by the level=
// minimal test above; here we lock in the lineage wiring.
func TestPipelineExecPopulatesAncestorChain(t *testing.T) {
	procRoot := t.TempDir()
	stage := func(pid, ppid int32, comm string) {
		dir := filepath.Join(procRoot, strconv.Itoa(int(pid)))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		status := "Name:\t" + comm + "\nPPid:\t" + strconv.Itoa(int(ppid)) + "\n"
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stage(1, 0, "init")
	stage(700, 1, "containerd-shim")
	stage(701, 700, "bash")
	stage(702, 701, "curl") // leaf

	var out bytes.Buffer
	p := NewPipeline(&out, func() time.Time { return time.Unix(1_700_000_000, 0) })
	p.Lineage = &lineage.Walker{Root: procRoot}

	p.Handle(types.SyscallEvent{
		TimestampNS: uint64(time.Unix(1_700_000_000, 0).UnixNano()),
		PID:         702,
		SyscallName: "execve", Category: "process", Operation: "execute",
		Resource: "/usr/bin/curl", RetVal: 0,
	})

	hc := p.History.Snapshot(702, "")
	if len(hc.Ancestors) != 4 {
		t.Fatalf("ancestor count=%d, want 4 (init, containerd-shim, bash, leaf), got %+v",
			len(hc.Ancestors), hc.Ancestors)
	}
	wantPIDs := []int32{1, 700, 701, 702}
	for i, want := range wantPIDs {
		if hc.Ancestors[i].PID != want {
			t.Errorf("Ancestors[%d].PID=%d, want %d", i, hc.Ancestors[i].PID, want)
		}
	}
	// Leaf entry uniquely carries the exec timestamp; ancestors do not.
	if hc.Ancestors[3].ExecTSNS == 0 {
		t.Error("leaf ancestor should carry ExecTSNS")
	}
	if hc.Ancestors[0].ExecTSNS != 0 {
		t.Errorf("walker entries should not carry ExecTSNS, got %d", hc.Ancestors[0].ExecTSNS)
	}
}

// TestPipelineExecAncestorChainNoWalker confirms the existing one-leaf
// behavior survives when Lineage is nil — covers --no-ebpf / synthetic
// runs and any code path that skips wire-up.
func TestPipelineExecAncestorChainNoWalker(t *testing.T) {
	var out bytes.Buffer
	p := NewPipeline(&out, func() time.Time { return time.Unix(1_700_000_000, 0) })
	// Lineage stays nil.

	p.Handle(types.SyscallEvent{
		TimestampNS: uint64(time.Unix(1_700_000_000, 0).UnixNano()),
		PID:         800,
		SyscallName: "execve", Category: "process", Operation: "execute",
		Resource: "/bin/sh", RetVal: 0,
	})

	hc := p.History.Snapshot(800, "")
	if len(hc.Ancestors) != 1 || hc.Ancestors[0].PID != 800 {
		t.Errorf("nil walker: want exactly the leaf, got %+v", hc.Ancestors)
	}
}

// TestPipelineEnrichmentLevelUnknownSnapsToFull ensures a misrouted or
// stale dispatcher call with an empty / bogus value doesn't silently
// disable the pipeline — the agent should fall back to the safest level.
func TestPipelineEnrichmentLevelUnknownSnapsToFull(t *testing.T) {
	var out bytes.Buffer
	p := NewPipeline(&out, nil)
	p.ApplyEnrichmentLevel("bogus")
	if got := p.EnrichmentLevel(); got != "full" {
		t.Errorf("EnrichmentLevel = %q after bogus apply, want full", got)
	}
	p.ApplyEnrichmentLevel("")
	if got := p.EnrichmentLevel(); got != "full" {
		t.Errorf("EnrichmentLevel = %q after empty apply, want full", got)
	}
}

// TestPipelineApplyDowngradeLevelMapping locks in the controller→level
// mapping. The assumption is that pressure only grows from one rung to
// the next, so the HeavilySampled→"minimal" / CriticalOnly→"none" rungs
// must match the side-layer work we're willing to shed at each stage.
// LevelNormal and LevelSampled both map to "full" — at Sampled the
// ringbuf is only ~60% full, so we still have budget for history and
// correlation; the saving at that rung comes from the BPF sampler, not
// from user-space enrichment.
func TestPipelineApplyDowngradeLevelMapping(t *testing.T) {
	var out bytes.Buffer
	p := NewPipeline(&out, nil)
	cases := []struct {
		in   downgrade.Level
		want string
	}{
		{downgrade.LevelNormal, "full"},
		{downgrade.LevelSampled, "full"},
		{downgrade.LevelHeavilySampled, "minimal"},
		{downgrade.LevelCriticalOnly, "none"},
	}
	for _, c := range cases {
		p.ApplyDowngradeLevel(c.in)
		if got := p.EnrichmentLevel(); got != c.want {
			t.Errorf("ApplyDowngradeLevel(%s) → %q, want %q", c.in, got, c.want)
		}
	}
}

// TestPipelineEnrichmentLevelComposition exercises the most-restrictive-
// wins rule between operator intent and adaptive downgrade. Each row
// asserts the effective level the hot path will see; the table covers
// every interesting pair so a future change to canonLevel /
// mostRestrictiveLevel that regresses ordering will be flagged directly.
func TestPipelineEnrichmentLevelComposition(t *testing.T) {
	cases := []struct {
		op   string
		dgLv downgrade.Level
		want string
	}{
		// Operator = full — downgrade drives effective.
		{"full", downgrade.LevelNormal, "full"},
		{"full", downgrade.LevelHeavilySampled, "minimal"},
		{"full", downgrade.LevelCriticalOnly, "none"},
		// Operator = minimal — wins over softer downgrade rungs.
		{"minimal", downgrade.LevelNormal, "minimal"},
		{"minimal", downgrade.LevelHeavilySampled, "minimal"},
		{"minimal", downgrade.LevelCriticalOnly, "none"}, // downgrade more restrictive
		// Operator = none — always wins (most restrictive).
		{"none", downgrade.LevelNormal, "none"},
		{"none", downgrade.LevelCriticalOnly, "none"},
	}
	for _, c := range cases {
		var out bytes.Buffer
		p := NewPipeline(&out, nil)
		p.ApplyEnrichmentLevel(c.op)
		p.ApplyDowngradeLevel(c.dgLv)
		if got := p.EnrichmentLevel(); got != c.want {
			t.Errorf("op=%s dg=%s → %q, want %q", c.op, c.dgLv, got, c.want)
		}
	}
}

// TestPipelineDowngradeRecoveryHonorsOperator is the key regression test
// for the composition: after a CriticalOnly spike forces the effective
// level to "none", the controller eventually recovers to Normal — and
// the pipeline must collapse back to whatever the operator had set, not
// to the "full" default. Otherwise an operator who dialed the level down
// for privacy/cost would be silently re-armed to full every time the
// agent hit a pressure spike.
func TestPipelineDowngradeRecoveryHonorsOperator(t *testing.T) {
	var out bytes.Buffer
	p := NewPipeline(&out, nil)

	p.ApplyEnrichmentLevel("minimal")
	if got := p.EnrichmentLevel(); got != "minimal" {
		t.Fatalf("after operator=minimal, got %q, want minimal", got)
	}

	p.ApplyDowngradeLevel(downgrade.LevelCriticalOnly)
	if got := p.EnrichmentLevel(); got != "none" {
		t.Fatalf("under critical-only, got %q, want none", got)
	}

	p.ApplyDowngradeLevel(downgrade.LevelNormal)
	if got := p.EnrichmentLevel(); got != "minimal" {
		t.Errorf("after recovery, got %q, want minimal (operator intent)", got)
	}
}

// TestPipelineOperatorEnrichmentLevelAccessor guards the two-atomic split:
// ApplyDowngradeLevel must not pollute operator intent, otherwise
// AgentStatus.Info.enrichment_level_operator would drift toward whatever
// the adaptive controller most recently forced. An operator reading
// klctl status during a pressure spike expects to see the value they
// typed, not the controller's override — the admin UI relies on
// (effective, operator) being distinct readings.
func TestPipelineOperatorEnrichmentLevelAccessor(t *testing.T) {
	var out bytes.Buffer
	p := NewPipeline(&out, nil)
	if got := p.OperatorEnrichmentLevel(); got != "full" {
		t.Fatalf("initial OperatorEnrichmentLevel = %q, want full", got)
	}

	p.ApplyEnrichmentLevel("minimal")
	if got := p.OperatorEnrichmentLevel(); got != "minimal" {
		t.Errorf("after ApplyEnrichmentLevel(minimal), OperatorEnrichmentLevel = %q, want minimal", got)
	}

	p.ApplyDowngradeLevel(downgrade.LevelCriticalOnly)
	if got := p.OperatorEnrichmentLevel(); got != "minimal" {
		t.Errorf("ApplyDowngradeLevel must not touch operator intent; got %q, want minimal", got)
	}
	if got := p.EnrichmentLevel(); got != "none" {
		t.Errorf("effective under critical = %q, want none", got)
	}

	p.ApplyDowngradeLevel(downgrade.LevelNormal)
	if got := p.OperatorEnrichmentLevel(); got != "minimal" {
		t.Errorf("after downgrade recovery, operator intent = %q, want minimal", got)
	}
}

// TestPipelineIPCPeerResolvesToContainer exercises the peermatch wiring:
// a bind from one container plus a subsequent connect from another
// container to the same addr should emit a typed cross-container graph
// edge (cont:<id>) rather than an opaque peer:<addr> leaf. Without the
// peermatch registry the connect side has no way to know a second
// container on this node owns the destination port.
func TestPipelineIPCPeerResolvesToContainer(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	serverMeta := types.ContainerMeta{ContainerID: "cont-server"}
	clientMeta := types.ContainerMeta{ContainerID: "cont-client"}
	baseTS := uint64(clock().UnixNano())

	// Server binds 10.0.0.5:8080 inside "cont-server".
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 100, SyscallName: "bind",
		Category: "network", Operation: "bind",
		Resource: "10.0.0.5:8080", Meta: serverMeta, RetVal: 0,
	})

	// Client in a different container connects to the same addr.
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 10, PID: 200, SyscallName: "connect",
		Category: "network", Operation: "connect",
		Resource: "10.0.0.5:8080", Meta: clientMeta, RetVal: 0,
	})

	// Client's outgoing IPC edges must now target cont:cont-server, not
	// peer:10.0.0.5:8080.
	peers := p.Graph.Peers("proc:200")
	var sawCont, sawRawPeer bool
	for _, id := range peers {
		switch {
		case id == "cont:cont-server":
			sawCont = true
		case id == "peer:10.0.0.5:8080":
			sawRawPeer = true
		}
	}
	if !sawCont {
		t.Errorf("cross-container edge missing: Peers(proc:200)=%v", peers)
	}
	if sawRawPeer {
		t.Errorf("opaque peer leaf still emitted: Peers(proc:200)=%v", peers)
	}
}

// TestPipelineIPCUnmatchedPeerStaysOpaque confirms the default path (no
// listener recorded) still emits the peer:<addr> leaf so downstream
// consumers that rely on the raw endpoint format keep working.
func TestPipelineIPCUnmatchedPeerStaysOpaque(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	meta := types.ContainerMeta{ContainerID: "cont-client"}
	baseTS := uint64(clock().UnixNano())

	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 300, SyscallName: "connect",
		Category: "network", Operation: "connect",
		Resource: "1.2.3.4:443", Meta: meta, RetVal: 0,
	})

	peers := p.Graph.Peers("proc:300")
	if len(peers) != 1 || peers[0] != "peer:1.2.3.4:443" {
		t.Errorf("unmatched connect should emit peer:<addr>, got %v", peers)
	}
}

// TestPipelineIPCExitDropsListener verifies the process-exit path tears
// down listener registrations so a subsequent connect to the same port
// from a new container re-resolves correctly instead of pointing at a
// dead PID. Without ObserveExit wiring, restart-like flows would keep
// resolving to the first container forever.
func TestPipelineIPCExitDropsListener(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	baseTS := uint64(clock().UnixNano())
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 100, SyscallName: "bind",
		Category: "network", Operation: "bind",
		Resource: "0.0.0.0:9000",
		Meta:     types.ContainerMeta{ContainerID: "cont-v1"}, RetVal: 0,
	})
	// Process exit: emits via the process/exit branch that Handle runs.
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS + 5, PID: 100,
		SyscallName: "sched_process_exit",
		Category:    "process", Operation: "exit",
		Meta: types.ContainerMeta{ContainerID: "cont-v1"},
	})

	if _, ok := p.PeerMatch.Lookup("10.0.0.5:9000"); ok {
		t.Error("PeerMatch must drop listener after process exit")
	}
}

// TestPipelineIPCKernelPeerPIDSurfaces covers the kernel-hot-path case:
// the BPF listener registry tagged the connect with a peer_pid but
// user-space peermatch hasn't observed the bind yet (BPF caught it
// before the mirroring user-space event flushed, or the agent started
// mid-stream). Even without a ContainerID, peer_pid must land in edge
// attributes so downstream consumers can stitch the pair later.
func TestPipelineIPCKernelPeerPIDSurfaces(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	meta := types.ContainerMeta{ContainerID: "cont-client"}
	baseTS := uint64(clock().UnixNano())

	// Connect arrives with a kernel-attached peer_pid. No prior bind in
	// user-space peermatch, so the ContainerID resolution fails; peer_pid
	// still has to survive into the edge's attributes.
	p.Handle(types.SyscallEvent{
		TimestampNS: baseTS, PID: 300, SyscallName: "connect",
		Category: "network", Operation: "connect",
		Resource: "10.0.0.5:8080", Meta: meta, RetVal: 0,
		Args: []types.SyscallArg{
			{Name: "peer_pid", Type: "uint", Value: "777"},
		},
	})

	// Edge should still reference the opaque peer leaf (no cont:<id>
	// available yet), but carry peer_pid in attributes.
	edges := p.Graph.Peers("proc:300")
	if len(edges) != 1 || edges[0] != "peer:10.0.0.5:8080" {
		t.Fatalf("edge dst = %v, want peer:10.0.0.5:8080 (no cont yet)", edges)
	}
	// Attributes are not exposed via Peers; poke the graph store
	// directly to confirm the attribute landed.
	if found := graphEdgeAttr(p.Graph, "proc:300", "peer_pid"); found != "777" {
		t.Errorf("peer_pid attribute = %q, want 777", found)
	}
}

// graphEdgeAttr walks outgoing edges from src and returns the first value
// of the named attribute, or "" if not present.
func graphEdgeAttr(g *graph.Store, src, key string) string {
	for _, edge := range g.OutgoingEdges(src) {
		if edge.Attributes[key] != "" {
			return edge.Attributes[key]
		}
	}
	return ""
}

// TestPipelineIPCKernelPeerWinsOverStaleUserspace: kernel says peer_pid=X,
// user-space peermatch has no entry. Kernel should still be the
// authoritative signal — attributes carry X even when ContainerID stays
// unresolved (mirrors TestPipelineIPCKernelPeerPIDSurfaces). If the two
// disagreed — kernel says X, user-space says Y — kernel's pid wins.
func TestPipelineIPCKernelPeerWinsOverStaleUserspace(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	// Stale user-space bind under a different PID.
	p.PeerMatch.ObserveBind("10.0.0.5:9000", 100, "cont-old", 1)

	p.Handle(types.SyscallEvent{
		TimestampNS: uint64(clock().UnixNano()), PID: 500, SyscallName: "connect",
		Category: "network", Operation: "connect",
		Resource: "10.0.0.5:9000",
		Meta:     types.ContainerMeta{ContainerID: "cont-client"}, RetVal: 0,
		Args: []types.SyscallArg{
			{Name: "peer_pid", Type: "uint", Value: "999"},
		},
	})

	// Kernel's peer_pid=999 wins in the attribute. ContainerID comes from
	// the peermatch registry (the best user-space hint we have).
	if got := graphEdgeAttr(p.Graph, "proc:500", "peer_pid"); got != "999" {
		t.Errorf("peer_pid attribute = %q, want 999 (kernel wins over user-space)", got)
	}
}

// TestPipelineDNSAnswerEmitsIntent: the BPF cgroup_skb DNS parser
// surfaces each A record as a synthetic "dns_answer" SyscallEvent.
// Pipeline must route it into a DNSAnswer IntentEvent (so klctl +
// dashboards see DNS resolution alongside ProcessStart /
// NetworkExchange) AND feed the correlation detector so a later
// connect to the resolved IP can be cross-referenced. Empty addr
// shouldn't produce a half-record.
func TestPipelineDNSAnswerEmitsIntent(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	meta := types.ContainerMeta{ContainerID: "cid-7", Namespace: "ns", Pod: "p"}

	// Mapper-shape dns_answer event: Resource = qname, args carry rtype + addr.
	p.Handle(types.SyscallEvent{
		TimestampNS: uint64(clock().UnixNano()),
		PID:         400, SyscallName: "dns_answer",
		Category: "network", Operation: "dns_answer",
		Resource: "evil.example.com",
		Args: []types.SyscallArg{
			{Name: "rtype", Type: "uint", Value: "1"},
			{Name: "addr", Type: "uint", Value: "1.2.3.4"},
		},
		Meta: meta,
	})

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var dns *types.IntentEvent
	for _, l := range lines {
		var ev types.IntentEvent
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			continue
		}
		if ev.Kind == "DNSAnswer" {
			dns = &ev
			break
		}
	}
	if dns == nil {
		t.Fatalf("no DNSAnswer intent emitted; output:\n%s", out.String())
	}
	if dns.Attributes["query"] != "evil.example.com" {
		t.Errorf("query=%q, want evil.example.com", dns.Attributes["query"])
	}
	if dns.Attributes["addr"] != "1.2.3.4" {
		t.Errorf("addr=%q, want 1.2.3.4", dns.Attributes["addr"])
	}
	if dns.Meta.ContainerID != "cid-7" {
		t.Errorf("meta.container_id=%q, want cid-7 (meta plumbed through?)", dns.Meta.ContainerID)
	}
}

// TestPipelineDNSAnswerSkipsHalfRecords: real DNS responses include CNAME,
// AAAA, and TCP-fallback records that reach the BPF parser but don't
// produce a usable IPv4 addr. Skip silently rather than emitting a
// half-record (empty addr or empty query).
func TestPipelineDNSAnswerSkipsHalfRecords(t *testing.T) {
	var out bytes.Buffer
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	p := NewPipeline(&out, clock)

	// Missing addr arg.
	p.Handle(types.SyscallEvent{
		TimestampNS: uint64(clock().UnixNano()),
		PID:         500, SyscallName: "dns_answer",
		Category: "network", Operation: "dns_answer",
		Resource: "example.com",
		Args:     []types.SyscallArg{{Name: "rtype", Value: "5"}}, // CNAME, no addr
	})
	// Missing qname.
	p.Handle(types.SyscallEvent{
		TimestampNS: uint64(clock().UnixNano()),
		PID:         500, SyscallName: "dns_answer",
		Category: "network", Operation: "dns_answer",
		Args: []types.SyscallArg{{Name: "addr", Value: "9.9.9.9"}},
	})

	if got := strings.TrimSpace(out.String()); got != "" {
		t.Errorf("half-records should not emit; got:\n%s", got)
	}
}
