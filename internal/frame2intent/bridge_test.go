// SPDX-License-Identifier: Apache-2.0

package frame2intent

import (
	"context"
	"sync"
	"testing"

	"github.com/boanlab/kloudlens/internal/bpf2frame"
	"github.com/boanlab/kloudlens/internal/intent"
	"github.com/boanlab/kloudlens/internal/syscalls"
	"github.com/boanlab/kloudlens/pkg/types"
)

type collectEmitter struct {
	mu sync.Mutex
	ev []types.IntentEvent
}

func (c *collectEmitter) emit(e types.IntentEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ev = append(c.ev, e)
}

func (c *collectEmitter) byKind(kind string) []types.IntentEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []types.IntentEvent
	for _, e := range c.ev {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func newBridgeTest() (*Bridge, *collectEmitter, *intent.Aggregator) {
	ce := &collectEmitter{}
	agg := intent.NewAggregator(intent.Config{}, ce.emit)
	return NewBridge(agg, nil), ce, agg
}

func TestBridgeExecEmitsProcessStart(t *testing.T) {
	b, ce, _ := newBridgeTest()
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysExecve, PID: 100, HostPID: 100, RetVal: 0, Timestamp: 1000},
		[]any{"/bin/sh", []string{"sh", "-c", "id"}, "/bin/sh"},
	))
	if got := ce.byKind("ProcessStart"); len(got) != 1 {
		t.Fatalf("want 1 ProcessStart, got %d (all=%d)", len(got), len(ce.ev))
	}
	if got := ce.byKind("ProcessStart")[0].Attributes["binary"]; got != "/bin/sh" {
		t.Fatalf("binary attribute: %q", got)
	}
}

func TestBridgeFileOpenClose(t *testing.T) {
	b, ce, _ := newBridgeTest()
	// open(O_RDONLY) returns fd=7 — Pkg 30 layout: dirfd first.
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysOpenat, PID: 200, RetVal: 7, Timestamp: 2000},
		[]any{int32(AtFDCWD), "/etc/passwd", int32(0), uint32(0), "/bin/cat"},
	))
	// close(7) — mapper records fd arg
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysClose, PID: 200, RetVal: 0, Timestamp: 2100},
		[]any{int32(7), "/bin/cat"},
	))
	// Pkg 27: the bridge propagates the open-flags direction hint to the
	// aggregator, so an O_RDONLY open→close pair resolves to FileRead even
	// without byte counters (previously collapsed to FileAccess).
	got := ce.byKind("FileRead")
	if len(got) != 1 {
		t.Fatalf("want 1 FileRead, got kinds: %v", kindList(ce.ev))
	}
	if got[0].Attributes["path"] != "/etc/passwd" {
		t.Fatalf("path attribute: %+v", got[0].Attributes)
	}
}

// TestBridgeFileOpenWriteEmitsFileWrite covers the Pkg 27 write-direction
// path end-to-end: openat with O_WRONLY|O_CREAT|O_TRUNC flips the mapper's
// Operation to "open_write", the bridge forwards the "openw" hint, and the
// aggregator emits FileWrite on close even without byte counters.
func TestBridgeFileOpenWriteEmitsFileWrite(t *testing.T) {
	b, ce, _ := newBridgeTest()
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysOpenat, PID: 210, RetVal: 8, Timestamp: 4000},
		[]any{int32(AtFDCWD), "/var/log/app.log", int32(0x241), uint32(0o644), "/bin/tee"}, // O_WRONLY|O_CREAT|O_TRUNC
	))
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysClose, PID: 210, RetVal: 0, Timestamp: 4100},
		[]any{int32(8), "/bin/tee"},
	))
	got := ce.byKind("FileWrite")
	if len(got) != 1 {
		t.Fatalf("want 1 FileWrite, got kinds: %v", kindList(ce.ev))
	}
	if got[0].Attributes["path"] != "/var/log/app.log" {
		t.Fatalf("path: %+v", got[0].Attributes)
	}
}

func TestBridgeSocketConnectTracked(t *testing.T) {
	b, ce, _ := newBridgeTest()
	// socket returns fd=5
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysSocket, PID: 300, RetVal: 5, Timestamp: 3000},
		[]any{int32(2), int32(1), int32(6), "/bin/curl"},
	))
	// connect 10.0.0.9:443
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysConnect, PID: 300, RetVal: 0, Timestamp: 3100},
		[]any{int32(5), int32(2), uint32(0x0900000a), uint32(443), "/bin/curl"},
	))
	// close(5) → bridge should route to ObserveSocketClose
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysClose, PID: 300, RetVal: 0, Timestamp: 3200},
		[]any{int32(5), "/bin/curl"},
	))

	got := ce.byKind("NetworkExchange")
	if len(got) != 1 {
		t.Fatalf("want 1 NetworkExchange, got kinds: %v", kindList(ce.ev))
	}
	if got[0].Attributes["peer"] != "10.0.0.9:443" {
		t.Fatalf("peer: %+v", got[0].Attributes)
	}
}

// TestBridgeSocketIOAccumulatesBytes drives socket → connect → 2x sendmsg
// → recvmsg → close and asserts the resulting NetworkExchange carries
// tx/rx attributes summed from the per-call retval. Locks in the bridge
// → ObserveSocketIO → aggregator path that the BPF send/recv exits feed.
func TestBridgeSocketIOAccumulatesBytes(t *testing.T) {
	b, ce, _ := newBridgeTest()
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysSocket, PID: 310, RetVal: 7, Timestamp: 4000},
		[]any{int32(2), int32(1), int32(6), "/bin/curl"},
	))
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysConnect, PID: 310, RetVal: 0, Timestamp: 4100},
		[]any{int32(7), int32(2), uint32(0x0a00000a), uint32(80), "/bin/curl"},
	))
	// sendmsg twice (1024 + 512 bytes), recvmsg once (2048 bytes).
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysSendmsg, PID: 310, RetVal: 1024, Timestamp: 4200},
		[]any{int32(7), int32(0), "/bin/curl"},
	))
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysSendmsg, PID: 310, RetVal: 512, Timestamp: 4300},
		[]any{int32(7), int32(0), "/bin/curl"},
	))
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysRecvmsg, PID: 310, RetVal: 2048, Timestamp: 4400},
		[]any{int32(7), int32(0), "/bin/curl"},
	))
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysClose, PID: 310, RetVal: 0, Timestamp: 4500},
		[]any{int32(7), "/bin/curl"},
	))

	got := ce.byKind("NetworkExchange")
	if len(got) != 1 {
		t.Fatalf("want 1 NetworkExchange, got kinds: %v", kindList(ce.ev))
	}
	if got[0].Attributes["tx"] != "1536" {
		t.Errorf("tx=%q, want 1536 (1024+512)", got[0].Attributes["tx"])
	}
	if got[0].Attributes["rx"] != "2048" {
		t.Errorf("rx=%q, want 2048", got[0].Attributes["rx"])
	}
}

// TestBridgeSocketIOIgnoresMmsg: sendmmsg/recvmmsg retval is a message
// count, not a byte count. The bridge tags those events with is_mmsg=1
// and skips ObserveSocketIO so byte counters don't get polluted with
// fake totals. The connect tracking still works.
func TestBridgeSocketIOIgnoresMmsg(t *testing.T) {
	b, ce, _ := newBridgeTest()
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysSocket, PID: 320, RetVal: 8, Timestamp: 5000},
		[]any{int32(2), int32(1), int32(6), "/bin/curl"},
	))
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysConnect, PID: 320, RetVal: 0, Timestamp: 5100},
		[]any{int32(8), int32(2), uint32(0x0b00000a), uint32(80), "/bin/curl"},
	))
	// sendmmsg with retval=4 (4 messages, NOT 4 bytes).
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysSendmmsg, PID: 320, RetVal: 4, Timestamp: 5200},
		[]any{int32(8), uint32(0), uint32(4), int32(0), "/bin/curl"},
	))
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysClose, PID: 320, RetVal: 0, Timestamp: 5300},
		[]any{int32(8), "/bin/curl"},
	))

	got := ce.byKind("NetworkExchange")
	if len(got) != 1 {
		t.Fatalf("want 1 NetworkExchange, got %d", len(got))
	}
	// tx/rx default to "0" in the aggregator when nothing was observed.
	if got[0].Attributes["tx"] != "0" {
		t.Errorf("tx=%q, want 0 (mmsg retval is not bytes)", got[0].Attributes["tx"])
	}
}

// TestBridgeSocketIONegativeRetvalSkipped: a failing send (retval = -1
// for EAGAIN, or any negative errno) must not bump tx/rx — userspace
// would otherwise count failed attempts as successful bytes.
func TestBridgeSocketIONegativeRetvalSkipped(t *testing.T) {
	b, ce, _ := newBridgeTest()
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysSocket, PID: 330, RetVal: 9, Timestamp: 6000},
		[]any{int32(2), int32(1), int32(6), "/bin/curl"},
	))
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysConnect, PID: 330, RetVal: 0, Timestamp: 6100},
		[]any{int32(9), int32(2), uint32(0x0c00000a), uint32(80), "/bin/curl"},
	))
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysSendmsg, PID: 330, RetVal: -11, Timestamp: 6200}, // -EAGAIN
		[]any{int32(9), int32(0), "/bin/curl"},
	))
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysClose, PID: 330, RetVal: 0, Timestamp: 6300},
		[]any{int32(9), "/bin/curl"},
	))

	got := ce.byKind("NetworkExchange")
	if len(got) != 1 {
		t.Fatalf("want 1 NetworkExchange, got %d", len(got))
	}
	if got[0].Attributes["tx"] != "0" {
		t.Errorf("tx=%q, want 0 (negative retval is errno)", got[0].Attributes["tx"])
	}
}

func TestBridgeProcExitFlushesState(t *testing.T) {
	b, ce, agg := newBridgeTest()
	// Open fd=9 on pid=400 and don't close — simulate crash.
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysOpenat, PID: 400, RetVal: 9, Timestamp: 4000},
		[]any{int32(AtFDCWD), "/tmp/x", int32(0), uint32(0), "/usr/bin/ls"},
	))
	if s := agg.Snapshot(); s.FileKeys != 1 {
		t.Fatalf("precondition: want FileKeys=1, got %d", s.FileKeys)
	}
	// sched_process_exit
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysSchedProcessExit, PID: 400, Timestamp: 4100},
		[]any{"/usr/bin/ls"},
	))
	if s := agg.Snapshot(); s.FileKeys != 0 {
		t.Fatalf("want FileKeys=0 after exit, got %d", s.FileKeys)
	}
	// Pkg 27: O_RDONLY hint → FileRead even at force-flush time.
	if got := ce.byKind("FileRead"); len(got) != 1 {
		t.Fatalf("want 1 flushed FileRead intent, got kinds: %v", kindList(ce.ev))
	}
}

// TestBridgeResolveDirfd covers Pkg 30: an earlier absolute open of a
// directory fd must let a later openat(fd, relative) resolve to the full
// cgroup-fs path. AT_FDCWD is deliberately a no-op here — it's the CWD
// completer's job, not the bridge's.
func TestBridgeResolveDirfd(t *testing.T) {
	b, _, _ := newBridgeTest()
	// Stage 1: absolute openat stores the cgroup dir fd.
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysOpenat, PID: 500, RetVal: 7, Timestamp: 5000},
		[]any{int32(AtFDCWD), "/sys/fs/cgroup/foo", int32(0), uint32(0), "/bin/cat"},
	))
	// Resolving a relative path against fd=7 should prepend the cached base.
	got, ok := b.ResolveDirfd(500, 7, "hugetlb.2MB.current")
	if !ok {
		t.Fatalf("ResolveDirfd unexpected miss")
	}
	if got != "/sys/fs/cgroup/foo/hugetlb.2MB.current" {
		t.Fatalf("resolved=%q", got)
	}
	// Unknown dirfd → miss, caller decides what to do.
	if _, ok := b.ResolveDirfd(500, 99, "foo"); ok {
		t.Fatalf("unknown dirfd should miss")
	}
	// Already-absolute paths pass through untouched (short-circuit).
	if got, ok := b.ResolveDirfd(500, 7, "/etc/hosts"); !ok || got != "/etc/hosts" {
		t.Fatalf("abs passthrough: got=%q ok=%v", got, ok)
	}
	// After close(7), the cache entry is evicted and subsequent lookups miss.
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysClose, PID: 500, RetVal: 0, Timestamp: 5100},
		[]any{int32(7), "/bin/cat"},
	))
	if _, ok := b.ResolveDirfd(500, 7, "x"); ok {
		t.Fatalf("closed dirfd should miss")
	}
}

// TestBridgeDirfdFromArgs round-trips the dirfd arg through mapper → bridge.
func TestBridgeDirfdFromArgs(t *testing.T) {
	se := bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysOpenat, PID: 600, RetVal: 9},
		[]any{int32(-100), "foo", int32(0), uint32(0), "/bin/cat"},
	)
	got, ok := DirfdFromArgs(se)
	if !ok || got != -100 {
		t.Fatalf("DirfdFromArgs: got=%d ok=%v", got, ok)
	}
}

// TestBridgeResolverReceivesNS covers Pkg 31 enrichment plumbing: the mapper
// surfaces the wire header's (PidNsID, MntNsID()) on Meta, and the bridge must
// pass them to the resolver and merge the result into the emitted Meta.
// A zero-value resolver result still preserves the NS pair so downstream
// exporters see the namespace identity.
func TestBridgeResolverReceivesNS(t *testing.T) {
	const pidNS uint32 = 4026531836
	const mntNS uint32 = 4026532001
	stub := &stubResolver{
		reply: types.ContainerMeta{
			Namespace: "multiubuntu", Pod: "ubuntu-1", Container: "ubuntu-1-container",
			ContainerID: "cid-42",
		},
	}
	ce := &collectEmitter{}
	agg := intent.NewAggregator(intent.Config{}, ce.emit)
	b := NewBridge(agg, stub)

	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysExecve, PID: 1000, HostPID: 1000, RetVal: 0, Timestamp: 10000, PidNsID: pidNS, MntNsID: mntNS},
		[]any{"/bin/sh", []string{"sh"}, "/bin/sh"},
	))

	if stub.gotPidNS != pidNS || stub.gotMntNS != mntNS {
		t.Fatalf("resolver NS args: want (%d,%d) got (%d,%d)", pidNS, mntNS, stub.gotPidNS, stub.gotMntNS)
	}
	got := ce.byKind("ProcessStart")
	if len(got) != 1 {
		t.Fatalf("want 1 ProcessStart, kinds=%v", kindList(ce.ev))
	}
	m := got[0].Meta
	if m.Pod != "ubuntu-1" || m.ContainerID != "cid-42" {
		t.Fatalf("enriched meta: %+v", m)
	}
	if m.PidNS != pidNS || m.MntNS != mntNS {
		t.Fatalf("NS preserved: want (%d,%d) got (%d,%d)", pidNS, mntNS, m.PidNS, m.MntNS)
	}
}

// TestBridgeResolverEmptyPreservesNS asserts the pre-enrichment NS pair still
// reaches the emitted Meta even when the resolver has no entry — useful during
// the warmup window right after a container starts.
func TestBridgeResolverEmptyPreservesNS(t *testing.T) {
	const pidNS uint32 = 4026532099
	const mntNS uint32 = 4026532100
	ce := &collectEmitter{}
	agg := intent.NewAggregator(intent.Config{}, ce.emit)
	b := NewBridge(agg, &stubResolver{}) // zero-value reply
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysExecve, PID: 1010, RetVal: 0, Timestamp: 11000, PidNsID: pidNS, MntNsID: mntNS},
		[]any{"/bin/ls", []string{"ls"}, "/bin/ls"},
	))
	got := ce.byKind("ProcessStart")
	if len(got) != 1 {
		t.Fatalf("want 1 ProcessStart, kinds=%v", kindList(ce.ev))
	}
	m := got[0].Meta
	if m.Pod != "" || m.PidNS != pidNS || m.MntNS != mntNS {
		t.Fatalf("unresolved NS should still be preserved: %+v", m)
	}
}

type stubResolver struct {
	reply    types.ContainerMeta
	gotPidNS uint32
	gotMntNS uint32
}

func (s *stubResolver) Resolve(pidNS, mntNS uint32) types.ContainerMeta {
	s.gotPidNS, s.gotMntNS = pidNS, mntNS
	return s.reply
}

// stubCgroupResolver implements both MetaResolver and CgroupMetaResolver
// so tests can drive the bridge's cgroup-id preference path. Each lookup
// path records its input so a test can assert which one fired.
type stubCgroupResolver struct {
	nsReply        types.ContainerMeta
	cgroupReply    types.ContainerMeta
	gotPidNS       uint32
	gotMntNS       uint32
	gotCgroupID    uint64
	resolveCalls   int
	cgResolveCalls int
}

func (s *stubCgroupResolver) Resolve(pidNS, mntNS uint32) types.ContainerMeta {
	s.gotPidNS, s.gotMntNS = pidNS, mntNS
	s.resolveCalls++
	return s.nsReply
}

func (s *stubCgroupResolver) ResolveByCgroupID(cgroupID uint64) types.ContainerMeta {
	s.gotCgroupID = cgroupID
	s.cgResolveCalls++
	return s.cgroupReply
}

// TestBridgePrefersCgroupResolution: when the wire header carries a
// non-zero cgroup_id and the resolver implements CgroupMetaResolver,
// the bridge MUST use the cgroup lookup and skip the NS lookup. Locks
// in the attribution path that survives hostPID/hostNetwork sharing.
func TestBridgePrefersCgroupResolution(t *testing.T) {
	stub := &stubCgroupResolver{
		cgroupReply: types.ContainerMeta{
			Cluster: "k1", NodeName: "n1",
			Namespace: "ns", Pod: "p1", ContainerID: "cid-cg",
		},
		nsReply: types.ContainerMeta{
			ContainerID: "cid-ns-WRONG",
		},
	}
	ce := &collectEmitter{}
	agg := intent.NewAggregator(intent.Config{}, ce.emit)
	b := NewBridge(agg, stub)

	b.Handle(bpf2frame.Map(
		bpf2frame.Event{
			SyscallID: syscalls.SysExecve, PID: 1100, HostPID: 1100, RetVal: 0, Timestamp: 12000,
			PidNsID: 4026531836, MntNsID: 4026531837, // host-ish pair
			CgroupID: 7777,
		},
		[]any{"/bin/sh", []string{"sh"}, "/bin/sh"},
	))

	if stub.cgResolveCalls != 1 {
		t.Errorf("cgroup-id resolution should fire exactly once, got %d", stub.cgResolveCalls)
	}
	if stub.resolveCalls != 0 {
		t.Errorf("NS resolution should be skipped when cgroup-id resolves, got %d calls", stub.resolveCalls)
	}
	if stub.gotCgroupID != 7777 {
		t.Errorf("cgroup-id arg=%d, want 7777", stub.gotCgroupID)
	}
	got := ce.byKind("ProcessStart")
	if len(got) != 1 || got[0].Meta.ContainerID != "cid-cg" {
		t.Fatalf("expected cgroup-derived ContainerID, got %+v", got)
	}
}

// TestBridgeFallsBackToNSWhenCgroupMisses: a non-zero cgroup_id whose
// lookup returns nothing useful (zero meta — walker missed AND not even
// a host-process Cluster/NodeName stamp) should fall through to NS-pair
// resolution rather than dropping the event.
func TestBridgeFallsBackToNSWhenCgroupMisses(t *testing.T) {
	stub := &stubCgroupResolver{
		cgroupReply: types.ContainerMeta{}, // empty — cgroup walker missed
		nsReply: types.ContainerMeta{
			Pod: "p2", ContainerID: "cid-ns",
		},
	}
	ce := &collectEmitter{}
	agg := intent.NewAggregator(intent.Config{}, ce.emit)
	b := NewBridge(agg, stub)

	b.Handle(bpf2frame.Map(
		bpf2frame.Event{
			SyscallID: syscalls.SysExecve, PID: 1200, HostPID: 1200, RetVal: 0, Timestamp: 13000,
			PidNsID: 4026532001, MntNsID: 4026532002,
			CgroupID: 9999,
		},
		[]any{"/bin/sh", []string{"sh"}, "/bin/sh"},
	))

	if stub.cgResolveCalls != 1 || stub.resolveCalls != 1 {
		t.Fatalf("expected one of each, got cg=%d ns=%d", stub.cgResolveCalls, stub.resolveCalls)
	}
	got := ce.byKind("ProcessStart")
	if len(got) != 1 || got[0].Meta.ContainerID != "cid-ns" {
		t.Fatalf("fallback to NS-derived meta failed: %+v", got)
	}
}

// TestBridgeZeroCgroupSkipsCgroupLookup: legacy frames whose CgroupID
// field is zero (e.g. older BPF object, replay fixtures, decoded from
// a pre-72-byte wire) must not call the cgroup resolver.
func TestBridgeZeroCgroupSkipsCgroupLookup(t *testing.T) {
	stub := &stubCgroupResolver{
		nsReply: types.ContainerMeta{ContainerID: "cid-only-ns"},
	}
	ce := &collectEmitter{}
	agg := intent.NewAggregator(intent.Config{}, ce.emit)
	b := NewBridge(agg, stub)

	b.Handle(bpf2frame.Map(
		bpf2frame.Event{
			SyscallID: syscalls.SysExecve, PID: 1300, HostPID: 1300, RetVal: 0, Timestamp: 14000,
			PidNsID: 4026532010, MntNsID: 4026532011,
			CgroupID: 0,
		},
		[]any{"/bin/sh", []string{"sh"}, "/bin/sh"},
	))

	if stub.cgResolveCalls != 0 {
		t.Errorf("cgroup-id=0 must skip cgroup resolver, got %d calls", stub.cgResolveCalls)
	}
	if stub.resolveCalls != 1 {
		t.Errorf("NS resolver should fire as the only path, got %d calls", stub.resolveCalls)
	}
}

type countingBirth struct{ n int }

func (c *countingBirth) Notify(context.Context) { c.n++ }

func TestBridgeNotifiesOnNamespaceClone(t *testing.T) {
	b, _, _ := newBridgeTest()
	bn := &countingBirth{}
	b.AttachBirthNotifier(context.Background(), bn)

	// Plain thread clone (no CLONE_NEW*) — should not notify.
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysClone, PID: 100, HostPID: 100, Timestamp: 1},
		[]any{uint64(0x00004000 /* CLONE_VM */)},
	))
	if bn.n != 0 {
		t.Fatalf("thread-only clone should not fire BirthNotifier, got n=%d", bn.n)
	}

	// Container-birth clone (CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET) — notify.
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysClone, PID: 101, HostPID: 101, Timestamp: 2},
		[]any{uint64(cloneNewPID | cloneNewNS | cloneNewNet)},
	))
	if bn.n != 1 {
		t.Fatalf("namespace-creating clone should fire BirthNotifier once, got n=%d", bn.n)
	}
}

func TestBridgeNotifiesOnSetnsPidNS(t *testing.T) {
	b, _, _ := newBridgeTest()
	bn := &countingBirth{}
	b.AttachBirthNotifier(context.Background(), bn)

	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysSetns, PID: 200, HostPID: 200, Timestamp: 1},
		[]any{int32(5), int32(cloneNewPID)},
	))
	if bn.n != 1 {
		t.Fatalf("setns(pid_ns) should fire BirthNotifier once, got n=%d", bn.n)
	}
}

func TestBridgeNotifiesFailOpenOnMissingFlags(t *testing.T) {
	// Older/degraded wire may leave the flags arg un-parseable — fail open
	// (notify anyway) rather than miss a container birth. We stand in for
	// that by feeding a clone event whose only arg is the trailing source
	// string, so the mapper's asUint64 test fails and no "flags" arg lands.
	b, _, _ := newBridgeTest()
	bn := &countingBirth{}
	b.AttachBirthNotifier(context.Background(), bn)
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysClone, PID: 300, HostPID: 300, Timestamp: 1},
		[]any{"runc"},
	))
	if bn.n != 1 {
		t.Fatalf("missing-flags clone should fire BirthNotifier (fail open), got n=%d", bn.n)
	}
}

func kindList(es []types.IntentEvent) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Kind)
	}
	return out
}

// TestBridgeSkipsEmptyPathOpen guards the bridge against turning a
// path-cleared open (Pipeline.Handle zeroes Resource when dirfd can't be
// resolved) into a downstream FileAccess intent with attributes.path="".
// Such intents leak into the JSONL stream and confuse consumers that
// expect a usable path. After the fix the open is a no-op: aggregator
// state is not created and no intent is emitted on the matching close.
func TestBridgeSkipsEmptyPathOpen(t *testing.T) {
	b, ce, agg := newBridgeTest()
	const pid int32 = 8888

	// openat with cleared Resource (mirrors Pipeline.Handle's behavior
	// when dirfd resolution fails — see cmd/kloudlens/pipeline.go:231).
	se := bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysOpenat, PID: pid, RetVal: 11, Timestamp: 100},
		[]any{int32(AtFDCWD), "/etc/x", int32(0), uint32(0), "/bin/cat"},
	)
	se.Resource = "" // simulate Pipeline.Handle's clearing
	b.Handle(se)

	if s := agg.Snapshot(); s.FileKeys != 0 {
		t.Errorf("empty-path open created %d aggregator state entries (want 0)", s.FileKeys)
	}
	b.mu.Lock()
	cached := len(b.fdPath)
	b.mu.Unlock()
	if cached != 0 {
		t.Errorf("empty-path open populated %d fdPath entries (want 0)", cached)
	}

	// close(11) — would have flushed an empty-path FileAccess if the
	// open had created state. Should be a no-op now.
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysClose, PID: pid, RetVal: 0, Timestamp: 200},
		[]any{int32(11), "/bin/cat"},
	))
	if len(ce.ev) != 0 {
		t.Errorf("emitted %d intents from empty-path open+close (want 0): %v",
			len(ce.ev), kindList(ce.ev))
	}
}

// TestBridgeForgetPIDClearsSockOnlyFDs guards against a leak where socket
// runs but connect never does (DNS resolver canceled, connection-pool
// pre-create) — fdIsSock holds the entry but fdPath does not. Without this
// fix forgetPID iterated only fdPath, so the fdIsSock entry survived the
// process exit and accumulated unbounded for workloads with high
// transient-socket churn (health checkers, DNS resolvers, etc.).
func TestBridgeForgetPIDClearsSockOnlyFDs(t *testing.T) {
	b, _, _ := newBridgeTest()
	const pid int32 = 7777

	// socket, no connect — this is the leak path.
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysSocket, PID: pid, RetVal: 5, Timestamp: 100},
		[]any{int32(2), int32(1), int32(6), "/bin/curl"},
	))
	// One regular file open so fdPath also has an entry — confirms both
	// halves get cleaned, not just one.
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysOpenat, PID: pid, RetVal: 9, Timestamp: 110},
		[]any{int32(AtFDCWD), "/etc/hosts", int32(0), uint32(0), "/bin/curl"},
	))

	b.mu.Lock()
	beforeSock := len(b.fdIsSock)
	beforePath := len(b.fdPath)
	b.mu.Unlock()
	if beforeSock != 1 || beforePath != 1 {
		t.Fatalf("precondition: fdIsSock=%d fdPath=%d, want 1/1", beforeSock, beforePath)
	}

	// sched_process_exit triggers forgetPID under the hood.
	b.Handle(bpf2frame.Map(
		bpf2frame.Event{SyscallID: syscalls.SysSchedProcessExit, PID: pid, Timestamp: 200},
		[]any{"/bin/curl"},
	))

	b.mu.Lock()
	afterSock := len(b.fdIsSock)
	afterPath := len(b.fdPath)
	b.mu.Unlock()
	if afterSock != 0 {
		t.Errorf("fdIsSock leaked %d entries past process exit (want 0)", afterSock)
	}
	if afterPath != 0 {
		t.Errorf("fdPath leaked %d entries past process exit (want 0)", afterPath)
	}
}
