// SPDX-License-Identifier: Apache-2.0

package history

import (
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

func tsNS(t time.Time) uint64 { return uint64(t.UnixNano()) }

func TestProcExecRingPreservesOrderAndCapsDepth(t *testing.T) {
	now := time.Unix(1000, 0)
	s := New(Config{ProcExecDepth: 3, Clock: func() time.Time { return now }})
	for i := range 5 {
		s.RecordExec(100, types.ProcessAncestor{PID: int32(i), Binary: "/bin/sh"})
	}
	snap := s.Snapshot(100, "")
	if len(snap.Ancestors) != 3 {
		t.Fatalf("depth cap broken: got %d entries, want 3", len(snap.Ancestors))
	}
	// Oldest two should have been dropped: we expect PIDs 2,3,4.
	got := []int32{snap.Ancestors[0].PID, snap.Ancestors[1].PID, snap.Ancestors[2].PID}
	want := []int32{2, 3, 4}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("order broken: got %v want %v", got, want)
		}
	}
}

func TestProcRecentRingDropsExpiredByTTL(t *testing.T) {
	current := time.Unix(1000, 0)
	clock := func() time.Time { return current }
	s := New(Config{ProcRecentDepth: 8, ProcRecentTTL: 5 * time.Second, Clock: clock})

	s.RecordProcessIntent(42, types.HistoryEntry{TSNS: tsNS(current), Kind: "FileWrite", Summary: "/tmp/a"})
	current = current.Add(10 * time.Second)
	s.RecordProcessIntent(42, types.HistoryEntry{TSNS: tsNS(current), Kind: "NetworkExchange", Summary: "1.2.3.4:443"})

	snap := s.Snapshot(42, "")
	if len(snap.RecentProcess) != 1 {
		t.Fatalf("TTL filter broken: got %d want 1", len(snap.RecentProcess))
	}
	if snap.RecentProcess[0].Kind != "NetworkExchange" {
		t.Fatalf("wrong entry survived: %+v", snap.RecentProcess[0])
	}
}

func TestContRecentRingTTLAndDepth(t *testing.T) {
	current := time.Unix(0, 0)
	s := New(Config{ContRecentDepth: 2, ContRecentTTL: 30 * time.Second, Clock: func() time.Time { return current }})
	for i := range 4 {
		s.RecordContainerIntent("cid-x", types.HistoryEntry{TSNS: tsNS(current), Kind: "Exec", Summary: "cmd-" + itoa(i)})
	}
	snap := s.Snapshot(0, "cid-x")
	if len(snap.RecentContainer) != 2 {
		t.Fatalf("container depth cap broken: %d", len(snap.RecentContainer))
	}
	if snap.RecentContainer[0].Summary != "cmd-2" || snap.RecentContainer[1].Summary != "cmd-3" {
		t.Fatalf("wrong entries retained: %+v", snap.RecentContainer)
	}
}

func TestBootstrapWindow(t *testing.T) {
	current := time.Unix(1_000_000, 0)
	s := New(Config{BootstrapWindow: 10 * time.Second, Clock: func() time.Time { return current }})
	s.StartBootstrap("cid-a", tsNS(current))
	s.RecordBootstrap("cid-a", "exec", "/bin/sh")
	s.RecordBootstrap("cid-a", "read", "/etc/hosts")
	s.RecordBootstrap("cid-a", "peer", "10.0.0.5:80")
	// Duplicate exec should be deduped.
	s.RecordBootstrap("cid-a", "exec", "/bin/sh")

	snap := s.Snapshot(0, "cid-a")
	if snap.Bootstrap == nil || len(snap.Bootstrap.FirstExecs) != 1 {
		t.Fatalf("bootstrap exec dedup broken: %+v", snap.Bootstrap)
	}
	if len(snap.Bootstrap.FirstReads) != 1 || len(snap.Bootstrap.FirstPeers) != 1 {
		t.Fatalf("bootstrap content: %+v", snap.Bootstrap)
	}
	if !snap.Bootstrap.BootstrapOngoing {
		t.Fatal("should still be ongoing inside window")
	}
	// Outside window, new records are ignored and flag flips.
	current = current.Add(20 * time.Second)
	s.RecordBootstrap("cid-a", "exec", "/bin/ls")
	snap2 := s.Snapshot(0, "cid-a")
	if len(snap2.Bootstrap.FirstExecs) != 1 {
		t.Fatalf("post-window recording should have been dropped: %+v", snap2.Bootstrap)
	}
	if snap2.Bootstrap.BootstrapOngoing {
		t.Fatal("bootstrap window expired; flag should be false")
	}
}

func TestCredTimelineCapped(t *testing.T) {
	now := time.Unix(10, 0)
	s := New(Config{CredDepth: 3, Clock: func() time.Time { return now }})
	s.RecordCred(7, types.CredTransition{TSNS: 1, From: "uid=1000", To: "uid=0", Cause: "setuid"})
	s.RecordCred(7, types.CredTransition{TSNS: 2, From: "cap=none", To: "cap=all", Cause: "capset"})
	s.RecordCred(7, types.CredTransition{TSNS: 3, From: "gid=100", To: "gid=0", Cause: "setgid"})
	s.RecordCred(7, types.CredTransition{TSNS: 4, From: "euid=1000", To: "euid=0", Cause: "exec-suid"})

	snap := s.Snapshot(7, "")
	if len(snap.CredTimeline) != 3 {
		t.Fatalf("cred cap broken: %d", len(snap.CredTimeline))
	}
	if snap.CredTimeline[0].TSNS != 2 || snap.CredTimeline[2].TSNS != 4 {
		t.Fatalf("cred order wrong: %+v", snap.CredTimeline)
	}
}

func TestOnProcessExitClearsRings(t *testing.T) {
	now := time.Unix(0, 0)
	s := New(Config{Clock: func() time.Time { return now }})
	s.RecordExec(55, types.ProcessAncestor{PID: 55})
	s.RecordProcessIntent(55, types.HistoryEntry{TSNS: tsNS(now), Kind: "FileRead"})
	s.RecordCred(55, types.CredTransition{TSNS: 1, Cause: "setuid"})

	s.OnProcessExit(55)
	snap := s.Snapshot(55, "")
	if len(snap.Ancestors) != 0 || len(snap.RecentProcess) != 0 || len(snap.CredTimeline) != 0 {
		t.Fatalf("exit did not clear state: %+v", snap)
	}
	if s.Sizes().ProcKeys != 0 {
		t.Fatalf("proc keys not zero: %d", s.Sizes().ProcKeys)
	}
}

func TestLRUEvictionOverCap(t *testing.T) {
	now := time.Unix(0, 0)
	s := New(Config{MaxProcKeys: 3, Clock: func() time.Time { return now }})
	s.RecordProcessIntent(1, types.HistoryEntry{TSNS: tsNS(now), Kind: "x"})
	s.RecordProcessIntent(2, types.HistoryEntry{TSNS: tsNS(now), Kind: "x"})
	s.RecordProcessIntent(3, types.HistoryEntry{TSNS: tsNS(now), Kind: "x"})
	// touch 1 to push 2 to oldest.
	s.RecordProcessIntent(1, types.HistoryEntry{TSNS: tsNS(now), Kind: "x"})
	s.RecordProcessIntent(4, types.HistoryEntry{TSNS: tsNS(now), Kind: "x"})

	if sz := s.Sizes(); sz.ProcKeys != 3 {
		t.Fatalf("cap not enforced: %d", sz.ProcKeys)
	}
	// pid 2 (LRU) should have been evicted.
	snap := s.Snapshot(2, "")
	if len(snap.RecentProcess) != 0 {
		t.Fatalf("expected pid 2 evicted, still has %d entries", len(snap.RecentProcess))
	}
	// pids 1,3,4 still present.
	for _, pid := range []int32{1, 3, 4} {
		if len(s.Snapshot(pid, "").RecentProcess) == 0 {
			t.Fatalf("pid %d should still be present", pid)
		}
	}
}

func TestSnapshotCrossSection(t *testing.T) {
	now := time.Unix(42, 0)
	s := New(Config{Clock: func() time.Time { return now }})
	s.RecordExec(1, types.ProcessAncestor{PID: 1, Binary: "/bin/bash"})
	s.RecordExec(1, types.ProcessAncestor{PID: 10, Binary: "/usr/bin/curl"})
	s.RecordProcessIntent(1, types.HistoryEntry{TSNS: tsNS(now), Kind: "FileRead", Summary: "/etc/passwd"})
	s.RecordContainerIntent("cid", types.HistoryEntry{TSNS: tsNS(now), Kind: "NetworkExchange", Summary: "8.8.8.8:443"})
	s.StartBootstrap("cid", tsNS(now))
	s.RecordBootstrap("cid", "exec", "/bin/bash")
	s.RecordCred(1, types.CredTransition{TSNS: tsNS(now), From: "uid=0", To: "uid=1000", Cause: "setuid"})

	h := s.Snapshot(1, "cid")
	if len(h.Ancestors) != 2 || h.Ancestors[1].Binary != "/usr/bin/curl" {
		t.Fatalf("ancestors: %+v", h.Ancestors)
	}
	if len(h.RecentProcess) != 1 || h.RecentProcess[0].Summary != "/etc/passwd" {
		t.Fatalf("recent process: %+v", h.RecentProcess)
	}
	if len(h.RecentContainer) != 1 {
		t.Fatalf("recent container: %+v", h.RecentContainer)
	}
	if h.Bootstrap == nil || len(h.Bootstrap.FirstExecs) != 1 {
		t.Fatalf("bootstrap: %+v", h.Bootstrap)
	}
	if len(h.CredTimeline) != 1 {
		t.Fatalf("cred: %+v", h.CredTimeline)
	}
}

// TestSetHistoryDepthShrinkKeepsNewest verifies that shrinking an existing
// ring drops the oldest entries first — the operator intuition for a knob
// labeled "history depth" is that shrinking preserves recency. A regression
// here would silently lose the tail of a currently-live ring when an operator
// tightens the window via `klctl apply`.
func TestSetHistoryDepthShrinkKeepsNewest(t *testing.T) {
	now := time.Unix(1000, 0)
	s := New(Config{ProcRecentDepth: 8, ContRecentDepth: 8, Clock: func() time.Time { return now }})
	for i := range 8 {
		s.RecordProcessIntent(42, types.HistoryEntry{TSNS: tsNS(now), Kind: "x", Summary: itoa(i)})
		s.RecordContainerIntent("cid", types.HistoryEntry{TSNS: tsNS(now), Kind: "x", Summary: itoa(i)})
	}
	s.SetHistoryDepth(3)

	snap := s.Snapshot(42, "cid")
	if len(snap.RecentProcess) != 3 {
		t.Fatalf("proc recent depth after shrink = %d, want 3", len(snap.RecentProcess))
	}
	want := []string{"5", "6", "7"}
	for i, e := range snap.RecentProcess {
		if e.Summary != want[i] {
			t.Fatalf("proc recent[%d]=%q want %q (snap=%+v)", i, e.Summary, want[i], snap.RecentProcess)
		}
	}
	if len(snap.RecentContainer) != 3 {
		t.Fatalf("cont recent depth after shrink = %d, want 3", len(snap.RecentContainer))
	}
	for i, e := range snap.RecentContainer {
		if e.Summary != want[i] {
			t.Fatalf("cont recent[%d]=%q want %q", i, e.Summary, want[i])
		}
	}
}

// TestSetHistoryDepthGrowAcceptsMore verifies that after growing the cap,
// subsequent pushes retain up to the new cap rather than the old one.
func TestSetHistoryDepthGrowAcceptsMore(t *testing.T) {
	now := time.Unix(1000, 0)
	s := New(Config{ProcRecentDepth: 2, Clock: func() time.Time { return now }})
	s.RecordProcessIntent(7, types.HistoryEntry{TSNS: tsNS(now), Summary: "a"})
	s.RecordProcessIntent(7, types.HistoryEntry{TSNS: tsNS(now), Summary: "b"})
	s.SetHistoryDepth(5)
	for _, v := range []string{"c", "d", "e"} {
		s.RecordProcessIntent(7, types.HistoryEntry{TSNS: tsNS(now), Summary: v})
	}
	snap := s.Snapshot(7, "")
	if len(snap.RecentProcess) != 5 {
		t.Fatalf("after grow should hold 5 entries, got %d", len(snap.RecentProcess))
	}
	want := []string{"a", "b", "c", "d", "e"}
	for i, e := range snap.RecentProcess {
		if e.Summary != want[i] {
			t.Fatalf("recent[%d]=%q want %q", i, e.Summary, want[i])
		}
	}
}

// TestSetHistoryDepthZeroOrNegativeIsNoop pins the "leave unchanged" semantics
// that match the YAML default (omitted → 0 → no-op), so operators who push
// a HookSubscription without setting HistoryDepth don't accidentally collapse
// the ring to cap=1.
func TestSetHistoryDepthZeroOrNegativeIsNoop(t *testing.T) {
	now := time.Unix(1000, 0)
	s := New(Config{ProcRecentDepth: 4, Clock: func() time.Time { return now }})
	for i := range 4 {
		s.RecordProcessIntent(9, types.HistoryEntry{TSNS: tsNS(now), Summary: itoa(i)})
	}
	s.SetHistoryDepth(0)
	s.SetHistoryDepth(-3)
	snap := s.Snapshot(9, "")
	if len(snap.RecentProcess) != 4 {
		t.Fatalf("no-op calls mutated ring: got %d entries", len(snap.RecentProcess))
	}
}

// TestSetHistoryTTLAffectsSnapshotFilter confirms that lowering the TTL
// below an existing entry's age drops it from the next Snapshot, and that
// non-positive values are ignored.
func TestSetHistoryTTLAffectsSnapshotFilter(t *testing.T) {
	current := time.Unix(1000, 0)
	clock := func() time.Time { return current }
	s := New(Config{ProcRecentDepth: 8, ProcRecentTTL: time.Hour, Clock: clock})
	s.RecordProcessIntent(5, types.HistoryEntry{TSNS: tsNS(current), Summary: "old"})
	current = current.Add(10 * time.Second)
	s.RecordProcessIntent(5, types.HistoryEntry{TSNS: tsNS(current), Summary: "new"})

	// With TTL=1h both survive.
	if n := len(s.Snapshot(5, "").RecentProcess); n != 2 {
		t.Fatalf("baseline expected 2 entries, got %d", n)
	}
	// Shrink to 5s — the 10s-old entry drops.
	s.SetHistoryTTL(5 * time.Second)
	snap := s.Snapshot(5, "")
	if len(snap.RecentProcess) != 1 || snap.RecentProcess[0].Summary != "new" {
		t.Fatalf("after TTL shrink expected [new], got %+v", snap.RecentProcess)
	}
	// Zero and negative TTL → no-op; old entry stays dropped regardless.
	s.SetHistoryTTL(0)
	s.SetHistoryTTL(-time.Second)
	if n := len(s.Snapshot(5, "").RecentProcess); n != 1 {
		t.Fatalf("non-positive TTL should not alter filter, got %d", n)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 4)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
