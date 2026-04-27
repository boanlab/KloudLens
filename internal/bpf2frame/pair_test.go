// SPDX-License-Identifier: Apache-2.0

package bpf2frame

import (
	"testing"

	"github.com/boanlab/kloudlens/internal/syscalls"
)

// Pkg 27a: the live BPF side emits sys_enter_openat (ArgNum=4, RetVal=0,
// carrying path+flags) and sys_exit_openat (ArgNum=0, RetVal=fd) as two
// separate ring-buffer records. The pairer stitches them so the bridge
// sees one merged event with both the path and the resolved fd.
func TestPairerMergesOpenEnterExit(t *testing.T) {
	p := NewPairer()

	// ENTER: path + flags, RetVal=0. No output expected yet.
	_, ok := p.Merge(
		Event{SyscallID: syscalls.SysOpenat, HostTID: 42, PID: 42, EventType: EventTypeEnter, ArgNum: 2, RetVal: 0},
		[]any{"/etc/passwd", int32(0)}, // O_RDONLY
	)
	if ok {
		t.Fatal("ENTER should not emit")
	}
	if p.Pending() != 1 {
		t.Fatalf("pending=%d, want 1", p.Pending())
	}

	// EXIT: RetVal=fd, no args. Merged event must carry the ENTER's path
	// and the EXIT's fd.
	ev, ok := p.Merge(
		Event{SyscallID: syscalls.SysOpenat, HostTID: 42, PID: 42, EventType: EventTypeExit, ArgNum: 0, RetVal: 7},
		nil,
	)
	if !ok {
		t.Fatal("EXIT should emit merged event")
	}
	if ev.Operation != "open" {
		t.Fatalf("operation=%q, want open", ev.Operation)
	}
	if ev.Resource != "/etc/passwd" {
		t.Fatalf("resource=%q, want /etc/passwd", ev.Resource)
	}
	if ev.RetVal != 7 {
		t.Fatalf("retval=%d, want 7", ev.RetVal)
	}
	if p.Pending() != 0 {
		t.Fatalf("pending should drain after EXIT, got %d", p.Pending())
	}
}

// Write-mode flags must flow through the pairer so the mapper still flips
// Operation to "open_write" (Pkg 26) and the bridge forwards the "openw"
// hint (Pkg 27).
func TestPairerPreservesWriteFlags(t *testing.T) {
	p := NewPairer()
	_, _ = p.Merge(
		Event{SyscallID: syscalls.SysOpenat, HostTID: 100, EventType: EventTypeEnter, ArgNum: 2},
		[]any{"/var/log/app.log", int32(0x241)}, // O_WRONLY|O_CREAT|O_TRUNC
	)
	ev, ok := p.Merge(
		Event{SyscallID: syscalls.SysOpenat, HostTID: 100, EventType: EventTypeExit, RetVal: 9},
		nil,
	)
	if !ok || ev.Operation != "open_write" {
		t.Fatalf("want open_write, got ok=%v op=%q", ok, ev.Operation)
	}
}

// EXIT without ENTER falls through to direct Map so pre-merged test fixtures
// and records that survived an ENTER drop still produce an event.
func TestPairerExitWithoutEnterFallsThrough(t *testing.T) {
	p := NewPairer()
	ev, ok := p.Merge(
		Event{SyscallID: syscalls.SysSchedProcessExit, HostTID: 1, EventType: EventTypeExit, ArgNum: 1},
		[]any{"/bin/sh"},
	)
	if !ok {
		t.Fatal("orphan EXIT should still dispatch")
	}
	if ev.Operation != "exit" {
		t.Fatalf("op=%q, want exit", ev.Operation)
	}
}

// Unary events (sched_process_exit style) must not touch the pending map.
func TestPairerUnaryPassesThrough(t *testing.T) {
	p := NewPairer()
	ev, ok := p.Merge(
		Event{SyscallID: syscalls.SysSchedProcessExit, HostTID: 1, EventType: EventTypeUnary, ArgNum: 1},
		[]any{"/bin/sh"},
	)
	if !ok || ev.Operation != "exit" {
		t.Fatalf("unary dispatch broken: ok=%v op=%q", ok, ev.Operation)
	}
	if p.Pending() != 0 {
		t.Fatalf("unary leaked into pending map: %d", p.Pending())
	}
}

// When the pending map hits its cap, one arbitrary ENTER is dropped and the
// evicted counter ticks. Feeds the /metrics kloudlens_pair_evicted_total
// counter that dashboards alert on as a proxy for BPF ringbuf loss of EXITs.
func TestPairerEvictsAtCap(t *testing.T) {
	p := NewPairer()
	p.maxSize = 4 // shrink so the test stays cheap

	for i := 0; i < p.maxSize; i++ {
		_, _ = p.Merge(
			Event{SyscallID: syscalls.SysOpenat, HostTID: int32(i + 1), EventType: EventTypeEnter, ArgNum: 2},
			[]any{"/path", int32(0)},
		)
	}
	if p.Pending() != p.maxSize {
		t.Fatalf("pending=%d, want %d", p.Pending(), p.maxSize)
	}
	if p.Evicted() != 0 {
		t.Fatalf("evicted=%d before overflow, want 0", p.Evicted())
	}

	const overflow = 3
	for i := 0; i < overflow; i++ {
		_, _ = p.Merge(
			Event{SyscallID: syscalls.SysOpenat, HostTID: int32(100 + i), EventType: EventTypeEnter, ArgNum: 2},
			[]any{"/path", int32(0)},
		)
	}
	if got := p.Evicted(); got != overflow {
		t.Fatalf("evicted=%d, want %d", got, overflow)
	}
	if p.Pending() != p.maxSize {
		t.Fatalf("pending=%d after overflow, want %d", p.Pending(), p.maxSize)
	}
}

// Different threads calling the same syscall concurrently must not collide —
// the key includes HostTID so each has its own pending slot.
func TestPairerKeysPerThread(t *testing.T) {
	p := NewPairer()
	_, _ = p.Merge(
		Event{SyscallID: syscalls.SysOpenat, HostTID: 1, EventType: EventTypeEnter, ArgNum: 2},
		[]any{"/a", int32(0)},
	)
	_, _ = p.Merge(
		Event{SyscallID: syscalls.SysOpenat, HostTID: 2, EventType: EventTypeEnter, ArgNum: 2},
		[]any{"/b", int32(1)}, // O_WRONLY
	)
	if p.Pending() != 2 {
		t.Fatalf("want 2 pending, got %d", p.Pending())
	}
	ev1, _ := p.Merge(
		Event{SyscallID: syscalls.SysOpenat, HostTID: 1, EventType: EventTypeExit, RetVal: 10},
		nil,
	)
	if ev1.Resource != "/a" {
		t.Fatalf("tid=1 merged /b instead of /a: %+v", ev1)
	}
	ev2, _ := p.Merge(
		Event{SyscallID: syscalls.SysOpenat, HostTID: 2, EventType: EventTypeExit, RetVal: 11},
		nil,
	)
	if ev2.Resource != "/b" || ev2.Operation != "open_write" {
		t.Fatalf("tid=2 lost write flags: %+v", ev2)
	}
}
