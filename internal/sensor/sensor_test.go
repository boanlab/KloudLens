// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/internal/bpf2frame"
	"github.com/boanlab/kloudlens/internal/bpf2frame/frametest"
	"github.com/boanlab/kloudlens/internal/syscalls"
	"github.com/boanlab/kloudlens/pkg/types"
)

func TestMockSensorRoundTrip(t *testing.T) {
	mt := NewMockSensor(8)
	var mu sync.Mutex
	var got []types.SyscallEvent

	ctx := t.Context()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = mt.Start(ctx, func(e types.SyscallEvent) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, e)
		})
	}()

	mt.Feed(bpf2frame.Frame{
		Header: bpf2frame.Event{SyscallID: syscalls.SysExecve, HostPID: 10, RetVal: 0},
		Args:   []any{"/bin/sh", []string{"sh"}, "/bin/sh"},
	})
	mt.Feed(bpf2frame.Frame{
		Header: bpf2frame.Event{SyscallID: syscalls.SysOpenat, HostPID: 10, RetVal: 5},
		Args:   []any{"/etc/passwd", int32(0), uint32(0), "/bin/cat"},
	})

	// Give the pump a moment to consume.
	waitFor(t, 200*time.Millisecond, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 2
	})

	_ = mt.Stop()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("want 2 events, got %d", len(got))
	}
	if got[0].Category != "process" || got[1].Category != "file" {
		t.Errorf("categories: %q %q", got[0].Category, got[1].Category)
	}
}

func TestDecodeFrameFromRawBytes(t *testing.T) {
	// Assemble one execve record: header + 3 args.
	var buf bytes.Buffer
	frametest.Header(&buf, bpf2frame.Event{
		Timestamp: 1_000_000, HostPID: 77, PID: 77, UID: 1000, GID: 1000,
		SyscallID: syscalls.SysExecve, ArgNum: 3, EventType: bpf2frame.EventTypeExit, RetVal: 0,
	})
	frametest.ResourceArg(&buf, "/bin/echo")
	frametest.StrArrArg(&buf, []string{"echo", "hello"})
	frametest.SourceArg(&buf, "/bin/echo")

	fr, err := bpf2frame.DecodeFrame(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if fr.Header.SyscallID != syscalls.SysExecve || len(fr.Args) != 3 {
		t.Fatalf("frame: %+v", fr)
	}
	mapped := bpf2frame.Map(fr.Header, fr.Args)
	if mapped.Resource != "/bin/echo" || mapped.Category != "process" {
		t.Fatalf("mapped: %+v", mapped)
	}
}

func TestMockSensorStopIdempotent(t *testing.T) {
	mt := NewMockSensor(1)
	if err := mt.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := mt.Stop(); err != nil { // second call should no-op
		t.Fatal(err)
	}
	// Feeds after Stop should silently drop, not panic.
	mt.Feed(bpf2frame.Frame{})
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("waitFor: condition never met")
}
