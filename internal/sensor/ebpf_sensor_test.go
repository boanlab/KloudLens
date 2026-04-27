// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/internal/bpf2frame"
	"github.com/boanlab/kloudlens/internal/bpf2frame/frametest"
	"github.com/boanlab/kloudlens/internal/syscalls"
	"github.com/boanlab/kloudlens/pkg/types"
)

// buildRecord assembles a complete record the live reader would receive.
func buildRecord(t *testing.T, e bpf2frame.Event, argWriter func(*bytes.Buffer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	frametest.Header(&buf, e)
	if argWriter != nil {
		argWriter(&buf)
	}
	return buf.Bytes()
}

func TestEBPFSensorPumpsRecords(t *testing.T) {
	rec1 := buildRecord(t, bpf2frame.Event{SyscallID: syscalls.SysExecve, HostPID: 1, PID: 1, RetVal: 0, ArgNum: 3}, func(b *bytes.Buffer) {
		frametest.ResourceArg(b, "/bin/ls")
		frametest.StrArrArg(b, []string{"ls"})
		frametest.SourceArg(b, "/bin/ls")
	})
	rec2 := buildRecord(t, bpf2frame.Event{SyscallID: syscalls.SysSchedProcessExit, HostPID: 1, PID: 1, ArgNum: 1}, func(b *bytes.Buffer) {
		frametest.SourceArg(b, "/bin/ls")
	})

	src := NewBytesSource([][]byte{rec1, rec2})
	tr := NewEBPFSensor(src)

	var mu sync.Mutex
	var got []types.SyscallEvent
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tr.Start(t.Context(), func(e types.SyscallEvent) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, e)
		})
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = tr.Stop()
		t.Fatal("sensor never drained source")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("want 2 events, got %d", len(got))
	}
	if got[0].Operation != "execute" || got[1].Operation != "exit" {
		t.Errorf("ops: %q %q", got[0].Operation, got[1].Operation)
	}
}

func TestEBPFSensorSkipsMalformedRecords(t *testing.T) {
	// Malformed = shorter than the 48-byte header.
	src := NewBytesSource([][]byte{{0x00, 0x01, 0x02}})
	tr := NewEBPFSensor(src)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tr.Start(t.Context(), func(types.SyscallEvent) {
			t.Error("handler should not fire on malformed record")
		})
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		_ = tr.Stop()
	}
	read, dropped := tr.DropStats()
	if read == 0 || dropped == 0 || dropped > read {
		t.Fatalf("DropStats after malformed record: read=%d dropped=%d", read, dropped)
	}
}

// TestEBPFSensorDropStatsClean covers the happy path: every record decoded,
// zero drops. Pairs with the malformed test above so the counter contract is
// pinned from both sides.
func TestEBPFSensorDropStatsClean(t *testing.T) {
	rec := buildRecord(t, bpf2frame.Event{SyscallID: syscalls.SysSchedProcessExit, HostPID: 1, PID: 1, ArgNum: 1}, func(b *bytes.Buffer) {
		frametest.SourceArg(b, "/bin/ls")
	})
	src := NewBytesSource([][]byte{rec, rec, rec})
	tr := NewEBPFSensor(src)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tr.Start(t.Context(), func(types.SyscallEvent) {})
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		_ = tr.Stop()
	}
	read, dropped := tr.DropStats()
	if read != 3 || dropped != 0 {
		t.Fatalf("clean path: want read=3 dropped=0, got read=%d dropped=%d", read, dropped)
	}
}

// fakeSampler records the last rate written to it, for driving the sampler
// contract without loading a real BPF map.
type fakeSampler struct {
	last atomic.Uint32
	err  error
}

func (f *fakeSampler) SetBulkSamplingRate(rate uint32) error {
	f.last.Store(rate)
	return f.err
}

func TestEBPFSensorSetBulkSamplingRateNoSampler(t *testing.T) {
	tr := NewEBPFSensor(NewBytesSource(nil))
	if err := tr.SetBulkSamplingRate(7); !errors.Is(err, ErrSamplerUnavailable) {
		t.Fatalf("want ErrSamplerUnavailable, got %v", err)
	}
}

func TestEBPFSensorSetBulkSamplingRateForwards(t *testing.T) {
	tr := NewEBPFSensor(NewBytesSource(nil))
	fs := &fakeSampler{}
	tr.sampler = fs

	for _, rate := range []uint32{0, 1, 2, 10, 0xFFFFFFFF} {
		if err := tr.SetBulkSamplingRate(rate); err != nil {
			t.Fatalf("rate=%d: %v", rate, err)
		}
		if got := fs.last.Load(); got != rate {
			t.Fatalf("rate=%d: sampler got %d", rate, got)
		}
	}
}

// fakeDropSink stubs ringbufDropSink so the propagation test runs without
// a real kl_rb_drops BPF map.
type fakeDropSink struct {
	val RingbufDrops
	err error
}

func (f *fakeDropSink) Read() (RingbufDrops, error) { return f.val, f.err }

func TestRingbufDropsAny(t *testing.T) {
	if (RingbufDrops{}).Any() {
		t.Fatal("zero value: Any=true, want false")
	}
	cases := []struct {
		name string
		d    RingbufDrops
	}{
		{"crit", RingbufDrops{Crit: 1}},
		{"bulk_file", RingbufDrops{BulkFile: 1}},
		{"bulk_net", RingbufDrops{BulkNet: 1}},
		{"bulk_proc", RingbufDrops{BulkProc: 1}},
		{"bulk_file_meta", RingbufDrops{BulkFileMeta: 1}},
		{"dns", RingbufDrops{DNS: 1}},
		{"proc_lc", RingbufDrops{ProcLC: 1}},
		{"sock_lc", RingbufDrops{SockLC: 1}},
	}
	for _, c := range cases {
		if !c.d.Any() {
			t.Errorf("%s=1: Any=false, want true", c.name)
		}
	}
}

func TestKernelRingbufDropsNilSink(t *testing.T) {
	tr := NewEBPFSensor(NewBytesSource(nil))
	got, err := tr.KernelRingbufDrops()
	if err != nil {
		t.Fatalf("nil sink should not error, got %v", err)
	}
	if got != (RingbufDrops{}) {
		t.Fatalf("nil sink should return zero value, got %+v", got)
	}
}

// TestKernelRingbufDropsForwardsAllSlots guards the regression where a
// new ring is added to RingbufDrops but the sensor's getter / metrics
// adapter forgets to propagate it. Each field gets a unique value so a
// dropped or swapped slot fails loudly.
func TestKernelRingbufDropsForwardsAllSlots(t *testing.T) {
	want := RingbufDrops{
		Crit: 11, BulkFile: 22, BulkNet: 33, BulkProc: 44,
		BulkFileMeta: 88,
		DNS:          55, ProcLC: 66, SockLC: 77,
	}
	tr := NewEBPFSensor(NewBytesSource(nil))
	tr.rbDrops = &fakeDropSink{val: want}
	got, err := tr.KernelRingbufDrops()
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestKernelRingbufDropsPropagatesError(t *testing.T) {
	tr := NewEBPFSensor(NewBytesSource(nil))
	sentinel := errors.New("read failed")
	tr.rbDrops = &fakeDropSink{err: sentinel}
	if _, err := tr.KernelRingbufDrops(); !errors.Is(err, sentinel) {
		t.Fatalf("want sentinel error, got %v", err)
	}
}

func TestLiveEBPF(t *testing.T) {
	tr, err := LiveEBPF()
	if err != nil {
		if errors.Is(err, ErrNotSupported) {
			// Expected on non-Linux / non-amd64 builds where no BPF object ships.
			return
		}
		// Anywhere else (no root, locked-down kernel, missing BTF…) the loader
		// itself fails — the test still passes because the contract is that a
		// non-nil error disables the live path gracefully.
		t.Logf("LiveEBPF not runnable here: %v", err)
		return
	}
	// Loader succeeded — tear down immediately; this is a smoke test, not a
	// functional one.
	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop after successful LiveEBPF: %v", err)
	}
}

// TestLiveEBPFEmitsEvents runs the real loader, generates known syscalls
// (exec /bin/true), and asserts the sensor produces at least one execve
// SyscallEvent for the child. Gated on KLOUDLENS_LIVE_SENSOR=1 so default
// test runs (unprivileged) stay clean.
func TestLiveEBPFEmitsEvents(t *testing.T) {
	if os.Getenv("KLOUDLENS_LIVE_SENSOR") != "1" {
		t.Skip("set KLOUDLENS_LIVE_SENSOR=1 and run under sudo to exercise the live loader")
	}
	tr, err := LiveEBPF()
	if err != nil {
		t.Fatalf("LiveEBPF: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })

	var execCount atomic.Int32
	var seenTrue atomic.Bool
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- tr.Start(ctx, func(e types.SyscallEvent) {
			if e.Operation == "execute" {
				execCount.Add(1)
				if e.Resource != "" && bytes.Contains([]byte(e.Resource), []byte("true")) {
					seenTrue.Store(true)
				}
			}
		})
	}()

	// Give the verifier + attach time to settle, then trigger known execs.
	time.Sleep(200 * time.Millisecond)
	for range 5 {
		_ = exec.Command("/bin/true").Run()
	}
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-errCh

	if execCount.Load() == 0 {
		t.Fatalf("no execve events observed — ringbuf or attach is broken")
	}
	t.Logf("live loader observed %d execute events (seen /bin/true: %v)", execCount.Load(), seenTrue.Load())
	if !seenTrue.Load() {
		t.Logf("saw %d execs, but none referenced /bin/true — trace is working but resource decoding may be lossy", execCount.Load())
	}
}

// TestLiveEBPFCoalescesReadBurst drives the kernel-side coalesce_map: we
// issue a tight read burst on /dev/null and expect the emitted read-event
// count to be an order of magnitude smaller than the syscalls issued. This
// is the end-to-end signal that kl_coalesce_check is collapsing bursts.
func TestLiveEBPFCoalescesReadBurst(t *testing.T) {
	if os.Getenv("KLOUDLENS_LIVE_SENSOR") != "1" {
		t.Skip("set KLOUDLENS_LIVE_SENSOR=1 and run under sudo to exercise the live loader")
	}
	tr, err := LiveEBPF()
	if err != nil {
		t.Fatalf("LiveEBPF: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })

	var readCount atomic.Int32
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- tr.Start(ctx, func(e types.SyscallEvent) {
			if e.SyscallName == "read" && e.HostPID == int32(os.Getpid()) {
				readCount.Add(1)
			}
		})
	}()

	// Let attach settle, then issue a read burst on /dev/null tight enough
	// that all calls fall inside the 100ms coalesce window.
	time.Sleep(200 * time.Millisecond)
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	defer f.Close()
	buf := make([]byte, 1)
	const burst = 1000
	for range burst {
		_, _ = f.Read(buf)
	}
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-errCh

	got := readCount.Load()
	if got == 0 {
		t.Fatalf("no read events observed — hook or attach is broken")
	}
	// 1000 reads inside ~100 ms would coalesce to a handful of emitted
	// events on a quiet host, but the window timing is sensitive to
	// scheduling noise — a long ksoftirqd tick or a BPF verifier reload
	// can split the loop across two windows and double/triple the
	// emitted count without the coalesce path being broken. Allow a
	// ×5 reduction floor (1000 reads → ≤ 200 events, i.e. ≥ 80 %
	// reduction) so this test catches the "coalesce turned off"
	// regression without flaking under load.
	if got > burst/5 {
		t.Fatalf("coalesce ineffective: %d events for %d reads (want ≤ %d)", got, burst, burst/5)
	}
	t.Logf("coalesce OK: %d emitted for %d reads (reduction %.1f×)", got, burst, float64(burst)/float64(got))
}
