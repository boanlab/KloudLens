// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package exporter

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/internal/wal"
	"github.com/boanlab/kloudlens/pkg/types"
	"github.com/boanlab/kloudlens/protobuf"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// TestSubmitFunnelsThroughOnLiveIntent guards the IntentSink adapter the
// pipeline uses: every call to Submit must reach OnLiveIntent so the WAL +
// fan-out path is exercised. A regression here (e.g. accidentally returning
// a no-op Submit) would make the SubscribeServer go silent for the entire
// agent without any error surface.
func TestSubmitFunnelsThroughOnLiveIntent(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	s := NewSubscribeServer(w, nil, "node-a")
	s.Submit(types.IntentEvent{IntentID: "via-submit", Kind: "FileRead"})

	// One write should produce a WAL entry that ReadFrom can replay.
	var got string
	err = w.ReadFrom(0, "intent", func(e wal.Entry) error {
		got = e.Event.IntentID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "via-submit" {
		t.Errorf("got %q, want via-submit", got)
	}
}

// SubscriberCount and SubscriberDropped power the /metrics gauges
// kloudlens_subscribers_active{stream="..."} and
// kloudlens_subscribers_dropped_total. Operators rely on those to alert
// on slow-consumer fanout; a regression where the counters silently lock
// at zero would defeat that. This test attaches a live subscriber, drives
// the fan-out queue past its bound, and verifies the gauges move.
func TestSubscriberCountAndDropped(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	s := NewSubscribeServer(w, nil, "node-a")
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	if env, dev, sess := s.SubscriberCount(); env+dev+sess != 0 {
		t.Errorf("baseline SubscriberCount = (%d,%d,%d), want all zero", env, dev, sess)
	}
	if got := s.SubscriberDropped(); got != 0 {
		t.Errorf("baseline SubscriberDropped = %d, want 0", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := client.Subscribe(ctx, &protobuf.SubscribeRequest{
		ConsumerId:        "c-cnt",
		Streams:           []string{"intent"},
		FlowControlWindow: 1, // tiny queue → easy to overflow
	})
	if err != nil {
		t.Fatal(err)
	}
	// Read once to confirm the listener attached, then stop reading so the
	// fan-out queue saturates on subsequent OnLiveIntent calls.
	s.OnLiveIntent(types.IntentEvent{IntentID: "warm", Kind: "FileRead"})
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("warmup recv: %v", err)
	}

	// Wait for SubscriberCount to reflect the listener — Subscribe
	// appends to s.listeners after the first WAL replay round trip; the
	// gauge poll will see >0 once the goroutine reaches the live-tail loop.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if env, _, _ := s.SubscriberCount(); env >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if env, _, _ := s.SubscriberCount(); env < 1 {
		t.Fatalf("SubscriberCount.envelope=%d, want ≥1 after Subscribe attached", env)
	}

	// Pump enough events that the 1-slot fan-out queue must drop some.
	for i := 0; i < 200; i++ {
		s.OnLiveIntent(types.IntentEvent{IntentID: "drop", Kind: "FileRead"})
	}
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if s.SubscriberDropped() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.SubscriberDropped(); got == 0 {
		t.Errorf("SubscriberDropped=0 after saturating a 1-slot queue with 200 sends; counter regressed")
	}

	// Detach: cancel the stream, and SubscriberCount should drop while the
	// running drop count remains visible (folded into droppedAccum).
	prev := s.SubscriberDropped()
	cancel()
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		env, _, _ := s.SubscriberCount()
		if env == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if env, _, _ := s.SubscriberCount(); env != 0 {
		t.Errorf("SubscriberCount.envelope=%d after stream cancel, want 0", env)
	}
	if after := s.SubscriberDropped(); after < prev {
		t.Errorf("SubscriberDropped decreased on disconnect: prev=%d after=%d", prev, after)
	}
}

// Snapshot is the standalone RPC counterpart to RESET_TO_SNAPSHOT — klctl
// `snapshot` and the aggregator's bootstrap path rely on it. The existing
// cursor-expired test only hits sendSnapshot indirectly; this exercises the
// public RPC end-to-end so a wiring regression (forgotten Stream handler)
// surfaces.
func TestSubscribeSnapshotRPC(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	snap := &fakeSnap{
		edges: []*protobuf.GraphEdge{
			{EdgeId: "g1", Kind: "exec→exec"},
			{EdgeId: "g2", Kind: "exec→connect"},
		},
		lifes: []*protobuf.ContainerLifecycleEvent{
			{Phase: "started", Meta: &protobuf.ContainerMeta{ContainerId: "c1"}},
		},
	}
	s := NewSubscribeServer(w, snap, "node-a")
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	stream, err := client.Snapshot(context.Background(), &protobuf.SnapshotRequest{})
	if err != nil {
		t.Fatal(err)
	}
	gotEdges, gotLife := 0, 0
	for {
		env, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("recv: %v", rerr)
		}
		if env.GetGraphEdge() != nil {
			gotEdges++
			if env.GetCursor().GetStream() != "graph-edge" {
				t.Errorf("edge cursor.stream=%q", env.GetCursor().GetStream())
			}
		}
		if env.GetLifecycle() != nil {
			gotLife++
			if env.GetCursor().GetStream() != "lifecycle" {
				t.Errorf("lifecycle cursor.stream=%q", env.GetCursor().GetStream())
			}
		}
	}
	if gotEdges != 2 || gotLife != 1 {
		t.Errorf("edges=%d lifecycle=%d, want 2/1", gotEdges, gotLife)
	}
}

// TestSubscribeSnapshotNilProvider asserts the early-return: when no
// SnapshotProvider is wired (kloudlens runs without a graph store), the
// RPC must complete cleanly with zero envelopes rather than panicking.
func TestSubscribeSnapshotNilProvider(t *testing.T) {
	dir := t.TempDir()
	w, _ := wal.Open(wal.Options{Dir: dir})
	defer w.Close()
	s := NewSubscribeServer(w, nil, "node-a") // snap=nil
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	stream, err := client.Snapshot(context.Background(), &protobuf.SnapshotRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for {
		_, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			return
		}
		if rerr != nil {
			t.Fatalf("expected clean EOF, got %v", rerr)
		}
	}
}

// passesFilter is the WAL-entry-keyed wrapper used by SubscribeIntents to
// drop unmatched entries during replay. It also accepts entries the
// envelope encoder doesn't recognize (returns true so the reader keeps
// scanning rather than silently swallowing). The envelope-keyed branch is
// already covered through SubscribeIntents/SubscribeFilterByKind — this
// test isolates the WAL-side helper.
func TestPassesFilterEntryShapes(t *testing.T) {
	cases := []struct {
		name string
		e    wal.Entry
		f    *protobuf.EventFilter
		want bool
	}{
		{
			name: "nil filter passes",
			e:    wal.Entry{Stream: "intent", Event: types.IntentEvent{Kind: "FileRead"}},
			f:    nil,
			want: true,
		},
		{
			name: "intent kind matches",
			e:    wal.Entry{Stream: "intent", Event: types.IntentEvent{Kind: "FileWrite"}},
			f:    &protobuf.EventFilter{Kinds: []string{"FileWrite"}},
			want: true,
		},
		{
			name: "intent kind mismatched",
			e:    wal.Entry{Stream: "intent", Event: types.IntentEvent{Kind: "Exec"}},
			f:    &protobuf.EventFilter{Kinds: []string{"FileWrite"}},
			want: false,
		},
		{
			name: "raw stream missing payload still passes",
			e:    wal.Entry{Stream: "raw"}, // Syscall=nil → entryToEnvelope returns nil
			f:    &protobuf.EventFilter{Kinds: []string{"FileWrite"}},
			want: true, // helper treats unknown shape as pass-through
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := passesFilter(c.e, c.f); got != c.want {
				t.Errorf("passesFilter=%v want %v", got, c.want)
			}
		})
	}
}

// envelopePassesFilter has three shape branches (intent, deviation,
// raw_syscall). Subscribe end-to-end tests already cover the intent
// branch; this rounds out the deviation and raw_syscall branches so a
// future filter-key change can't silently break them.
func TestEnvelopePassesFilterDeviationAndRaw(t *testing.T) {
	dev := func(kind, ns, pod string) *protobuf.EventEnvelope {
		return &protobuf.EventEnvelope{
			Payload: &protobuf.EventEnvelope_Deviation{Deviation: &protobuf.DeviationEvent{
				Kind: kind,
				Meta: &protobuf.ContainerMeta{Namespace: ns, Pod: pod},
			}},
		}
	}
	raw := func(name, cat, ns string, sev uint32) *protobuf.EventEnvelope {
		return &protobuf.EventEnvelope{
			Payload: &protobuf.EventEnvelope_RawSyscall{RawSyscall: &protobuf.SyscallEvent{
				SyscallName: name, Category: cat, Severity: sev,
				Meta: &protobuf.ContainerMeta{Namespace: ns},
			}},
		}
	}

	if !envelopePassesFilter(dev("new_exec", "ns1", "p1"), &protobuf.EventFilter{Kinds: []string{"new_exec"}}) {
		t.Error("deviation kind match should pass")
	}
	if envelopePassesFilter(dev("new_exec", "ns1", "p1"), &protobuf.EventFilter{Kinds: []string{"new_dns"}}) {
		t.Error("deviation kind mismatch should drop")
	}
	if envelopePassesFilter(dev("new_exec", "ns1", "p1"), &protobuf.EventFilter{Namespaces: []string{"other"}}) {
		t.Error("deviation ns mismatch should drop")
	}
	if envelopePassesFilter(dev("new_exec", "ns1", "p1"), &protobuf.EventFilter{Pods: []string{"otherpod"}}) {
		t.Error("deviation pod mismatch should drop")
	}

	// raw: kinds match against syscall name OR category — operators set one or the other.
	if !envelopePassesFilter(raw("openat", "file", "ns1", 0), &protobuf.EventFilter{Kinds: []string{"openat"}}) {
		t.Error("raw kind=name should pass")
	}
	if !envelopePassesFilter(raw("openat", "file", "ns1", 0), &protobuf.EventFilter{Kinds: []string{"file"}}) {
		t.Error("raw kind=category should pass")
	}
	if envelopePassesFilter(raw("openat", "file", "ns1", 0), &protobuf.EventFilter{Kinds: []string{"network"}}) {
		t.Error("raw kind mismatch should drop")
	}
	// Severity gate: filter min=2, event sev=1 → drop.
	if envelopePassesFilter(raw("openat", "file", "ns1", 1), &protobuf.EventFilter{MinSeverity: 2}) {
		t.Error("raw severity below floor should drop")
	}
	if !envelopePassesFilter(raw("openat", "file", "ns1", 3), &protobuf.EventFilter{MinSeverity: 2}) {
		t.Error("raw severity above floor should pass")
	}
}

// QueueLen surfaces the gRPC client's pending event count to /metrics. A
// non-running client (no server) must still report exactly the number of
// items the queue is holding. This guards against a regression where
// QueueLen might lock at zero for offline clients.
func TestGRPCQueueLen(t *testing.T) {
	c := &GRPCClient{
		addr:   "nowhere.invalid:1",
		queue:  make(chan *protobuf.IntentEvent, 4),
		cancel: func() {},
		done:   make(chan struct{}),
	}
	if got := c.QueueLen(); got != 0 {
		t.Errorf("baseline QueueLen=%d want 0", got)
	}
	c.queue <- &protobuf.IntentEvent{IntentId: "x"}
	c.queue <- &protobuf.IntentEvent{IntentId: "y"}
	if got := c.QueueLen(); got != 2 {
		t.Errorf("QueueLen after 2 pushes = %d, want 2", got)
	}
}

// nextBackoff doubles up to a 5-second cap. Off-by-one in the cap (e.g.
// `>=` instead of `>`) would either let backoff drift up to 10s or pin it
// at 2.5s, both of which slow recovery on flaky collectors.
func TestNextBackoff(t *testing.T) {
	cases := []struct {
		in, want time.Duration
	}{
		{200 * time.Millisecond, 400 * time.Millisecond},
		{2 * time.Second, 4 * time.Second},
		{3 * time.Second, 5 * time.Second},  // cap kicks in
		{5 * time.Second, 5 * time.Second},  // already capped
		{10 * time.Second, 5 * time.Second}, // far above cap → clamped
	}
	for _, c := range cases {
		if got := nextBackoff(c.in); got != c.want {
			t.Errorf("nextBackoff(%v)=%v want %v", c.in, got, c.want)
		}
	}
}

// sleepCtx returns true when the timer fires, false when ctx cancels first.
// The shutdown path of GRPCClient.run depends on the cancel branch — a bug
// where sleepCtx swallowed cancellation would block agent stop for the
// full backoff window (up to 5 s).
func TestSleepCtx(t *testing.T) {
	t.Run("timer wins", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		start := time.Now()
		if !sleepCtx(ctx, 10*time.Millisecond) {
			t.Fatal("expected true (timer fired)")
		}
		if elapsed := time.Since(start); elapsed < 5*time.Millisecond {
			t.Errorf("returned too early: %v", elapsed)
		}
	})
	t.Run("ctx cancel wins", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(5 * time.Millisecond)
			cancel()
		}()
		start := time.Now()
		if sleepCtx(ctx, 5*time.Second) {
			t.Fatal("expected false (cancel won)")
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Errorf("ctx cancel did not preempt sleep promptly: %v", elapsed)
		}
	})
}

// FileClient.setErr is exercised by Submit when MarshalJSON fails — but the
// IntentEvent type can't fail to marshal in practice, so the path is hit
// only via direct invocation. We assert Stats reports the error so /metrics
// can surface it as kloudlens_exporter_last_error.
func TestFileClientSetErr(t *testing.T) {
	dir := t.TempDir()
	c, err := OpenFileSink(FileOptions{Dir: dir, Shards: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	target := errors.New("induced")
	c.setErr(target)
	_, last := c.Stats()
	if !errors.Is(last, target) {
		t.Errorf("Stats.lastErr=%v want %v", last, target)
	}
}

// Sanity that bufconn round-trip helper resists a race when no events flow.
// Probes the dialer code path that newBufconnClient is built on; without
// at least one negative test, a regression that broke server registration
// would only surface in the live-traffic tests.
func TestSubscribeServerRegisters(t *testing.T) {
	dir := t.TempDir()
	w, _ := wal.Open(wal.Options{Dir: dir})
	defer w.Close()
	s := NewSubscribeServer(w, nil, "n")
	lis := bufconn.Listen(1 << 16)
	srv := grpc.NewServer()
	protobuf.RegisterEventServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient(
		"passthrough:bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cli := protobuf.NewEventServiceClient(conn)
	if _, err := cli.Ack(context.Background(), &protobuf.AckRequest{ConsumerId: "x", Cursor: &protobuf.Cursor{Seq: 1}}); err != nil {
		t.Errorf("Ack on freshly-registered server failed: %v", err)
	}
}
