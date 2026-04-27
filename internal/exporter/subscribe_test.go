// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package exporter

import (
	"context"
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

type fakeSnap struct {
	edges []*protobuf.GraphEdge
	lifes []*protobuf.ContainerLifecycleEvent
}

func (f *fakeSnap) DumpSessions() []*protobuf.GraphEdge                { return f.edges }
func (f *fakeSnap) DumpLifecycle() []*protobuf.ContainerLifecycleEvent { return f.lifes }

func startSubscribeServer(t *testing.T, s *SubscribeServer) (*bufconn.Listener, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 16)
	srv := grpc.NewServer()
	protobuf.RegisterEventServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	return lis, func() { srv.Stop() }
}

func dialSubscribe(t *testing.T, lis *bufconn.Listener) protobuf.EventServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(
		"passthrough:bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return protobuf.NewEventServiceClient(conn)
}

func TestSubscribeLiveFanOut(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Subscribe(ctx, &protobuf.SubscribeRequest{
		ConsumerId:        "c1",
		Streams:           []string{"intent"},
		FlowControlWindow: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Give the server a moment to attach the listener.
	time.Sleep(50 * time.Millisecond)

	s.OnLiveIntent(types.IntentEvent{IntentID: "e1", Kind: "FileRead"})
	s.OnLiveIntent(types.IntentEvent{IntentID: "e2", Kind: "FileWrite"})

	for i, want := range []string{"e1", "e2"} {
		env, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv[%d]: %v", i, err)
		}
		if got := env.GetIntent().GetIntentId(); got != want {
			t.Errorf("recv[%d]: got %q, want %q", i, got, want)
		}
		if env.GetCursor().GetNodeId() != "node-a" {
			t.Errorf("recv[%d]: node_id=%q", i, env.GetCursor().GetNodeId())
		}
	}
}

func TestSubscribeReplayFromCursor(t *testing.T) {
	dir := t.TempDir()
	w, _ := wal.Open(wal.Options{Dir: dir})
	defer w.Close()

	// Preload WAL with 5 intents.
	for i := 0; i < 5; i++ {
		_, _ = w.Append("intent", types.IntentEvent{IntentID: string(rune('a' + i))})
	}
	s := NewSubscribeServer(w, nil, "node-a")
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := client.Subscribe(ctx, &protobuf.SubscribeRequest{
		ConsumerId: "c2",
		Streams:    []string{"intent"},
		Cursor:     &protobuf.Cursor{Seq: 2}, // skip first 2
	})
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for i := 0; i < 3; i++ {
		env, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv[%d]: %v", i, err)
		}
		got = append(got, env.GetIntent().GetIntentId())
	}
	if want := []string{"c", "d", "e"}; !equalSS(got, want) {
		t.Errorf("replay got=%v want=%v", got, want)
	}
}

// Deviations land in the WAL under their own stream and replay through the
// envelope API like intents do. Before wal.AppendDeviation existed, the typed
// SubscribeDeviations RPC was live-only and envelope clients could not ask
// for deviation resume at all.
func TestSubscribeReplaysDeviationFromWAL(t *testing.T) {
	dir := t.TempDir()
	w, _ := wal.Open(wal.Options{Dir: dir})
	defer w.Close()

	s := NewSubscribeServer(w, nil, "node-a")
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	// Emit one intent and one deviation before any subscriber connects.
	// Both must survive replay at cursor=0 with streams=[intent,deviation].
	s.OnLiveIntent(types.IntentEvent{IntentID: "i1", Kind: "FileRead"})
	s.SubmitDeviation(types.DeviationEvent{
		DeviationID:    "d1",
		ProfileID:      "prof-1",
		Kind:           "new_exec",
		DeviationScore: 0.9,
		Evidence:       "unseen binary /bin/curl",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Subscribe(ctx, &protobuf.SubscribeRequest{
		ConsumerId: "c-dev",
		Streams:    []string{"intent", "deviation"},
	})
	if err != nil {
		t.Fatal(err)
	}

	gotIntent, gotDev := 0, 0
	var devID string
	var devSeq uint64
	for gotIntent+gotDev < 2 {
		env, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		switch {
		case env.GetIntent() != nil:
			gotIntent++
		case env.GetDeviation() != nil:
			gotDev++
			devID = env.GetDeviation().GetDeviationId()
			devSeq = env.GetCursor().GetSeq()
			if env.GetCursor().GetStream() != "deviation" {
				t.Errorf("cursor.stream=%q, want deviation", env.GetCursor().GetStream())
			}
		}
	}
	if gotIntent != 1 {
		t.Errorf("intent envelope count=%d, want 1", gotIntent)
	}
	if gotDev != 1 {
		t.Errorf("deviation envelope count=%d, want 1", gotDev)
	}
	if devID != "d1" {
		t.Errorf("deviation_id=%q, want d1", devID)
	}
	if devSeq == 0 {
		t.Errorf("cursor.seq=0 — deviation did not get a WAL seq stamped")
	}
}

func TestSubscribeAckStoresCursor(t *testing.T) {
	dir := t.TempDir()
	w, _ := wal.Open(wal.Options{Dir: dir})
	defer w.Close()
	s := NewSubscribeServer(w, nil, "node-a")
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	_, err := client.Ack(context.Background(), &protobuf.AckRequest{
		ConsumerId: "c3",
		Cursor:     &protobuf.Cursor{NodeId: "node-a", Stream: "intent", Seq: 42},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c := s.CursorOf("c3"); c == nil || c.Seq != 42 {
		t.Errorf("CursorOf(c3) = %+v", c)
	}
}

func TestSubscribeSnapshotOnExpired(t *testing.T) {
	dir := t.TempDir()
	w, _ := wal.Open(wal.Options{Dir: dir})
	defer w.Close()
	_, _ = w.Append("intent", types.IntentEvent{IntentID: "x"})
	// Force the stored startSeq high so cursor=1 looks expired.
	w.TrimForTest(100)

	snap := &fakeSnap{
		edges: []*protobuf.GraphEdge{{EdgeId: "g1", Kind: "x→y"}},
		lifes: []*protobuf.ContainerLifecycleEvent{{Phase: "started"}},
	}
	s := NewSubscribeServer(w, snap, "node-a")
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Subscribe(ctx, &protobuf.SubscribeRequest{
		ConsumerId: "c4",
		Streams:    []string{"intent"},
		Cursor:     &protobuf.Cursor{Seq: 1},
		OnExpired:  protobuf.OnExpiredPolicy_RESET_TO_SNAPSHOT,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for {
		env, err := stream.Recv()
		if err == io.EOF || err == context.DeadlineExceeded {
			break
		}
		if err != nil && ctx.Err() != nil {
			break
		}
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		got++
		if got >= 2 { // edge + lifecycle
			cancel()
			break
		}
		_ = env
	}
	if got < 2 {
		t.Errorf("got %d envelopes, want >=2 snapshot items", got)
	}
}

func TestSubscribeFilterByKind(t *testing.T) {
	dir := t.TempDir()
	w, _ := wal.Open(wal.Options{Dir: dir})
	defer w.Close()
	s := NewSubscribeServer(w, nil, "node-a")
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Subscribe(ctx, &protobuf.SubscribeRequest{
		ConsumerId: "c5",
		Streams:    []string{"intent"},
		Filter:     &protobuf.EventFilter{Kinds: []string{"FileWrite"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	s.OnLiveIntent(types.IntentEvent{IntentID: "drop1", Kind: "FileRead"})
	s.OnLiveIntent(types.IntentEvent{IntentID: "keep1", Kind: "FileWrite"})
	s.OnLiveIntent(types.IntentEvent{IntentID: "drop2", Kind: "Exec"})
	s.OnLiveIntent(types.IntentEvent{IntentID: "keep2", Kind: "FileWrite"})

	for i, want := range []string{"keep1", "keep2"} {
		env, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv[%d]: %v", i, err)
		}
		if got := env.GetIntent().GetIntentId(); got != want {
			t.Errorf("recv[%d]: got %q, want %q", i, got, want)
		}
	}
}

// A closed WAL rejects Append/AppendDeviation with wal.ErrClosed. Both
// SubmitDeviation and OnLiveIntent swallow the error (they intentionally
// never block the pipeline on WAL health), but the loss has to be visible
// on /metrics as kloudlens_wal_append_errors_total. Without the counter,
// operators can't distinguish "no events" from "events dropped silently".
func TestSubscribeWALAppendErrorsCounted(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	s := NewSubscribeServer(w, nil, "node-a")
	if err := w.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}

	// Post-Close writes would have nil-derefed in the original code; now
	// they must return ErrClosed and bump the counter.
	s.OnLiveIntent(types.IntentEvent{IntentID: "dropped-1", Kind: "FileRead"})
	s.OnLiveIntent(types.IntentEvent{IntentID: "dropped-2", Kind: "FileWrite"})
	s.SubmitDeviation(types.DeviationEvent{DeviationID: "d-drop", Kind: "new_exec"})

	if got := s.WALAppendErrors(); got != 3 {
		t.Errorf("WALAppendErrors=%d, want 3", got)
	}
}

func equalSS(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
