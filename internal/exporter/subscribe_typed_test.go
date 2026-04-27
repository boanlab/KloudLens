// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package exporter

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/internal/wal"
	"github.com/boanlab/kloudlens/pkg/types"
	"github.com/boanlab/kloudlens/protobuf"
)

// fakeGraph is the narrowest GraphSource stub: callers seed canned answers
// keyed by query kind, and the test asserts we routed node_id + query
// correctly. No locking — tests drive the fake from one goroutine.
type fakeGraph struct {
	lineage map[string][]string
	peers   map[string][]string
	touches map[string][]string
	reaches map[string][]string
}

func (g *fakeGraph) Lineage(id string) []string        { return g.lineage[id] }
func (g *fakeGraph) Peers(id string) []string          { return g.peers[id] }
func (g *fakeGraph) Touches(id string) []string        { return g.touches[id] }
func (g *fakeGraph) Reaches(id string, _ int) []string { return g.reaches[id] }

func newTypedServer(t *testing.T) *SubscribeServer {
	t.Helper()
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return NewSubscribeServer(w, nil, "node-a")
}

func TestSubscribeIntentsLiveTail(t *testing.T) {
	s := newTypedServer(t)
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.SubscribeIntents(ctx, &protobuf.IntentStreamRequest{FlowControlWindow: 8})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	s.OnLiveIntent(types.IntentEvent{IntentID: "i1", Kind: "FileRead"})
	s.OnLiveIntent(types.IntentEvent{IntentID: "i2", Kind: "FileWrite"})

	for i, want := range []string{"i1", "i2"} {
		iv, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv[%d]: %v", i, err)
		}
		if iv.GetIntentId() != want {
			t.Errorf("recv[%d]: got %q want %q", i, iv.GetIntentId(), want)
		}
	}
}

func TestSubscribeDeviationsFilter(t *testing.T) {
	s := newTypedServer(t)
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Filter: only kind=new_exec with score ≥ 0.5.
	stream, err := client.SubscribeDeviations(ctx, &protobuf.DeviationStreamRequest{
		Kinds:             []string{"new_exec"},
		MinScore:          0.5,
		FlowControlWindow: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	// Mix: one filtered-out (low score), one filtered-out (wrong kind), one pass.
	s.SubmitDeviation(types.DeviationEvent{DeviationID: "d1", Kind: "new_exec", DeviationScore: 0.2})
	s.SubmitDeviation(types.DeviationEvent{DeviationID: "d2", Kind: "rare_syscall", DeviationScore: 0.9})
	s.SubmitDeviation(types.DeviationEvent{DeviationID: "d3", Kind: "new_exec", DeviationScore: 0.8})

	dv, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if dv.GetDeviationId() != "d3" {
		t.Errorf("got %q, want d3 (filter should skip d1 low-score and d2 wrong-kind)", dv.GetDeviationId())
	}
}

func TestQueryGraphDispatch(t *testing.T) {
	s := newTypedServer(t)
	g := &fakeGraph{
		lineage: map[string][]string{"proc:1": {"proc:0"}},
		peers:   map[string][]string{"proc:1": {"peer:10.0.0.1:443"}},
		touches: map[string][]string{"proc:1": {"file:/etc/hosts"}},
		reaches: map[string][]string{"proc:1": {"proc:2", "proc:3"}},
	}
	s.SetGraph(g)
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	cases := []struct {
		query string
		want  []string
	}{
		{"lineage", []string{"proc:0"}},
		{"peers", []string{"peer:10.0.0.1:443"}},
		{"touches", []string{"file:/etc/hosts"}},
		{"reaches", []string{"proc:2", "proc:3"}},
	}
	for _, c := range cases {
		resp, err := client.QueryGraph(context.Background(), &protobuf.GraphQuery{
			NodeId: "proc:1",
			Query:  c.query,
		})
		if err != nil {
			t.Errorf("query=%s err=%v", c.query, err)
			continue
		}
		if !equalSS(resp.GetResultIds(), c.want) {
			t.Errorf("query=%s got=%v want=%v", c.query, resp.GetResultIds(), c.want)
		}
	}

	// Unknown query kind returns error.
	if _, err := client.QueryGraph(context.Background(), &protobuf.GraphQuery{
		NodeId: "proc:1", Query: "bogus",
	}); err == nil {
		t.Error("QueryGraph(bogus): expected error, got nil")
	}
}

func TestQueryGraphUnconfigured(t *testing.T) {
	s := newTypedServer(t)
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	if _, err := client.QueryGraph(context.Background(), &protobuf.GraphQuery{
		NodeId: "proc:1", Query: "lineage",
	}); err == nil {
		t.Error("expected error when graph source unset, got nil")
	}
}

func TestSubscribeSessionEdgeThenClose(t *testing.T) {
	s := newTypedServer(t)
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.SubscribeSession(ctx, &protobuf.SessionStreamRequest{
		SessionId: "sess-abc", FlowControlWindow: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	// An edge for a different session is dropped.
	s.OnLiveGraphEdge(types.GraphEdge{EdgeID: "eX", SessionID: "other"})
	// Two edges for the subscribed session.
	s.OnLiveGraphEdge(types.GraphEdge{EdgeID: "e1", SessionID: "sess-abc", Kind: "exec", SrcNode: "cont:x", DstNode: "proc:1"})
	s.OnLiveGraphEdge(types.GraphEdge{EdgeID: "e2", SessionID: "sess-abc", Kind: "file_touch", SrcNode: "proc:1", DstNode: "file:/tmp/a"})

	for i, want := range []string{"e1", "e2"} {
		upd, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv[%d]: %v", i, err)
		}
		if upd.GetClosed() {
			t.Fatalf("recv[%d]: unexpected closed=true", i)
		}
		if got := upd.GetEdge().GetEdgeId(); got != want {
			t.Errorf("recv[%d]: got %q want %q", i, got, want)
		}
	}

	// Close the session; expect a terminal SessionUpdate{closed=true} and EOF.
	s.OnSessionClosed("sess-abc")
	upd, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv(close): %v", err)
	}
	if !upd.GetClosed() {
		t.Errorf("recv(close): closed=false, want true")
	}
	if upd.GetSessionId() != "sess-abc" {
		t.Errorf("recv(close): session_id=%q", upd.GetSessionId())
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Errorf("recv after close: err=%v, want io.EOF", err)
	}
}

func TestSubscribeSessionRequiresID(t *testing.T) {
	s := newTypedServer(t)
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	stream, err := client.SubscribeSession(context.Background(), &protobuf.SessionStreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err == nil {
		t.Error("expected error on empty session_id, got nil")
	}
}

// TestSubscribeRawLiveTail covers the typed SubscribeRaw fan-out — every
// SubmitSyscall call should deliver a matching SyscallEvent over the
// stream, filtered server-side by syscall / category / namespace / pod.
func TestSubscribeRawLiveTail(t *testing.T) {
	s := newTypedServer(t)
	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Filter: only syscall_name=openat in category=file.
	stream, err := client.SubscribeRaw(ctx, &protobuf.RawStreamRequest{
		Syscalls:          []string{"openat"},
		Categories:        []string{"file"},
		FlowControlWindow: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	// Mix: filtered-out (wrong syscall), filtered-out (wrong category), pass.
	s.SubmitSyscall(types.SyscallEvent{EventID: "s1", SyscallName: "close", Category: "file"})
	s.SubmitSyscall(types.SyscallEvent{EventID: "s2", SyscallName: "openat", Category: "network"})
	s.SubmitSyscall(types.SyscallEvent{EventID: "s3", SyscallName: "openat", Category: "file", Resource: "/etc/hosts"})

	sc, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if sc.GetEventId() != "s3" {
		t.Errorf("got %q, want s3 (filter should skip s1 wrong-syscall and s2 wrong-category)", sc.GetEventId())
	}
	if sc.GetResource() != "/etc/hosts" {
		t.Errorf("resource not propagated: %q", sc.GetResource())
	}
}

// TestSubscribeRawReplayFromWAL covers the envelope Subscribe(streams=["raw"])
// path: an operator restarts and resumes from a cursor, and the WAL replays
// every appended SyscallEvent as an EventEnvelope_RawSyscall.
func TestSubscribeRawReplayFromWAL(t *testing.T) {
	s := newTypedServer(t)
	// Append before any client connects so the replay path (not the live
	// fan-out) is what delivers the events.
	s.SubmitSyscall(types.SyscallEvent{EventID: "r1", SyscallName: "openat", Category: "file"})
	s.SubmitSyscall(types.SyscallEvent{EventID: "r2", SyscallName: "close", Category: "file"})

	lis, stop := startSubscribeServer(t, s)
	defer stop()
	client := dialSubscribe(t, lis)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Subscribe(ctx, &protobuf.SubscribeRequest{
		Streams: []string{"raw"},
		Cursor:  &protobuf.Cursor{Seq: 0},
	})
	if err != nil {
		t.Fatal(err)
	}

	for i, want := range []string{"r1", "r2"} {
		env, err := stream.Recv()
		if err == io.EOF {
			t.Fatalf("recv[%d]: unexpected EOF", i)
		}
		if err != nil {
			t.Fatalf("recv[%d]: %v", i, err)
		}
		rs := env.GetRawSyscall()
		if rs == nil {
			t.Fatalf("recv[%d]: envelope has no raw_syscall payload: %+v", i, env)
		}
		if rs.GetEventId() != want {
			t.Errorf("recv[%d]: got %q want %q", i, rs.GetEventId(), want)
		}
		if c := env.GetCursor(); c == nil || c.GetStream() != "raw" {
			t.Errorf("recv[%d]: cursor stream = %v, want raw", i, c)
		}
	}
}
