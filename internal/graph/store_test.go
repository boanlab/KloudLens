// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"slices"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

func mkEdge(id, kind, src, dst, session string) types.GraphEdge {
	return types.GraphEdge{EdgeID: id, Kind: kind, SrcNode: src, DstNode: dst, SessionID: session, TSNS: 1}
}

func TestAddEdgeCreatesNodesWithInferredKind(t *testing.T) {
	s := New(Config{})
	if err := s.AddEdge(mkEdge("e1", EdgeExec, "proc:100", "proc:200", "sess-a")); err != nil {
		t.Fatalf("add edge: %v", err)
	}
	if n, ok := s.NodeByID("proc:100"); !ok || n.Kind != NodeProcess {
		t.Fatalf("src node: %+v ok=%v", n, ok)
	}
	if n, ok := s.NodeByID("proc:200"); !ok || n.Kind != NodeProcess {
		t.Fatalf("dst node: %+v ok=%v", n, ok)
	}
	if s.EdgeCount() != 1 || s.SessionCount() != 1 {
		t.Fatalf("counts: edges=%d sessions=%d", s.EdgeCount(), s.SessionCount())
	}
}

func TestAddEdgeRejectsMalformed(t *testing.T) {
	s := New(Config{})
	err := s.AddEdge(types.GraphEdge{EdgeID: "e1", Kind: EdgeExec}) // missing src/dst
	if err == nil {
		t.Fatal("expected error for missing fields")
	}
}

func TestAddEdgeIdempotent(t *testing.T) {
	s := New(Config{})
	e := mkEdge("e1", EdgeExec, "proc:1", "proc:2", "s")
	if err := s.AddEdge(e); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEdge(e); err != nil {
		t.Fatal(err)
	}
	if s.EdgeCount() != 1 {
		t.Fatalf("duplicate add: %d", s.EdgeCount())
	}
}

func TestLineageWalksForkExecChain(t *testing.T) {
	s := New(Config{})
	// init → bash → sh → curl
	_ = s.AddEdge(mkEdge("e1", EdgeFork, "proc:1", "proc:10", "s"))
	_ = s.AddEdge(mkEdge("e2", EdgeExec, "proc:10", "proc:20", "s"))
	_ = s.AddEdge(mkEdge("e3", EdgeFork, "proc:20", "proc:30", "s"))

	got := s.Lineage("proc:30")
	want := []string{"proc:20", "proc:10", "proc:1"}
	if !slices.Equal(got, want) {
		t.Fatalf("lineage got %v want %v", got, want)
	}
}

func TestLineageHandlesCycle(t *testing.T) {
	s := New(Config{})
	// Pathological cycle — shouldn't infinite-loop.
	_ = s.AddEdge(mkEdge("e1", EdgeExec, "proc:a", "proc:b", "s"))
	_ = s.AddEdge(mkEdge("e2", EdgeExec, "proc:b", "proc:a", "s"))
	got := s.Lineage("proc:b")
	if len(got) != 1 || got[0] != "proc:a" {
		t.Fatalf("cycle-guard broken: %v", got)
	}
}

func TestPeersReturnsIPCTargets(t *testing.T) {
	s := New(Config{})
	_ = s.AddEdge(mkEdge("e1", EdgeIPCConnect, "proc:1", "peer:1.2.3.4:443", "s"))
	_ = s.AddEdge(mkEdge("e2", EdgeIPCConnect, "proc:1", "peer:10.0.0.5:80", "s"))
	_ = s.AddEdge(mkEdge("e3", EdgeFileTouch, "proc:1", "file:/etc/hosts", "s")) // not a peer
	// duplicate peer should dedupe
	_ = s.AddEdge(mkEdge("e4", EdgeIPCConnect, "proc:1", "peer:1.2.3.4:443", "s"))

	got := s.Peers("proc:1")
	slices.Sort(got)
	want := []string{"peer:1.2.3.4:443", "peer:10.0.0.5:80"}
	if !slices.Equal(got, want) {
		t.Fatalf("peers got %v want %v", got, want)
	}
}

func TestTouchesReturnsFileTargets(t *testing.T) {
	s := New(Config{})
	_ = s.AddEdge(mkEdge("e1", EdgeFileTouch, "proc:1", "file:/etc/passwd", "s"))
	_ = s.AddEdge(mkEdge("e2", EdgeFileTouch, "proc:1", "file:/tmp/x", "s"))
	_ = s.AddEdge(mkEdge("e3", EdgeIPCConnect, "proc:1", "peer:1.1.1.1:53", "s"))

	got := s.Touches("proc:1")
	slices.Sort(got)
	want := []string{"file:/etc/passwd", "file:/tmp/x"}
	if !slices.Equal(got, want) {
		t.Fatalf("touches got %v want %v", got, want)
	}
}

func TestReachesBFSDepthLimit(t *testing.T) {
	s := New(Config{})
	// A → B → C → D
	_ = s.AddEdge(mkEdge("e1", EdgeExec, "proc:A", "proc:B", "s"))
	_ = s.AddEdge(mkEdge("e2", EdgeExec, "proc:B", "proc:C", "s"))
	_ = s.AddEdge(mkEdge("e3", EdgeExec, "proc:C", "proc:D", "s"))
	// Plus a branch from A to a file
	_ = s.AddEdge(mkEdge("e4", EdgeFileTouch, "proc:A", "file:/etc/foo", "s"))

	got := s.Reaches("proc:A", 1)
	slices.Sort(got)
	want := []string{"file:/etc/foo", "proc:B"}
	if !slices.Equal(got, want) {
		t.Fatalf("depth 1: got %v want %v", got, want)
	}

	got3 := s.Reaches("proc:A", 3)
	slices.Sort(got3)
	want3 := []string{"file:/etc/foo", "proc:B", "proc:C", "proc:D"}
	if !slices.Equal(got3, want3) {
		t.Fatalf("depth 3: got %v want %v", got3, want3)
	}
}

func TestCloseSessionThenPurgeAfterTTL(t *testing.T) {
	current := time.Unix(1000, 0)
	s := New(Config{SessionTTL: 60 * time.Second, Clock: func() time.Time { return current }})
	_ = s.AddEdge(mkEdge("e1", EdgeExec, "proc:1", "proc:2", "sess-a"))
	_ = s.AddEdge(mkEdge("e2", EdgeFileTouch, "proc:2", "file:/tmp/z", "sess-a"))

	s.CloseSession("sess-a")
	current = current.Add(30 * time.Second)
	if n := s.Purge(); n != 0 {
		t.Fatalf("early purge dropped: %d", n)
	}
	current = current.Add(60 * time.Second)
	if n := s.Purge(); n != 1 {
		t.Fatalf("late purge: %d", n)
	}
	if s.EdgeCount() != 0 {
		t.Fatalf("edges not dropped: %d", s.EdgeCount())
	}
	if s.NodeCount() != 0 {
		t.Fatalf("orphan nodes not dropped: %d", s.NodeCount())
	}
}

// TestPurgeBumpsPurgedTotal ensures the cumulative accumulator used by
// kloudlens_graph_sessions_purged_total actually advances when sessions
// fall out of TTL. A regression that left it at 0 would make the "is
// the purger running at all?" dashboard panel useless even though
// Purge itself worked — a class of bug that already bit WAL GC.
func TestPurgeBumpsPurgedTotal(t *testing.T) {
	current := time.Unix(1000, 0)
	s := New(Config{SessionTTL: 10 * time.Second, Clock: func() time.Time { return current }})
	_ = s.AddEdge(mkEdge("e1", EdgeExec, "proc:1", "proc:2", "sess-a"))
	_ = s.AddEdge(mkEdge("e2", EdgeExec, "proc:3", "proc:4", "sess-b"))
	s.CloseSession("sess-a")
	s.CloseSession("sess-b")

	if got := s.PurgedTotal(); got != 0 {
		t.Fatalf("PurgedTotal before TTL = %d, want 0", got)
	}
	current = current.Add(30 * time.Second)
	if n := s.Purge(); n != 2 {
		t.Fatalf("Purge dropped %d, want 2", n)
	}
	if got := s.PurgedTotal(); got != 2 {
		t.Errorf("PurgedTotal after first Purge = %d, want 2", got)
	}
	// Idempotent second call should not move the counter.
	_ = s.Purge()
	if got := s.PurgedTotal(); got != 2 {
		t.Errorf("PurgedTotal after empty Purge = %d, want 2", got)
	}
}

func TestLRUEvictsOldestWhenOverCap(t *testing.T) {
	s := New(Config{MaxSessions: 2})
	_ = s.AddEdge(mkEdge("e1", EdgeExec, "proc:1", "proc:2", "sess-a"))
	_ = s.AddEdge(mkEdge("e2", EdgeExec, "proc:3", "proc:4", "sess-b"))
	// Touching sess-a again makes sess-b the LRU.
	_ = s.AddEdge(mkEdge("e3", EdgeExec, "proc:2", "proc:5", "sess-a"))
	// Adding sess-c pushes over cap → sess-b evicted.
	_ = s.AddEdge(mkEdge("e4", EdgeExec, "proc:10", "proc:11", "sess-c"))

	if s.SessionCount() != 2 {
		t.Fatalf("cap not enforced: %d", s.SessionCount())
	}
	// sess-b's edge should be gone.
	if _, ok := s.edges["e2"]; ok {
		t.Fatal("LRU victim's edge not removed")
	}
	// sess-a and sess-c edges remain.
	if _, ok := s.edges["e1"]; !ok {
		t.Fatal("sess-a e1 should remain")
	}
	if _, ok := s.edges["e4"]; !ok {
		t.Fatal("sess-c e4 should remain")
	}
}

func TestNodeWithSharedEdgeSurvivesPartialPurge(t *testing.T) {
	current := time.Unix(0, 0)
	s := New(Config{SessionTTL: 10 * time.Second, Clock: func() time.Time { return current }})
	// Same src node participates in two sessions.
	_ = s.AddEdge(mkEdge("e1", EdgeExec, "proc:init", "proc:child1", "sess-1"))
	_ = s.AddEdge(mkEdge("e2", EdgeExec, "proc:init", "proc:child2", "sess-2"))

	s.CloseSession("sess-1")
	current = current.Add(20 * time.Second)
	s.Purge()

	if _, ok := s.NodeByID("proc:init"); !ok {
		t.Fatal("proc:init should remain — still referenced by sess-2")
	}
	if _, ok := s.NodeByID("proc:child1"); ok {
		t.Fatal("proc:child1 should be gone — only in sess-1")
	}
	if _, ok := s.NodeByID("proc:child2"); !ok {
		t.Fatal("proc:child2 should remain — part of sess-2")
	}
}

func TestAddNodeEnrichesExisting(t *testing.T) {
	s := New(Config{})
	_ = s.AddEdge(mkEdge("e1", EdgeExec, "proc:1", "proc:2", "s"))
	s.AddNode(Node{ID: "proc:1", Label: "bash", Attrs: map[string]string{"binary": "/bin/bash"}})
	n, _ := s.NodeByID("proc:1")
	if n.Label != "bash" || n.Attrs["binary"] != "/bin/bash" || n.Kind != NodeProcess {
		t.Fatalf("enrichment: %+v", n)
	}
}
