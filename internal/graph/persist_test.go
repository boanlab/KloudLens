// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

func openTestBolt(t *testing.T) (*BoltPersister, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.db")
	p, err := OpenBolt(path, 2*time.Second)
	if err != nil {
		t.Fatalf("OpenBolt: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, path
}

func TestBoltPersisterSurvivesReopen(t *testing.T) {
	p, path := openTestBolt(t)

	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	s := New(Config{Clock: clock})
	s.Persist(p)

	_ = s.AddEdge(mkEdge("e1", EdgeExec, "proc:1", "proc:2", "sess-a"))
	_ = s.AddEdge(mkEdge("e2", EdgeFork, "proc:2", "proc:3", "sess-a"))
	_ = s.AddEdge(mkEdge("e3", EdgeIPCConnect, "proc:3", "peer:10.0.0.1:443", "sess-b"))
	s.CloseSession("sess-a")

	_ = p.Close()

	// Reopen as a fresh store and replay.
	p2, err := OpenBolt(path, 2*time.Second)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer p2.Close()

	s2 := New(Config{Clock: clock})
	if err := s2.LoadInto(p2); err != nil {
		t.Fatalf("LoadInto: %v", err)
	}

	if s2.NodeCount() != 4 {
		t.Fatalf("nodes after reload = %d (want 4)", s2.NodeCount())
	}
	if s2.EdgeCount() != 3 {
		t.Fatalf("edges after reload = %d (want 3)", s2.EdgeCount())
	}
	if s2.SessionCount() != 2 {
		t.Fatalf("sessions after reload = %d (want 2)", s2.SessionCount())
	}

	// Lineage/Peers must work against the reloaded graph.
	lin := s2.Lineage("proc:3")
	if len(lin) == 0 || lin[0] != "proc:2" {
		t.Fatalf("lineage(proc:3) = %v (want proc:2 first)", lin)
	}
	peers := s2.Peers("proc:3")
	if len(peers) != 1 || peers[0] != "peer:10.0.0.1:443" {
		t.Fatalf("peers(proc:3) = %v", peers)
	}

	// Closed session should still be closed on disk (closedAt non-zero).
	_, _, sessions, err := p2.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if sa, ok := sessions["sess-a"]; !ok || sa.ClosedAt.IsZero() {
		t.Fatalf("sess-a closedAt not persisted: %+v ok=%v", sa, ok)
	}
	if sb, ok := sessions["sess-b"]; !ok || !sb.ClosedAt.IsZero() {
		t.Fatalf("sess-b should still be open: %+v ok=%v", sb, ok)
	}
}

func TestBoltPersisterDropSessionRemovesEdges(t *testing.T) {
	p, _ := openTestBolt(t)

	clock := func() time.Time { return time.Unix(2_000_000_000, 0) }
	s := New(Config{Clock: clock, SessionTTL: time.Second})
	s.Persist(p)

	_ = s.AddEdge(mkEdge("e1", EdgeExec, "proc:1", "proc:2", "s1"))
	s.CloseSession("s1")

	// Advance clock past TTL so Purge drops s1.
	s.cfg.Clock = func() time.Time { return time.Unix(2_000_000_100, 0) }
	if n := s.Purge(); n != 1 {
		t.Fatalf("Purge dropped %d (want 1)", n)
	}

	nodes, edges, sessions, err := p.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, ok := sessions["s1"]; ok {
		t.Fatalf("sess still on disk: %+v", sessions)
	}
	if len(edges) != 0 {
		t.Fatalf("edges still on disk: %+v", edges)
	}
	if len(nodes) != 0 {
		t.Fatalf("nodes not orphan-GC'd: %+v", nodes)
	}
}

func TestBoltPersisterWriteThroughShape(t *testing.T) {
	p, _ := openTestBolt(t)
	clock := func() time.Time { return time.Unix(1_700_000_100, 0) }
	s := New(Config{Clock: clock})
	s.Persist(p)

	s.AddNode(Node{ID: "proc:42", Kind: NodeProcess, Label: "custom", Attrs: map[string]string{"pod": "ubuntu-1"}})
	_ = s.AddEdge(types.GraphEdge{
		EdgeID: "e1", Kind: EdgeFileTouch,
		SrcNode: "proc:42", DstNode: "file:/etc/hosts",
		SessionID: "s1", TSNS: 1,
		Attributes: map[string]string{"op": "read"},
	})

	nodes, edges, sessions, err := p.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	var gotCustom bool
	for _, n := range nodes {
		if n.ID == "proc:42" {
			if n.Label != "custom" || n.Attrs["pod"] != "ubuntu-1" {
				t.Fatalf("proc:42 not round-tripped: %+v", n)
			}
			gotCustom = true
		}
	}
	if !gotCustom {
		t.Fatalf("proc:42 missing from snapshot")
	}
	if len(edges) != 1 || edges[0].EdgeID != "e1" || edges[0].Attributes["op"] != "read" {
		t.Fatalf("edge round-trip: %+v", edges)
	}
	if sess, ok := sessions["s1"]; !ok || !sess.Edges["e1"] {
		t.Fatalf("session s1 not tracked: %+v", sess)
	}
}

func TestLoadIntoEmptyDBIsNoOp(t *testing.T) {
	p, _ := openTestBolt(t)
	s := New(Config{})
	if err := s.LoadInto(p); err != nil {
		t.Fatalf("LoadInto empty: %v", err)
	}
	if s.NodeCount() != 0 || s.EdgeCount() != 0 || s.SessionCount() != 0 {
		t.Fatalf("non-zero state after empty LoadInto")
	}
}
