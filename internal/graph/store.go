// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package graph implements the node-local session graph. The in-memory
// store is a typed-edge graph with fixed queries (lineage / peers /
// touches / reaches), session partitioning, and per-session LRU. A
// companion bbolt persister (persist.go) provides optional durability;
// the public API is the same whether persistence is configured or not.
package graph

import (
	"container/list"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

// Edge kinds. These mirror the values accepted on types.GraphEdge.Kind.
const (
	EdgeFork       = "FORK"
	EdgeExec       = "EXEC"
	EdgeIPCConnect = "IPC_CONNECT"
	EdgeFileTouch  = "FILE_TOUCH"
	EdgeSignal     = "SIGNAL"
	EdgePtrace     = "PTRACE"
	EdgeMountShare = "MOUNT_SHARE"
)

// Node kinds.
const (
	NodeProcess   = "process"
	NodeContainer = "container"
	NodeFile      = "file"
	NodePeer      = "peer"
)

// Node is a vertex in the graph. ID is assumed globally unique; callers
// typically use "proc:<pid>", "file:<path>", "peer:<ip:port>", "cont:<cid>".
type Node struct {
	ID    string
	Kind  string
	Label string
	Attrs map[string]string
}

// Config controls caps and retention.
type Config struct {
	// MaxSessions is a hard ceiling on tracked sessions. When exceeded, the
	// LRU session is evicted regardless of close state.
	MaxSessions int // default 1024
	// SessionTTL is the post-close retention window.
	SessionTTL time.Duration // default 1h
	Clock      func() time.Time
}

func (c *Config) withDefaults() {
	if c.MaxSessions == 0 {
		c.MaxSessions = 1024
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = time.Hour
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
}

// Store is goroutine-safe.
type Store struct {
	mu  sync.RWMutex
	cfg Config

	nodes map[string]*Node
	edges map[string]*types.GraphEdge
	out   map[string][]string // nodeID -> edge IDs outgoing
	in    map[string][]string // nodeID -> edge IDs incoming

	sessions map[string]*sessionState
	lru      *list.List
	lruIdx   map[string]*list.Element

	// persist is an optional write-through hook; nil means memory-only.
	persist Persister

	// purgedTotal is the cumulative count of sessions Purge has evicted
	// since startup. Surfaced on /metrics as
	// kloudlens_graph_sessions_purged_total so operators can tell whether
	// the janitor is actually running — a flat series across a multi-day
	// node would mean Purge is not being called or the TTL is unreached.
	purgedTotal atomic.Uint64
}

type sessionState struct {
	id       string
	edges    map[string]struct{}
	lastTS   time.Time
	closedAt time.Time // zero = still open
}

// ErrEdgeMissingFields is returned when AddEdge receives a malformed edge.
var ErrEdgeMissingFields = errors.New("graph: edge missing required fields")

// New returns a Store with cfg defaults applied.
func New(cfg Config) *Store {
	cfg.withDefaults()
	return &Store{
		cfg:      cfg,
		nodes:    map[string]*Node{},
		edges:    map[string]*types.GraphEdge{},
		out:      map[string][]string{},
		in:       map[string][]string{},
		sessions: map[string]*sessionState{},
		lru:      list.New(),
		lruIdx:   map[string]*list.Element{},
	}
}

// AddNode registers (or replaces) a node. Returning existing label fields are
// preserved if n has empty strings.
func (s *Store) AddNode(n Node) {
	if n.ID == "" {
		return
	}
	s.mu.Lock()
	if prev, ok := s.nodes[n.ID]; ok {
		if n.Kind == "" {
			n.Kind = prev.Kind
		}
		if n.Label == "" {
			n.Label = prev.Label
		}
	}
	cp := n
	s.nodes[n.ID] = &cp
	p := s.persist
	s.mu.Unlock()
	if p != nil {
		_ = p.SaveNode(cp)
	}
}

// AddEdge inserts an edge and creates referenced nodes if missing. The edge
// is attached to its session and the session's LRU position is updated.
func (s *Store) AddEdge(e types.GraphEdge) error {
	if e.EdgeID == "" || e.SrcNode == "" || e.DstNode == "" || e.Kind == "" {
		return ErrEdgeMissingFields
	}
	s.mu.Lock()

	srcNew := s.ensureNodeLocked(e.SrcNode)
	dstNew := s.ensureNodeLocked(e.DstNode)

	// Replace an existing edge with the same id (idempotent).
	if _, ok := s.edges[e.EdgeID]; ok {
		s.mu.Unlock()
		return nil
	}
	cp := e
	s.edges[e.EdgeID] = &cp
	s.out[e.SrcNode] = append(s.out[e.SrcNode], e.EdgeID)
	s.in[e.DstNode] = append(s.in[e.DstNode], e.EdgeID)

	var sessUpdate *sessionState
	if e.SessionID != "" {
		ss := s.sessions[e.SessionID]
		now := s.cfg.Clock()
		if ss == nil {
			ss = &sessionState{id: e.SessionID, edges: map[string]struct{}{}}
			s.sessions[e.SessionID] = ss
			s.lruIdx[e.SessionID] = s.lru.PushFront(e.SessionID)
		} else {
			if el, ok := s.lruIdx[e.SessionID]; ok {
				s.lru.MoveToFront(el)
			}
		}
		ss.edges[e.EdgeID] = struct{}{}
		ss.lastTS = now
		sessUpdate = ss
		s.enforceSessionCapLocked()
	}
	p := s.persist
	// Snapshot any newly-materialised nodes for write-through before unlocking.
	var newNodes []Node
	if p != nil {
		if srcNew != nil {
			newNodes = append(newNodes, *srcNew)
		}
		if dstNew != nil && dstNew != srcNew {
			newNodes = append(newNodes, *dstNew)
		}
	}
	s.mu.Unlock()
	if p != nil {
		for _, n := range newNodes {
			_ = p.SaveNode(n)
		}
		_ = p.SaveEdge(cp)
		if sessUpdate != nil {
			_ = p.UpdateSession(sessUpdate.id, sessUpdate.lastTS, sessUpdate.closedAt, e.EdgeID)
		}
	}
	return nil
}

// ensureNodeLocked derives a minimal node from an ID prefix when the caller
// hasn't explicitly added one yet. Returns the pointer to a newly-created
// node for write-through, or nil when the node already existed.
func (s *Store) ensureNodeLocked(id string) *Node {
	if _, ok := s.nodes[id]; ok {
		return nil
	}
	kind := ""
	switch {
	case hasPrefix(id, "proc:"):
		kind = NodeProcess
	case hasPrefix(id, "cont:"):
		kind = NodeContainer
	case hasPrefix(id, "file:"):
		kind = NodeFile
	case hasPrefix(id, "peer:"):
		kind = NodePeer
	}
	n := &Node{ID: id, Kind: kind, Label: id}
	s.nodes[id] = n
	return n
}

// CloseSession marks a session closed. Its edges/nodes are kept until TTL.
func (s *Store) CloseSession(id string) {
	s.mu.Lock()
	ss := s.sessions[id]
	if ss == nil {
		s.mu.Unlock()
		return
	}
	ss.closedAt = s.cfg.Clock()
	p := s.persist
	lastTS := ss.lastTS
	closedAt := ss.closedAt
	s.mu.Unlock()
	if p != nil {
		_ = p.UpdateSession(id, lastTS, closedAt, "")
	}
}

// Purge evicts sessions closed for longer than TTL. Returns the number of
// sessions dropped.
func (s *Store) Purge() int {
	s.mu.Lock()
	now := s.cfg.Clock()
	type drop struct {
		id       string
		edges    []string
		orphaned []string
	}
	var drops []drop
	for id, ss := range s.sessions {
		if ss.closedAt.IsZero() {
			continue
		}
		if now.Sub(ss.closedAt) >= s.cfg.SessionTTL {
			eids, orph := s.dropSessionLocked(id)
			drops = append(drops, drop{id: id, edges: eids, orphaned: orph})
		}
	}
	p := s.persist
	s.mu.Unlock()
	if p != nil {
		for _, d := range drops {
			_ = p.DropSession(d.id, d.edges, d.orphaned)
		}
	}
	if n := len(drops); n > 0 {
		s.purgedTotal.Add(uint64(n))
	}
	return len(drops)
}

// PurgedTotal is the monotonic count of sessions Purge has evicted since
// startup.
func (s *Store) PurgedTotal() uint64 {
	return s.purgedTotal.Load()
}

func (s *Store) enforceSessionCapLocked() {
	for len(s.sessions) > s.cfg.MaxSessions {
		el := s.lru.Back()
		if el == nil {
			return
		}
		id := el.Value.(string)
		eids, orph := s.dropSessionLocked(id)
		// Persist is best-effort even under cap enforcement; we already hold
		// the lock, so dispatch after returning would be cleaner — but
		// enforce-on-add is rare and keeping it inline avoids a deferred
		// queue. The persist call itself does not touch Store state.
		if s.persist != nil {
			_ = s.persist.DropSession(id, eids, orph)
		}
	}
}

// dropSessionLocked removes a session in-memory and returns the edge IDs it
// owned plus any nodes that became orphaned, so the caller can replicate the
// deletion to the persister.
func (s *Store) dropSessionLocked(id string) (edgeIDs []string, orphanedNodes []string) {
	ss := s.sessions[id]
	if ss == nil {
		return nil, nil
	}
	// Track nodes that could become orphaned after edge removal.
	candidates := map[string]struct{}{}
	for eid := range ss.edges {
		e := s.edges[eid]
		if e == nil {
			continue
		}
		s.out[e.SrcNode] = removeString(s.out[e.SrcNode], eid)
		s.in[e.DstNode] = removeString(s.in[e.DstNode], eid)
		candidates[e.SrcNode] = struct{}{}
		candidates[e.DstNode] = struct{}{}
		delete(s.edges, eid)
		edgeIDs = append(edgeIDs, eid)
	}
	delete(s.sessions, id)
	if el, ok := s.lruIdx[id]; ok {
		s.lru.Remove(el)
		delete(s.lruIdx, id)
	}
	for nid := range candidates {
		if len(s.out[nid]) == 0 && len(s.in[nid]) == 0 {
			delete(s.nodes, nid)
			delete(s.out, nid)
			delete(s.in, nid)
			orphanedNodes = append(orphanedNodes, nid)
		}
	}
	return edgeIDs, orphanedNodes
}

// Lineage returns the ancestor chain of nodeID, closest first, walking
// backwards through FORK/EXEC edges. Cycles are guarded against.
func (s *Store) Lineage(nodeID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	seen := map[string]bool{nodeID: true}
	cur := nodeID
	for {
		var parent string
		for _, eid := range s.in[cur] {
			e := s.edges[eid]
			if e == nil {
				continue
			}
			if e.Kind == EdgeFork || e.Kind == EdgeExec {
				parent = e.SrcNode
				break
			}
		}
		if parent == "" || seen[parent] {
			break
		}
		seen[parent] = true
		out = append(out, parent)
		cur = parent
	}
	return out
}

// Peers returns node IDs reached by outgoing IPC_CONNECT edges.
func (s *Store) Peers(nodeID string) []string {
	return s.outgoingByKind(nodeID, EdgeIPCConnect)
}

// Touches returns file nodes reached by outgoing FILE_TOUCH edges.
func (s *Store) Touches(nodeID string) []string {
	return s.outgoingByKind(nodeID, EdgeFileTouch)
}

// Reaches performs a BFS of depth ≤ maxDepth over outgoing edges of any kind
// and returns reachable node IDs (excluding the start).
func (s *Store) Reaches(nodeID string, maxDepth int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if maxDepth <= 0 {
		return nil
	}
	visited := map[string]bool{nodeID: true}
	frontier := []string{nodeID}
	var out []string
	for depth := 0; depth < maxDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, n := range frontier {
			for _, eid := range s.out[n] {
				e := s.edges[eid]
				if e == nil {
					continue
				}
				if !visited[e.DstNode] {
					visited[e.DstNode] = true
					out = append(out, e.DstNode)
					next = append(next, e.DstNode)
				}
			}
		}
		frontier = next
	}
	return out
}

func (s *Store) outgoingByKind(nodeID, kind string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	seen := map[string]bool{}
	for _, eid := range s.out[nodeID] {
		e := s.edges[eid]
		if e == nil || e.Kind != kind {
			continue
		}
		if seen[e.DstNode] {
			continue
		}
		seen[e.DstNode] = true
		out = append(out, e.DstNode)
	}
	return out
}

// OutgoingEdges returns a copy of every outgoing edge from nodeID. Order
// is insertion order. Used by admin / test paths that need edge-level
// attributes; hot-path consumers should use Peers/Lineage instead.
func (s *Store) OutgoingEdges(nodeID string) []types.GraphEdge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.out[nodeID]
	if len(ids) == 0 {
		return nil
	}
	out := make([]types.GraphEdge, 0, len(ids))
	for _, eid := range ids {
		if e := s.edges[eid]; e != nil {
			out = append(out, *e)
		}
	}
	return out
}

// NodeCount returns the number of vertices.
func (s *Store) NodeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nodes)
}

// EdgeCount returns the number of edges.
func (s *Store) EdgeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.edges)
}

// SessionCount returns the number of tracked sessions.
func (s *Store) SessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// NodeByID returns a copy of the stored node, if any.
func (s *Store) NodeByID(id string) (Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.nodes[id]
	if !ok {
		return Node{}, false
	}
	return *n, true
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

func removeString(ss []string, v string) []string {
	for i, s := range ss {
		if s == v {
			return append(ss[:i], ss[i+1:]...)
		}
	}
	return ss
}
