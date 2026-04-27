// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package graph

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"

	bolt "go.etcd.io/bbolt"
)

// Persister is the write-through hook that captures mutations of the in-memory
// store so they can survive agent restarts. Errors are surfaced to the caller
// of the Store method that triggered the write — Store itself never hides a
// persistence error.
//
// Implementations MUST be goroutine-safe; Store already serializes callers on
// its own mutex, so a no-op RWMutex on the persister is typically enough.
type Persister interface {
	SaveNode(n Node) error
	SaveEdge(e types.GraphEdge) error
	UpdateSession(id string, lastTS time.Time, closedAt time.Time, edgeID string) error
	DropSession(id string, edgeIDs []string, orphanedNodes []string) error
	Close() error
}

// BoltPersister implements Persister over a single bbolt file. The file lives
// at path (created with 0o600 on first open) and uses three buckets:
//
//	nodes nodeID → Node (json)
//	edges edgeID → types.GraphEdge (json)
//	sessions sessID → boltSession (json; lastTS/closedAt + edge id set)
//
// JSON was chosen for forward-compat: the on-disk representation is
// self-describing and can be inspected with `bolt` / `strings` for
// debugging. For the expected session-graph working set (O(10⁴–10⁵)
// edges) throughput is not a concern.
type BoltPersister struct {
	db *bolt.DB
}

const (
	boltBucketNodes    = "nodes"
	boltBucketEdges    = "edges"
	boltBucketSessions = "sessions"
)

// OpenBolt opens or creates a graph store at path. Timeout governs the file
// lock wait; 0 = block forever. The caller owns Close.
func OpenBolt(path string, timeout time.Duration) (*BoltPersister, error) {
	if path == "" {
		return nil, fmt.Errorf("graph: empty bolt path")
	}
	opts := &bolt.Options{Timeout: timeout}
	db, err := bolt.Open(path, 0o600, opts)
	if err != nil {
		return nil, fmt.Errorf("graph: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range []string{boltBucketNodes, boltBucketEdges, boltBucketSessions} {
			if _, err := tx.CreateBucketIfNotExists([]byte(b)); err != nil {
				return fmt.Errorf("create bucket %s: %w", b, err)
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &BoltPersister{db: db}, nil
}

// Close flushes and closes the underlying database.
func (p *BoltPersister) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	return p.db.Close()
}

// SaveNode encodes n as JSON under the nodes bucket.
func (p *BoltPersister) SaveNode(n Node) error {
	body, err := json.Marshal(n)
	if err != nil {
		return err
	}
	return p.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(boltBucketNodes)).Put([]byte(n.ID), body)
	})
}

// SaveEdge encodes e under the edges bucket.
func (p *BoltPersister) SaveEdge(e types.GraphEdge) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return p.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(boltBucketEdges)).Put([]byte(e.EdgeID), body)
	})
}

type boltSession struct {
	LastTS   time.Time       `json:"last_ts"`
	ClosedAt time.Time       `json:"closed_at,omitempty"`
	Edges    map[string]bool `json:"edges"`
}

// UpdateSession upserts the given session record; if edgeID is non-empty it
// is added to the session's edge set. ClosedAt is only overwritten when the
// new value is non-zero so callers can touch lastTS without clobbering a
// previously recorded close.
func (p *BoltPersister) UpdateSession(id string, lastTS time.Time, closedAt time.Time, edgeID string) error {
	return p.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(boltBucketSessions))
		cur := boltSession{Edges: map[string]bool{}}
		if raw := bkt.Get([]byte(id)); raw != nil {
			if err := json.Unmarshal(raw, &cur); err != nil {
				return fmt.Errorf("decode session %s: %w", id, err)
			}
			if cur.Edges == nil {
				cur.Edges = map[string]bool{}
			}
		}
		if !lastTS.IsZero() {
			cur.LastTS = lastTS
		}
		if !closedAt.IsZero() {
			cur.ClosedAt = closedAt
		}
		if edgeID != "" {
			cur.Edges[edgeID] = true
		}
		body, err := json.Marshal(cur)
		if err != nil {
			return err
		}
		return bkt.Put([]byte(id), body)
	})
}

// DropSession removes the session record and any edges/nodes the caller has
// determined are orphaned. Idempotent — missing keys are silently skipped.
func (p *BoltPersister) DropSession(id string, edgeIDs []string, orphanedNodes []string) error {
	return p.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte(boltBucketSessions)).Delete([]byte(id)); err != nil {
			return err
		}
		eb := tx.Bucket([]byte(boltBucketEdges))
		for _, eid := range edgeIDs {
			if err := eb.Delete([]byte(eid)); err != nil {
				return err
			}
		}
		nb := tx.Bucket([]byte(boltBucketNodes))
		for _, nid := range orphanedNodes {
			if err := nb.Delete([]byte(nid)); err != nil {
				return err
			}
		}
		return nil
	})
}

// Snapshot returns the full on-disk state. Callers use this from LoadInto.
func (p *BoltPersister) Snapshot() (nodes []Node, edges []types.GraphEdge, sessions map[string]boltSession, err error) {
	sessions = map[string]boltSession{}
	err = p.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte(boltBucketNodes)).ForEach(func(_, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err != nil {
				return err
			}
			nodes = append(nodes, n)
			return nil
		}); err != nil {
			return err
		}
		if err := tx.Bucket([]byte(boltBucketEdges)).ForEach(func(_, v []byte) error {
			var e types.GraphEdge
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			edges = append(edges, e)
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket([]byte(boltBucketSessions)).ForEach(func(k, v []byte) error {
			var s boltSession
			if err := json.Unmarshal(v, &s); err != nil {
				return err
			}
			sessions[string(k)] = s
			return nil
		})
	})
	return
}

// LoadInto replays the persisted graph into s. It is meant to be called once
// on startup, before any mutation, with an empty Store — existing entries are
// kept but will be overwritten by any matching id.
func (s *Store) LoadInto(p *BoltPersister) error {
	if p == nil {
		return nil
	}
	nodes, edges, sessions, err := p.Snapshot()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range nodes {
		cp := n
		s.nodes[n.ID] = &cp
	}
	for _, e := range edges {
		cp := e
		s.edges[e.EdgeID] = &cp
		s.out[e.SrcNode] = append(s.out[e.SrcNode], e.EdgeID)
		s.in[e.DstNode] = append(s.in[e.DstNode], e.EdgeID)
	}
	for id, bs := range sessions {
		ss := &sessionState{id: id, edges: map[string]struct{}{}, lastTS: bs.LastTS, closedAt: bs.ClosedAt}
		for eid := range bs.Edges {
			ss.edges[eid] = struct{}{}
		}
		s.sessions[id] = ss
		s.lruIdx[id] = s.lru.PushFront(id)
	}
	return nil
}

// Persist wires p into s. Subsequent mutations are written through. Pass nil
// to disable persistence.
func (s *Store) Persist(p Persister) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persist = p
}
