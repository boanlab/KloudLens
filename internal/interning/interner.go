// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package interning implements the string intern table
// A full string is inserted on first use and assigned a stable u32 id; subsequent
// occurrences flow as id only. Definition events that tell consumers about new
// (id → string) mappings are emitted out-of-band via the Definitions channel.
//
// Collisions on the 64-bit fnv1a hash fall back to storing the full string on
// the wire — correctness trumps volume savings. Purge expires entries whose
// last-use age exceeds TTL.
package interning

import (
	"hash/fnv"
	"sync"
	"time"
)

// Definition is emitted whenever a new (id,string) mapping is assigned.
// Consumers on the wire use these to rehydrate; it is also the one time the
// string payload itself crosses the bpf2frame.
type Definition struct {
	ID    uint32
	Value string
}

// Interner is safe for concurrent use.
type Interner struct {
	mu      sync.RWMutex
	byHash  map[uint64]uint32
	byID    map[uint32]entry
	nextID  uint32
	defChan chan Definition
	ttl     time.Duration
	clock   func() time.Time
	// metrics
	hits       uint64
	misses     uint64
	collisions uint64
}

type entry struct {
	value    string
	lastUsed time.Time
}

// Config controls interner behavior. Zero values are safe.
type Config struct {
	TTL     time.Duration // default 10 minutes
	DefChan chan Definition
	Clock   func() time.Time
}

// New creates an Interner. If cfg.DefChan is nil one is created with cap=1024.
func New(cfg Config) *Interner {
	if cfg.TTL == 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.DefChan == nil {
		cfg.DefChan = make(chan Definition, 1024)
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Interner{
		byHash:  map[uint64]uint32{},
		byID:    map[uint32]entry{},
		nextID:  1,
		defChan: cfg.DefChan,
		ttl:     cfg.TTL,
		clock:   cfg.Clock,
	}
}

// Definitions returns the channel producers emit on for new (id,string) pairs.
func (i *Interner) Definitions() <-chan Definition { return i.defChan }

// Intern returns (id, isNewDef). When isNewDef is true the caller should attach
// a Definition event at the stream boundary.
func (i *Interner) Intern(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	h := hash64(s)
	now := i.clock()

	i.mu.RLock()
	if id, ok := i.byHash[h]; ok {
		// Verify identity to guard against rare collisions.
		e := i.byID[id]
		if e.value == s {
			i.mu.RUnlock()
			i.touch(id, now)
			return id, false
		}
		// Hash collision — return 0 so caller falls back to raw string.
		i.mu.RUnlock()
		i.mu.Lock()
		i.collisions++
		i.mu.Unlock()
		return 0, false
	}
	i.mu.RUnlock()

	i.mu.Lock()
	defer i.mu.Unlock()
	// Recheck after upgrade.
	if id, ok := i.byHash[h]; ok {
		if i.byID[id].value == s {
			i.byID[id] = entry{value: s, lastUsed: now}
			i.hits++
			return id, false
		}
		i.collisions++
		return 0, false
	}
	id := i.nextID
	i.nextID++
	if i.nextID == 0 {
		// Wrap around — unlikely but reset just to avoid clashing with 0 sentinel.
		i.nextID = 1
	}
	i.byHash[h] = id
	i.byID[id] = entry{value: s, lastUsed: now}
	i.misses++
	// Non-blocking deliver; if consumer is slow, definition is dropped and the
	// caller is expected to send the raw string on the wire instead.
	select {
	case i.defChan <- Definition{ID: id, Value: s}:
		return id, true
	default:
		// Consumer backlogged — pretend this wasn't interned. The string will
		// go out in full on this record; future calls will re-attempt the
		// definition.
		delete(i.byHash, h)
		delete(i.byID, id)
		return 0, false
	}
}

func (i *Interner) touch(id uint32, now time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if e, ok := i.byID[id]; ok {
		e.lastUsed = now
		i.byID[id] = e
		i.hits++
	}
}

// Purge removes entries idle longer than TTL. Returns the number purged.
func (i *Interner) Purge() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.clock()
	n := 0
	for id, e := range i.byID {
		if now.Sub(e.lastUsed) >= i.ttl {
			h := hash64(e.value)
			delete(i.byID, id)
			if mappedID, ok := i.byHash[h]; ok && mappedID == id {
				delete(i.byHash, h)
			}
			n++
		}
	}
	return n
}

// Metrics reflects current accumulated counters.
type Metrics struct {
	Hits       uint64
	Misses     uint64
	Collisions uint64
	Size       int
}

// Metrics returns a snapshot.
func (i *Interner) Metrics() Metrics {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return Metrics{Hits: i.hits, Misses: i.misses, Collisions: i.collisions, Size: len(i.byID)}
}

func hash64(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}
