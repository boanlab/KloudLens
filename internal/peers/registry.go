// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package peermatch tracks listening sockets per container on this node
// so the Session Graph can resolve a connect destination to its owning
// container — turning an opaque "peer:10.0.0.5:8080" leaf into a typed
// cross-container edge.
//
// Scope: same-node cross-container only. The registry observes bind
// events, keys them on (addr, port) plus a wildcard-port fallback, and
// drops entries when the owning PID exits. Cross-node resolution would
// need either a cluster-aware side channel or kernel-level skb tagging;
// both are out of scope here.
package peers

import (
	"strings"
	"sync"
)

// Peer is a single listening socket binding observed on this node.
type Peer struct {
	Addr        string // "ip:port" as emitted by wire/mapper.decodeSockAddr
	PID         int32  // the PID that called bind
	ContainerID string // empty for host-namespace listeners
	TSNs        uint64 // timestamp of the bind call (ns)
}

// Registry is the in-memory listener table. Safe for concurrent
// Observe/Lookup calls.
type Registry struct {
	mu sync.RWMutex

	// byExact: exact "ip:port" match, e.g. "10.0.0.5:8080". A bind to
	// 10.0.0.5 explicitly means that address only.
	byExact map[string]Peer

	// byPort: wildcard-address match keyed by ":port" alone. Populated
	// when a process binds to 0.0.0.0 or ::. Any connect to that port
	// on any routable node IP matches.
	byPort map[string]Peer

	// byPID: reverse index so ObserveExit can drop every entry owned by
	// the exiting PID in one pass. Stores the keys (exact or ":port")
	// that point back to this PID.
	byPID map[int32][]string

	// max caps the table to prevent unbounded growth on a host under
	// scan-style workloads that bind/rebind rapidly. 0 disables the cap.
	max int
}

// NewRegistry returns a Registry with a default 4096-entry cap.
func NewRegistry() *Registry {
	return &Registry{
		byExact: map[string]Peer{},
		byPort:  map[string]Peer{},
		byPID:   map[int32][]string{},
		max:     4096,
	}
}

// SetMax overrides the entry cap. 0 disables the cap (unbounded).
func (r *Registry) SetMax(n int) {
	r.mu.Lock()
	r.max = n
	r.mu.Unlock()
}

// ObserveBind records a listening socket. addr is the "ip:port" string
// emitted by the wire mapper; empty / malformed values are ignored so the
// pipeline can call this unconditionally on every bind event.
func (r *Registry) ObserveBind(addr string, pid int32, containerID string, tsNs uint64) {
	if addr == "" {
		return
	}
	ip, port, ok := splitAddr(addr)
	if !ok {
		return
	}
	p := Peer{Addr: addr, PID: pid, ContainerID: containerID, TSNs: tsNs}
	key := addr
	isWildcard := ip == "0.0.0.0" || ip == "::" || ip == ""
	if isWildcard {
		key = ":" + port
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.max > 0 && len(r.byExact)+len(r.byPort) >= r.max {
		// Cap hit: drop the oldest entry for this PID if one exists so
		// bind/rebind cycles by the same process don't exhaust the table.
		// Otherwise refuse to add. A refused entry just means the connect
		// side stays opaque — correct under pressure, just less informative.
		if keys, ok := r.byPID[pid]; ok && len(keys) > 0 {
			r.removeKeyLocked(keys[0], pid)
		} else {
			return
		}
	}
	if isWildcard {
		r.byPort[key] = p
	} else {
		r.byExact[key] = p
	}
	r.byPID[pid] = append(r.byPID[pid], key)
}

// ObserveExit drops every entry owned by the given PID. Wired from the
// sched_process_exit path so dead listeners don't linger and mismatch
// future connects.
func (r *Registry) ObserveExit(pid int32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	keys, ok := r.byPID[pid]
	if !ok {
		return
	}
	for _, k := range keys {
		if strings.HasPrefix(k, ":") {
			delete(r.byPort, k)
		} else {
			delete(r.byExact, k)
		}
	}
	delete(r.byPID, pid)
}

// Lookup resolves a connect destination to a (Peer, true) pair when
// another container on this node is bound to that address. Exact match
// wins over wildcard so a container bound to a specific IP isn't masked
// by a host-wide wildcard on the same port.
func (r *Registry) Lookup(addr string) (Peer, bool) {
	if addr == "" {
		return Peer{}, false
	}
	_, port, ok := splitAddr(addr)
	if !ok {
		return Peer{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, ok := r.byExact[addr]; ok {
		return p, true
	}
	if p, ok := r.byPort[":"+port]; ok {
		return p, true
	}
	return Peer{}, false
}

// Size returns the current number of tracked entries. Useful for tests
// and for exposing a gauge on /metrics.
func (r *Registry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byExact) + len(r.byPort)
}

// removeKeyLocked drops a key from whichever map holds it and prunes
// that key from the owning PID's index. Caller must hold r.mu for write.
func (r *Registry) removeKeyLocked(key string, pid int32) {
	if strings.HasPrefix(key, ":") {
		delete(r.byPort, key)
	} else {
		delete(r.byExact, key)
	}
	keys := r.byPID[pid]
	for i, k := range keys {
		if k == key {
			keys = append(keys[:i], keys[i+1:]...)
			break
		}
	}
	if len(keys) == 0 {
		delete(r.byPID, pid)
	} else {
		r.byPID[pid] = keys
	}
}

// splitAddr splits "ip:port" into components. It tolerates IPv6 in
// bracketed form ("[::1]:80") but the wire mapper only emits AF_INET
// today, so the bracketed branch is defensive rather than load-bearing.
func splitAddr(addr string) (ip, port string, ok bool) {
	if addr == "" {
		return "", "", false
	}
	if addr[0] == '[' {
		end := strings.Index(addr, "]")
		if end < 0 || end+1 >= len(addr) || addr[end+1] != ':' {
			return "", "", false
		}
		return addr[1:end], addr[end+2:], true
	}
	i := strings.LastIndex(addr, ":")
	if i < 0 || i == len(addr)-1 {
		return "", "", false
	}
	return addr[:i], addr[i+1:], true
}
