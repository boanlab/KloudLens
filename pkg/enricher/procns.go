// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package enricher

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// NSKey is the (pidNS, mntNS) inode pair the enricher uses as its primary
// cache key. It matches the tuple surfaced by tracer.MetaResolver.Resolve.
type NSKey struct {
	PidNS uint32
	MntNS uint32
}

// RawEntry is the intermediate record produced by the /proc walker: a raw
// container ID + sample PID + pod UID (when in kubepods). Higher layers
// (CRI lookup) promote this to a full ContainerMeta.
type RawEntry struct {
	ContainerID string
	PodUID      string
	// SamplePID keeps one live PID from the container so callers that need
	// fresh /proc lookups (image path, exe, labels) have an entry point.
	SamplePID int32
}

// ProcScanner walks /proc and builds NSKey → RawEntry. It's safe to call Scan
// concurrently; each call returns a fresh snapshot.
//
// The scanner is intentionally tolerant of racing processes (a PID can exit
// between readdir and readlink): any filesystem error on a specific PID is
// silently skipped, never surfaced. Callers treat the returned map as a
// best-effort index, not an authority on "what is running right now".
type ProcScanner struct {
	// Root is the procfs mount to scan. Defaults to "/proc"; tests override
	// with a tmpdir fixture.
	Root string
}

// NewProcScanner returns a ProcScanner rooted at /proc. Zero-value usage
// (scanner := ProcScanner{}) works the same — the Scan method falls back to
// "/proc" on empty Root.
func NewProcScanner() *ProcScanner { return &ProcScanner{Root: "/proc"} }

// Scan walks every numeric entry under Root and records its NS identity +
// cgroup-derived container ID. Duplicate NSKeys (multiple PIDs per container)
// keep the earliest PID so the SamplePID is stable across calls as long as
// pid 1 of the container is still alive. Entries with zero container ID
// (host processes, systemd services) are omitted.
func (s *ProcScanner) Scan() (map[NSKey]RawEntry, error) {
	root := s.Root
	if root == "" {
		root = "/proc"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := make(map[NSKey]RawEntry, 64)
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		name := de.Name()
		// Skip non-numeric entries (self, kernel, etc).
		pid, ok := parsePID(name)
		if !ok {
			continue
		}
		key, rawEntry, ok := inspectPID(root, pid)
		if !ok {
			continue
		}
		if existing, present := out[key]; present {
			// Keep the earlier PID (usually pid 1 of the container) as the
			// canonical sample. Not strictly required but makes SamplePID
			// deterministic across rescans.
			if existing.SamplePID < rawEntry.SamplePID {
				continue
			}
		}
		out[key] = rawEntry
	}
	return out, nil
}

// inspectPID reads /proc/<pid>/ns/{pid,mnt} and /proc/<pid>/cgroup; returns
// the NS key + entry when the PID is inside a recognizable container, or
// ok=false when anything is missing.
func inspectPID(root string, pid int32) (NSKey, RawEntry, bool) {
	pidNS, ok := readNSInode(filepath.Join(root, strconv.Itoa(int(pid)), "ns", "pid"))
	if !ok {
		return NSKey{}, RawEntry{}, false
	}
	mntNS, ok := readNSInode(filepath.Join(root, strconv.Itoa(int(pid)), "ns", "mnt"))
	if !ok {
		return NSKey{}, RawEntry{}, false
	}
	cgroupBytes, err := os.ReadFile(filepath.Join(root, strconv.Itoa(int(pid)), "cgroup")) // #nosec G304 -- /proc/<pid>/cgroup from a trusted procfs root
	if err != nil {
		return NSKey{}, RawEntry{}, false
	}
	cid := ContainerIDFromCgroupFile(string(cgroupBytes))
	if cid == "" {
		return NSKey{}, RawEntry{}, false
	}
	uid := ""
	for _, line := range strings.Split(string(cgroupBytes), "\n") {
		if u := PodUIDFromCgroup(strings.TrimSpace(line)); u != "" {
			uid = u
			break
		}
	}
	return NSKey{PidNS: pidNS, MntNS: mntNS}, RawEntry{
		ContainerID: cid,
		PodUID:      uid,
		SamplePID:   pid,
	}, true
}

// readNSInode expects a "/proc/<pid>/ns/<ns>" path whose readlink target is
// the kernel's "ns:[<inode>]" encoding. Returns the inode as uint32 (the
// widths align with the BPF wire header).
func readNSInode(path string) (uint32, bool) {
	target, err := os.Readlink(path)
	if err != nil {
		return 0, false
	}
	// Expected shape: "pid:[4026531836]" — we tolerate leading spaces and a
	// missing trailing bracket (some kernels format slightly differently on
	// init NS).
	lb := strings.Index(target, "[")
	if lb < 0 {
		return 0, false
	}
	tail := target[lb+1:]
	if rb := strings.Index(tail, "]"); rb >= 0 {
		tail = tail[:rb]
	}
	v, err := strconv.ParseUint(tail, 10, 64)
	if err != nil {
		return 0, false
	}
	return uint32(v), true // #nosec G115 -- ParseUint(_, 10, 64) result used as /proc/ns inode (32-bit on Linux)
}

func parsePID(s string) (int32, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		return 0, false
	}
	return int32(v), true // #nosec G109 G115 -- kernel PIDs fit in int32 on Linux; caller pre-validates the string is numeric
}

// NSMap is a concurrency-safe cache of NSKey → meta that the enricher
// maintains. A separate Stats counter records hit/miss so the pipeline can
// log resolver effectiveness.
type NSMap struct {
	mu      sync.RWMutex
	entries map[NSKey]RawEntry
	hits    uint64
	misses  uint64
}

// NewNSMap returns an empty NSMap.
func NewNSMap() *NSMap { return &NSMap{entries: map[NSKey]RawEntry{}} }

// Replace atomically swaps the map contents for a fresh snapshot. Used by
// the periodic scanner after Scan succeeds.
func (m *NSMap) Replace(next map[NSKey]RawEntry) {
	m.mu.Lock()
	m.entries = next
	m.mu.Unlock()
}

// Lookup returns the cached entry for key; the second return value records
// whether it came from the cache so the caller can decide to trigger a lazy
// refresh on miss.
func (m *NSMap) Lookup(key NSKey) (RawEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if ok {
		m.hits++
	} else {
		m.misses++
	}
	return e, ok
}

// Set stores one entry (used by the on-miss lazy path).
func (m *NSMap) Set(key NSKey, v RawEntry) {
	m.mu.Lock()
	if m.entries == nil {
		m.entries = map[NSKey]RawEntry{}
	}
	m.entries[key] = v
	m.mu.Unlock()
}

// Stats returns (hits, misses, size) — useful for periodic diagnostics.
func (m *NSMap) Stats() (hits, misses uint64, size int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.hits, m.misses, len(m.entries)
}
