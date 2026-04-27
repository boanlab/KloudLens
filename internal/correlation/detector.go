// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package correlation implements the 5 user-space heuristics from plan
// Each heuristic keeps a short sliding window of recent observations
// keyed by pid (or globally, where appropriate) and, when a triggering event
// arrives (exec / connect / send / setuid-tainted op), emits a
// types.Correlation the enricher can attach to the outgoing event.
//
// Heuristics are individually gated so policy can turn any subset on/off
// without code changes. Windows are swept at observation time rather than by
// a background goroutine — test-friendly and allocation-free in the common
// case.
package correlation

import (
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

// Kind identifiers match
const (
	KindFileWrittenThenExecuted = "file_written_then_executed"
	KindConnectAfterDNS         = "connect_after_dns"
	KindExecAfterChmodX         = "exec_after_chmod_x"
	KindReadSensitiveBeforeSend = "read_sensitive_before_send"
	KindPrivEscalationWindow    = "privilege_escalation_window"
)

// KnownKinds returns the set of heuristic identifiers this detector
// understands. Callers that accept user-authored correlation names
// (HookSubscription.spec.enrichment.correlations, admin linters) use
// this as the single source of truth — adding a new heuristic here is
// automatically reflected in parse-time validation downstream.
func KnownKinds() []string {
	return []string{
		KindFileWrittenThenExecuted,
		KindConnectAfterDNS,
		KindExecAfterChmodX,
		KindReadSensitiveBeforeSend,
		KindPrivEscalationWindow,
	}
}

// Config controls the correlation detector.
type Config struct {
	// Window is the look-back horizon for each heuristic. Older observations
	// are swept lazily on the next Record/Check call.
	Window time.Duration
	// Enabled controls which heuristics emit Correlations. A nil map enables
	// all of them.
	Enabled map[string]bool
	// SensitivePaths lists path substrings considered sensitive for the
	// read_sensitive_before_send heuristic. Defaults applied if empty.
	SensitivePaths []string
	Clock          func() time.Time
}

func (c *Config) withDefaults() {
	if c.Window == 0 {
		c.Window = 30 * time.Second
	}
	if len(c.SensitivePaths) == 0 {
		c.SensitivePaths = []string{"/etc/shadow", "/etc/gshadow", "/proc/", "/etc/ssh/", ".aws/credentials", ".kube/config"}
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
}

func (c *Config) enabled(kind string) bool {
	if c.Enabled == nil {
		return true
	}
	return c.Enabled[kind]
}

// Detector keeps sliding windows of observations and answers Check* queries
// with the correlations that match at the current instant.
type Detector struct {
	mu  sync.Mutex
	cfg Config

	// per-inode and per-path maps for written files.
	writtenByInode map[uint64]fileWrite
	writtenByPath  map[string]fileWrite
	// chmod +x by path.
	chmodX map[string]time.Time
	// last DNS answers by IP.
	dnsAnswers map[string]dnsAnswer
	// sensitive reads per pid.
	sensReads map[int32][]sensRead
	// setuid-to-root transitions per pid.
	setuidRoot map[int32]time.Time
}

type fileWrite struct {
	ts   time.Time
	pid  int32
	path string
}

type dnsAnswer struct {
	ts    time.Time
	query string
}

type sensRead struct {
	ts   time.Time
	path string
}

// New returns a detector with config defaults applied.
func New(cfg Config) *Detector {
	cfg.withDefaults()
	return &Detector{
		cfg:            cfg,
		writtenByInode: map[uint64]fileWrite{},
		writtenByPath:  map[string]fileWrite{},
		chmodX:         map[string]time.Time{},
		dnsAnswers:     map[string]dnsAnswer{},
		sensReads:      map[int32][]sensRead{},
		setuidRoot:     map[int32]time.Time{},
	}
}

// EnabledFromNames turns a validated HookSubscription
// spec.enrichment.correlations list into a Config.Enabled map.
//
// Semantics match Config.enabled:
// - nil slice → nil map (all heuristics enabled — the zero-policy default)
// - empty list → empty map (every heuristic disabled — an explicit opt-out)
// - non-empty → {name: true} for each listed heuristic; others disabled
//
// Names are expected to be pre-validated via policy.Parse (which calls
// correlation.KnownKinds()). Unknown names are silently kept — the map is
// just passed to Config.enabled which returns false for unknown kinds
// either way, so there's no footgun and we don't drop operator input.
func EnabledFromNames(names []string) map[string]bool {
	if names == nil {
		return nil
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// SetEnabled swaps the Config.Enabled map atomically under the detector
// lock. Callers that react to a HookSubscription change at runtime use
// this to re-dispatch heuristics without rebuilding the sliding windows.
// Pass nil to restore the "all heuristics on" default.
func (d *Detector) SetEnabled(m map[string]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if m == nil {
		d.cfg.Enabled = nil
		return
	}
	copied := make(map[string]bool, len(m))
	maps.Copy(copied, m)
	d.cfg.Enabled = copied
}

// RecordFileWrite notes a file write. inode=0 means unknown; we'll fall back
// to path matching when correlating.
func (d *Detector) RecordFileWrite(pid int32, path string, inode uint64, ts time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweepLocked(ts)
	fw := fileWrite{ts: ts, pid: pid, path: path}
	if inode != 0 {
		d.writtenByInode[inode] = fw
	}
	if path != "" {
		d.writtenByPath[path] = fw
	}
}

// RecordChmodX notes a chmod/fchmod that set the execute bit on path.
func (d *Detector) RecordChmodX(path string, ts time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweepLocked(ts)
	d.chmodX[path] = ts
}

// RecordDNSAnswer notes that ip was returned as a DNS answer for query.
func (d *Detector) RecordDNSAnswer(ip, query string, ts time.Time) {
	if ip == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweepLocked(ts)
	d.dnsAnswers[ip] = dnsAnswer{ts: ts, query: query}
}

// RecordSensitiveRead only stores the read if path matches a sensitive pattern.
func (d *Detector) RecordSensitiveRead(pid int32, path string, ts time.Time) {
	if !d.isSensitive(path) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweepLocked(ts)
	d.sensReads[pid] = append(d.sensReads[pid], sensRead{ts: ts, path: path})
}

// RecordSetuidRoot notes that pid gained uid=0 (or ruid→0 transition).
func (d *Detector) RecordSetuidRoot(pid int32, ts time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweepLocked(ts)
	d.setuidRoot[pid] = ts
}

// CheckExec returns any correlations triggered by a newly-observed exec of
// (path, inode) by pid at ts.
func (d *Detector) CheckExec(pid int32, path string, inode uint64, ts time.Time) []types.Correlation {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweepLocked(ts)
	var out []types.Correlation
	if d.cfg.enabled(KindFileWrittenThenExecuted) {
		var fw fileWrite
		ok := false
		if inode != 0 {
			fw, ok = d.writtenByInode[inode]
		}
		if !ok && path != "" {
			fw, ok = d.writtenByPath[path]
		}
		if ok && ts.Sub(fw.ts) <= d.cfg.Window {
			out = append(out, types.Correlation{
				Kind:    KindFileWrittenThenExecuted,
				Summary: "exec target was written " + ts.Sub(fw.ts).String() + " ago",
				RefID:   fw.path,
				Score:   1.0,
			})
		}
	}
	if d.cfg.enabled(KindExecAfterChmodX) && path != "" {
		if cts, ok := d.chmodX[path]; ok && ts.Sub(cts) <= d.cfg.Window {
			out = append(out, types.Correlation{
				Kind:    KindExecAfterChmodX,
				Summary: "x-bit set " + ts.Sub(cts).String() + " before exec",
				RefID:   path,
				Score:   1.0,
			})
		}
	}
	if c := d.checkPrivEscLocked(pid, "exec", ts); c != nil {
		out = append(out, *c)
	}
	return out
}

// CheckConnect returns correlations triggered by a newly-observed connect to
// ip by pid at ts.
func (d *Detector) CheckConnect(pid int32, ip string, ts time.Time) []types.Correlation {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweepLocked(ts)
	var out []types.Correlation
	if d.cfg.enabled(KindConnectAfterDNS) && ip != "" {
		if ans, ok := d.dnsAnswers[ip]; ok && ts.Sub(ans.ts) <= d.cfg.Window {
			out = append(out, types.Correlation{
				Kind:    KindConnectAfterDNS,
				Summary: "connect target matches DNS answer for " + ans.query,
				RefID:   ip,
				Score:   1.0,
			})
		}
	}
	if c := d.checkPrivEscLocked(pid, "connect", ts); c != nil {
		out = append(out, *c)
	}
	return out
}

// CheckNetworkSend returns correlations triggered by a send event (post-connect
// data flow) by pid at ts.
func (d *Detector) CheckNetworkSend(pid int32, ts time.Time) []types.Correlation {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweepLocked(ts)
	var out []types.Correlation
	if d.cfg.enabled(KindReadSensitiveBeforeSend) {
		if reads := d.sensReads[pid]; len(reads) > 0 {
			last := reads[len(reads)-1]
			if ts.Sub(last.ts) <= d.cfg.Window {
				out = append(out, types.Correlation{
					Kind:    KindReadSensitiveBeforeSend,
					Summary: "sensitive read " + last.path + " " + ts.Sub(last.ts).String() + " before send",
					RefID:   last.path,
					Score:   1.0,
				})
			}
		}
	}
	if c := d.checkPrivEscLocked(pid, "send", ts); c != nil {
		out = append(out, *c)
	}
	return out
}

// checkPrivEscLocked returns the privilege escalation correlation when pid
// had a recent setuid(0) and is now doing something sensitive.
func (d *Detector) checkPrivEscLocked(pid int32, op string, ts time.Time) *types.Correlation {
	if !d.cfg.enabled(KindPrivEscalationWindow) {
		return nil
	}
	t, ok := d.setuidRoot[pid]
	if !ok {
		return nil
	}
	if ts.Sub(t) > d.cfg.Window {
		return nil
	}
	return &types.Correlation{
		Kind:    KindPrivEscalationWindow,
		Summary: op + " within " + ts.Sub(t).String() + " of setuid(0)",
		Score:   1.0,
	}
}

func (d *Detector) isSensitive(path string) bool {
	if path == "" {
		return false
	}
	for _, p := range d.cfg.SensitivePaths {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

// sweepLocked drops observations older than the window.
func (d *Detector) sweepLocked(now time.Time) {
	cutoff := now.Add(-d.cfg.Window)
	for k, v := range d.writtenByInode {
		if v.ts.Before(cutoff) {
			delete(d.writtenByInode, k)
		}
	}
	for k, v := range d.writtenByPath {
		if v.ts.Before(cutoff) {
			delete(d.writtenByPath, k)
		}
	}
	for k, v := range d.chmodX {
		if v.Before(cutoff) {
			delete(d.chmodX, k)
		}
	}
	for k, v := range d.dnsAnswers {
		if v.ts.Before(cutoff) {
			delete(d.dnsAnswers, k)
		}
	}
	for k, arr := range d.sensReads {
		trimmed := arr[:0]
		for _, r := range arr {
			if !r.ts.Before(cutoff) {
				trimmed = append(trimmed, r)
			}
		}
		if len(trimmed) == 0 {
			delete(d.sensReads, k)
		} else {
			d.sensReads[k] = trimmed
		}
	}
	for k, v := range d.setuidRoot {
		if v.Before(cutoff) {
			delete(d.setuidRoot, k)
		}
	}
}

// Sizes returns counts of in-window observations, for metrics and tests.
type Sizes struct {
	Writes, ChmodX, DNS, SensReadsPids, SetuidRoots int
}

func (d *Detector) Sizes() Sizes {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweepLocked(d.cfg.Clock())
	return Sizes{
		Writes:        len(d.writtenByPath),
		ChmodX:        len(d.chmodX),
		DNS:           len(d.dnsAnswers),
		SensReadsPids: len(d.sensReads),
		SetuidRoots:   len(d.setuidRoot),
	}
}
