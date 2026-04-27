// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package policy implements the HookSubscription YAML loader, selector matcher,
// and graceful fallback resolution against a CapabilityReport.
package policy

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/boanlab/kloudlens/internal/correlation"
	"github.com/boanlab/kloudlens/pkg/types"
	"gopkg.in/yaml.v3"
)

// HookSubscription mirrors the YAML schema +
type HookSubscription struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name   string            `yaml:"name"`
	Labels map[string]string `yaml:"labels,omitempty"`
}

type Spec struct {
	Selector   Selector          `yaml:"selector"`
	Pairing    string            `yaml:"pairing,omitempty"` // enter_only|exit_only|enter_exit
	Syscalls   HookList          `yaml:"syscalls,omitempty"`
	LSM        HookList          `yaml:"lsm,omitempty"`
	Tracepoint HookList          `yaml:"tracepoint,omitempty"`
	Kprobe     HookList          `yaml:"kprobe,omitempty"`
	Decode     DecodeOpts        `yaml:"decode,omitempty"`
	Sampling   map[string]string `yaml:"sampling,omitempty"`
	Priority   Priority          `yaml:"priority,omitempty"`
	Graceful   Graceful          `yaml:"graceful,omitempty"`
	Enrichment Enrichment        `yaml:"enrichment,omitempty"`
}

type Selector struct {
	Namespaces        []string          `yaml:"namespaces,omitempty"`
	ExcludeNamespaces []string          `yaml:"excludeNamespaces,omitempty"`
	Labels            map[string]string `yaml:"labels,omitempty"`
}

type HookList struct {
	Include []string `yaml:"include,omitempty"`
	Exclude []string `yaml:"exclude,omitempty"`
}

type DecodeOpts struct {
	ResolvePath bool   `yaml:"resolvePath,omitempty"`
	ResolveFd   bool   `yaml:"resolveFd,omitempty"`
	DumpArgv    string `yaml:"dumpArgv,omitempty"`
}

type Priority struct {
	Critical []string `yaml:"critical,omitempty"`
	Normal   string   `yaml:"normal,omitempty"` // usually "*"
}

// Graceful —
type Graceful struct {
	OnMissing string            `yaml:"onMissing,omitempty"` // fail|skip|fallback
	Fallback  map[string]string `yaml:"fallback,omitempty"`  // hook → alt hook ("kprobe:security_bprm_check")
}

// Enrichment — history depth/width selection.
type Enrichment struct {
	Level             string   `yaml:"level,omitempty"` // full|minimal|none
	HistoryDepth      int      `yaml:"historyDepth,omitempty"`
	HistoryWindowSecs int      `yaml:"historyWindowSecs,omitempty"`
	Correlations      []string `yaml:"correlations,omitempty"`
}

// Default values filled in when spec omits them.
const (
	defaultPairing          = "enter_exit"
	defaultOnMissing        = "fail"
	defaultHistoryDepth     = 32
	defaultHistoryWindowSec = 30
)

// Parse loads a single HookSubscription YAML document and normalizes defaults.
func Parse(raw []byte) (*HookSubscription, error) {
	var h HookSubscription
	if err := yaml.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("parse HookSubscription: %w", err)
	}
	if h.Kind == "" {
		return nil, fmt.Errorf("kind is required")
	}
	if h.Kind != "HookSubscription" {
		return nil, fmt.Errorf("unsupported kind %q", h.Kind)
	}
	if h.Metadata.Name == "" {
		return nil, fmt.Errorf("metadata.name is required")
	}
	if h.Spec.Pairing == "" {
		h.Spec.Pairing = defaultPairing
	}
	switch h.Spec.Pairing {
	case "enter_only", "exit_only", "enter_exit":
	default:
		return nil, fmt.Errorf("invalid spec.pairing %q", h.Spec.Pairing)
	}
	if h.Spec.Graceful.OnMissing == "" {
		h.Spec.Graceful.OnMissing = defaultOnMissing
	}
	switch h.Spec.Graceful.OnMissing {
	case "fail", "skip", "fallback":
	default:
		return nil, fmt.Errorf("invalid spec.graceful.onMissing %q", h.Spec.Graceful.OnMissing)
	}
	if h.Spec.Enrichment.Level == "" {
		h.Spec.Enrichment.Level = "full"
	}
	switch h.Spec.Enrichment.Level {
	case "full", "minimal", "none":
	default:
		return nil, fmt.Errorf("invalid spec.enrichment.level %q (accepted: full, minimal, none)", h.Spec.Enrichment.Level)
	}
	if h.Spec.Enrichment.HistoryDepth == 0 {
		h.Spec.Enrichment.HistoryDepth = defaultHistoryDepth
	}
	if h.Spec.Enrichment.HistoryWindowSecs == 0 {
		h.Spec.Enrichment.HistoryWindowSecs = defaultHistoryWindowSec
	}
	if len(h.Spec.Enrichment.Correlations) > 0 {
		known := map[string]bool{}
		for _, k := range correlation.KnownKinds() {
			known[k] = true
		}
		for _, want := range h.Spec.Enrichment.Correlations {
			if !known[want] {
				return nil, fmt.Errorf("invalid spec.enrichment.correlations %q (accepted: %s)", want, strings.Join(correlation.KnownKinds(), ", "))
			}
		}
	}
	return &h, nil
}

// PodRef is what the matcher compares a Selector against.
type PodRef struct {
	Namespace string
	Name      string
	Labels    map[string]string
}

// MatchPod returns true if the subscription should apply to the given pod.
func (h *HookSubscription) MatchPod(p PodRef) bool {
	return h.Spec.Selector.Match(p)
}

// Match returns true when the pod matches this selector.
// Namespace globs use * wildcard. Labels use exact equality (AND semantics).
func (s Selector) Match(p PodRef) bool {
	for _, excl := range s.ExcludeNamespaces {
		if matchGlob(excl, p.Namespace) {
			return false
		}
	}
	if len(s.Namespaces) > 0 {
		ok := false
		for _, inc := range s.Namespaces {
			if matchGlob(inc, p.Namespace) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for k, v := range s.Labels {
		if got, ok := p.Labels[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// matchGlob supports simple shell-style glob wildcards (*, ?).
func matchGlob(pattern, s string) bool {
	if pattern == "*" || pattern == s {
		return true
	}
	ok, err := path.Match(pattern, s)
	if err != nil {
		return false
	}
	return ok
}

// ResolutionError is returned by Resolve when onMissing=fail and a hook is unavailable.
type ResolutionError struct {
	Missing []MissingHook
}

type MissingHook struct {
	Kind   string
	Name   string
	Reason string
}

func (e *ResolutionError) Error() string {
	parts := make([]string, 0, len(e.Missing))
	for _, m := range e.Missing {
		parts = append(parts, fmt.Sprintf("%s:%s(%s)", m.Kind, m.Name, m.Reason))
	}
	sort.Strings(parts)
	return "hooks unavailable: " + strings.Join(parts, ",")
}

// Resolved is the outcome of policy resolution against a CapabilityReport.
// It lists the concrete (kind,name) hooks the agent should attempt to attach,
// along with any missing hooks that were skipped.
type Resolved struct {
	Attach   []AttachSpec
	Skipped  []MissingHook
	Fallback map[string]string // original → chosen alt
}

// AttachSpec is one concrete hook attachment order.
type AttachSpec struct {
	Kind     string // syscall_tracepoint|lsm_bpf|kprobe|tracepoint
	Name     string
	Priority string // critical|normal
	Sample   string // "1/10" or ""
}

// Resolve cross-checks the subscription against a CapabilityReport
// and produces an attach plan honoring graceful.onMissing (fail|skip|fallback).
func (h *HookSubscription) Resolve(r *types.CapabilityReport) (*Resolved, error) {
	out := &Resolved{Fallback: map[string]string{}}

	type want struct {
		kind, name string
	}
	var wants []want
	for _, n := range h.Spec.Syscalls.Include {
		if !contains(h.Spec.Syscalls.Exclude, n) {
			wants = append(wants, want{"syscall_tracepoint", n})
		}
	}
	for _, n := range h.Spec.LSM.Include {
		if !contains(h.Spec.LSM.Exclude, n) {
			wants = append(wants, want{"lsm_bpf", n})
		}
	}
	for _, n := range h.Spec.Tracepoint.Include {
		if !contains(h.Spec.Tracepoint.Exclude, n) {
			wants = append(wants, want{"tracepoint", n})
		}
	}
	for _, n := range h.Spec.Kprobe.Include {
		if !contains(h.Spec.Kprobe.Exclude, n) {
			wants = append(wants, want{"kprobe", n})
		}
	}

	critical := map[string]bool{}
	for _, n := range h.Spec.Priority.Critical {
		critical[n] = true
	}

	for _, w := range wants {
		hc, ok := r.HookAvailable(w.kind, w.name)
		priority := "normal"
		if critical[w.name] {
			priority = "critical"
		}
		sample := h.Spec.Sampling[w.name]
		if ok && hc.Available {
			out.Attach = append(out.Attach, AttachSpec{Kind: w.kind, Name: w.name, Priority: priority, Sample: sample})
			continue
		}
		reason := "hook_not_found"
		if ok {
			reason = hc.UnavailableReason
		}
		switch h.Spec.Graceful.OnMissing {
		case "fail":
			out.Skipped = append(out.Skipped, MissingHook{Kind: w.kind, Name: w.name, Reason: reason})
		case "skip":
			out.Skipped = append(out.Skipped, MissingHook{Kind: w.kind, Name: w.name, Reason: reason})
		case "fallback":
			alt := h.Spec.Graceful.Fallback[w.name]
			if alt == "" {
				out.Skipped = append(out.Skipped, MissingHook{Kind: w.kind, Name: w.name, Reason: reason + " (no fallback)"})
				continue
			}
			kind, name, ok := splitFallback(alt)
			if !ok {
				out.Skipped = append(out.Skipped, MissingHook{Kind: w.kind, Name: w.name, Reason: "malformed fallback " + alt})
				continue
			}
			if hc2, ok := r.HookAvailable(kind, name); ok && hc2.Available {
				out.Attach = append(out.Attach, AttachSpec{Kind: kind, Name: name, Priority: priority, Sample: sample})
				out.Fallback[w.kind+":"+w.name] = alt
			} else {
				out.Skipped = append(out.Skipped, MissingHook{Kind: w.kind, Name: w.name, Reason: "fallback " + alt + " also unavailable"})
			}
		}
	}

	if h.Spec.Graceful.OnMissing == "fail" && len(out.Skipped) > 0 {
		return out, &ResolutionError{Missing: out.Skipped}
	}
	return out, nil
}

// splitFallback parses "kprobe:security_bprm_check" style.
func splitFallback(s string) (kind, name string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
