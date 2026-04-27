// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package contract

import (
	"slices"
	"strings"
)

// Finding is a single row in a Gap report.
type Finding struct {
	Kind     string   // "unused_allowance" | "observed_but_denied"
	Category string   // "exec" | "file.read" | "file.write" | "network.egress" | "capability" | "syscalls"
	Subject  string   // the rule key (binary, path, peer, ...)
	Reason   string   // human-readable
	RefIDs   []string // intent IDs or evidence pointers (optional)
}

// Report is the output of gap analysis.
type Report struct {
	UnusedAllowance     []Finding
	ObservedButDenied   []Finding
	DriftScore          float64 // Jaccard distance between allow-sets
	CoveragePercent     float64 // % of observed items that are permitted by policy
	TotalObserved       int
	TotalObservedDenied int
}

// GapCategories selects which Contract subtrees participate in a Gap run.
// A policy format that cannot express a category (e.g., seccomp has no exec
// rules) should drop it here — otherwise every observed exec reads as
// "denied" against a policy that never had the ability to allow it.
type GapCategories struct {
	Exec         bool
	FileRead     bool
	FileWrite    bool
	NetEgress    bool
	Capabilities bool
	Syscalls     bool
}

// AllCategories turns on every field — the default for backward-compatible
// callers that compare two Contract IRs with full coverage.
func AllCategories() GapCategories {
	return GapCategories{
		Exec: true, FileRead: true, FileWrite: true,
		NetEgress: true, Capabilities: true, Syscalls: true,
	}
}

// GapOptions bundles tunables for GapWith. Categories gates which rule
// subtrees are scored; zero-value Categories means "no comparisons" which
// yields an empty Report.
type GapOptions struct {
	Categories GapCategories
}

// Gap compares `observed` against `policy` across every category. Equivalent
// to GapWith with all categories enabled.
func Gap(observed, policy *Contract) Report {
	return GapWith(observed, policy, GapOptions{Categories: AllCategories()})
}

// GapWith is Gap with explicit category scoping. Categories not enabled in
// opts are skipped from findings, drift, and coverage — they contribute
// nothing to the report.
func GapWith(observed, policy *Contract, opts GapOptions) Report {
	var r Report
	cats := opts.Categories

	obsExec := execSet(observed)
	polExec := execSet(policy)
	obsReadPaths := filePathSet(observed.Spec.File.Read)
	polReadRules := policy.Spec.File.Read
	obsWritePaths := filePathSet(observed.Spec.File.Write)
	polWriteRules := policy.Spec.File.Write
	obsEgress := egressSet(observed)
	polEgress := egressSet(policy)
	obsCaps := toSet(observed.Spec.Capabilities)
	polCaps := toSet(policy.Spec.Capabilities)
	obsSyscalls := toSet(observed.Spec.Syscalls)
	polSyscalls := toSet(policy.Spec.Syscalls)

	// observed_but_denied: observed items not permitted by policy.
	if cats.Exec {
		for b := range obsExec {
			if !policy.AllowsExec(b) {
				r.ObservedButDenied = append(r.ObservedButDenied, Finding{
					Kind: "observed_but_denied", Category: "exec", Subject: b,
					Reason: "policy does not allow this exec target",
				})
			}
		}
	}
	if cats.FileRead {
		for p := range obsReadPaths {
			if !policy.AllowsFileRead(p) {
				r.ObservedButDenied = append(r.ObservedButDenied, Finding{
					Kind: "observed_but_denied", Category: "file.read", Subject: p,
					Reason: "policy does not allow reading this path",
				})
			}
		}
	}
	if cats.FileWrite {
		for p := range obsWritePaths {
			if !policy.AllowsFileWrite(p) {
				r.ObservedButDenied = append(r.ObservedButDenied, Finding{
					Kind: "observed_but_denied", Category: "file.write", Subject: p,
					Reason: "policy does not allow writing this path",
				})
			}
		}
	}
	if cats.NetEgress {
		for p := range obsEgress {
			if !policy.AllowsEgress(p) {
				r.ObservedButDenied = append(r.ObservedButDenied, Finding{
					Kind: "observed_but_denied", Category: "network.egress", Subject: p,
					Reason: "policy does not allow this egress peer",
				})
			}
		}
	}
	if cats.Capabilities {
		for c := range obsCaps {
			if _, ok := polCaps[c]; !ok {
				r.ObservedButDenied = append(r.ObservedButDenied, Finding{
					Kind: "observed_but_denied", Category: "capability", Subject: c,
					Reason: "policy does not allow this capability",
				})
			}
		}
	}
	if cats.Syscalls {
		for s := range obsSyscalls {
			if _, ok := polSyscalls[s]; !ok {
				r.ObservedButDenied = append(r.ObservedButDenied, Finding{
					Kind: "observed_but_denied", Category: "syscalls", Subject: s,
					Reason: "policy does not allow this syscall",
				})
			}
		}
	}

	// unused_allowance: policy items never observed.
	if cats.Exec {
		for b := range polExec {
			if _, ok := obsExec[b]; !ok {
				r.UnusedAllowance = append(r.UnusedAllowance, Finding{
					Kind: "unused_allowance", Category: "exec", Subject: b,
					Reason: "policy allows this exec but runtime never used it",
				})
			}
		}
	}
	if cats.FileRead {
		for _, rule := range polReadRules {
			key := ruleKey(rule)
			if !observed.AllowsFileRead(key) && !matchAnyObservedPath(rule, obsReadPaths) {
				r.UnusedAllowance = append(r.UnusedAllowance, Finding{
					Kind: "unused_allowance", Category: "file.read", Subject: key,
					Reason: "policy allows read but no observation matched",
				})
			}
		}
	}
	if cats.FileWrite {
		for _, rule := range polWriteRules {
			key := ruleKey(rule)
			if !observed.AllowsFileWrite(key) && !matchAnyObservedPath(rule, obsWritePaths) {
				r.UnusedAllowance = append(r.UnusedAllowance, Finding{
					Kind: "unused_allowance", Category: "file.write", Subject: key,
					Reason: "policy allows write but no observation matched",
				})
			}
		}
	}
	if cats.NetEgress {
		for p := range polEgress {
			if _, ok := obsEgress[p]; !ok {
				r.UnusedAllowance = append(r.UnusedAllowance, Finding{
					Kind: "unused_allowance", Category: "network.egress", Subject: p,
					Reason: "policy allows egress peer but runtime never connected",
				})
			}
		}
	}
	if cats.Capabilities {
		for c := range polCaps {
			if _, ok := obsCaps[c]; !ok {
				r.UnusedAllowance = append(r.UnusedAllowance, Finding{
					Kind: "unused_allowance", Category: "capability", Subject: c,
					Reason: "policy allows capability but runtime never used it",
				})
			}
		}
	}
	if cats.Syscalls {
		for s := range polSyscalls {
			if _, ok := obsSyscalls[s]; !ok {
				r.UnusedAllowance = append(r.UnusedAllowance, Finding{
					Kind: "unused_allowance", Category: "syscalls", Subject: s,
					Reason: "policy allows syscall but runtime never used it",
				})
			}
		}
	}
	sortFindings(r.UnusedAllowance)
	sortFindings(r.ObservedButDenied)

	// Drift: Jaccard distance over union of enabled-category keys.
	obsKeys := enabledKeys(cats, obsExec, obsReadPaths, obsWritePaths, obsEgress, obsCaps, obsSyscalls)
	polKeys := enabledKeys(cats,
		polExec,
		filePathSet(policy.Spec.File.Read), filePathSet(policy.Spec.File.Write),
		polEgress, polCaps, polSyscalls,
	)
	r.DriftScore = jaccardDistance(obsKeys, polKeys)

	// Coverage: fraction of observed items the policy permits, scoped to
	// enabled categories only.
	r.TotalObserved = len(obsKeys)
	r.TotalObservedDenied = len(r.ObservedButDenied)
	if r.TotalObserved > 0 {
		permitted := max(r.TotalObserved-r.TotalObservedDenied, 0)
		r.CoveragePercent = float64(permitted) / float64(r.TotalObserved) * 100
	}
	return r
}

func sortFindings(fs []Finding) {
	slices.SortFunc(fs, func(a, b Finding) int {
		if c := strings.Compare(a.Category, b.Category); c != 0 {
			return c
		}
		return strings.Compare(a.Subject, b.Subject)
	})
}

func execSet(c *Contract) map[string]struct{} {
	out := map[string]struct{}{}
	for _, r := range c.Spec.Process.Exec {
		out[r.Binary] = struct{}{}
	}
	return out
}

func egressSet(c *Contract) map[string]struct{} {
	out := map[string]struct{}{}
	for _, r := range c.Spec.Network.Egress {
		out[r.Peer] = struct{}{}
	}
	return out
}

func filePathSet(rs []FileRule) map[string]struct{} {
	out := map[string]struct{}{}
	for _, r := range rs {
		if r.Path != "" {
			out[r.Path] = struct{}{}
		} else if r.PathGlob != "" {
			out[r.PathGlob] = struct{}{}
		}
	}
	return out
}

func toSet(ss []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, s := range ss {
		out[s] = struct{}{}
	}
	return out
}

func ruleKey(r FileRule) string {
	if r.PathGlob != "" {
		return r.PathGlob
	}
	return r.Path
}

// matchAnyObservedPath checks if the policy rule's key matches any observed
// literal path. This lets policy globs cover multiple observed literals.
func matchAnyObservedPath(rule FileRule, observed map[string]struct{}) bool {
	if rule.Path != "" {
		_, ok := observed[rule.Path]
		return ok
	}
	if rule.PathGlob == "" {
		return false
	}
	tmp := Contract{Spec: Spec{File: FileSpec{Read: []FileRule{rule}, Write: []FileRule{rule}}}}
	for p := range observed {
		if tmp.AllowsFileRead(p) {
			return true
		}
	}
	return false
}

// enabledKeys unions keys from per-category sets, skipping categories that
// aren't selected. Keeping the union scoped to enabled categories is what
// makes drift/coverage meaningful for narrow-scope formats like seccomp —
// otherwise a syscalls-only policy scores 0% coverage against file+net
// observations it could never constrain.
func enabledKeys(cats GapCategories, exec, read, write, egress, caps, syscalls map[string]struct{}) map[string]struct{} {
	out := map[string]struct{}{}
	if cats.Exec {
		for k := range exec {
			out[k] = struct{}{}
		}
	}
	if cats.FileRead {
		for k := range read {
			out[k] = struct{}{}
		}
	}
	if cats.FileWrite {
		for k := range write {
			out[k] = struct{}{}
		}
	}
	if cats.NetEgress {
		for k := range egress {
			out[k] = struct{}{}
		}
	}
	if cats.Capabilities {
		for k := range caps {
			out[k] = struct{}{}
		}
	}
	if cats.Syscalls {
		for k := range syscalls {
			out[k] = struct{}{}
		}
	}
	return out
}

func jaccardDistance(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return 1.0 - float64(inter)/float64(union)
}
