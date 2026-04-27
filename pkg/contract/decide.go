// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package contract

import "github.com/boanlab/kloudlens/pkg/types"

// Decision is the outcome of evaluating an event against a contract.
type Decision struct {
	Allow  bool
	Reason string
}

// Decide evaluates a single IntentEvent against the contract.
// Kinds the contract IR has no rule shape for return Allow=true with
// reason "out_of_scope" so replay doesn't fail on events the policy is
// silent on. Currently covered: ProcessStart/Exec, FileRead(), FileWrite(),
// FileAccess, FileReadWrite(), NetworkExchange(), DNSAnswer.
func Decide(c *Contract, ev types.IntentEvent) Decision {
	switch ev.Kind {
	case "ProcessStart", "Exec":
		bin := ev.Attributes["binary"]
		if bin == "" {
			return Decision{Allow: true, Reason: "missing binary attr"}
		}
		if c.AllowsExec(bin) {
			return Decision{Allow: true, Reason: "exec permitted"}
		}
		return Decision{Allow: false, Reason: "exec not in allow-set: " + bin}
	case "FileRead":
		p := ev.Attributes["path"]
		if p == "" {
			return Decision{Allow: true, Reason: "missing path attr"}
		}
		if c.AllowsFileRead(p) {
			return Decision{Allow: true, Reason: "file.read permitted"}
		}
		return Decision{Allow: false, Reason: "file.read not in allow-set: " + p}
	case "FileWrite":
		p := ev.Attributes["path"]
		if p == "" {
			return Decision{Allow: true, Reason: "missing path attr"}
		}
		if c.AllowsFileWrite(p) {
			return Decision{Allow: true, Reason: "file.write permitted"}
		}
		return Decision{Allow: false, Reason: "file.write not in allow-set: " + p}
	case "FileAccess":
		// Open without observable IO direction. Either rule covers it,
		// since the fd could have been used for read or write.
		p := ev.Attributes["path"]
		if p == "" {
			return Decision{Allow: true, Reason: "missing path attr"}
		}
		if c.AllowsFileRead(p) || c.AllowsFileWrite(p) {
			return Decision{Allow: true, Reason: "file.access permitted"}
		}
		return Decision{Allow: false, Reason: "file.access not in allow-set: " + p}
	case "FileReadWrite":
		// Both read AND write happened on the same fd window — both
		// rules must permit the path. Stricter than FileAccess on
		// purpose: an IO-heavy workload that's only allow-listed for
		// read should still trip on observed writes.
		p := ev.Attributes["path"]
		if p == "" {
			return Decision{Allow: true, Reason: "missing path attr"}
		}
		if !c.AllowsFileRead(p) {
			return Decision{Allow: false, Reason: "file.read not in allow-set: " + p}
		}
		if !c.AllowsFileWrite(p) {
			return Decision{Allow: false, Reason: "file.write not in allow-set: " + p}
		}
		return Decision{Allow: true, Reason: "file.read+write permitted"}
	case "NetworkExchange":
		peer := ev.Attributes["peer"]
		if peer == "" {
			return Decision{Allow: true, Reason: "missing peer attr"}
		}
		if c.AllowsEgress(peer) {
			return Decision{Allow: true, Reason: "egress permitted"}
		}
		return Decision{Allow: false, Reason: "egress not in allow-set: " + peer}
	case "DNSAnswer":
		// Evaluate against the FQDN side of the egress allow-list.
		// Empty query (TCP DNS, AAAA suppression, …) is silently
		// allowed — the upstream NetworkExchange evaluation still
		// guards the actual peer.
		q := ev.Attributes["query"]
		if q == "" {
			return Decision{Allow: true, Reason: "missing query attr"}
		}
		if c.AllowsDNS(q) {
			return Decision{Allow: true, Reason: "dns permitted"}
		}
		return Decision{Allow: false, Reason: "dns not in allow-set: " + q}
	}
	return Decision{Allow: true, Reason: "out_of_scope"}
}

// ReplaySummary aggregates decisions from a dry-run over historical intents.
type ReplaySummary struct {
	Total   int
	Allowed int
	Denied  int
	// First N denies, to display to the user without carrying MBs of context.
	Samples []DeniedSample
}

type DeniedSample struct {
	IntentID string
	Kind     string
	Reason   string
}

// Replay runs Decide over a slice of events and returns a summary.
func Replay(c *Contract, events []types.IntentEvent, maxSamples int) ReplaySummary {
	if maxSamples == 0 {
		maxSamples = 20
	}
	var rs ReplaySummary
	for _, ev := range events {
		rs.Total++
		d := Decide(c, ev)
		if d.Allow {
			rs.Allowed++
			continue
		}
		rs.Denied++
		if len(rs.Samples) < maxSamples {
			rs.Samples = append(rs.Samples, DeniedSample{IntentID: ev.IntentID, Kind: ev.Kind, Reason: d.Reason})
		}
	}
	return rs
}
