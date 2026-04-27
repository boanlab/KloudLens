// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package contract implements the Behavior Contract IR and Gap Analysis
// engine. A Contract is the tool-agnostic policy artifact derived from an
// observed Profile. Gap analysis compares two contracts (usually observed
// vs imported existing-policy) and reports `unused_allowance`,
// `observed_but_denied`, `drift_score`, and `coverage`. A Decide function
// supports dry-run replay.
package contract

import (
	"errors"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/boanlab/kloudlens/pkg/baseline"
)

const APIVersion = "kloudlens.io/v1"
const Kind = "BehaviorContract"

// Contract is the tool-agnostic behavioral policy IR.
type Contract struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Metadata   Metadata `yaml:"metadata" json:"metadata"`
	Spec       Spec     `yaml:"spec" json:"spec"`
}

type Metadata struct {
	ContractID  string      `yaml:"contractID" json:"contractID"`
	DerivedFrom DerivedFrom `yaml:"derivedFrom,omitempty" json:"derivedFrom,omitempty"`
}

type DerivedFrom struct {
	ProfileID   string    `yaml:"profileID,omitempty" json:"profileID,omitempty"`
	LearnStart  time.Time `yaml:"learnStart,omitempty" json:"learnStart,omitempty"`
	LearnEnd    time.Time `yaml:"learnEnd,omitempty" json:"learnEnd,omitempty"`
	SampleCount uint64    `yaml:"sampleCount,omitempty" json:"sampleCount,omitempty"`
	Confidence  float64   `yaml:"confidence,omitempty" json:"confidence,omitempty"`
}

type Spec struct {
	Process      ProcessSpec `yaml:"process,omitempty" json:"process,omitempty"`
	File         FileSpec    `yaml:"file,omitempty" json:"file,omitempty"`
	Network      NetworkSpec `yaml:"network,omitempty" json:"network,omitempty"`
	Capabilities []string    `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	Creds        CredsSpec   `yaml:"creds,omitempty" json:"creds,omitempty"`
	Syscalls     []string    `yaml:"syscalls,omitempty" json:"syscalls,omitempty"`
}

type ProcessSpec struct {
	Exec []ExecRule `yaml:"exec,omitempty" json:"exec,omitempty"`
}

type ExecRule struct {
	Binary   string   `yaml:"binary" json:"binary"`
	Evidence Evidence `yaml:"evidence,omitempty" json:"evidence,omitempty"`
}

type FileSpec struct {
	Read  []FileRule `yaml:"read,omitempty" json:"read,omitempty"`
	Write []FileRule `yaml:"write,omitempty" json:"write,omitempty"`
}

type FileRule struct {
	Path     string   `yaml:"path,omitempty" json:"path,omitempty"`
	PathGlob string   `yaml:"pathGlob,omitempty" json:"pathGlob,omitempty"`
	Evidence Evidence `yaml:"evidence,omitempty" json:"evidence,omitempty"`
}

type NetworkSpec struct {
	Egress []EgressRule `yaml:"egress,omitempty" json:"egress,omitempty"`
}

// EgressRule allows a single egress destination. Peer is the literal
// IP:port form emitted by NetworkExchange; FQDN (optional) carries a
// hostname or glob (e.g. `*.example.com`) used to evaluate DNSAnswer
// intents whose `query` matches the rule. A rule may set Peer alone
// (IP-only allow), FQDN alone (DNS-only allow), or both.
type EgressRule struct {
	Peer     string   `yaml:"peer,omitempty" json:"peer,omitempty"`
	FQDN     string   `yaml:"fqdn,omitempty" json:"fqdn,omitempty"`
	Proto    string   `yaml:"proto,omitempty" json:"proto,omitempty"`
	Evidence Evidence `yaml:"evidence,omitempty" json:"evidence,omitempty"`
}

type CredsSpec struct {
	UIDs []uint32 `yaml:"uids,omitempty" json:"uids,omitempty"`
}

type Evidence struct {
	Count     uint64    `yaml:"count,omitempty" json:"count,omitempty"`
	FirstSeen time.Time `yaml:"firstSeen,omitempty" json:"firstSeen,omitempty"`
	LastSeen  time.Time `yaml:"lastSeen,omitempty" json:"lastSeen,omitempty"`
	IntentIDs []string  `yaml:"intentIDs,omitempty" json:"intentIDs,omitempty"`
}

// ErrInsufficientConfidence is returned by FromProfile when the upstream
// profile didn't meet the confidence bar safety.
var ErrInsufficientConfidence = errors.New("contract: profile confidence below minimum")

// FromProfile converts a promoted baseline.Profile to a Contract. Callers
// supply the minimum confidence required
func FromProfile(p *baseline.Profile, minConfidence float64) (*Contract, error) {
	if p == nil {
		return nil, errors.New("contract: nil profile")
	}
	if p.Confidence < minConfidence {
		return nil, ErrInsufficientConfidence
	}
	c := &Contract{
		APIVersion: APIVersion,
		Kind:       Kind,
		Metadata: Metadata{
			ContractID: p.ID,
			DerivedFrom: DerivedFrom{
				ProfileID:   p.ID,
				LearnStart:  p.LearnStart,
				LearnEnd:    p.LearnEnd,
				SampleCount: p.SampleCount,
				Confidence:  p.Confidence,
			},
		},
	}
	execs, paths, writePaths, peers, caps, syscalls, uids := p.SortedAllowSet()
	for _, b := range execs {
		c.Spec.Process.Exec = append(c.Spec.Process.Exec, ExecRule{Binary: b})
	}
	writeSet := make(map[string]struct{}, len(writePaths))
	for _, pat := range writePaths {
		writeSet[pat] = struct{}{}
	}
	for _, pat := range paths {
		r := FileRule{}
		if containsGlob(pat) {
			r.PathGlob = pat
		} else {
			r.Path = pat
		}
		// A path that the baseline observed via a write-style op lands in
		// Spec.File.Write(); "write" subsumes "read" at enforcement time, so
		// we don't duplicate the entry into Read. Paths seen only through
		// reads, or direction-unknown observations, go into Read.
		if _, isWrite := writeSet[pat]; isWrite {
			c.Spec.File.Write = append(c.Spec.File.Write, r)
		} else {
			c.Spec.File.Read = append(c.Spec.File.Read, r)
		}
	}
	for _, peer := range peers {
		c.Spec.Network.Egress = append(c.Spec.Network.Egress, EgressRule{Peer: peer, Proto: "tcp"})
	}
	c.Spec.Capabilities = append(c.Spec.Capabilities, caps...)
	c.Spec.Creds.UIDs = append(c.Spec.Creds.UIDs, uids...)
	c.Spec.Syscalls = append(c.Spec.Syscalls, syscalls...)
	c.Sort()
	return c, nil
}

// Sort brings the contract into a deterministic order
func (c *Contract) Sort() {
	slices.SortFunc(c.Spec.Process.Exec, func(a, b ExecRule) int { return strings.Compare(a.Binary, b.Binary) })
	sortFileRules(c.Spec.File.Read)
	sortFileRules(c.Spec.File.Write)
	slices.SortFunc(c.Spec.Network.Egress, func(a, b EgressRule) int { return strings.Compare(a.Peer, b.Peer) })
	slices.Sort(c.Spec.Capabilities)
	slices.Sort(c.Spec.Creds.UIDs)
	slices.Sort(c.Spec.Syscalls)
}

func sortFileRules(rs []FileRule) {
	slices.SortFunc(rs, func(a, b FileRule) int {
		ka := a.Path
		if a.PathGlob != "" {
			ka = a.PathGlob
		}
		kb := b.Path
		if b.PathGlob != "" {
			kb = b.PathGlob
		}
		return strings.Compare(ka, kb)
	})
}

func containsGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// Allows returns true if the contract permits the given operation. Used by
// Decide for dry-run replay and by gap analysis.
func (c *Contract) AllowsExec(binary string) bool {
	for _, r := range c.Spec.Process.Exec {
		if r.Binary == binary {
			return true
		}
	}
	return false
}

func (c *Contract) AllowsFileRead(query string) bool {
	return allowsFile(c.Spec.File.Read, query)
}

func (c *Contract) AllowsFileWrite(query string) bool {
	return allowsFile(c.Spec.File.Write, query)
}

func allowsFile(rules []FileRule, query string) bool {
	for _, r := range rules {
		if r.Path != "" && r.Path == query {
			return true
		}
		if r.PathGlob != "" {
			if m, err := path.Match(r.PathGlob, query); err == nil && m {
				return true
			}
		}
	}
	return false
}

func (c *Contract) AllowsEgress(peer string) bool {
	for _, r := range c.Spec.Network.Egress {
		if r.Peer != "" && r.Peer == peer {
			return true
		}
	}
	return false
}

// AllowsDNS reports whether any egress rule's FQDN matches qname. Rules
// may use exact strings (`api.example.com`) or shell globs
// (`*.example.com`); both forms route through path.Match. Rules with an
// empty FQDN are skipped — they're peer-only entries that AllowsEgress
// handles separately.
func (c *Contract) AllowsDNS(qname string) bool {
	if qname == "" {
		return false
	}
	for _, r := range c.Spec.Network.Egress {
		if r.FQDN == "" {
			continue
		}
		if r.FQDN == qname {
			return true
		}
		if m, err := path.Match(r.FQDN, qname); err == nil && m {
			return true
		}
	}
	return false
}
