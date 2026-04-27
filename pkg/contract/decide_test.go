// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package contract

import (
	"testing"

	"github.com/boanlab/kloudlens/pkg/types"
)

// fixedContract returns a contract that allows enough surface to
// exercise every Decide arm: a binary, a read-only path, a
// read+write path, an IP peer, and an FQDN glob.
func fixedContract() *Contract {
	c := &Contract{
		APIVersion: APIVersion,
		Kind:       Kind,
		Spec: Spec{
			Process: ProcessSpec{Exec: []ExecRule{{Binary: "/usr/bin/curl"}}},
			File: FileSpec{
				Read:  []FileRule{{Path: "/etc/resolv.conf"}, {Path: "/var/lib/data"}},
				Write: []FileRule{{Path: "/var/lib/data"}, {Path: "/var/log/app.log"}},
			},
			Network: NetworkSpec{Egress: []EgressRule{
				{Peer: "10.0.0.1:443"},
				{FQDN: "*.example.com"},
				{FQDN: "api.anthropic.com"},
			}},
		},
	}
	c.Sort()
	return c
}

func TestDecideExec(t *testing.T) {
	c := fixedContract()
	if d := Decide(c, types.IntentEvent{Kind: "ProcessStart", Attributes: map[string]string{"binary": "/usr/bin/curl"}}); !d.Allow {
		t.Errorf("permitted exec denied: %+v", d)
	}
	if d := Decide(c, types.IntentEvent{Kind: "Exec", Attributes: map[string]string{"binary": "/bin/sh"}}); d.Allow {
		t.Errorf("non-allow-set exec passed: %+v", d)
	}
	if d := Decide(c, types.IntentEvent{Kind: "ProcessStart"}); !d.Allow {
		t.Errorf("missing binary attr should pass with reason: %+v", d)
	}
}

// TestDecideFileAccessAcceptsEitherRule covers an open without IO
// direction: either Read or Write covering the path is enough since the
// fd was never observed used. Locks in the "less strict than RW"
// invariant the comment in decide.go states.()
func TestDecideFileAccessAcceptsEitherRule(t *testing.T) {
	c := fixedContract()
	// Read-only path → allowed (Read covers it).
	if d := Decide(c, types.IntentEvent{Kind: "FileAccess", Attributes: map[string]string{"path": "/etc/resolv.conf"}}); !d.Allow {
		t.Errorf("read-only path should pass FileAccess: %+v", d)
	}
	// Write-only path → allowed (Write covers it).
	if d := Decide(c, types.IntentEvent{Kind: "FileAccess", Attributes: map[string]string{"path": "/var/log/app.log"}}); !d.Allow {
		t.Errorf("write-only path should pass FileAccess: %+v", d)
	}
	// Neither rule covers it → denied.
	if d := Decide(c, types.IntentEvent{Kind: "FileAccess", Attributes: map[string]string{"path": "/etc/shadow"}}); d.Allow {
		t.Errorf("uncovered path passed FileAccess: %+v", d)
	}
}

// TestDecideFileReadWriteRequiresBothRules locks in the stricter
// FileReadWrite invariant: an observed read+write window needs both
// permissions, even if either rule alone would permit a one-direction
// IO event.
func TestDecideFileReadWriteRequiresBothRules(t *testing.T) {
	c := fixedContract()
	if d := Decide(c, types.IntentEvent{Kind: "FileReadWrite", Attributes: map[string]string{"path": "/var/lib/data"}}); !d.Allow {
		t.Errorf("dual-allowed path denied: %+v", d)
	}
	// Read-only path observed with a write → deny on the write.
	if d := Decide(c, types.IntentEvent{Kind: "FileReadWrite", Attributes: map[string]string{"path": "/etc/resolv.conf"}}); d.Allow {
		t.Errorf("RW on read-only path passed: %+v", d)
	}
	// Write-only path observed with a read → deny on the read.
	if d := Decide(c, types.IntentEvent{Kind: "FileReadWrite", Attributes: map[string]string{"path": "/var/log/app.log"}}); d.Allow {
		t.Errorf("RW on write-only path passed: %+v", d)
	}
}

func TestDecideNetworkExchange(t *testing.T) {
	c := fixedContract()
	if d := Decide(c, types.IntentEvent{Kind: "NetworkExchange", Attributes: map[string]string{"peer": "10.0.0.1:443"}}); !d.Allow {
		t.Errorf("permitted peer denied: %+v", d)
	}
	if d := Decide(c, types.IntentEvent{Kind: "NetworkExchange", Attributes: map[string]string{"peer": "10.99.0.1:443"}}); d.Allow {
		t.Errorf("non-allow-set peer passed: %+v", d)
	}
}

// TestDecideDNSAnswerMatchesFQDN: exact and glob FQDNs both succeed;
// peer-only egress entries don't accidentally allow arbitrary qnames.
func TestDecideDNSAnswerMatchesFQDN(t *testing.T) {
	c := fixedContract()
	if d := Decide(c, types.IntentEvent{Kind: "DNSAnswer", Attributes: map[string]string{"query": "api.anthropic.com"}}); !d.Allow {
		t.Errorf("exact FQDN denied: %+v", d)
	}
	if d := Decide(c, types.IntentEvent{Kind: "DNSAnswer", Attributes: map[string]string{"query": "foo.example.com"}}); !d.Allow {
		t.Errorf("glob FQDN denied: %+v", d)
	}
	if d := Decide(c, types.IntentEvent{Kind: "DNSAnswer", Attributes: map[string]string{"query": "evil.com"}}); d.Allow {
		t.Errorf("non-allow-set FQDN passed: %+v", d)
	}
	// Peer-only egress entries don't satisfy DNS rules.
	cIPOnly := &Contract{Spec: Spec{Network: NetworkSpec{Egress: []EgressRule{{Peer: "10.0.0.1:443"}}}}}
	if d := Decide(cIPOnly, types.IntentEvent{Kind: "DNSAnswer", Attributes: map[string]string{"query": "anything.com"}}); d.Allow {
		t.Errorf("peer-only contract allowed DNS: %+v", d)
	}
	// Empty query short-circuits to allow (NetworkExchange guards the actual peer).
	if d := Decide(c, types.IntentEvent{Kind: "DNSAnswer"}); !d.Allow {
		t.Errorf("empty query should pass: %+v", d)
	}
}

func TestDecideOutOfScopeKindAllows(t *testing.T) {
	c := fixedContract()
	if d := Decide(c, types.IntentEvent{Kind: "CapabilityUse"}); !d.Allow || d.Reason != "out_of_scope" {
		t.Errorf("CapabilityUse should pass with out_of_scope, got %+v", d)
	}
}

// TestAllowsEgressIgnoresFQDNOnlyRules: an FQDN-only entry must not
// satisfy a peer:IP:PORT lookup. Catches the regression where the
// AllowsEgress loop accidentally short-circuits on an empty Peer and
// returns true.
func TestAllowsEgressIgnoresFQDNOnlyRules(t *testing.T) {
	c := &Contract{Spec: Spec{Network: NetworkSpec{Egress: []EgressRule{{FQDN: "*.example.com"}}}}}
	if c.AllowsEgress("10.0.0.1:443") {
		t.Error("FQDN-only rule must not match peer lookup")
	}
}
