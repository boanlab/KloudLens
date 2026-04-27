// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"strings"
	"testing"
)

func TestParseGoodYAML(t *testing.T) {
	raw := []byte(`apiVersion: kloudlens.io/v1
kind: BehaviorContract
metadata:
  contractID: c1
spec:
  process:
    exec:
      - binary: /bin/sh
      - binary: /bin/ls
  capabilities: [CAP_NET_ADMIN, CAP_CHOWN]
`)
	c, err := Parse(raw)
	if err != nil {
		t.Fatalf("good YAML rejected: %v", err)
	}
	if c.Metadata.ContractID != "c1" {
		t.Errorf("metadata.contractID = %q", c.Metadata.ContractID)
	}
	// Sort ran: exec ordered by binary, caps alpha-sorted.
	if len(c.Spec.Process.Exec) != 2 || c.Spec.Process.Exec[0].Binary != "/bin/ls" {
		t.Errorf("exec not sorted: %+v", c.Spec.Process.Exec)
	}
	if c.Spec.Capabilities[0] != "CAP_CHOWN" {
		t.Errorf("capabilities not sorted: %+v", c.Spec.Capabilities)
	}
}

func TestParseGoodJSON(t *testing.T) {
	raw := []byte(` {"apiVersion":"kloudlens.io/v1","kind":"BehaviorContract",
		"metadata":{"contractID":"c2"},
		"spec":{"capabilities":["CAP_B","CAP_A"]}}`)
	c, err := Parse(raw)
	if err != nil {
		t.Fatalf("good JSON rejected: %v", err)
	}
	if c.Metadata.ContractID != "c2" {
		t.Errorf("metadata.contractID = %q", c.Metadata.ContractID)
	}
	if c.Spec.Capabilities[0] != "CAP_A" {
		t.Errorf("capabilities not sorted: %+v", c.Spec.Capabilities)
	}
}

func TestParseEmptyOrWhitespace(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Error("nil payload must be rejected")
	}
	if _, err := Parse([]byte("")); err == nil {
		t.Error("empty payload must be rejected")
	}
	if _, err := Parse([]byte(" \n\t ")); err == nil {
		t.Error("whitespace-only payload must be rejected")
	}
}

func TestParseWrongKind(t *testing.T) {
	raw := []byte(`apiVersion: kloudlens.io/v1
kind: HookSubscription
metadata: {contractID: c3}
`)
	_, err := Parse(raw)
	if err == nil {
		t.Fatal("wrong Kind must be rejected")
	}
	if !strings.Contains(err.Error(), "kind") {
		t.Errorf("error should mention kind: %v", err)
	}
}

func TestParseWrongAPIVersion(t *testing.T) {
	raw := []byte(`apiVersion: example.com/v1
kind: BehaviorContract
metadata: {contractID: c4}
`)
	_, err := Parse(raw)
	if err == nil {
		t.Fatal("foreign apiVersion must be rejected")
	}
	if !strings.Contains(err.Error(), "apiVersion") {
		t.Errorf("error should mention apiVersion: %v", err)
	}
}

func TestParseMalformedYAML(t *testing.T) {
	raw := []byte("apiVersion: kloudlens.io/v1\nkind: [unterminated")
	if _, err := Parse(raw); err == nil {
		t.Fatal("malformed YAML must be rejected")
	}
}

func TestParseMalformedJSON(t *testing.T) {
	// Leading `{` forces JSON path; body is truncated.
	raw := []byte(`{"apiVersion":"kloudlens.io/v1","kind":"BehaviorContract",`)
	if _, err := Parse(raw); err == nil {
		t.Fatal("truncated JSON must be rejected")
	}
}
