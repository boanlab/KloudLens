// SPDX-License-Identifier: Apache-2.0

package policyspec

import (
	"strings"
	"testing"
)

func TestValidateHookSubscriptionGoodAndBad(t *testing.T) {
	good := []byte("kind: HookSubscription\nmetadata: {name: ok}\nspec: {syscalls: {include: [openat]}}")
	if err := ValidateHookSubscription(good); err != nil {
		t.Fatalf("valid document should pass: %v", err)
	}
	bad := []byte("kind: HookSubscription\nmetadata: {name: bad}\nspec: {enrichment: {level: full2}}")
	err := ValidateHookSubscription(bad)
	if err == nil {
		t.Fatal("bad enrichment.level should be rejected")
	}
	if !strings.Contains(err.Error(), "enrichment.level") {
		t.Errorf("error should name the field: %v", err)
	}
}

// TestValidateBaselineProfileGoodAndBad exercises the BaselinePolicy
// façade. Good path: round-trip a MarshalProfile output. Bad path:
// malformed JSON — caught before it reaches the admin's profile store.
func TestValidateBaselineProfileGoodAndBad(t *testing.T) {
	// Minimal well-formed profile JSON matching profileWire — schema v3,
	// empty allow-sets. UnmarshalProfile accepts a sparse profile, so
	// this is the contract: structural validity only.
	good := []byte(`{"schemaVersion":3,"id":"p1","sampleCount":0,"confidence":0}`)
	if err := ValidateBaselineProfile(good); err != nil {
		t.Fatalf("valid profile should pass: %v", err)
	}
	bad := []byte(`{"schemaVersion":3, "id":`) // truncated
	if err := ValidateBaselineProfile(bad); err == nil {
		t.Fatal("truncated JSON should be rejected")
	}
	wrongType := []byte(`{"schemaVersion":"three"}`)
	if err := ValidateBaselineProfile(wrongType); err == nil {
		t.Fatal("string-for-int type error should be rejected")
	}
}

// TestValidateDispatchesOnKind confirms Validate routes to the right
// parser and is a no-op for kinds without a public parser — the admin
// server keeps the whitelist; this package only validates what it can.
func TestValidateDispatchesOnKind(t *testing.T) {
	bad := []byte("kind: HookSubscription\nmetadata: {name: bad}\nspec: {pairing: wrong}")
	if err := Validate("HookSubscription", bad); err == nil {
		t.Error("HookSubscription dispatch must reject bad pairing")
	}
	// BaselinePolicy dispatch — bad JSON routes through UnmarshalProfile.
	if err := Validate("BaselinePolicy", []byte("not json")); err == nil {
		t.Error("BaselinePolicy dispatch must reject malformed JSON")
	}
	// BehaviorContract strict-parses through pkg/contract.Parse. A
	// freeform string has no kind/apiVersion and must be rejected.
	if err := Validate("BehaviorContract", []byte("anything")); err == nil {
		t.Error("BehaviorContract dispatch must reject non-contract payloads")
	}
	// Happy path — well-formed BehaviorContract must pass dispatch.
	goodBC := []byte("apiVersion: kloudlens.io/v1\nkind: BehaviorContract\nmetadata: {contractID: x}\n")
	if err := Validate("BehaviorContract", goodBC); err != nil {
		t.Errorf("BehaviorContract dispatch rejected a valid contract: %v", err)
	}
	// Unknown-kind fall-through stays a no-op — admin whitelist still gates.
	if err := Validate("SomethingElse", []byte("anything")); err != nil {
		t.Errorf("unknown kind should be no-op for offline linter, got %v", err)
	}
}
