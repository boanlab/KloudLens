// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package policyspec is a thin public façade over the internal policy
// loaders so out-of-tree callers (klctl, CI linters, IDE plugins) can
// validate KloudLens policy YAML without an agent running.
//
// The admin server reuses the same underlying parsers, so a document
// accepted here is accepted at klctl apply time — and a document this
// package rejects is the same one the agent would reject. Keeping the
// parse path single-sourced is the whole point of this package; do not
// add validation rules here that diverge from internal/policy.
package policyspec

import (
	"github.com/boanlab/kloudlens/internal/policy"
	"github.com/boanlab/kloudlens/pkg/baseline"
	"github.com/boanlab/kloudlens/pkg/contract"
)

// ValidateHookSubscription parses a HookSubscription YAML/JSON document.
// Returns the same error the admin ApplyPolicy RPC would return for the
// same payload — enum violations (pairing, graceful.onMissing,
// enrichment.level), missing kind or metadata.name, etc.
func ValidateHookSubscription(raw []byte) error {
	_, err := policy.Parse(raw)
	return err
}

// ValidateBaselineProfile parses a BaselinePolicy payload (the JSON form
// emitted by `klctl baseline promote` / pkg/baseline.MarshalProfile()).
// Malformed JSON or fields with the wrong type surface here; semantic
// emptiness (all allow-sets empty) is intentionally accepted — a freshly
// promoted profile is allowed to be sparse.
func ValidateBaselineProfile(raw []byte) error {
	_, err := baseline.UnmarshalProfile(raw)
	return err
}

// ValidateBehaviorContract parses a BehaviorContract payload (YAML or
// JSON — auto-detected from the first non-whitespace byte). Surfaces
// malformed documents, wrong Kind, and unsupported apiVersion prefixes
// at klctl apply / lint time instead of silently storing a shape-valid
// but semantically wrong contract that would later confuse gap analysis
// or decide-replay. Routes through pkg/contract.Parse so the admin
// server and the offline linter share a single parser.
func ValidateBehaviorContract(raw []byte) error {
	_, err := contract.Parse(raw)
	return err
}

// Validate dispatches on kind. `kind` is the Policy.Kind string used by
// klctl apply (HookSubscription | BaselinePolicy | BehaviorContract).
// Unknown kinds return nil — the admin server's kind whitelist still
// gates them, but the offline linter stays quiet on kinds this package
// hasn't learned to parse. Callers that want stricter behavior can gate
// on kind first.
func Validate(kind string, raw []byte) error {
	switch kind {
	case "HookSubscription":
		return ValidateHookSubscription(raw)
	case "BaselinePolicy":
		return ValidateBaselineProfile(raw)
	case "BehaviorContract":
		return ValidateBehaviorContract(raw)
	default:
		return nil
	}
}
