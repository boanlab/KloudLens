// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Parse decodes a BehaviorContract document in YAML or JSON form. The
// input format is auto-detected by peeking at the first non-whitespace
// byte: `{` or `[` routes through encoding/json, anything else through
// yaml.v3. Both struct-tag sets (`yaml:"..."` and `json:"..."`) live on
// the Contract type, so field coverage is identical across formats.
//
// On success the returned contract has been normalized via Sort so gap
// analysis and round-trips are deterministic. Parse rejects:
// - empty payloads (bytes-only or whitespace-only)
// - malformed YAML/JSON
// - wrong Kind (must equal contract.Kind)
// - APIVersion that does not start with "kloudlens.io/" — callers can
// accept any minor version under the v1 family this way
//
// Parse is the single source of truth for BehaviorContract strict-parse.
// `internal/admin.validatePolicy` and `pkg/policyspec.ValidateBehaviorContract`
// both route through here so that `klctl apply` (live) and the offline
// linter accept or reject the exact same documents.
func Parse(raw []byte) (*Contract, error) {
	if len(raw) == 0 {
		return nil, errors.New("contract: empty payload")
	}
	trimmed := strings.TrimLeftFunc(string(raw), unicode.IsSpace)
	if trimmed == "" {
		return nil, errors.New("contract: whitespace-only payload")
	}

	var c Contract
	first := trimmed[0]
	if first == '{' || first == '[' {
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("contract: invalid JSON: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("contract: invalid YAML: %w", err)
		}
	}

	if c.Kind != Kind {
		return nil, fmt.Errorf("contract: kind %q (want %q)", c.Kind, Kind)
	}
	if !strings.HasPrefix(c.APIVersion, "kloudlens.io/") {
		return nil, fmt.Errorf("contract: apiVersion %q (want kloudlens.io/*)", c.APIVersion)
	}

	c.Sort()
	return &c, nil
}
