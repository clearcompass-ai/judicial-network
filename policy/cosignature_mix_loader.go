/*
FILE PATH: policy/cosignature_mix_loader.go

DESCRIPTION:
    File-backed loader for the cosignature-mix policy. Reads a
    JSON file with shape:

      {
        "rules": [
          {
            "event_type": "motion_continuance",
            "allowed_filer_roles": ["defense_counsel", "civil_attorney"],
            "required_signer_roles": ["court_clerk", "judge"],
            "min_signer_cosigners": 1,
            "intra_exchange_only": true,
            "required_credentials": ["bpr_number"]
          },
          ...
        ]
      }

    Mirrors the role-catalog loader pattern: ParseJSON for in-memory
    deserialization, LoadFile for disk + parse, ReloadFromFile for
    the SIGHUP hot-reload path. Failed reload (missing file, parse
    error, validation error) keeps the previous policy in effect —
    the system never goes policy-less at runtime.

    Production deployments may skip the file path entirely and use
    the Davidson reference fixture (cosignature_mix_davidson.go) or
    a custom Go-defined slice.

OVERVIEW:
    ParseJSON          — bytes → InMemoryPolicy.
    LoadFile           — path → InMemoryPolicy.
    ReloadFromFile     — atomic refresh of an existing policy.

KEY DEPENDENCIES:
    - policy/cosignature_mix.go (CosignatureRule, InMemoryPolicy).
*/
package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

// policyFile is the on-disk JSON shape.
type policyFile struct {
	Rules []CosignatureRule `json:"rules"`
}

// ParseJSON decodes JSON bytes into a fresh InMemoryPolicy. Used
// by tests and by operators piping content from a config service.
func ParseJSON(data []byte) (*InMemoryPolicy, error) {
	var f policyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("policy/cosignature_mix: parse: %w", err)
	}
	return NewInMemoryPolicy(f.Rules)
}

// LoadFile reads, parses, and validates a policy JSON file.
func LoadFile(path string) (*InMemoryPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy/cosignature_mix: read %q: %w", path, err)
	}
	return ParseJSON(data)
}

// ReloadFromFile re-reads a JSON file and atomically replaces the
// policy's rules. Used by SIGHUP handlers; failed reloads bubble
// up and the caller leaves the previous policy in effect.
func (p *InMemoryPolicy) ReloadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("policy/cosignature_mix: read %q: %w", path, err)
	}
	var f policyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("policy/cosignature_mix: parse %q: %w", path, err)
	}
	return p.Replace(f.Rules)
}
