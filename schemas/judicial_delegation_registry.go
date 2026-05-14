/*
FILE PATH: schemas/judicial_delegation_registry.go

DESCRIPTION:

	Marshal helpers, schema parameters, and registry registrations
	for the three delegation entry shapes. Split out of
	judicial_delegation.go to keep that file focused on the
	payload types + Validate methods.

OVERVIEW:

	Marshal{Delegation,Revocation,Succession}Payload — validate-then-JSON.
	Unmarshal{Delegation,Revocation,Succession}Payload — JSON-then-validate.
	Default{Delegation,Revocation,Succession}Params  — registry params bytes.
	judicial{Delegation,Revocation,Succession}Registration — registry entries
	    consumed by registry.go's registerAll().

KEY DEPENDENCIES:
  - schemas/judicial_delegation.go (payload types + Validate)
  - schemas/registry.go (SchemaRegistration, ErrDeserialize,
    IdentifierScopeRealDID)
*/
package schemas

import (
	"encoding/json"
	"fmt"
)

// ─── Delegation marshal/unmarshal ──────────────────────────────────────

// MarshalJudicialDelegationPayload is a convenience helper for the
// IssueDelegation builder.
func MarshalJudicialDelegationPayload(p *JudicialDelegationPayload) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// UnmarshalJudicialDelegationPayload parses a Domain Payload bytes
// blob into the typed payload. Validates on parse.
func UnmarshalJudicialDelegationPayload(data []byte) (*JudicialDelegationPayload, error) {
	var p JudicialDelegationPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("schemas/judicial_delegation: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// ─── Revocation marshal/unmarshal ──────────────────────────────────────

// MarshalJudicialRevocationPayload serializes after validating.
func MarshalJudicialRevocationPayload(p *JudicialRevocationPayload) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// UnmarshalJudicialRevocationPayload parses and validates.
func UnmarshalJudicialRevocationPayload(data []byte) (*JudicialRevocationPayload, error) {
	var p JudicialRevocationPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("schemas/judicial_delegation: parse revocation: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// ─── Succession marshal/unmarshal ──────────────────────────────────────

// MarshalJudicialSuccessionPayload serializes after validating.
func MarshalJudicialSuccessionPayload(p *JudicialSuccessionPayload) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// UnmarshalJudicialSuccessionPayload parses and validates.
func UnmarshalJudicialSuccessionPayload(data []byte) (*JudicialSuccessionPayload, error) {
	var p JudicialSuccessionPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("schemas/judicial_delegation: parse succession: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// ─── Schema parameters ──────────────────────────────────────────────

// DefaultJudicialDelegationParams returns canonical-JSON parameters
// bytes for judicial-delegation-v1: real_did identifier scope, no
// witness override (the granter signs as themselves), amendment
// migration (revocation amends; succession amends).
func DefaultJudicialDelegationParams() []byte {
	params := map[string]interface{}{
		"identifier_scope":          "real_did",
		"override_requires_witness": false,
		"migration_policy":          "amendment",
		// v1.3.0 wire field — Board concurrence on delegation issuance.
		// See schemas/attestation_policies.go.
		"attestation_policies": judicialDelegationPolicies(),
	}
	b, _ := json.Marshal(params)
	return b
}

// DefaultJudicialRevocationParams returns canonical-JSON parameters
// bytes for judicial-revocation-v1.
func DefaultJudicialRevocationParams() []byte {
	params := map[string]interface{}{
		"identifier_scope":          "real_did",
		"override_requires_witness": false,
		"migration_policy":          "amendment",
		// v1.3.0 wire field — Board concurrence on revocation.
		// See schemas/attestation_policies.go.
		"attestation_policies": judicialRevocationPolicies(),
	}
	b, _ := json.Marshal(params)
	return b
}

// DefaultJudicialSuccessionParams returns canonical-JSON parameters
// bytes for judicial-succession-v1. override_requires_witness=true
// because the institutional DID's Authority_Set cosignatures are the
// witnesses confirming top-of-chain transition.
func DefaultJudicialSuccessionParams() []byte {
	params := map[string]interface{}{
		"identifier_scope":          "real_did",
		"override_requires_witness": true,
		"migration_policy":          "amendment",
		// v1.3.0 wire field — incoming-officer concurrence on
		// succession. See schemas/attestation_policies.go.
		"attestation_policies": judicialSuccessionPolicies(),
	}
	b, _ := json.Marshal(params)
	return b
}

// ─── Registry entries ────────────────────────────────────────────────

func judicialDelegationRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaJudicialDelegationV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*JudicialDelegationPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return MarshalJudicialDelegationPayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return UnmarshalJudicialDelegationPayload(data)
		},
		DefaultParams:   DefaultJudicialDelegationParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}

func judicialRevocationRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaJudicialRevocationV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*JudicialRevocationPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return MarshalJudicialRevocationPayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return UnmarshalJudicialRevocationPayload(data)
		},
		DefaultParams:   DefaultJudicialRevocationParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}

func judicialSuccessionRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaJudicialSuccessionV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*JudicialSuccessionPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return MarshalJudicialSuccessionPayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return UnmarshalJudicialSuccessionPayload(data)
		},
		DefaultParams:   DefaultJudicialSuccessionParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
