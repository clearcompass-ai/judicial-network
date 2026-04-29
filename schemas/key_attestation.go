/*
FILE PATH: schemas/key_attestation.go

DESCRIPTION:
    tn-key-attestation-v1 — judicial domain attestation entry per
    ortholog-sdk/docs/attestation-entries.md. Records the institution
    that witnessed key generation for a named entity at a named
    position. Replaces the removed pre-v7.5 KeyGenerationMode
    ControlHeader field; the institutional witness IS the trust
    boundary, not the entity itself.

KEY ARCHITECTURAL DECISIONS:
    - Path A entry: AuthorityPath = AuthoritySameSigner. The
      attesting institution (typically the court's exchange) signs
      on its own authority. SubjectIdentifier = the attested
      entity's DID for operator-side index queries.
    - SchemaParameters: identifier_scope = real_did,
      override_requires_witness = true (judicial domains require an
      independent witness for any override of attestation claims),
      migration_policy = amendment.
    - GenerationMode is a closed string enum:
        "exchange_managed"     — keys held by a custodial exchange
        "client_side_enclave"  — keys held by the entity in a TEE
        "hsm_fips_140_3"       — keys held in a certified HSM
      Domain code resolves the legal/regulatory implications; the
      schema only enumerates the modes.
    - AttestationEvidence is opaque — Apple App Attest, Android Key
      Attestation, HSM quote, etc. — domain verifiers parse it.
      The SDK never inspects.
    - WitnessArtifactHash binds the attestation to a specific
      proof artifact stored off-log; verifiers re-fetch the artifact
      via this hash to confirm the institution actually performed
      the witness rather than fabricating the claim.

KEY DEPENDENCIES:
    - schemas/registry.go (registration)
    - SDK consumers: schema.JSONParameterExtractor handles the
      parameters fields; the payload struct lives here.
*/
package schemas

import "encoding/json"

// SchemaKeyAttestationV1 is the canonical schema URI.
const SchemaKeyAttestationV1 = "tn-key-attestation-v1"

// GenerationMode enumerates the key custody model the institution
// is attesting to. Domain code maps to legal/regulatory tiers; the
// schema is neutral on those mappings.
type GenerationMode string

const (
	// GenerationModeExchangeManaged: keys held by the entity's
	// custodial exchange. Sole-control claims do NOT hold; the
	// custodian can sign.
	GenerationModeExchangeManaged GenerationMode = "exchange_managed"

	// GenerationModeClientSideEnclave: keys generated and held in a
	// platform TEE (Apple Secure Enclave, Android Strongbox, etc.)
	// under the entity's sole control. Sole-control claims hold
	// subject to the platform's own security model.
	GenerationModeClientSideEnclave GenerationMode = "client_side_enclave"

	// GenerationModeHSMFips140_3: keys held in a FIPS 140-3
	// certified HSM operated by the institution. Custodial
	// arrangement with stronger attested-non-extractability
	// guarantees than exchange-managed software keys.
	GenerationModeHSMFips140_3 GenerationMode = "hsm_fips_140_3"
)

// IsValidGenerationMode reports whether m is one of the closed-set
// modes. Domain code calls this at parse time; payloads carrying an
// out-of-set mode are rejected (closed-by-default per ADR-001).
func IsValidGenerationMode(m GenerationMode) bool {
	switch m {
	case GenerationModeExchangeManaged,
		GenerationModeClientSideEnclave,
		GenerationModeHSMFips140_3:
		return true
	default:
		return false
	}
}

// KeyAttestationPayload is the canonical DomainPayload shape for
// tn-key-attestation-v1 entries. JSON tags are stable; reordering
// or renaming is a breaking schema change.
type KeyAttestationPayload struct {
	// AttestedEntity is the DID of the entity whose key generation
	// is being attested. Required.
	AttestedEntity string `json:"attested_entity"`

	// AttestedEntityPosition pins the attestation to a specific
	// log position — typically the entity's root entry.
	// (LogDID, Sequence) tuple per ADR-004.
	AttestedEntityPosition SchemaPosition `json:"attested_entity_position"`

	// GenerationMode is one of the closed-set modes. Required.
	GenerationMode GenerationMode `json:"generation_mode"`

	// AttestationTime is the unix-microseconds timestamp the
	// witnessing institution observed the generation.
	AttestationTime int64 `json:"attestation_time"`

	// WitnessArtifactHash is the hex-encoded SHA-256 of the
	// off-log attestation evidence. Verifiers re-fetch the
	// evidence via this hash; required to be non-empty.
	WitnessArtifactHash string `json:"witness_artifact_hash"`

	// EnclavePlatform names the platform when GenerationMode is
	// client_side_enclave or hsm_fips_140_3 — e.g.,
	// "apple_secure_enclave", "android_strongbox", "thales_luna_g7".
	// Optional but expected when relevant.
	EnclavePlatform string `json:"enclave_platform,omitempty"`

	// AttestationEvidence is the opaque evidence blob the platform
	// produced (App Attest token, Key Attestation chain, HSM
	// quote). Domain verifiers parse it; the SDK never inspects.
	// Hex-encoded per the schema convention; empty allowed when
	// the WitnessArtifactHash alone is sufficient (the artifact is
	// stored off-log).
	AttestationEvidence string `json:"attestation_evidence,omitempty"`
}

// Validate runs structural checks on a deserialized payload. Returns
// nil iff every required field is populated and GenerationMode is
// in the closed enum. Domain verifiers call this after deserialize
// before applying any payload-derived authorization decision.
func (p *KeyAttestationPayload) Validate() error {
	if p == nil {
		return ErrAttestationNil
	}
	if p.AttestedEntity == "" {
		return ErrAttestationMissingEntity
	}
	if p.AttestedEntityPosition.LogDID == "" {
		return ErrAttestationMissingPosition
	}
	if !IsValidGenerationMode(p.GenerationMode) {
		return ErrAttestationInvalidMode
	}
	if p.AttestationTime <= 0 {
		return ErrAttestationMissingTime
	}
	if p.WitnessArtifactHash == "" {
		return ErrAttestationMissingArtifactHash
	}
	return nil
}

// Errors are package-private sentinels so verification/attestation_check.go
// can reference them via errors.Is. Stable across releases.
var (
	ErrAttestationNil                 = newAttestationError("attestation payload is nil")
	ErrAttestationMissingEntity       = newAttestationError("attested_entity must be non-empty")
	ErrAttestationMissingPosition     = newAttestationError("attested_entity_position must reference a log")
	ErrAttestationInvalidMode         = newAttestationError("generation_mode is not in the closed enum")
	ErrAttestationMissingTime         = newAttestationError("attestation_time must be positive unix microseconds")
	ErrAttestationMissingArtifactHash = newAttestationError("witness_artifact_hash must be non-empty")
)

type attestationError struct{ msg string }

func (e *attestationError) Error() string { return "schemas/key_attestation: " + e.msg }

func newAttestationError(msg string) *attestationError { return &attestationError{msg: msg} }

// ─── Serialize / Deserialize ────────────────────────────────────────

// SerializeKeyAttestation marshals payload to canonical JSON bytes.
// Round-trips byte-stable when paired with DeserializeKeyAttestation.
func SerializeKeyAttestation(p *KeyAttestationPayload) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// DeserializeKeyAttestation parses canonical JSON. Validates the
// shape after unmarshal so a downstream caller cannot accidentally
// consume a malformed payload.
func DeserializeKeyAttestation(data []byte) (*KeyAttestationPayload, error) {
	var p KeyAttestationPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// ─── Schema parameters (SchemaParameters JSON for the registry) ───

// DefaultKeyAttestationParams returns the canonical-JSON schema
// parameters bytes the registry hands to lifecycle.SchemaSpec via
// JSONParameterExtractor.
func DefaultKeyAttestationParams() []byte {
	params := map[string]interface{}{
		"identifier_scope":          "real_did",
		"override_requires_witness": true,
		"migration_policy":          "amendment",
	}
	b, _ := json.Marshal(params)
	return b
}

// ─── Registry entry ─────────────────────────────────────────────────

func keyAttestationRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaKeyAttestationV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*KeyAttestationPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeKeyAttestation(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return DeserializeKeyAttestation(data)
		},
		DefaultParams:   DefaultKeyAttestationParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
