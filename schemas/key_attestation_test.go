/*
FILE PATH: schemas/key_attestation_test.go

COVERAGE:
    Every code path in key_attestation.go: enum membership,
    Validate's seven required-field branches, serialize/deserialize
    round-trip, registry registration, and DefaultParams stability.
*/
package schemas

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ─── GenerationMode enum ────────────────────────────────────────────

func TestIsValidGenerationMode(t *testing.T) {
	cases := []struct {
		mode GenerationMode
		want bool
	}{
		{GenerationModeExchangeManaged, true},
		{GenerationModeClientSideEnclave, true},
		{GenerationModeHSMFips140_3, true},
		{GenerationMode(""), false},
		{GenerationMode("custom"), false},
	}
	for _, c := range cases {
		if got := IsValidGenerationMode(c.mode); got != c.want {
			t.Errorf("IsValidGenerationMode(%q) = %v, want %v", c.mode, got, c.want)
		}
	}
}

// ─── Validate: every required-field branch ─────────────────────────

func mkValid() *KeyAttestationPayload {
	return &KeyAttestationPayload{
		AttestedEntity:         "did:web:judge",
		AttestedEntityPosition: SchemaPosition{LogDID: "did:web:l", Sequence: 5},
		GenerationMode:         GenerationModeExchangeManaged,
		AttestationTime:        1700000000,
		WitnessArtifactHash:    "deadbeef",
	}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := mkValid().Validate(); err != nil {
		t.Errorf("valid payload must pass: %v", err)
	}
}

func TestValidate_NilReceiver_Errors(t *testing.T) {
	var p *KeyAttestationPayload
	if err := p.Validate(); !errors.Is(err, ErrAttestationNil) {
		t.Errorf("err = %v, want ErrAttestationNil", err)
	}
}

func TestValidate_MissingEntity(t *testing.T) {
	p := mkValid()
	p.AttestedEntity = ""
	if err := p.Validate(); !errors.Is(err, ErrAttestationMissingEntity) {
		t.Errorf("err = %v", err)
	}
}

func TestValidate_MissingPosition(t *testing.T) {
	p := mkValid()
	p.AttestedEntityPosition.LogDID = ""
	if err := p.Validate(); !errors.Is(err, ErrAttestationMissingPosition) {
		t.Errorf("err = %v", err)
	}
}

func TestValidate_InvalidMode(t *testing.T) {
	p := mkValid()
	p.GenerationMode = "bogus"
	if err := p.Validate(); !errors.Is(err, ErrAttestationInvalidMode) {
		t.Errorf("err = %v", err)
	}
}

func TestValidate_MissingTime(t *testing.T) {
	p := mkValid()
	p.AttestationTime = 0
	if err := p.Validate(); !errors.Is(err, ErrAttestationMissingTime) {
		t.Errorf("err = %v", err)
	}
}

func TestValidate_MissingArtifactHash(t *testing.T) {
	p := mkValid()
	p.WitnessArtifactHash = ""
	if err := p.Validate(); !errors.Is(err, ErrAttestationMissingArtifactHash) {
		t.Errorf("err = %v", err)
	}
}

// ─── Serialize / Deserialize round-trip ─────────────────────────────

func TestSerialize_Deserialize_RoundTrip(t *testing.T) {
	p := mkValid()
	p.EnclavePlatform = "apple_secure_enclave"
	p.AttestationEvidence = "abcd1234"
	bytes, err := SerializeKeyAttestation(p)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	got, err := DeserializeKeyAttestation(bytes)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.AttestedEntity != p.AttestedEntity ||
		got.GenerationMode != p.GenerationMode ||
		got.AttestationTime != p.AttestationTime ||
		got.WitnessArtifactHash != p.WitnessArtifactHash ||
		got.EnclavePlatform != p.EnclavePlatform ||
		got.AttestationEvidence != p.AttestationEvidence {
		t.Errorf("round-trip drift: %+v vs %+v", got, p)
	}
}

func TestSerialize_RejectsInvalid(t *testing.T) {
	p := mkValid()
	p.AttestedEntity = ""
	if _, err := SerializeKeyAttestation(p); err == nil {
		t.Error("Serialize must reject invalid payload")
	}
}

func TestDeserialize_NotJSON_Errors(t *testing.T) {
	if _, err := DeserializeKeyAttestation([]byte("not json")); err == nil {
		t.Error("non-JSON must error")
	}
}

func TestDeserialize_ValidJSONMissingFields_Validates(t *testing.T) {
	bad := []byte(`{"attested_entity":"did:web:x"}`)
	if _, err := DeserializeKeyAttestation(bad); err == nil {
		t.Error("incomplete payload must fail Validate")
	}
}

// ─── Registry integration ──────────────────────────────────────────

func TestRegistry_RegistersKeyAttestation(t *testing.T) {
	r := NewRegistry()
	if !r.Has(SchemaKeyAttestationV1) {
		t.Fatal("registry must include tn-key-attestation-v1")
	}
	reg, err := r.Lookup(SchemaKeyAttestationV1)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if reg.IdentifierScope != IdentifierScopeRealDID {
		t.Errorf("IdentifierScope = %q", reg.IdentifierScope)
	}
}

func TestRegistry_SerializeDeserialize_RoundTrip_ViaRegistry(t *testing.T) {
	r := NewRegistry()
	p := mkValid()
	bytes, err := r.SerializePayload(SchemaKeyAttestationV1, p)
	if err != nil {
		t.Fatalf("Serialize via registry: %v", err)
	}
	got, err := r.DeserializePayload(SchemaKeyAttestationV1, bytes)
	if err != nil {
		t.Fatalf("Deserialize via registry: %v", err)
	}
	gp, ok := got.(*KeyAttestationPayload)
	if !ok {
		t.Fatalf("registry returned wrong type: %T", got)
	}
	if gp.AttestedEntity != p.AttestedEntity {
		t.Error("round-trip drift")
	}
}

func TestRegistry_SerializeWrongType_Errors(t *testing.T) {
	r := NewRegistry()
	if _, err := r.SerializePayload(SchemaKeyAttestationV1, "not the right struct"); !errors.Is(err, ErrDeserialize) {
		t.Errorf("err = %v, want ErrDeserialize", err)
	}
}

// ─── DefaultParams shape ───────────────────────────────────────────

func TestDefaultKeyAttestationParams_Stable(t *testing.T) {
	bytes := DefaultKeyAttestationParams()
	var got map[string]interface{}
	if err := json.Unmarshal(bytes, &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if got["identifier_scope"] != "real_did" {
		t.Errorf("identifier_scope = %v", got["identifier_scope"])
	}
	if got["override_requires_witness"] != true {
		t.Errorf("override_requires_witness = %v", got["override_requires_witness"])
	}
	if got["migration_policy"] != "amendment" {
		t.Errorf("migration_policy = %v", got["migration_policy"])
	}
}

// ─── Error message format ──────────────────────────────────────────

func TestAttestationError_String(t *testing.T) {
	err := ErrAttestationMissingEntity
	if !strings.HasPrefix(err.Error(), "schemas/key_attestation:") {
		t.Errorf("error prefix wrong: %q", err.Error())
	}
}
