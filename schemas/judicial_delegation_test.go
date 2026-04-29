/*
FILE PATH: schemas/judicial_delegation_test.go

DESCRIPTION:
    Validation and round-trip tests for the unified delegation schema:
    JudicialDelegationPayload, JudicialRevocationPayload,
    JudicialSuccessionPayload.

    The on-log truth is the JSON byte sequence; these tests pin the
    field set, the validation rules, and the deterministic
    serialization. Any drift here is a compatibility break: existing
    log entries would fail to round-trip through the new code.
*/
package schemas

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// JudicialDelegationPayload
// ─────────────────────────────────────────────────────────────────────

func makeValidDelegation() *JudicialDelegationPayload {
	now := time.Now().UTC()
	return &JudicialDelegationPayload{
		SchemaID:   SchemaJudicialDelegationV1,
		GranterDID: "did:key:zQ3shGRANTER",
		GranteeDID: "did:key:zQ3shGRANTEE",
		Role:       "judge",
		Scope:      []string{"case_filing", "case_decision"},
		ExpiresAt:  now.Add(365 * 24 * time.Hour).Format(time.RFC3339Nano),
		IssuedAt:   now.Format(time.RFC3339Nano),
		GranterDelegationRef: &LogPositionRef{
			LogDID:   "did:key:zQ3shINSTITUTIONAL",
			Sequence: 7,
		},
		Rationale: "Sworn in 2026-04-01; bar #12345.",
	}
}

func TestJudicialDelegationPayload_Validate_HappyPath(t *testing.T) {
	p := makeValidDelegation()
	if err := p.Validate(); err != nil {
		t.Fatalf("happy-path validate: %v", err)
	}
}

func TestJudicialDelegationPayload_Validate_SchemaIDMismatch(t *testing.T) {
	p := makeValidDelegation()
	p.SchemaID = "wrong-schema-v1"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "schema_id mismatch") {
		t.Fatalf("expected schema_id mismatch, got: %v", err)
	}
}

func TestJudicialDelegationPayload_Validate_MissingFields(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*JudicialDelegationPayload)
		wantSub string
	}{
		{"empty granter", func(p *JudicialDelegationPayload) { p.GranterDID = "" }, "granter_did"},
		{"empty grantee", func(p *JudicialDelegationPayload) { p.GranteeDID = "" }, "grantee_did"},
		{"empty role", func(p *JudicialDelegationPayload) { p.Role = "" }, "role"},
		{"empty expires_at", func(p *JudicialDelegationPayload) { p.ExpiresAt = "" }, "expires_at"},
		{"empty issued_at", func(p *JudicialDelegationPayload) { p.IssuedAt = "" }, "issued_at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := makeValidDelegation()
			tc.mutate(p)
			err := p.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("got %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestJudicialDelegationPayload_Validate_SelfDelegation(t *testing.T) {
	p := makeValidDelegation()
	p.GranteeDID = p.GranterDID
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "self-delegation") {
		t.Fatalf("expected self-delegation rejection, got: %v", err)
	}
}

func TestJudicialDelegationPayload_Validate_MalformedTimestamps(t *testing.T) {
	t.Run("expires_at malformed", func(t *testing.T) {
		p := makeValidDelegation()
		p.ExpiresAt = "yesterday"
		err := p.Validate()
		if err == nil || !strings.Contains(err.Error(), "expires_at") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("issued_at malformed", func(t *testing.T) {
		p := makeValidDelegation()
		p.IssuedAt = "tomorrow"
		err := p.Validate()
		if err == nil || !strings.Contains(err.Error(), "issued_at") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestJudicialDelegationPayload_Validate_ExpiresBeforeIssued(t *testing.T) {
	p := makeValidDelegation()
	now := time.Now().UTC()
	p.IssuedAt = now.Format(time.RFC3339Nano)
	p.ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "expires_at must be after issued_at") {
		t.Fatalf("got %v", err)
	}
}

func TestJudicialDelegationPayload_Validate_RationaleTooLarge(t *testing.T) {
	p := makeValidDelegation()
	p.Rationale = strings.Repeat("X", MaxRationaleBytes+1)
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "rationale exceeds") {
		t.Fatalf("got %v", err)
	}
}

func TestJudicialDelegationPayload_RoundTrip(t *testing.T) {
	p := makeValidDelegation()
	data, err := MarshalJudicialDelegationPayload(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := UnmarshalJudicialDelegationPayload(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.GranterDID != p.GranterDID || got.GranteeDID != p.GranteeDID || got.Role != p.Role {
		t.Errorf("round-trip drift: %+v vs %+v", got, p)
	}
	if len(got.Scope) != len(p.Scope) {
		t.Errorf("scope len drift: got %d want %d", len(got.Scope), len(p.Scope))
	}
}

func TestJudicialDelegationPayload_GranterRefOmitWhenInstitutional(t *testing.T) {
	// Depth-0 entry: institutional DID grants top-of-chain. The
	// schema permits a nil GranterDelegationRef in this case.
	p := makeValidDelegation()
	p.GranterDelegationRef = nil
	if err := p.Validate(); err != nil {
		t.Fatalf("nil granter_delegation_ref must validate (institutional grant): %v", err)
	}
	data, err := MarshalJudicialDelegationPayload(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "granter_delegation_ref") {
		t.Errorf("nil granter_delegation_ref should be omitted from JSON, got: %s", data)
	}
}

func TestJudicialDelegationPayload_ParsedTimestamps(t *testing.T) {
	p := makeValidDelegation()
	exp := p.ParsedExpiresAt()
	iss := p.ParsedIssuedAt()
	if exp.IsZero() || iss.IsZero() {
		t.Errorf("parsed timestamps should not be zero: exp=%v iss=%v", exp, iss)
	}
	if !exp.After(iss) {
		t.Errorf("parsed exp must be after iss: exp=%v iss=%v", exp, iss)
	}
}

// ─────────────────────────────────────────────────────────────────────
// JudicialRevocationPayload
// ─────────────────────────────────────────────────────────────────────

func makeValidRevocation() *JudicialRevocationPayload {
	return &JudicialRevocationPayload{
		SchemaID: SchemaJudicialRevocationV1,
		TargetDelegation: LogPositionRef{
			LogDID:   "did:key:zQ3shGRANTER",
			Sequence: 42,
		},
		Reason:    "officer_transfer",
		RevokedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func TestJudicialRevocationPayload_Validate_HappyPath(t *testing.T) {
	if err := makeValidRevocation().Validate(); err != nil {
		t.Fatalf("happy-path: %v", err)
	}
}

func TestJudicialRevocationPayload_Validate_MissingFields(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*JudicialRevocationPayload)
		wantSub string
	}{
		{"schema_id mismatch", func(p *JudicialRevocationPayload) { p.SchemaID = "x" }, "schema_id mismatch"},
		{"missing target log_did", func(p *JudicialRevocationPayload) { p.TargetDelegation.LogDID = "" }, "log_did"},
		{"missing reason", func(p *JudicialRevocationPayload) { p.Reason = "" }, "reason"},
		{"missing revoked_at", func(p *JudicialRevocationPayload) { p.RevokedAt = "" }, "revoked_at"},
		{"malformed revoked_at", func(p *JudicialRevocationPayload) { p.RevokedAt = "blah" }, "revoked_at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := makeValidRevocation()
			tc.mutate(p)
			err := p.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("got %v want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestJudicialRevocationPayload_RoundTrip(t *testing.T) {
	p := makeValidRevocation()
	data, err := MarshalJudicialRevocationPayload(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := UnmarshalJudicialRevocationPayload(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.TargetDelegation.Sequence != p.TargetDelegation.Sequence || got.Reason != p.Reason {
		t.Errorf("drift: %+v vs %+v", got, p)
	}
}

// ─────────────────────────────────────────────────────────────────────
// JudicialSuccessionPayload
// ─────────────────────────────────────────────────────────────────────

func makeValidSuccession() *JudicialSuccessionPayload {
	return &JudicialSuccessionPayload{
		SchemaID: SchemaJudicialSuccessionV1,
		TargetDelegation: LogPositionRef{
			LogDID:   "did:key:zQ3shINSTITUTIONAL",
			Sequence: 1,
		},
		SuccessorDID:       "did:key:zQ3shSUCCESSOR",
		Reason:             "death_in_office",
		Inheritance:        InheritanceFull,
		EffectiveAt:        time.Now().UTC().Format(time.RFC3339Nano),
		AuthoritySetCosigs: []string{"did:key:zQ3shCOSIG1", "did:key:zQ3shCOSIG2"},
	}
}

func TestJudicialSuccessionPayload_Validate_HappyPath(t *testing.T) {
	if err := makeValidSuccession().Validate(); err != nil {
		t.Fatalf("happy-path: %v", err)
	}
}

func TestJudicialSuccessionPayload_Validate_BadInheritance(t *testing.T) {
	p := makeValidSuccession()
	p.Inheritance = "expanded"
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "inheritance must be one of") {
		t.Fatalf("got %v", err)
	}
}

func TestJudicialSuccessionPayload_Validate_NarrowedRequiresScope(t *testing.T) {
	p := makeValidSuccession()
	p.Inheritance = InheritanceNarrowed
	p.NarrowedScope = nil
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "narrowed_scope") {
		t.Fatalf("got %v", err)
	}

	// providing a scope makes it valid
	p.NarrowedScope = []string{"case_filing"}
	if err := p.Validate(); err != nil {
		t.Fatalf("narrowed with scope must validate: %v", err)
	}
}

func TestJudicialSuccessionPayload_Validate_CleanSlate(t *testing.T) {
	p := makeValidSuccession()
	p.Inheritance = InheritanceCleanSlate
	if err := p.Validate(); err != nil {
		t.Fatalf("clean_slate must validate: %v", err)
	}
}

func TestJudicialSuccessionPayload_Validate_MissingFields(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*JudicialSuccessionPayload)
		wantSub string
	}{
		{"schema_id mismatch", func(p *JudicialSuccessionPayload) { p.SchemaID = "x" }, "schema_id mismatch"},
		{"missing log_did", func(p *JudicialSuccessionPayload) { p.TargetDelegation.LogDID = "" }, "log_did"},
		{"missing successor", func(p *JudicialSuccessionPayload) { p.SuccessorDID = "" }, "successor_did"},
		{"missing reason", func(p *JudicialSuccessionPayload) { p.Reason = "" }, "reason"},
		{"missing effective_at", func(p *JudicialSuccessionPayload) { p.EffectiveAt = "" }, "effective_at"},
		{"malformed effective_at", func(p *JudicialSuccessionPayload) { p.EffectiveAt = "blah" }, "effective_at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := makeValidSuccession()
			tc.mutate(p)
			err := p.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("got %v want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestJudicialSuccessionPayload_RoundTrip(t *testing.T) {
	p := makeValidSuccession()
	data, err := MarshalJudicialSuccessionPayload(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := UnmarshalJudicialSuccessionPayload(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SuccessorDID != p.SuccessorDID || got.Inheritance != p.Inheritance {
		t.Errorf("drift: %+v vs %+v", got, p)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Registry integration
// ─────────────────────────────────────────────────────────────────────

func TestDelegationSchemas_RegisteredInRegistry(t *testing.T) {
	r := NewRegistry()
	for _, uri := range []string{
		SchemaJudicialDelegationV1,
		SchemaJudicialRevocationV1,
		SchemaJudicialSuccessionV1,
	} {
		if !r.Has(uri) {
			t.Errorf("registry does not have %q", uri)
		}
	}
}

func TestDelegationSchemas_RegistryRoundTrip(t *testing.T) {
	r := NewRegistry()

	// Delegation
	p := makeValidDelegation()
	data, err := r.SerializePayload(SchemaJudicialDelegationV1, p)
	if err != nil {
		t.Fatalf("serialize delegation: %v", err)
	}
	got, err := r.DeserializePayload(SchemaJudicialDelegationV1, data)
	if err != nil {
		t.Fatalf("deserialize delegation: %v", err)
	}
	if _, ok := got.(*JudicialDelegationPayload); !ok {
		t.Errorf("registry deserialize returned wrong type: %T", got)
	}

	// Revocation
	rev := makeValidRevocation()
	data, err = r.SerializePayload(SchemaJudicialRevocationV1, rev)
	if err != nil {
		t.Fatalf("serialize revocation: %v", err)
	}
	if _, err := r.DeserializePayload(SchemaJudicialRevocationV1, data); err != nil {
		t.Fatalf("deserialize revocation: %v", err)
	}

	// Succession
	suc := makeValidSuccession()
	data, err = r.SerializePayload(SchemaJudicialSuccessionV1, suc)
	if err != nil {
		t.Fatalf("serialize succession: %v", err)
	}
	if _, err := r.DeserializePayload(SchemaJudicialSuccessionV1, data); err != nil {
		t.Fatalf("deserialize succession: %v", err)
	}
}

func TestDelegationSchemas_DefaultParamsAreCanonicalJSON(t *testing.T) {
	for _, fn := range []func() []byte{
		DefaultJudicialDelegationParams,
		DefaultJudicialRevocationParams,
		DefaultJudicialSuccessionParams,
	} {
		var v map[string]interface{}
		if err := json.Unmarshal(fn(), &v); err != nil {
			t.Errorf("default params not valid JSON: %v", err)
		}
		if v["identifier_scope"] != "real_did" {
			t.Errorf("identifier_scope must be real_did, got %v", v["identifier_scope"])
		}
	}
}
