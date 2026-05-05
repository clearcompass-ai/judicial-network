/*
FILE PATH: schemas/judicial_amendments_test.go

DESCRIPTION:

	Validation and round-trip tests for the two amendment payloads:
	JudicialRevocationPayload and JudicialSuccessionPayload. Split out
	of judicial_delegation_test.go to keep that file under the source-
	file line cap.

	Helpers makeValidRevocation/makeValidSuccession are defined here
	and re-used by the registry-integration tests in
	judicial_delegation_test.go (same test package, so unexported
	helpers are shared).
*/
package schemas

import (
	"strings"
	"testing"
	"time"
)

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
