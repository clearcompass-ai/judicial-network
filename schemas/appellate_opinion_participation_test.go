/*
FILE PATH: schemas/appellate_opinion_participation_test.go

DESCRIPTION:
    Tests for tn-appellate-opinion-participation-v1. Covers
    Validate happy + every rejection, serialize round-trip,
    registry round-trip, and a functional emulation of a
    3-judge panel (one judge dissents, one joins, one
    joined_in_part).
*/
package schemas

import (
	"errors"
	"strings"
	"testing"
)

func happyParticipation() *AppellateOpinionParticipationPayload {
	return &AppellateOpinionParticipationPayload{
		OpinionID: "op-001",
		JudgeDID:  "did:key:zJUDGE1",
		Role:      "joined",
		CaseRef:   "TN-COA-2027-0042",
	}
}

func TestPartValidate_HappyPath(t *testing.T) {
	if err := happyParticipation().Validate(); err != nil {
		t.Errorf("happy path must validate: %v", err)
	}
}

func TestPartValidate_NilReceiver(t *testing.T) {
	var p *AppellateOpinionParticipationPayload
	if err := p.Validate(); !errors.Is(err, ErrOpinionParticipationInvalid) {
		t.Errorf("nil receiver: %v", err)
	}
}

func TestPartValidate_MissingOpinionID(t *testing.T) {
	p := happyParticipation()
	p.OpinionID = ""
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "opinion_id required") {
		t.Errorf("missing opinion_id should reject, got %v", err)
	}
}

func TestPartValidate_MissingJudgeDID(t *testing.T) {
	p := happyParticipation()
	p.JudgeDID = ""
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "judge_did required") {
		t.Errorf("missing judge_did should reject, got %v", err)
	}
}

func TestPartValidate_MissingRole(t *testing.T) {
	p := happyParticipation()
	p.Role = ""
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "role required") {
		t.Errorf("missing role should reject, got %v", err)
	}
}

func TestPartValidate_MissingCaseRef(t *testing.T) {
	p := happyParticipation()
	p.CaseRef = ""
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "case_ref required") {
		t.Errorf("missing case_ref should reject, got %v", err)
	}
}

func TestPartSerialize_RoundTrip(t *testing.T) {
	p := happyParticipation()
	p.Parts = []string{"I", "II"}
	p.Role = "joined_in_part"
	data, err := SerializeOpinionParticipationPayload(p)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	got, err := DeserializeOpinionParticipationPayload(data)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.Role != "joined_in_part" || len(got.Parts) != 2 {
		t.Errorf("round-trip drift: %+v", got)
	}
}

func TestPartSerialize_NilPayload(t *testing.T) {
	if _, err := SerializeOpinionParticipationPayload(nil); err == nil {
		t.Error("nil must reject")
	}
}

func TestPartSerialize_RejectsInvalid(t *testing.T) {
	p := happyParticipation()
	p.Role = ""
	if _, err := SerializeOpinionParticipationPayload(p); err == nil {
		t.Error("invalid must reject")
	}
}

func TestPartDeserialize_BadJSON(t *testing.T) {
	if _, err := DeserializeOpinionParticipationPayload([]byte("nope")); err == nil {
		t.Error("malformed must reject")
	}
}

func TestPartDeserialize_FailsValidate(t *testing.T) {
	bad := []byte(`{"opinion_id":"","judge_did":"x","role":"joined","case_ref":"y"}`)
	if _, err := DeserializeOpinionParticipationPayload(bad); err == nil {
		t.Error("invalid payload must reject")
	}
}

func TestPartDefaultParams_Parses(t *testing.T) {
	if len(DefaultOpinionParticipationParams()) == 0 {
		t.Error("DefaultOpinionParticipationParams returned empty bytes")
	}
}

func TestPartRegistry_Lookup(t *testing.T) {
	r := NewRegistry()
	reg, err := r.Lookup(SchemaAppellateOpinionParticipationV1)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if reg.URI != SchemaAppellateOpinionParticipationV1 {
		t.Errorf("URI drift: %q", reg.URI)
	}
}

func TestPartRegistry_RoundTripViaInterface(t *testing.T) {
	r := NewRegistry()
	reg, _ := r.Lookup(SchemaAppellateOpinionParticipationV1)
	p := happyParticipation()
	data, err := reg.Serialize(p)
	if err != nil {
		t.Fatalf("Serialize via registry: %v", err)
	}
	got, _ := reg.Deserialize(data)
	gp, ok := got.(*AppellateOpinionParticipationPayload)
	if !ok {
		t.Fatalf("Deserialize returned %T", got)
	}
	if gp.OpinionID != p.OpinionID {
		t.Errorf("opinion_id drift: %q", gp.OpinionID)
	}
}

func TestPartRegistry_SerializeWrongType(t *testing.T) {
	r := NewRegistry()
	reg, _ := r.Lookup(SchemaAppellateOpinionParticipationV1)
	if _, err := reg.Serialize("not a payload"); err == nil {
		t.Error("Serialize must reject wrong type")
	}
}

// ─── functional emulation: 3-judge panel ────────────────────────

// TestFunctional_ThreeJudgePanel_MixedParticipation pins a
// realistic 2-1 split: one judge joins the majority, one
// joined_in_part, one dissents — three participation entries
// against one opinion_id.
func TestFunctional_ThreeJudgePanel_MixedParticipation(t *testing.T) {
	opinionID := "op-2027-0042-majority"
	caseRef := "TN-COA-2027-0042"

	entries := []*AppellateOpinionParticipationPayload{
		{OpinionID: opinionID, JudgeDID: "did:key:zJ1",
			Role: "joined", CaseRef: caseRef},
		{OpinionID: opinionID, JudgeDID: "did:key:zJ2",
			Role: "joined_in_part", Parts: []string{"I", "II"}, CaseRef: caseRef},
		{OpinionID: opinionID, JudgeDID: "did:key:zJ3",
			Role: "dissent", CaseRef: caseRef},
	}
	for i, e := range entries {
		if err := e.Validate(); err != nil {
			t.Errorf("entry %d failed validation: %v", i, err)
		}
		if _, err := SerializeOpinionParticipationPayload(e); err != nil {
			t.Errorf("entry %d failed Serialize: %v", i, err)
		}
	}
}
