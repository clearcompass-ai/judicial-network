/*
FILE PATH: schemas/appellate_opinion_publication_test.go

DESCRIPTION:
    Tests for tn-appellate-opinion-publication-v1. Covers
    Validate happy + every rejection path, serialize round-trip,
    registry round-trip, and a functional emulation of a 3-judge
    panel publishing a majority opinion.
*/
package schemas

import (
	"errors"
	"strings"
	"testing"
)

func happyPublication() *AppellateOpinionPublicationPayload {
	return &AppellateOpinionPublicationPayload{
		OpinionID:   "op-001",
		OpinionType: "majority",
		AuthorDID:   "did:key:zJUDGE",
		CaseRef:     "TN-COA-2027-0042",
		ContentHash: "sha256:abc",
	}
}

func TestPubValidate_HappyPath(t *testing.T) {
	if err := happyPublication().Validate(); err != nil {
		t.Errorf("happy path must validate: %v", err)
	}
}

func TestPubValidate_NilReceiver(t *testing.T) {
	var p *AppellateOpinionPublicationPayload
	if err := p.Validate(); !errors.Is(err, ErrOpinionPublicationInvalid) {
		t.Errorf("nil receiver: %v", err)
	}
}

func TestPubValidate_MissingOpinionID(t *testing.T) {
	p := happyPublication()
	p.OpinionID = ""
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "opinion_id required") {
		t.Errorf("missing opinion_id should reject, got %v", err)
	}
}

func TestPubValidate_MissingOpinionType(t *testing.T) {
	p := happyPublication()
	p.OpinionType = ""
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "opinion_type required") {
		t.Errorf("missing opinion_type should reject, got %v", err)
	}
}

func TestPubValidate_MissingCaseRef(t *testing.T) {
	p := happyPublication()
	p.CaseRef = ""
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "case_ref required") {
		t.Errorf("missing case_ref should reject, got %v", err)
	}
}

func TestPubValidate_PerCuriamHasNoAuthor(t *testing.T) {
	p := happyPublication()
	p.OpinionType = "per_curiam"
	p.AuthorDID = ""
	if err := p.Validate(); err != nil {
		t.Errorf("per_curiam without author_did must validate: %v", err)
	}
}

func TestPubSerialize_RoundTrip(t *testing.T) {
	p := happyPublication()
	data, err := SerializeOpinionPublicationPayload(p)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	got, err := DeserializeOpinionPublicationPayload(data)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.OpinionID != p.OpinionID || got.OpinionType != p.OpinionType ||
		got.AuthorDID != p.AuthorDID || got.CaseRef != p.CaseRef {
		t.Errorf("round-trip drift: %+v", got)
	}
}

func TestPubSerialize_NilPayload(t *testing.T) {
	if _, err := SerializeOpinionPublicationPayload(nil); err == nil {
		t.Error("nil must reject on Serialize")
	}
}

func TestPubSerialize_RejectsInvalid(t *testing.T) {
	p := happyPublication()
	p.OpinionType = ""
	if _, err := SerializeOpinionPublicationPayload(p); err == nil {
		t.Error("invalid must reject on Serialize")
	}
}

func TestPubDeserialize_BadJSON(t *testing.T) {
	if _, err := DeserializeOpinionPublicationPayload([]byte("nope")); err == nil {
		t.Error("malformed JSON must reject on Deserialize")
	}
}

func TestPubDeserialize_FailsValidate(t *testing.T) {
	bad := []byte(`{"opinion_id":"","opinion_type":"x","case_ref":"y"}`)
	if _, err := DeserializeOpinionPublicationPayload(bad); err == nil {
		t.Error("invalid payload must reject")
	}
}

func TestPubDefaultParams_Parses(t *testing.T) {
	if len(DefaultOpinionPublicationParams()) == 0 {
		t.Error("DefaultOpinionPublicationParams returned empty bytes")
	}
}

func TestPubRegistry_Lookup(t *testing.T) {
	r := NewRegistry()
	reg, err := r.Lookup(SchemaAppellateOpinionPublicationV1)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if reg.URI != SchemaAppellateOpinionPublicationV1 {
		t.Errorf("URI drift: %q", reg.URI)
	}
}

func TestPubRegistry_RoundTripViaInterface(t *testing.T) {
	r := NewRegistry()
	reg, _ := r.Lookup(SchemaAppellateOpinionPublicationV1)
	p := happyPublication()
	data, err := reg.Serialize(p)
	if err != nil {
		t.Fatalf("Serialize via registry: %v", err)
	}
	got, err := reg.Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize via registry: %v", err)
	}
	gp, ok := got.(*AppellateOpinionPublicationPayload)
	if !ok {
		t.Fatalf("Deserialize returned %T", got)
	}
	if gp.OpinionID != p.OpinionID {
		t.Errorf("opinion_id drift: %q", gp.OpinionID)
	}
}

func TestPubRegistry_SerializeWrongType(t *testing.T) {
	r := NewRegistry()
	reg, _ := r.Lookup(SchemaAppellateOpinionPublicationV1)
	if _, err := reg.Serialize("not a payload"); err == nil {
		t.Error("Serialize must reject wrong payload type")
	}
}

// ─── functional emulation: 3-judge panel publishes majority ─────

func TestFunctional_ThreeJudgePanel_PublishesMajority(t *testing.T) {
	p := &AppellateOpinionPublicationPayload{
		OpinionID:   "op-2027-0042-majority",
		OpinionType: "majority",
		AuthorDID:   "did:key:zCOA_JUDGE_1",
		CaseRef:     "TN-COA-2027-0042",
		Parts:       []string{"I", "II", "III"},
		ContentHash: "sha256:opinion-text-hash",
	}
	data, err := SerializeOpinionPublicationPayload(p)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	got, _ := DeserializeOpinionPublicationPayload(data)
	if len(got.Parts) != 3 {
		t.Errorf("parts must round-trip: %v", got.Parts)
	}
	if got.AuthorDID != p.AuthorDID {
		t.Errorf("author drift: %q", got.AuthorDID)
	}
}
