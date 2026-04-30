/*
FILE PATH: schemas/appellate_disposition_test.go

DESCRIPTION:
    Tests for tn-appellate-disposition-v1. Covers Validate
    happy + every rejection, serialize round-trip, registry
    round-trip, and a functional emulation of a TN COA 3-0
    disposition.
*/
package schemas

import (
	"errors"
	"strings"
	"testing"
)

func happyDisposition() *AppellateDispositionPayload {
	return &AppellateDispositionPayload{
		Outcome:   "affirmed",
		Panel:     []string{"did:key:zJ1", "did:key:zJ2", "did:key:zJ3"},
		VoteTally: "3-0",
		CaseRef:   "TN-COA-2027-0042",
	}
}

func TestDispValidate_HappyPath(t *testing.T) {
	if err := happyDisposition().Validate(); err != nil {
		t.Errorf("happy path must validate: %v", err)
	}
}

func TestDispValidate_NilReceiver(t *testing.T) {
	var p *AppellateDispositionPayload
	if err := p.Validate(); !errors.Is(err, ErrDispositionInvalid) {
		t.Errorf("nil receiver: %v", err)
	}
}

func TestDispValidate_MissingOutcome(t *testing.T) {
	p := happyDisposition()
	p.Outcome = ""
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "outcome required") {
		t.Errorf("missing outcome should reject, got %v", err)
	}
}

func TestDispValidate_EmptyPanel(t *testing.T) {
	p := happyDisposition()
	p.Panel = nil
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "panel must list") {
		t.Errorf("empty panel should reject, got %v", err)
	}
}

func TestDispValidate_EmptyJudgeDIDInPanel(t *testing.T) {
	p := happyDisposition()
	p.Panel = []string{"did:key:zJ1", ""}
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "panel[1]") {
		t.Errorf("empty panel[1] should reject, got %v", err)
	}
}

func TestDispValidate_MissingCaseRef(t *testing.T) {
	p := happyDisposition()
	p.CaseRef = ""
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "case_ref required") {
		t.Errorf("missing case_ref should reject, got %v", err)
	}
}

func TestDispSerialize_RoundTrip(t *testing.T) {
	p := happyDisposition()
	data, err := SerializeDispositionPayload(p)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	got, _ := DeserializeDispositionPayload(data)
	if got.Outcome != p.Outcome || got.VoteTally != p.VoteTally ||
		len(got.Panel) != len(p.Panel) {
		t.Errorf("round-trip drift: %+v", got)
	}
}

func TestDispSerialize_NilPayload(t *testing.T) {
	if _, err := SerializeDispositionPayload(nil); err == nil {
		t.Error("nil must reject")
	}
}

func TestDispSerialize_RejectsInvalid(t *testing.T) {
	p := happyDisposition()
	p.Outcome = ""
	if _, err := SerializeDispositionPayload(p); err == nil {
		t.Error("invalid must reject")
	}
}

func TestDispDeserialize_BadJSON(t *testing.T) {
	if _, err := DeserializeDispositionPayload([]byte("nope")); err == nil {
		t.Error("malformed must reject")
	}
}

func TestDispDeserialize_FailsValidate(t *testing.T) {
	bad := []byte(`{"outcome":"","panel":["x"],"case_ref":"y"}`)
	if _, err := DeserializeDispositionPayload(bad); err == nil {
		t.Error("invalid payload must reject")
	}
}

func TestDispDefaultParams_Parses(t *testing.T) {
	if len(DefaultDispositionParams()) == 0 {
		t.Error("DefaultDispositionParams returned empty bytes")
	}
}

func TestDispRegistry_Lookup(t *testing.T) {
	r := NewRegistry()
	reg, err := r.Lookup(SchemaAppellateDispositionV1)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if reg.URI != SchemaAppellateDispositionV1 {
		t.Errorf("URI drift: %q", reg.URI)
	}
}

func TestDispRegistry_RoundTripViaInterface(t *testing.T) {
	r := NewRegistry()
	reg, _ := r.Lookup(SchemaAppellateDispositionV1)
	p := happyDisposition()
	data, err := reg.Serialize(p)
	if err != nil {
		t.Fatalf("Serialize via registry: %v", err)
	}
	got, _ := reg.Deserialize(data)
	gp, ok := got.(*AppellateDispositionPayload)
	if !ok {
		t.Fatalf("Deserialize returned %T", got)
	}
	if gp.Outcome != p.Outcome {
		t.Errorf("outcome drift: %q", gp.Outcome)
	}
}

func TestDispRegistry_SerializeWrongType(t *testing.T) {
	r := NewRegistry()
	reg, _ := r.Lookup(SchemaAppellateDispositionV1)
	if _, err := reg.Serialize("not a payload"); err == nil {
		t.Error("Serialize must reject wrong type")
	}
}

// ─── functional emulation: TN COA 3-0 affirmance ───────────────

func TestFunctional_TNCOAAffirmance3Zero(t *testing.T) {
	p := &AppellateDispositionPayload{
		Outcome:   "affirmed",
		Panel:     []string{"did:key:zCOA1", "did:key:zCOA2", "did:key:zCOA3"},
		VoteTally: "3-0",
		CaseRef:   "TN-COA-2027-0042",
	}
	data, err := SerializeDispositionPayload(p)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	got, _ := DeserializeDispositionPayload(data)
	if len(got.Panel) != 3 {
		t.Errorf("3-judge panel must round-trip: len=%d", len(got.Panel))
	}
	if got.VoteTally != "3-0" {
		t.Errorf("vote_tally drift: %q", got.VoteTally)
	}
}

// TestFunctional_TwoOneSplit_AffirmedInPart pins the more
// nuanced disposition: 2-1 with affirmed_in_part_reversed_in_part.
func TestFunctional_TwoOneSplit_AffirmedInPart(t *testing.T) {
	p := &AppellateDispositionPayload{
		Outcome:   "affirmed_in_part_reversed_in_part",
		Panel:     []string{"did:key:zJ1", "did:key:zJ2", "did:key:zJ3"},
		VoteTally: "2-1",
		CaseRef:   "TN-COA-2027-0099",
	}
	if err := p.Validate(); err != nil {
		t.Errorf("2-1 split disposition must validate: %v", err)
	}
}
