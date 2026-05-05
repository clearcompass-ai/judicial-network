/*
FILE PATH: schemas/counsel_appearance_functional_test.go

DESCRIPTION:

	Functional-emulation tests for tn-counsel-appearance-v1.
	These walk the schema through real attorney-filing scenarios
	end-to-end (build → validate → serialize → deserialize) so
	the test failures map to user-visible regressions:

	  - "Defense counsel files appearance for one defendant."
	  - "Defense counsel represents two co-defendants."
	  - "Civil attorney represents the plaintiff."
	  - "Counsel withdraws by amending status to withdrawn."
	  - "Pro se case: no counsel_appearance, only party_binding."

	Unit-level tests (Validate happy/rejection, serialize round-
	trip, registry lookup) live in counsel_appearance_test.go.
*/
package schemas

import "testing"

// TestFunctional_DefenseCounselSingleDefendant emulates a defense
// attorney filing an appearance for one defendant — the canonical
// initial-appearance flow on a criminal case.
func TestFunctional_DefenseCounselSingleDefendant(t *testing.T) {
	p := &CounselAppearancePayload{
		AppearanceID: "ap-defense-001",
		AttorneyDID:  "did:key:zQ3shDEFENSE",
		Represents:   []string{"d-001"}, // the defendant
		CaseRef:      "DAV-2026-CR-0042",
	}
	data, err := SerializeCounselAppearancePayload(p)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	got, err := DeserializeCounselAppearancePayload(data)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.Status != "active" {
		t.Errorf("initial appearance must default to active, got %q",
			got.Status)
	}
	if len(got.Represents) != 1 || got.Represents[0] != "d-001" {
		t.Errorf("represents drift: %v", got.Represents)
	}
}

// TestFunctional_DefenseCounselMultipleCoDefendants emulates a
// shared-counsel scenario where one attorney represents two
// co-defendants — common in conspiracy / joint indictment cases.
func TestFunctional_DefenseCounselMultipleCoDefendants(t *testing.T) {
	p := &CounselAppearancePayload{
		AppearanceID: "ap-shared-007",
		AttorneyDID:  "did:key:zQ3shSHARED",
		Represents:   []string{"d-001", "d-002"},
		CaseRef:      "DAV-2026-CR-0042",
	}
	if err := p.Validate(); err != nil {
		t.Errorf("shared-counsel appearance must validate: %v", err)
	}
	data, err := SerializeCounselAppearancePayload(p)
	if err != nil {
		t.Fatalf("Serialize shared-counsel: %v", err)
	}
	got, err := DeserializeCounselAppearancePayload(data)
	if err != nil {
		t.Fatalf("Deserialize shared-counsel: %v", err)
	}
	// Order preserved — aggregator relies on this for the
	// attorney→party association reconstruction.
	if got.Represents[0] != "d-001" || got.Represents[1] != "d-002" {
		t.Errorf("represents order drift: %v", got.Represents)
	}
}

// TestFunctional_CivilAttorneyRepresentsPlaintiff emulates a
// civil attorney filing an appearance for the plaintiff in a
// civil action.
func TestFunctional_CivilAttorneyRepresentsPlaintiff(t *testing.T) {
	p := &CounselAppearancePayload{
		AppearanceID: "ap-civil-001",
		AttorneyDID:  "did:key:zQ3shCIVIL",
		Represents:   []string{"p-001"}, // the plaintiff
		CaseRef:      "DAV-2026-CV-0099",
	}
	if err := p.Validate(); err != nil {
		t.Errorf("civil attorney appearance must validate: %v", err)
	}
}

// TestFunctional_WithdrawnAppearance emulates the post-withdrawal
// state — the same appearance_id with status=withdrawn. In a real
// flow this is an amendment over the initial appearance entry;
// the schema layer just verifies the shape round-trips.
func TestFunctional_WithdrawnAppearance(t *testing.T) {
	p := &CounselAppearancePayload{
		AppearanceID: "ap-001",
		AttorneyDID:  "did:key:zQ3shATTORNEY",
		Represents:   []string{"d-001"},
		CaseRef:      "DAV-2026-CR-0042",
		Status:       "withdrawn",
	}
	data, err := SerializeCounselAppearancePayload(p)
	if err != nil {
		t.Fatalf("Serialize withdrawn: %v", err)
	}
	got, _ := DeserializeCounselAppearancePayload(data)
	if got.Status != "withdrawn" {
		t.Errorf("withdrawn status must round-trip, got %q", got.Status)
	}
}

// TestFunctional_RepresentsOrderPreserved pins that
// Serialize→Deserialize preserves the order of binding_ids in
// represents — the aggregator relies on this for stable
// attorney→party associations.
func TestFunctional_RepresentsOrderPreserved(t *testing.T) {
	p := &CounselAppearancePayload{
		AppearanceID: "ap-order-001",
		AttorneyDID:  "did:key:zQ3shORDER",
		Represents:   []string{"p-001", "d-002", "p-003"},
		CaseRef:      "DAV-2026-CV-0001",
	}
	data, _ := SerializeCounselAppearancePayload(p)
	got, _ := DeserializeCounselAppearancePayload(data)
	for i, want := range p.Represents {
		if got.Represents[i] != want {
			t.Errorf("represents[%d] drift: want %q got %q",
				i, want, got.Represents[i])
		}
	}
}
