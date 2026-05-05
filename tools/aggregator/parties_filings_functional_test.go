/*
FILE PATH: tools/aggregator/parties_filings_functional_test.go

DESCRIPTION:

	Functional emulation tests for BuildPartiesFilingRows.
	Each test reproduces a real on-log entry shape so failures
	map to user-visible regressions:

	  - Defense counsel files counsel_appearance, clerk cosigns.
	  - Pro Se litigant filing (no attorney_did, only binding_id).

	Unit-level tests live in parties_filings_test.go.
*/
package aggregator

import "testing"

// TestFunctional_CounselAppearance_Indexed pins the v1.8 §1
// canonical flow: defense counsel files counsel_appearance,
// court clerk cosigns. Two rows total — one filed_by_capacity
// row for the attorney, one signed_by_capacities row for the
// cosigning clerk.
func TestFunctional_CounselAppearance_Indexed(t *testing.T) {
	c := &ClassifiedEntry{
		Sequence: 200,
		LogDID:   "did:web:state:tn:davidson",
		Payload: map[string]any{
			"event_type":    "counsel_appearance",
			"case_ref":      "DAV-2027-CR-0042",
			"appearance_id": "ap-001",
			"attorney_did":  "did:key:zATTORNEY",
			"represents":    []any{"d-001"},
			"filed_by_capacity": map[string]any{
				"role": "defense_counsel",
				"did":  "did:key:zATTORNEY",
				"credentials": map[string]any{
					"bpr_number": "TN-12345",
				},
			},
			"signed_by_capacities": []any{
				map[string]any{
					"role": "court_clerk",
					"did":  "did:key:zCLERK",
				},
			},
		},
	}
	rows := BuildPartiesFilingRows(c)
	if len(rows) != 2 {
		t.Fatalf("counsel_appearance: want 2 rows, got %d", len(rows))
	}
	if rows[0].CapacityKind != "filed_by" ||
		rows[0].CapacityRole != "defense_counsel" {
		t.Errorf("first row drift: %+v", rows[0])
	}
	if rows[1].CapacityKind != "signed_by" ||
		rows[1].CapacityRole != "court_clerk" {
		t.Errorf("second row drift: %+v", rows[1])
	}
	for _, r := range rows {
		if r.EventType != "counsel_appearance" {
			t.Errorf("event_type must propagate to every row, got %q",
				r.EventType)
		}
	}
}

// TestFunctional_ProSeFiling_Indexed pins the Pro Se case where
// there is no attorney_did and no filed_by_capacity DID — only
// a binding_id reference. The signed_by row carries the clerk
// who proxy-filed.
func TestFunctional_ProSeFiling_Indexed(t *testing.T) {
	c := &ClassifiedEntry{
		Sequence: 201,
		LogDID:   "did:web:state:tn:davidson",
		Payload: map[string]any{
			"event_type": "responsive_pleading",
			"case_ref":   "DAV-2027-CV-0099",
			// Pro Se: no filed_by_capacity DID. The pro se
			// litigant is referenced via binding_id only.
			"filed_by_capacity": map[string]any{
				"role":       "pro_se",
				"binding_id": "p-001",
			},
			"signed_by_capacities": []any{
				map[string]any{"role": "court_clerk", "did": "did:key:zCLERK"},
			},
		},
	}
	rows := BuildPartiesFilingRows(c)
	if len(rows) != 2 {
		t.Fatalf("pro se: want 2 rows, got %d", len(rows))
	}
	if rows[0].CapacityDID != "" {
		t.Errorf("pro se filed_by must have empty DID, got %q",
			rows[0].CapacityDID)
	}
	if rows[0].CapacityBindingID != "p-001" {
		t.Errorf("pro se filed_by binding_id drift: %q",
			rows[0].CapacityBindingID)
	}
}
