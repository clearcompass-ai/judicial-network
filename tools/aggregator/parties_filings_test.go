/*
FILE PATH: tools/aggregator/parties_filings_test.go

DESCRIPTION:

	Unit + functional tests for BuildPartiesFilingRows — the
	pure extractor that produces parties_filings rows from
	ClassifiedEntry payloads. No Postgres needed. Covers:

	  - nil / empty payload → no rows.
	  - filed_by_capacity only → one row, kind=filed_by.
	  - signed_by_capacities only → one row per cosigner.
	  - both → rows for each capacity.
	  - missing optional fields default to empty strings (not
	    nil-dereference panics).

	Functional emulation:
	  - Defense counsel files motion_continuance — the canonical
	    Filer flow. One filed_by row + one signed_by row for
	    each cosigner.
	  - Pro Se filing (no attorney_did, only binding_id).
	  - counsel_appearance with represents list — one filed_by
	    row covering the appearance.
*/
package aggregator

import (
	"encoding/json"
	"testing"
)

// ─── nil / empty inputs ──────────────────────────────────────────

func TestBuildPartiesFilingRows_NilEntry(t *testing.T) {
	if rows := BuildPartiesFilingRows(nil); len(rows) != 0 {
		t.Errorf("nil entry should produce 0 rows, got %d", len(rows))
	}
}

func TestBuildPartiesFilingRows_NilPayload(t *testing.T) {
	c := &ClassifiedEntry{}
	if rows := BuildPartiesFilingRows(c); len(rows) != 0 {
		t.Errorf("nil payload should produce 0 rows, got %d", len(rows))
	}
}

func TestBuildPartiesFilingRows_NoCapacityBlocks(t *testing.T) {
	c := &ClassifiedEntry{
		Payload: map[string]any{
			"event_type": "case_initiated",
			"case_ref":   "DAV-2027-CR-0001",
		},
	}
	if rows := BuildPartiesFilingRows(c); len(rows) != 0 {
		t.Errorf("payload without capacities should produce 0 rows, got %d",
			len(rows))
	}
}

// ─── filed_by_capacity only ──────────────────────────────────────

func TestBuildPartiesFilingRows_FiledByOnly(t *testing.T) {
	c := &ClassifiedEntry{
		Sequence: 100,
		LogDID:   "did:web:state:tn:davidson",
		Payload: map[string]any{
			"event_type": "motion_continuance",
			"case_ref":   "DAV-2027-CR-0042",
			"filed_by_capacity": map[string]any{
				"actor": 1,
				"role":  "defense_counsel",
				"did":   "did:key:zATTORNEY",
				"credentials": map[string]any{
					"bpr_number": "TN-12345",
				},
				"sworn_at": "2027-04-30T10:00:00Z",
			},
		},
	}
	rows := BuildPartiesFilingRows(c)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	r := rows[0]
	if r.CapacityKind != "filed_by" {
		t.Errorf("kind drift: %q", r.CapacityKind)
	}
	if r.CapacityDID != "did:key:zATTORNEY" {
		t.Errorf("did drift: %q", r.CapacityDID)
	}
	if r.CapacityRole != "defense_counsel" {
		t.Errorf("role drift: %q", r.CapacityRole)
	}
	if r.EventType != "motion_continuance" {
		t.Errorf("event_type drift: %q", r.EventType)
	}
	if r.CaseRef != "DAV-2027-CR-0042" {
		t.Errorf("case_ref drift: %q", r.CaseRef)
	}
	if r.SwornAt != "2027-04-30T10:00:00Z" {
		t.Errorf("sworn_at drift: %q", r.SwornAt)
	}
	if r.LogPosition != 100 {
		t.Errorf("log_position drift: %d", r.LogPosition)
	}
	if r.LogDID != "did:web:state:tn:davidson" {
		t.Errorf("log_did drift: %q", r.LogDID)
	}
	// Credentials JSON should round-trip.
	var creds map[string]any
	if err := json.Unmarshal([]byte(r.CredentialsJSON), &creds); err != nil {
		t.Fatalf("credentials JSON parse: %v", err)
	}
	if creds["bpr_number"] != "TN-12345" {
		t.Errorf("credentials drift: %v", creds)
	}
}

// ─── signed_by_capacities list ───────────────────────────────────

func TestBuildPartiesFilingRows_SignedByList(t *testing.T) {
	c := &ClassifiedEntry{
		Sequence: 101,
		LogDID:   "did:web:state:tn:davidson",
		Payload: map[string]any{
			"event_type": "motion_continuance",
			"signed_by_capacities": []any{
				map[string]any{
					"actor": 0,
					"role":  "court_clerk",
					"did":   "did:key:zCLERK",
				},
				map[string]any{
					"actor": 0,
					"role":  "judge",
					"did":   "did:key:zJUDGE",
				},
			},
		},
	}
	rows := BuildPartiesFilingRows(c)
	if len(rows) != 2 {
		t.Fatalf("expected 2 signed_by rows, got %d", len(rows))
	}
	for _, r := range rows {
		if r.CapacityKind != "signed_by" {
			t.Errorf("kind drift: %q", r.CapacityKind)
		}
	}
	if rows[0].CapacityDID != "did:key:zCLERK" || rows[0].CapacityRole != "court_clerk" {
		t.Errorf("first signer drift: %+v", rows[0])
	}
	if rows[1].CapacityDID != "did:key:zJUDGE" || rows[1].CapacityRole != "judge" {
		t.Errorf("second signer drift: %+v", rows[1])
	}
}

// ─── filed_by + signed_by combined ───────────────────────────────

func TestBuildPartiesFilingRows_BothFiledAndSigned(t *testing.T) {
	c := &ClassifiedEntry{
		Sequence: 102,
		LogDID:   "did:web:state:tn:davidson",
		Payload: map[string]any{
			"event_type": "motion_continuance",
			"filed_by_capacity": map[string]any{
				"role": "defense_counsel",
				"did":  "did:key:zATTORNEY",
			},
			"signed_by_capacities": []any{
				map[string]any{"role": "court_clerk", "did": "did:key:zCLERK"},
			},
		},
	}
	rows := BuildPartiesFilingRows(c)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (1 filed_by + 1 signed_by), got %d", len(rows))
	}
	if rows[0].CapacityKind != "filed_by" {
		t.Error("first row should be filed_by")
	}
	if rows[1].CapacityKind != "signed_by" {
		t.Error("second row should be signed_by")
	}
}

// ─── malformed entries gracefully degrade ────────────────────────

func TestBuildPartiesFilingRows_MalformedSignedByItem(t *testing.T) {
	// One valid + one non-map item in signed_by_capacities. The
	// non-map item should be skipped without panic.
	c := &ClassifiedEntry{
		Sequence: 103,
		Payload: map[string]any{
			"event_type": "motion_continuance",
			"signed_by_capacities": []any{
				map[string]any{"role": "court_clerk", "did": "did:key:zCLERK"},
				"not a map",
			},
		},
	}
	rows := BuildPartiesFilingRows(c)
	if len(rows) != 1 {
		t.Errorf("malformed item should be skipped; want 1 row, got %d", len(rows))
	}
}

func TestBuildPartiesFilingRows_NoCredentials(t *testing.T) {
	c := &ClassifiedEntry{
		Sequence: 104,
		Payload: map[string]any{
			"event_type": "verdict",
			"signed_by_capacities": []any{
				map[string]any{"role": "judge", "did": "did:key:zJUDGE"},
			},
		},
	}
	rows := BuildPartiesFilingRows(c)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].CredentialsJSON != "" {
		t.Errorf("no credentials → empty CredentialsJSON; got %q",
			rows[0].CredentialsJSON)
	}
}

// Functional emulation tests live in
// parties_filings_functional_test.go to keep this file under
// the 300-line cap.
