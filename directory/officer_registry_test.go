/*
FILE PATH: directory/officer_registry_test.go

DESCRIPTION:
    Contract tests for InMemoryRegistry. Pin the surface every
    Registry implementation must satisfy: Add/Lookup, alias
    uniqueness, Update preservation rules, status transitions
    (revoke / succeed; refusal of illegal rewinds), List and
    ListByRole determinism, concurrency safety.
*/
package directory

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── helpers ────────────────────────────────────────────────────────

func sampleOfficer(did, alias, role string) Officer {
	return Officer{
		DID:           did,
		Alias:         alias,
		Role:          role,
		DelegationRef: schemas.LogPositionRef{LogDID: "did:web:da:davidson-tn", Sequence: 1},
	}
}

// ─── Add / Lookup ───────────────────────────────────────────────────

func TestInMemoryRegistry_Add_Lookup(t *testing.T) {
	r := NewInMemoryRegistry()
	o := sampleOfficer("did:key:zQ3shA", "Hon. Patricia Williams", "chief_justice")

	if err := r.Add(o); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := r.Lookup("did:key:zQ3shA")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Alias != o.Alias {
		t.Errorf("alias drift: %q", got.Alias)
	}
	if got.Status != StatusActive {
		t.Errorf("status default: got %q, want active", got.Status)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
}

func TestInMemoryRegistry_LookupByAlias(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shA", "Patricia W.", "chief_justice"))

	got, err := r.LookupByAlias("Patricia W.")
	if err != nil {
		t.Fatalf("LookupByAlias: %v", err)
	}
	if got.DID != "did:key:zQ3shA" {
		t.Errorf("did drift: %q", got.DID)
	}

	if _, err := r.LookupByAlias("nobody"); !errors.Is(err, ErrOfficerNotFound) {
		t.Errorf("expected ErrOfficerNotFound, got: %v", err)
	}
}

func TestInMemoryRegistry_Lookup_Unknown(t *testing.T) {
	r := NewInMemoryRegistry()
	_, err := r.Lookup("did:key:zQ3shNONE")
	if !errors.Is(err, ErrOfficerNotFound) {
		t.Errorf("expected ErrOfficerNotFound, got: %v", err)
	}
}

func TestInMemoryRegistry_Add_RejectsDuplicateDID(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shA", "Original", "chief_justice"))
	err := r.Add(sampleOfficer("did:key:zQ3shA", "Different", "judge"))
	if !errors.Is(err, ErrOfficerExists) {
		t.Errorf("expected ErrOfficerExists, got: %v", err)
	}
}

func TestInMemoryRegistry_Add_RejectsDuplicateAlias(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shA", "Same Name", "chief_justice"))
	err := r.Add(sampleOfficer("did:key:zQ3shB", "Same Name", "judge"))
	if !errors.Is(err, ErrAliasTaken) {
		t.Errorf("expected ErrAliasTaken, got: %v", err)
	}
}

func TestInMemoryRegistry_Add_RejectsInvalid(t *testing.T) {
	r := NewInMemoryRegistry()

	cases := []struct {
		name string
		mut  func(o *Officer)
		want string
	}{
		{"missing did", func(o *Officer) { o.DID = "" }, "did required"},
		{"missing alias", func(o *Officer) { o.Alias = "" }, "alias required"},
		{"missing role", func(o *Officer) { o.Role = "" }, "role required"},
		{"missing delegation_ref", func(o *Officer) { o.DelegationRef.LogDID = "" }, "delegation_ref"},
		{"bad status", func(o *Officer) { o.Status = "wat" }, "status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := sampleOfficer("did:key:zQ3shX", "X", "judge")
			tc.mut(&o)
			err := r.Add(o)
			if err == nil || !errors.Is(err, ErrInvalidOfficer) {
				t.Fatalf("expected ErrInvalidOfficer, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err missing %q: %v", tc.want, err)
			}
		})
	}
}

// ─── Update ─────────────────────────────────────────────────────────

func TestInMemoryRegistry_Update_PreservesCreatedAt(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shA", "Patricia W.", "chief_justice"))
	created, _ := r.Lookup("did:key:zQ3shA")
	time.Sleep(time.Millisecond)

	upd := sampleOfficer("did:key:zQ3shA", "Hon. Patricia Williams", "chief_justice")
	if err := r.Update(upd); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := r.Lookup("did:key:zQ3shA")
	if !got.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("CreatedAt mutated: was %v, now %v", created.CreatedAt, got.CreatedAt)
	}
	if !got.UpdatedAt.After(created.UpdatedAt) {
		t.Errorf("UpdatedAt did not advance: was %v, now %v", created.UpdatedAt, got.UpdatedAt)
	}
	if got.Alias != "Hon. Patricia Williams" {
		t.Errorf("alias not updated: %q", got.Alias)
	}
}

func TestInMemoryRegistry_Update_AliasReassignment(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shA", "Old", "chief_justice"))
	r.Add(sampleOfficer("did:key:zQ3shB", "Other", "judge"))

	// Rename A → "New" — should succeed, free up "Old".
	upd := sampleOfficer("did:key:zQ3shA", "New", "chief_justice")
	if err := r.Update(upd); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := r.LookupByAlias("Old"); !errors.Is(err, ErrOfficerNotFound) {
		t.Error("'Old' should be free after rename")
	}
	got, _ := r.LookupByAlias("New")
	if got.DID != "did:key:zQ3shA" {
		t.Errorf("New does not point to A: %q", got.DID)
	}

	// Rename B → "New" — should fail with ErrAliasTaken.
	updB := sampleOfficer("did:key:zQ3shB", "New", "judge")
	if err := r.Update(updB); !errors.Is(err, ErrAliasTaken) {
		t.Errorf("expected ErrAliasTaken, got: %v", err)
	}
}

func TestInMemoryRegistry_Update_RefusesUnRevoke(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shA", "P", "chief_justice"))
	r.MarkRevoked("did:key:zQ3shA")

	// Update with explicit Status=active — illegal rewind.
	upd := sampleOfficer("did:key:zQ3shA", "P", "chief_justice")
	upd.Status = StatusActive
	err := r.Update(upd)
	if !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("expected ErrIllegalTransition, got: %v", err)
	}
}

func TestInMemoryRegistry_Update_NotFound(t *testing.T) {
	r := NewInMemoryRegistry()
	err := r.Update(sampleOfficer("did:key:zQ3shGHOST", "Ghost", "judge"))
	if !errors.Is(err, ErrOfficerNotFound) {
		t.Errorf("expected ErrOfficerNotFound, got: %v", err)
	}
}

// (Lifecycle / List / Postgres-stub tests live in
//  officer_registry_lifecycle_test.go.)
