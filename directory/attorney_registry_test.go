/*
FILE PATH: directory/attorney_registry_test.go

DESCRIPTION:
    Contract tests for InMemoryAttorneys: validation, Register,
    Lookup / LookupByAlias / LookupByBarNumber, alias and bar
    uniqueness constraints. Status-transition + listing tests live
    in attorney_registry_lifecycle_test.go in the same test package.
*/
package directory

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// ─── helpers ────────────────────────────────────────────────────────

func sampleAttorney(id, alias, barNum string, t AttorneyType) Attorney {
	return Attorney{
		ID:        id,
		Alias:     alias,
		Type:      t,
		BarNumber: barNum,
	}
}

// ─── Type / Status enums ────────────────────────────────────────────

func TestAttorneyType_IsValid(t *testing.T) {
	for _, ty := range []AttorneyType{
		AttorneyTypeProsecutor, AttorneyTypeDefenseCounsel,
		AttorneyTypeCivilAttorney, AttorneyTypeFiduciary,
		AttorneyTypeGuardianAdLitem,
	} {
		if !ty.IsValid() {
			t.Errorf("%q must be valid", ty)
		}
	}
	for _, ty := range []AttorneyType{"", "wizard", "lawyer"} {
		if ty.IsValid() {
			t.Errorf("%q must NOT be valid", ty)
		}
	}
}

func TestAttorneyStatus_IsValid_IsTerminal(t *testing.T) {
	cases := []struct {
		s    AttorneyStatus
		valid, terminal bool
	}{
		{AttorneyActive, true, false},
		{AttorneySuspended, true, false},
		{AttorneyRetired, true, true},
		{AttorneyRevoked, true, true},
		{"", false, false},
		{"wat", false, false},
	}
	for _, tc := range cases {
		if got := tc.s.IsValid(); got != tc.valid {
			t.Errorf("%q IsValid = %v, want %v", tc.s, got, tc.valid)
		}
		if got := tc.s.IsTerminal(); got != tc.terminal {
			t.Errorf("%q IsTerminal = %v, want %v", tc.s, got, tc.terminal)
		}
	}
}

func TestAttorney_IsTier2(t *testing.T) {
	a := sampleAttorney("att:a", "Smith", "TN-1", AttorneyTypeProsecutor)
	if !a.IsTier2() {
		t.Error("valid prosecutor should be Tier2")
	}
	bad := Attorney{ID: "x", Type: "wizard"}
	if bad.IsTier2() {
		t.Error("invalid type should NOT be Tier2")
	}
	var nilA *Attorney
	if nilA.IsTier2() {
		t.Error("nil attorney should NOT be Tier2")
	}
}

// ─── Register / Lookup ──────────────────────────────────────────────

func TestInMemoryAttorneys_Register_Lookup(t *testing.T) {
	r := NewInMemoryAttorneys()
	a := sampleAttorney(
		"bar:TN:12345", "Jane Smith, Esq.", "TN-12345",
		AttorneyTypeDefenseCounsel)

	if err := r.Register(a); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := r.Lookup("bar:TN:12345")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Alias != a.Alias {
		t.Errorf("alias drift: %q", got.Alias)
	}
	if got.Status != AttorneyActive {
		t.Errorf("default status: got %q, want active", got.Status)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("CreatedAt/UpdatedAt must be set")
	}
}

func TestInMemoryAttorneys_LookupByAlias(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane Smith", "TN-1", AttorneyTypeProsecutor))

	got, err := r.LookupByAlias("Jane Smith")
	if err != nil {
		t.Fatalf("LookupByAlias: %v", err)
	}
	if got.ID != "bar:1" {
		t.Errorf("id drift: %q", got.ID)
	}

	if _, err := r.LookupByAlias("nobody"); !errors.Is(err, ErrAttorneyNotFound) {
		t.Errorf("expected ErrAttorneyNotFound, got: %v", err)
	}
}

func TestInMemoryAttorneys_LookupByBarNumber(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane Smith", "TN-1", AttorneyTypeProsecutor))

	got, err := r.LookupByBarNumber("TN-1")
	if err != nil {
		t.Fatalf("LookupByBarNumber: %v", err)
	}
	if got.ID != "bar:1" {
		t.Errorf("id drift: %q", got.ID)
	}

	// Empty bar number returns NotFound (fast-fail).
	if _, err := r.LookupByBarNumber(""); !errors.Is(err, ErrAttorneyNotFound) {
		t.Errorf("empty bar_number: expected ErrAttorneyNotFound, got: %v", err)
	}

	// Unknown bar number returns NotFound.
	if _, err := r.LookupByBarNumber("TN-999"); !errors.Is(err, ErrAttorneyNotFound) {
		t.Errorf("unknown bar_number: %v", err)
	}
}

// ─── Uniqueness ─────────────────────────────────────────────────────

func TestInMemoryAttorneys_Register_RejectsDuplicateID(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Smith", "TN-1", AttorneyTypeProsecutor))
	err := r.Register(sampleAttorney("bar:1", "Different", "TN-2", AttorneyTypeDefenseCounsel))
	if !errors.Is(err, ErrAttorneyExists) {
		t.Errorf("expected ErrAttorneyExists, got: %v", err)
	}
}

func TestInMemoryAttorneys_Register_RejectsDuplicateAlias(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Same Name", "TN-1", AttorneyTypeProsecutor))
	err := r.Register(sampleAttorney("bar:2", "Same Name", "TN-2", AttorneyTypeDefenseCounsel))
	if !errors.Is(err, ErrAliasTaken) {
		t.Errorf("expected ErrAliasTaken, got: %v", err)
	}
}

func TestInMemoryAttorneys_Register_RejectsDuplicateBarNumber(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane", "TN-1", AttorneyTypeProsecutor))
	err := r.Register(sampleAttorney("bar:2", "Joe", "TN-1", AttorneyTypeDefenseCounsel))
	if !errors.Is(err, ErrBarNumberTaken) {
		t.Errorf("expected ErrBarNumberTaken, got: %v", err)
	}
}

func TestInMemoryAttorneys_Register_AllowsEmptyBarNumberDuplicates(t *testing.T) {
	// Empty bar numbers are NOT indexed; multiple records with no
	// bar number coexist (e.g. fiduciaries, guardians ad litem
	// who aren't bar-admitted).
	r := NewInMemoryAttorneys()
	if err := r.Register(sampleAttorney("att:1", "Alpha", "", AttorneyTypeFiduciary)); err != nil {
		t.Fatalf("Register 1: %v", err)
	}
	if err := r.Register(sampleAttorney("att:2", "Beta", "", AttorneyTypeFiduciary)); err != nil {
		t.Errorf("Register 2 (empty bar #): %v", err)
	}
}

// ─── validation ─────────────────────────────────────────────────────

func TestInMemoryAttorneys_Register_RejectsInvalid(t *testing.T) {
	r := NewInMemoryAttorneys()

	cases := []struct {
		name string
		mut  func(a *Attorney)
		want string
	}{
		{"missing id", func(a *Attorney) { a.ID = "" }, "id required"},
		{"missing alias", func(a *Attorney) { a.Alias = "" }, "alias required"},
		{"unknown type", func(a *Attorney) { a.Type = "wizard" }, "type"},
		{"empty type", func(a *Attorney) { a.Type = "" }, "type"},
		{"bad status", func(a *Attorney) { a.Status = "wat" }, "status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := sampleAttorney("bar:X", "X", "TN-X", AttorneyTypeProsecutor)
			tc.mut(&a)
			err := r.Register(a)
			if err == nil || !errors.Is(err, ErrInvalidAttorney) {
				t.Fatalf("expected ErrInvalidAttorney, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err missing %q: %v", tc.want, err)
			}
		})
	}
}

// ─── Update ─────────────────────────────────────────────────────────

func TestInMemoryAttorneys_Update_PreservesCreatedAt(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Original", "TN-1", AttorneyTypeProsecutor))
	created, _ := r.Lookup("bar:1")
	time.Sleep(time.Millisecond)

	upd := sampleAttorney("bar:1", "Updated Name", "TN-1", AttorneyTypeProsecutor)
	if err := r.Update(upd); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := r.Lookup("bar:1")
	if !got.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("CreatedAt mutated: was %v, now %v", created.CreatedAt, got.CreatedAt)
	}
	if !got.UpdatedAt.After(created.UpdatedAt) {
		t.Errorf("UpdatedAt did not advance")
	}
	if got.Alias != "Updated Name" {
		t.Errorf("alias not updated: %q", got.Alias)
	}
}

func TestInMemoryAttorneys_Update_NotFound(t *testing.T) {
	r := NewInMemoryAttorneys()
	err := r.Update(sampleAttorney("bar:GHOST", "Ghost", "TN-9", AttorneyTypeProsecutor))
	if !errors.Is(err, ErrAttorneyNotFound) {
		t.Errorf("expected ErrAttorneyNotFound, got: %v", err)
	}
}

func TestInMemoryAttorneys_Update_AliasReassignment(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Old", "TN-1", AttorneyTypeProsecutor))
	r.Register(sampleAttorney("bar:2", "Other", "TN-2", AttorneyTypeProsecutor))

	if err := r.Update(sampleAttorney("bar:1", "New", "TN-1", AttorneyTypeProsecutor)); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := r.LookupByAlias("Old"); !errors.Is(err, ErrAttorneyNotFound) {
		t.Error("'Old' should be free after rename")
	}

	// Renaming bar:2 to "New" must collide.
	err := r.Update(sampleAttorney("bar:2", "New", "TN-2", AttorneyTypeProsecutor))
	if !errors.Is(err, ErrAliasTaken) {
		t.Errorf("expected ErrAliasTaken, got: %v", err)
	}
}

func TestInMemoryAttorneys_Update_BarNumberReassignment(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "A", "TN-1", AttorneyTypeProsecutor))
	r.Register(sampleAttorney("bar:2", "B", "TN-2", AttorneyTypeProsecutor))

	// Move bar:1 from TN-1 → TN-3 (free).
	if err := r.Update(sampleAttorney("bar:1", "A", "TN-3", AttorneyTypeProsecutor)); err != nil {
		t.Fatalf("bar # change: %v", err)
	}
	if _, err := r.LookupByBarNumber("TN-1"); !errors.Is(err, ErrAttorneyNotFound) {
		t.Error("TN-1 should be free after reassignment")
	}

	// Move bar:2 to TN-3 — collision.
	err := r.Update(sampleAttorney("bar:2", "B", "TN-3", AttorneyTypeProsecutor))
	if !errors.Is(err, ErrBarNumberTaken) {
		t.Errorf("expected ErrBarNumberTaken, got: %v", err)
	}
}
