/*
FILE PATH: deployments/TEMPLATE/rules/role_catalog_test.go

DESCRIPTION:
    Tests for the TEMPLATE role catalog. Pins:
      - the skeleton compiles and validates,
      - exactly 1 role is defined (the placeholder),
      - the placeholder is a Signer (HoldsKeys=true),
      - MustRoleCatalog does not panic.
*/
package rules

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

func TestRoles_Validates(t *testing.T) {
	if _, err := schemas.NewInMemoryCatalog(Roles()); err != nil {
		t.Errorf("TEMPLATE roles failed to construct: %v", err)
	}
}

func TestRoles_PlaceholderIsSigner(t *testing.T) {
	rs := Roles()
	if len(rs) != 1 {
		t.Fatalf("TEMPLATE skeleton must ship 1 role; got %d", len(rs))
	}
	r := rs[0]
	if r.Actor != schemas.ActorSigner {
		t.Errorf("placeholder role actor: want ActorSigner, got %s", r.Actor)
	}
	if !r.Actor.HoldsKeys() {
		t.Error("placeholder Signer must HoldsKeys=true")
	}
	if r.Name != "judge" {
		t.Errorf("placeholder name drift: want judge, got %q", r.Name)
	}
}

func TestMustRoleCatalog_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustRoleCatalog panicked: %v", r)
		}
	}()
	_ = MustRoleCatalog()
}

func TestMustRoleCatalog_IndependentCalls(t *testing.T) {
	a := MustRoleCatalog()
	b := MustRoleCatalog()
	if a == b {
		t.Error("MustRoleCatalog should return a fresh catalog per call")
	}
}
