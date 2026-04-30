/*
FILE PATH: schemas/actor_test.go

DESCRIPTION:
    Tests for the Actor classification surface. Pins:
      - Closed-set membership: only 1, 2, 3 are valid.
      - ActorUnspecified (zero value) is invalid — code that omits
        Actor produces a loud error, not a silent default.
      - HoldsKeys is true for ActorSigner, false for everything else
        (the property the Phase 3C cosignature-mix evaluator depends on).
      - Stable string forms for audit logs.
      - Stable integer values (JSON catalog round-trip contract).
*/
package schemas

import (
	"strings"
	"testing"
)

func TestActor_IsValid(t *testing.T) {
	cases := []struct {
		in   Actor
		want bool
	}{
		{ActorUnspecified, false}, // zero value MUST be invalid
		{ActorSigner, true},
		{ActorFiler, true},
		{ActorParty, true},
		{Actor(0), false},
		{Actor(4), false}, // unknown
		{Actor(-1), false},
		{Actor(99), false},
	}
	for _, tc := range cases {
		if got := tc.in.IsValid(); got != tc.want {
			t.Errorf("Actor(%d).IsValid() = %v, want %v", int(tc.in), got, tc.want)
		}
	}
}

func TestActor_HoldsKeys(t *testing.T) {
	if !ActorSigner.HoldsKeys() {
		t.Error("ActorSigner must HoldsKeys=true")
	}
	if ActorFiler.HoldsKeys() {
		t.Error("ActorFiler must HoldsKeys=false (filers hold own DID for cosig only)")
	}
	if ActorParty.HoldsKeys() {
		t.Error("ActorParty must HoldsKeys=false")
	}
	if ActorUnspecified.HoldsKeys() {
		t.Error("ActorUnspecified must HoldsKeys=false")
	}
	if Actor(99).HoldsKeys() {
		t.Error("unknown actor must HoldsKeys=false")
	}
}

func TestActor_String(t *testing.T) {
	cases := []struct {
		in   Actor
		want string
	}{
		{ActorUnspecified, "actor_unspecified"},
		{ActorSigner, "actor_signer"},
		{ActorFiler, "actor_filer"},
		{ActorParty, "actor_party"},
	}
	for _, tc := range cases {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("Actor(%d).String() = %q, want %q", int(tc.in), got, tc.want)
		}
	}
	// Unknown actors render deterministically with the int value
	// for debugging.
	got := Actor(42).String()
	if !strings.Contains(got, "42") {
		t.Errorf("unknown actor should embed the int: %q", got)
	}
}

func TestValidateActor(t *testing.T) {
	if err := validateActor(ActorSigner); err != nil {
		t.Errorf("ActorSigner: %v", err)
	}
	if err := validateActor(ActorFiler); err != nil {
		t.Errorf("ActorFiler: %v", err)
	}
	if err := validateActor(ActorParty); err != nil {
		t.Errorf("ActorParty: %v", err)
	}

	cases := []Actor{ActorUnspecified, Actor(0), Actor(4), Actor(-1), Actor(99)}
	for _, in := range cases {
		err := validateActor(in)
		if err == nil {
			t.Errorf("Actor(%d) should be invalid", int(in))
			continue
		}
		if !strings.Contains(err.Error(), "actor must be one of") {
			t.Errorf("Actor(%d) error message drift: %v", int(in), err)
		}
	}
}

// TestActor_StableIntegerValues pins the integer values — the
// dictionary's actor ordering is part of the public contract, the
// JSON catalog encodes the int, and the aggregator's Postgres
// schema (Phase 3E) will index on it. Renumbering would break
// stored catalogs and breaks audit logs.
func TestActor_StableIntegerValues(t *testing.T) {
	if int(ActorUnspecified) != 0 {
		t.Errorf("ActorUnspecified must be 0, got %d", int(ActorUnspecified))
	}
	if int(ActorSigner) != 1 {
		t.Errorf("ActorSigner must be 1, got %d", int(ActorSigner))
	}
	if int(ActorFiler) != 2 {
		t.Errorf("ActorFiler must be 2, got %d", int(ActorFiler))
	}
	if int(ActorParty) != 3 {
		t.Errorf("ActorParty must be 3, got %d", int(ActorParty))
	}
}
