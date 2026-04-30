/*
FILE PATH: schemas/tier_test.go

DESCRIPTION:
    Tests for the Tier classification surface. Pins:
      - Closed-set membership: only 1, 2, 3 are valid.
      - TierUnspecified (zero value) is invalid — code that omits
        Tier produces a loud error, not a silent default.
      - HoldsKeys is true for Tier 1, false for everything else
        (the property the Phase 3C cosignature-mix evaluator depends on).
      - Stable string forms for audit logs.
*/
package schemas

import (
	"strings"
	"testing"
)

func TestTier_IsValid(t *testing.T) {
	cases := []struct {
		in   Tier
		want bool
	}{
		{TierUnspecified, false}, // zero value MUST be invalid
		{Tier1Signer, true},
		{Tier2Advocate, true},
		{Tier3Party, true},
		{Tier(0), false},
		{Tier(4), false}, // unknown
		{Tier(-1), false},
		{Tier(99), false},
	}
	for _, tc := range cases {
		if got := tc.in.IsValid(); got != tc.want {
			t.Errorf("Tier(%d).IsValid() = %v, want %v", int(tc.in), got, tc.want)
		}
	}
}

func TestTier_HoldsKeys(t *testing.T) {
	if !Tier1Signer.HoldsKeys() {
		t.Error("Tier1Signer must HoldsKeys=true")
	}
	if Tier2Advocate.HoldsKeys() {
		t.Error("Tier2Advocate must HoldsKeys=false")
	}
	if Tier3Party.HoldsKeys() {
		t.Error("Tier3Party must HoldsKeys=false")
	}
	if TierUnspecified.HoldsKeys() {
		t.Error("TierUnspecified must HoldsKeys=false")
	}
	if Tier(99).HoldsKeys() {
		t.Error("unknown tier must HoldsKeys=false")
	}
}

func TestTier_String(t *testing.T) {
	cases := []struct {
		in   Tier
		want string
	}{
		{TierUnspecified, "tier_unspecified"},
		{Tier1Signer, "tier_1_signer"},
		{Tier2Advocate, "tier_2_advocate"},
		{Tier3Party, "tier_3_party"},
	}
	for _, tc := range cases {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("Tier(%d).String() = %q, want %q", int(tc.in), got, tc.want)
		}
	}
	// Unknown tier renders deterministically with the int value
	// for debugging.
	got := Tier(42).String()
	if !strings.Contains(got, "42") {
		t.Errorf("unknown tier should embed the int: %q", got)
	}
}

func TestValidateTier(t *testing.T) {
	if err := validateTier(Tier1Signer); err != nil {
		t.Errorf("Tier1Signer: %v", err)
	}
	if err := validateTier(Tier2Advocate); err != nil {
		t.Errorf("Tier2Advocate: %v", err)
	}
	if err := validateTier(Tier3Party); err != nil {
		t.Errorf("Tier3Party: %v", err)
	}

	cases := []Tier{TierUnspecified, Tier(0), Tier(4), Tier(-1), Tier(99)}
	for _, in := range cases {
		err := validateTier(in)
		if err == nil {
			t.Errorf("Tier(%d) should be invalid", int(in))
			continue
		}
		if !strings.Contains(err.Error(), "tier must be one of") {
			t.Errorf("Tier(%d) error message drift: %v", int(in), err)
		}
	}
}

// TierConsts pins the integer values — the dictionary's tier ordering
// is part of the public contract and renumbering would break aggregator
// indexing and audit logs.
func TestTier_StableIntegerValues(t *testing.T) {
	if int(TierUnspecified) != 0 {
		t.Errorf("TierUnspecified must be 0, got %d", int(TierUnspecified))
	}
	if int(Tier1Signer) != 1 {
		t.Errorf("Tier1Signer must be 1, got %d", int(Tier1Signer))
	}
	if int(Tier2Advocate) != 2 {
		t.Errorf("Tier2Advocate must be 2, got %d", int(Tier2Advocate))
	}
	if int(Tier3Party) != 3 {
		t.Errorf("Tier3Party must be 3, got %d", int(Tier3Party))
	}
}
