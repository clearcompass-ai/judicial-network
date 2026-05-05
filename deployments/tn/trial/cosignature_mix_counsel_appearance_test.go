/*
FILE PATH: deployments/tn/trial/cosignature_mix_counsel_appearance_test.go

DESCRIPTION:

	Targeted tests for the v1.8 §1 counsel_appearance cosignature
	rule. Pins:

	  - Filer set: defense_counsel, civil_attorney, prosecutor
	    — every advocate role on the Filer side.
	  - Filer rejection: fiduciary, guardian_ad_litem (those have
	    their own cosig rules and credential requirements).
	  - Signer: court_clerk only (no judge — appearance does not
	    require judicial review at filing time; the merits-side
	    review happens at motion-for-withdraw if any).
	  - Intra-exchange (a Davidson clerk does not cosign a
	    Shelby attorney's appearance on a Shelby case).
	  - bpr_number credential (TN attorney licensing) required.

	Functional emulation lives in
	cosignature_mix_counsel_appearance_functional_test.go.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

func TestCosignatureRules_CounselAppearancePresent(t *testing.T) {
	r, err := MustCosignaturePolicy().Lookup("counsel_appearance")
	if err != nil {
		t.Fatalf("counsel_appearance missing: %v", err)
	}

	// Allowed Filer roles.
	for _, want := range []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleCivilAttorney,
		schemas.FilerRoleProsecutor,
	} {
		if !r.PermitsFilerRole(want) {
			t.Errorf("counsel_appearance must permit %q", want)
		}
	}

	// Rejected Filer roles.
	for _, notWant := range []schemas.FilerRole{
		schemas.FilerRoleFiduciary,
		schemas.FilerRoleGuardianAdLitem,
	} {
		if r.PermitsFilerRole(notWant) {
			t.Errorf("counsel_appearance must NOT permit %q", notWant)
		}
	}

	if !r.IntraExchangeOnly {
		t.Error("counsel_appearance must be intra-exchange-only")
	}

	if len(r.RequiredSignerRoles) != 1 || r.RequiredSignerRoles[0] != "court_clerk" {
		t.Errorf("counsel_appearance signer drift: want [court_clerk], got %v",
			r.RequiredSignerRoles)
	}

	if r.MinSignerCosigners < 1 {
		t.Errorf("counsel_appearance must require ≥1 court_clerk cosigner; got %d",
			r.MinSignerCosigners)
	}

	bprFound := false
	for _, c := range r.RequiredCredentials {
		if c == "bpr_number" {
			bprFound = true
			break
		}
	}
	if !bprFound {
		t.Errorf("counsel_appearance must require bpr_number credential; got %v",
			r.RequiredCredentials)
	}
}

// TestCosignatureRules_CounselAppearance_FunctionalDefenseCounsel
// emulates the canonical scenario: a Davidson defense attorney
// files an appearance on a criminal case; a Davidson court_clerk
// cosigns. The bpr_number credential is the attorney-licensing
// surface.
func TestCosignatureRules_CounselAppearance_FunctionalDefenseCounsel(t *testing.T) {
	r, _ := MustCosignaturePolicy().Lookup("counsel_appearance")

	// Defense attorney is permitted.
	if !r.PermitsFilerRole(schemas.FilerRoleDefenseCounsel) {
		t.Fatal("defense_counsel must be permitted to file counsel_appearance")
	}
	// court_clerk is the cosigner.
	hasClerk := false
	for _, role := range r.RequiredSignerRoles {
		if role == "court_clerk" {
			hasClerk = true
			break
		}
	}
	if !hasClerk {
		t.Error("court_clerk must be in RequiredSignerRoles")
	}
}

// TestCosignatureRules_CounselAppearance_FunctionalProsecutorAppearance
// emulates a prosecutor filing an appearance on behalf of the
// State (binding_id of the State).
func TestCosignatureRules_CounselAppearance_FunctionalProsecutorAppearance(t *testing.T) {
	r, _ := MustCosignaturePolicy().Lookup("counsel_appearance")
	if !r.PermitsFilerRole(schemas.FilerRoleProsecutor) {
		t.Error("prosecutor must be permitted to file counsel_appearance")
	}
}
