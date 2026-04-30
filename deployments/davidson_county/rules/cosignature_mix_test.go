/*
FILE PATH: deployments/davidson_county/rules/cosignature_mix_test.go

DESCRIPTION:
    Tests for the Davidson reference cosignature-mix fixture.
    Lifted (3E.7) from policy/cosignature_mix_davidson_test.go.
    Pins:
      - Every rule validates structurally (via NewInMemoryPolicy).
      - Every FilerRole from the v1.6 dictionary appears at least
        once (the fixture covers the full Tier 2 surface).
      - Pure ActorSigner events have no AllowedFilerRoles.
      - Personnel events require ≥2 cosigners.
      - Cross-exchange events have IntraExchangeOnly=false.
      - Specific event lookups return expected shapes.
*/
package rules

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── basic invariants ──────────────────────────────────────────────

// TestCosignatureRules_AllValid runs every rule through
// NewInMemoryPolicy, which validates each one. A construction
// failure surfaces as a panic in MustCosignaturePolicy; here we
// surface it as a test failure for clearer error messages.
func TestCosignatureRules_AllValid(t *testing.T) {
	if _, err := policy.NewInMemoryPolicy(CosignatureRules()); err != nil {
		t.Errorf("davidson cosig rules failed to construct: %v", err)
	}
}

func TestMustCosignaturePolicy_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustCosignaturePolicy panicked: %v", r)
		}
	}()
	p := MustCosignaturePolicy()
	if got := len(p.List()); got == 0 {
		t.Error("Davidson cosig policy should have rules")
	}
}

// ─── coverage of every FilerRole ───────────────────────────────────

func TestCosignatureRules_CoversEveryFilerRole(t *testing.T) {
	want := map[schemas.FilerRole]bool{
		schemas.FilerRoleProsecutor:      false,
		schemas.FilerRoleDefenseCounsel:  false,
		schemas.FilerRoleCivilAttorney:   false,
		schemas.FilerRoleFiduciary:       false,
		schemas.FilerRoleGuardianAdLitem: false,
	}
	for _, r := range CosignatureRules() {
		for _, fr := range r.AllowedFilerRoles {
			want[fr] = true
		}
	}
	for fr, present := range want {
		if !present {
			t.Errorf("FilerRole %q not covered by any Davidson rule", fr)
		}
	}
}

// ─── pure ActorSigner events ───────────────────────────────────────

func TestCosignatureRules_PureSignerEventsHaveNoFilers(t *testing.T) {
	pureSigner := []string{"verdict", "final_judgment", "transcript_publication"}
	p := MustCosignaturePolicy()
	for _, ev := range pureSigner {
		r, err := p.Lookup(ev)
		if err != nil {
			t.Errorf("%s missing: %v", ev, err)
			continue
		}
		if r.RequiresFiler() {
			t.Errorf("%s must not require a filer; got AllowedFilerRoles=%v",
				ev, r.AllowedFilerRoles)
		}
	}
}

// ─── personnel events: ≥2 cosigners, intra-exchange ────────────────

func TestCosignatureRules_PersonnelEventsRequireMultipleCosigners(t *testing.T) {
	personnel := []string{
		"judicial_appointment",
		"clerk_appointment",
		"court_reporter_appointment",
	}
	p := MustCosignaturePolicy()
	for _, ev := range personnel {
		r, err := p.Lookup(ev)
		if err != nil {
			t.Errorf("%s missing: %v", ev, err)
			continue
		}
		if r.MinSignerCosigners < 2 {
			t.Errorf("%s must require ≥2 cosigners; got %d",
				ev, r.MinSignerCosigners)
		}
		if !r.IntraExchangeOnly {
			t.Errorf("%s must be intra-exchange-only", ev)
		}
	}
}

// ─── cross-exchange events: Flag #2 false ──────────────────────────

func TestCosignatureRules_CrossExchangeEventsFlagSetCorrectly(t *testing.T) {
	crossExchange := []string{
		"case_transfer_outbound",
		"case_transfer_inbound",
		"relay_attestation",
	}
	p := MustCosignaturePolicy()
	for _, ev := range crossExchange {
		r, err := p.Lookup(ev)
		if err != nil {
			t.Errorf("%s missing: %v", ev, err)
			continue
		}
		if r.IntraExchangeOnly {
			t.Errorf("%s must be cross-exchange-permitted (IntraExchangeOnly=false)", ev)
		}
	}
}

// ─── attorney filings: bpr_number required ─────────────────────────

func TestCosignatureRules_AttorneyFilingsRequireBPR(t *testing.T) {
	attorneyFilings := []string{
		"motion_continuance",
		"motion_summary_judgment",
		"responsive_pleading",
		"motion_state_dismissal",
	}
	p := MustCosignaturePolicy()
	for _, ev := range attorneyFilings {
		r, err := p.Lookup(ev)
		if err != nil {
			t.Errorf("%s missing: %v", ev, err)
			continue
		}
		found := false
		for _, c := range r.RequiredCredentials {
			if c == "bpr_number" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s must require bpr_number; RequiredCredentials=%v",
				ev, r.RequiredCredentials)
		}
	}
}

// ─── fiduciary filings: letters_of_administration_ref required ─────

func TestCosignatureRules_FiduciaryFilingsRequireLetters(t *testing.T) {
	fiduciaryFilings := []string{
		"fiduciary_accounting",
		"asset_disposition_order",
	}
	p := MustCosignaturePolicy()
	for _, ev := range fiduciaryFilings {
		r, err := p.Lookup(ev)
		if err != nil {
			t.Errorf("%s missing: %v", ev, err)
			continue
		}
		found := false
		for _, c := range r.RequiredCredentials {
			if c == "letters_of_administration_ref" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s must require letters_of_administration_ref; got %v",
				ev, r.RequiredCredentials)
		}
		if !r.PermitsFilerRole(schemas.FilerRoleFiduciary) {
			t.Errorf("%s must permit fiduciary filer role", ev)
		}
	}
}

// ─── guardian ad litem: appointment_order_ref required ─────────────

func TestCosignatureRules_GuardianAdLitemRequiresAppointment(t *testing.T) {
	r, err := MustCosignaturePolicy().Lookup("appointment_guardian_ad_litem")
	if err != nil {
		t.Fatalf("appointment_guardian_ad_litem missing: %v", err)
	}
	found := false
	for _, c := range r.RequiredCredentials {
		if c == "appointment_order_ref" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("must require appointment_order_ref; got %v", r.RequiredCredentials)
	}
	if !r.PermitsFilerRole(schemas.FilerRoleGuardianAdLitem) {
		t.Errorf("must permit guardian_ad_litem filer role")
	}
}

// ─── motion_continuance permits multiple filer roles ───────────────

func TestCosignatureRules_MotionContinuanceMultipleFilers(t *testing.T) {
	r, err := MustCosignaturePolicy().Lookup("motion_continuance")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	for _, want := range []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleCivilAttorney,
		schemas.FilerRoleProsecutor,
	} {
		if !r.PermitsFilerRole(want) {
			t.Errorf("motion_continuance must permit %q", want)
		}
	}
	if r.PermitsFilerRole(schemas.FilerRoleFiduciary) {
		t.Error("motion_continuance must NOT permit fiduciary filer role")
	}
}
