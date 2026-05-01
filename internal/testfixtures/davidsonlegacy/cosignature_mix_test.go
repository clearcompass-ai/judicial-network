/*
FILE PATH: internal/testfixtures/davidsonlegacy/cosignature_mix_test.go

DESCRIPTION:
    Tests for the legacy v1.6 Davidson cosignature-mix fixture.
    Mirrors the original deployments/davidson_county/rules/
    cosignature_mix_test.go invariants.
*/
package davidsonlegacy

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── basic invariants ──────────────────────────────────────────────

func TestCosignatureRules_AllValid(t *testing.T) {
	if _, err := policy.NewInMemoryPolicy(CosignatureRules()); err != nil {
		t.Errorf("legacy davidson cosig rules failed to construct: %v", err)
	}
}

func TestMustCosignaturePolicy_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustCosignaturePolicy panicked: %v", r)
		}
	}()
	if got := len(MustCosignaturePolicy().List()); got == 0 {
		t.Error("legacy davidson cosig policy should have rules")
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
			t.Errorf("FilerRole %q not covered", fr)
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

// ─── cross-exchange events ──────────────────────────────────────────

func TestCosignatureRules_CrossExchangeEventsFlagSetCorrectly(t *testing.T) {
	cross := []string{
		"case_transfer_outbound",
		"case_transfer_inbound",
		"relay_attestation",
	}
	p := MustCosignaturePolicy()
	for _, ev := range cross {
		r, err := p.Lookup(ev)
		if err != nil {
			t.Errorf("%s missing: %v", ev, err)
			continue
		}
		if r.IntraExchangeOnly {
			t.Errorf("%s must be cross-exchange-permitted", ev)
		}
	}
}

// ─── attorney filings: bpr_number required ─────────────────────────

func TestCosignatureRules_AttorneyFilingsRequireBPR(t *testing.T) {
	for _, ev := range []string{
		"motion_continuance",
		"motion_summary_judgment",
		"responsive_pleading",
		"motion_state_dismissal",
	} {
		r, err := MustCosignaturePolicy().Lookup(ev)
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
			t.Errorf("%s must require bpr_number; got %v",
				ev, r.RequiredCredentials)
		}
	}
}

// ─── fiduciary filings: letters_of_administration_ref ──────────────

func TestCosignatureRules_FiduciaryFilingsRequireLetters(t *testing.T) {
	for _, ev := range []string{
		"fiduciary_accounting",
		"asset_disposition_order",
	} {
		r, err := MustCosignaturePolicy().Lookup(ev)
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
			t.Errorf("%s must require letters_of_administration_ref",
				ev)
		}
	}
}

// ─── guardian ad litem ─────────────────────────────────────────────

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
		t.Error("must require appointment_order_ref")
	}
	if !r.PermitsFilerRole(schemas.FilerRoleGuardianAdLitem) {
		t.Error("must permit guardian_ad_litem filer role")
	}
}
