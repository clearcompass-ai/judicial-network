/*
FILE PATH: policy/cosignature_mix_davidson_test.go

DESCRIPTION:
    Tests for the Davidson reference cosignature-mix fixture.
    Pins:
      - Every rule validates structurally.
      - Every FilerRole from the v1.4 dictionary appears at least
        once (the fixture covers the full Tier 2 surface).
      - Pure ActorSigner events (verdict, final_judgment,
        transcript_publication) have no AllowedFilerRoles.
      - Personnel events (judicial_appointment, clerk_appointment,
        court_reporter_appointment) require ≥2 cosigners.
      - Cross-exchange events (case_transfer_*, relay_attestation)
        have IntraExchangeOnly=false (Flag #2).
      - All other events default to IntraExchangeOnly=true.
      - Specific event lookups return expected shapes.
*/
package policy

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── basic invariants ──────────────────────────────────────────────

func TestDavidsonRules_AllValid(t *testing.T) {
	for _, r := range DavidsonRules() {
		if err := validateRule(r); err != nil {
			t.Errorf("davidson rule %q invalid: %v", r.EventType, err)
		}
	}
}

func TestMustDavidsonPolicy_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustDavidsonPolicy panicked: %v", r)
		}
	}()
	p := MustDavidsonPolicy()
	if got := len(p.List()); got == 0 {
		t.Error("Davidson policy should have rules")
	}
}

// ─── coverage of every FilerRole ───────────────────────────────────

func TestDavidsonRules_CoversEveryFilerRole(t *testing.T) {
	want := map[schemas.FilerRole]bool{
		schemas.FilerRoleProsecutor:       false,
		schemas.FilerRoleDefenseCounsel:   false,
		schemas.FilerRoleCivilAttorney:    false,
		schemas.FilerRoleFiduciary:        false,
		schemas.FilerRoleGuardianAdLitem:  false,
	}
	for _, r := range DavidsonRules() {
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

func TestDavidsonRules_PureSignerEventsHaveNoFilers(t *testing.T) {
	pureSigner := []string{"verdict", "final_judgment", "transcript_publication"}
	p := MustDavidsonPolicy()
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

func TestDavidsonRules_PersonnelEventsRequireMultipleCosigners(t *testing.T) {
	personnel := []string{
		"judicial_appointment",
		"clerk_appointment",
		"court_reporter_appointment",
	}
	p := MustDavidsonPolicy()
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

func TestDavidsonRules_CrossExchangeEventsFlagSetCorrectly(t *testing.T) {
	crossExchange := []string{
		"case_transfer_outbound",
		"case_transfer_inbound",
		"relay_attestation",
	}
	p := MustDavidsonPolicy()
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

func TestDavidsonRules_AttorneyFilingsRequireBPR(t *testing.T) {
	attorneyFilings := []string{
		"motion_continuance",
		"motion_summary_judgment",
		"responsive_pleading",
		"motion_state_dismissal",
	}
	p := MustDavidsonPolicy()
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

func TestDavidsonRules_FiduciaryFilingsRequireLetters(t *testing.T) {
	fiduciaryFilings := []string{
		"fiduciary_accounting",
		"asset_disposition_order",
	}
	p := MustDavidsonPolicy()
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

func TestDavidsonRules_GuardianAdLitemRequiresAppointment(t *testing.T) {
	r, err := MustDavidsonPolicy().Lookup("appointment_guardian_ad_litem")
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

func TestDavidsonRules_MotionContinuanceMultipleFilers(t *testing.T) {
	r, err := MustDavidsonPolicy().Lookup("motion_continuance")
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
	// Fiduciary cannot file a motion_continuance per the fixture.
	if r.PermitsFilerRole(schemas.FilerRoleFiduciary) {
		t.Error("motion_continuance must NOT permit fiduciary filer role")
	}
}
