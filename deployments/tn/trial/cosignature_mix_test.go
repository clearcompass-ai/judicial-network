/*
FILE PATH: deployments/tn/trial/cosignature_mix_test.go

DESCRIPTION:
    Tests for the TN trial cosignature-mix fixture. Lifted from
    deployments/davidson_county/rules/cosignature_mix_test.go and
    re-scoped to the shared TN trial framework. Pins:
      - Every rule validates structurally (via NewInMemoryPolicy).
      - Every FilerRole from the v1.8 dictionary appears at least
        once (the fixture covers the full Filer surface).
      - Pure Signer-only events have no AllowedFilerRoles.
      - Personnel events require ≥2 cosigners.
      - Cross-exchange events have IntraExchangeOnly=false.
      - Specific event lookups return expected shapes.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── basic invariants ──────────────────────────────────────────────

func TestCosignatureRules_AllValid(t *testing.T) {
	if _, err := policy.NewInMemoryPolicy(CosignatureRules()); err != nil {
		t.Errorf("TN trial cosig rules failed to construct: %v", err)
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
		t.Error("TN trial cosig policy should have rules")
	}
}

func TestMustCosignaturePolicy_IndependentCalls(t *testing.T) {
	a := MustCosignaturePolicy()
	b := MustCosignaturePolicy()
	if a == b {
		t.Error("MustCosignaturePolicy should return a fresh policy per call")
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
			t.Errorf("FilerRole %q not covered by any TN trial rule", fr)
		}
	}
}

// ─── pure Signer-only events ───────────────────────────────────────

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

// ─── cross-exchange events: IntraExchangeOnly=false ────────────────

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

// TestCosignatureRules_ExpectedCount pins the rule count so an
// accidental addition / deletion shows up in CI. Total = 17 base
// (16 + counsel_appearance) + every §3 motion currently declared.
func TestCosignatureRules_ExpectedCount(t *testing.T) {
	const baseRules = 17
	want := baseRules + len(motionCosignatureRules())
	if got := len(CosignatureRules()); got != want {
		t.Errorf("TN trial cosig rule count: want %d, got %d", want, got)
	}
}

// ─── v1.8 actor simplification: no chief_justice ──────────────────

// TestCosignatureRules_NoNonV18Roles guarantees no non-v1.8 role
// names slip into the cosig fixture. The simplified TN trial role
// catalog has 3 names: judge, court_clerk, court_reporter. Any
// other RequiredSignerRoles entry indicates drift.
func TestCosignatureRules_NoNonV18Roles(t *testing.T) {
	allowed := map[string]bool{
		"judge":          true,
		"court_clerk":    true,
		"court_reporter": true,
	}
	for _, r := range CosignatureRules() {
		for _, role := range r.RequiredSignerRoles {
			if !allowed[role] {
				t.Errorf("rule %q references non-v1.8 role %q",
					r.EventType, role)
			}
		}
	}
}

// TestCosignatureRules_PersonnelEventsJudgeOnly pins that the
// personnel events (judicial_appointment, clerk_appointment,
// court_reporter_appointment) require ONLY judge cosignatures —
// chief_justice has been retired per the v1.8 simplification.
func TestCosignatureRules_PersonnelEventsJudgeOnly(t *testing.T) {
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
		if len(r.RequiredSignerRoles) != 1 || r.RequiredSignerRoles[0] != "judge" {
			t.Errorf("%s RequiredSignerRoles drift: want [judge], got %v",
				ev, r.RequiredSignerRoles)
		}
		if r.MinSignerCosigners < 2 {
			t.Errorf("%s must require ≥2 cosigners (intra-exchange judges); got %d",
				ev, r.MinSignerCosigners)
		}
	}
}
