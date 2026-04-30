/*
FILE PATH: policy/cosignature_mix_davidson.go

DESCRIPTION:
    Reference cosignature-mix policy for the Davidson County
    deployment. Production deployments load their own JSON file but
    typically start from this template.

    The fixture covers a representative slice of the v1.4 dictionary's
    event_type space — enough to exercise every shape of rule:

      - Filer-driven motions (defense_counsel/civil_attorney/prosecutor →
        court_clerk cosignature, intra-exchange-only,
        bpr_number required).
      - Pure ActorSigner events (verdict, final_judgment) with NO
        AllowedFilerRoles — no filer permitted.
      - Intra-exchange-only personnel events (judicial_appointment,
        clerk_appointment) requiring multiple Adjudicator
        cosignatures.
      - Cross-exchange-permitted events (case_transfer_outbound,
        relay_attestation) with IntraExchangeOnly=false.
      - Fiduciary filings (fiduciary_accounting,
        asset_disposition_order) with letters_of_administration_ref
        required credential.
      - Guardian ad litem appointment-driven submissions with
        appointment_order_ref required.

    Every Tier 2 role from the v1.4 dictionary appears at least once.

OVERVIEW:
    DavidsonRules         — slice of CosignatureRule.
    MustDavidsonPolicy    — convenience constructor (panics on error).

KEY DEPENDENCIES:
    - policy/cosignature_mix.go (CosignatureRule, NewInMemoryPolicy).
    - schemas/capacity.go (FilerRole consts).
*/
package policy

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// DavidsonRules is the reference policy fixture.
func DavidsonRules() []CosignatureRule {
	return []CosignatureRule{
		// ── attorney-driven filings ──────────────────────────────
		{
			EventType: "motion_continuance",
			AllowedFilerRoles: []schemas.FilerRole{
				schemas.FilerRoleDefenseCounsel,
				schemas.FilerRoleCivilAttorney,
				schemas.FilerRoleProsecutor,
			},
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
			RequiredCredentials: []string{"bpr_number"},
		},
		{
			EventType: "motion_summary_judgment",
			AllowedFilerRoles: []schemas.FilerRole{
				schemas.FilerRoleDefenseCounsel,
				schemas.FilerRoleCivilAttorney,
			},
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
			RequiredCredentials: []string{"bpr_number"},
		},
		{
			EventType: "responsive_pleading",
			AllowedFilerRoles: []schemas.FilerRole{
				schemas.FilerRoleDefenseCounsel,
				schemas.FilerRoleCivilAttorney,
			},
			RequiredSignerRoles: []string{"court_clerk"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
			RequiredCredentials: []string{"bpr_number"},
		},

		// ── prosecutor-driven ────────────────────────────────────
		{
			EventType: "motion_state_dismissal",
			AllowedFilerRoles: []schemas.FilerRole{
				schemas.FilerRoleProsecutor,
			},
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
			RequiredCredentials: []string{"bpr_number"},
		},

		// ── fiduciary filings ────────────────────────────────────
		{
			EventType: "fiduciary_accounting",
			AllowedFilerRoles: []schemas.FilerRole{
				schemas.FilerRoleFiduciary,
			},
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
			RequiredCredentials: []string{"letters_of_administration_ref"},
		},
		{
			EventType: "asset_disposition_order",
			AllowedFilerRoles: []schemas.FilerRole{
				schemas.FilerRoleFiduciary,
			},
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
			RequiredCredentials: []string{"letters_of_administration_ref"},
		},

		// ── guardian ad litem ────────────────────────────────────
		{
			EventType: "appointment_guardian_ad_litem",
			AllowedFilerRoles: []schemas.FilerRole{
				schemas.FilerRoleGuardianAdLitem,
			},
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
			RequiredCredentials: []string{"appointment_order_ref"},
		},

		// ── pure ActorSigner events (no filer permitted) ─────────
		{
			EventType:           "verdict",
			RequiredSignerRoles: []string{"judge"},
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "final_judgment",
			RequiredSignerRoles: []string{"judge"},
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "transcript_publication",
			RequiredSignerRoles: []string{"court_reporter"},
			IntraExchangeOnly:   true,
		},

		// ── intra-exchange personnel events ──────────────────────
		// Multiple Adjudicator cosignatures (Flag #3 will refine
		// the threshold per-event; default is 2 here).
		{
			EventType:           "judicial_appointment",
			RequiredSignerRoles: []string{"judge", "chief_justice"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "clerk_appointment",
			RequiredSignerRoles: []string{"judge", "chief_justice"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "court_reporter_appointment",
			RequiredSignerRoles: []string{"judge", "chief_justice"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},

		// ── cross-exchange events (Flag #2 — false) ──────────────
		// Case transfers and relay attestations span exchanges.
		// The cosigner roles are drawn from EITHER exchange.
		{
			EventType:           "case_transfer_outbound",
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   false,
		},
		{
			EventType:           "case_transfer_inbound",
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   false,
		},
		{
			EventType:           "relay_attestation",
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   false,
		},
	}
}

// MustDavidsonPolicy returns a policy populated with DavidsonRules
// or panics. Convenience for tests and the default boot path.
func MustDavidsonPolicy() *InMemoryPolicy {
	p, err := NewInMemoryPolicy(DavidsonRules())
	if err != nil {
		panic(fmt.Sprintf("policy/cosignature_mix: Davidson fixture invalid: %v", err))
	}
	return p
}
