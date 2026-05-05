/*
FILE PATH: internal/testfixtures/davidsonlegacy/cosignature_mix.go

DESCRIPTION:

	Test-only fixture: the legacy v1.6 Davidson cosignature-mix
	policy that pairs with the legacy 6-role catalog in
	role_catalog.go. NOT a production deployment.

	Production TN counties use the simplified TN trial cosig
	fixture in deployments/tn/trial/cosignature_mix.go (with the
	full §3 motion vocabulary lifted in via motions_3X.go); this
	fixture exists for contract tests that need pre-
	simplification rule shapes.

	The fixture covers a representative slice of the v1.6 dictionary
	event_type space — every shape of rule:

	  - Filer-driven motions (defense_counsel/civil_attorney/
	    prosecutor → court_clerk cosignature, intra-exchange-only,
	    bpr_number required).
	  - Pure ActorSigner events (verdict, final_judgment) with NO
	    AllowedFilerRoles — no filer permitted.
	  - Intra-exchange-only personnel events (judicial_appointment,
	    clerk_appointment, court_reporter_appointment) requiring
	    2 Adjudicator cosignatures.
	  - Cross-exchange-permitted events (case_transfer_outbound,
	    case_transfer_inbound, relay_attestation) with
	    IntraExchangeOnly=false.
	  - Fiduciary filings with letters_of_administration_ref
	    required credential.
	  - Guardian ad litem with appointment_order_ref required.

OVERVIEW:

	CosignatureRules         — slice of CosignatureRule.
	MustCosignaturePolicy    — convenience constructor (panics).

KEY DEPENDENCIES:
  - policy.CosignatureRule / policy.NewInMemoryPolicy.
  - schemas.FilerRole consts.
*/
package davidsonlegacy

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// CosignatureRules is the legacy v1.6 Davidson cosig fixture
// preserved as a test fixture. Production callers use
// deployments/tn/trial.CosignatureRules().
func CosignatureRules() []policy.CosignatureRule {
	return []policy.CosignatureRule{
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
		// Multiple Adjudicator cosignatures.
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

		// ── cross-exchange events (Flag #2 = false) ──────────────
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

// MustCosignaturePolicy returns a policy populated with
// CosignatureRules or panics.
func MustCosignaturePolicy() *policy.InMemoryPolicy {
	p, err := policy.NewInMemoryPolicy(CosignatureRules())
	if err != nil {
		panic(fmt.Sprintf("internal/testfixtures/davidsonlegacy: cosignature policy invalid: %v", err))
	}
	return p
}
