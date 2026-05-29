/*
FILE PATH: deployments/tn/trial/cosignature_mix.go

DESCRIPTION:

	TN trial-court framework — cosignature-mix policy shared by
	every Tennessee county exchange. Lifted from
	internal/testfixtures/davidsonlegacy/cosignature_mix.go so
	multi-county deployments reuse one fixture.

	The fixture covers a representative slice of the v1.8
	dictionary event_type space — every shape of rule:

	  - Filer-driven motions (defense_counsel/civil_attorney/
	    prosecutor → court_clerk cosignature, intra-exchange-only,
	    bpr_number required).
	  - Pure Signer-only events (verdict, final_judgment) with NO
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

	NOTE: v1.8 actor alignment (drop chief_justice from trial-
	level personnel cosignatures, replace with the appropriate
	sitting-Adjudicator threshold) lands in a follow-on commit.
	Until then, this file mirrors the Davidson source verbatim.

OVERVIEW:

	CosignatureRules         — slice of CosignatureRule.
	MustCosignaturePolicy    — convenience constructor (panics).

KEY DEPENDENCIES:
  - policy.CosignatureRule / policy.NewInMemoryPolicy.
  - schemas.FilerRole consts.
*/
package trial

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// CosignatureRules is the TN trial-court reference cosig fixture
// shared across every county exchange.
func CosignatureRules() []policy.CosignatureRule {
	rules := []policy.CosignatureRule{
		// ── §0 case genesis: case_initiation ─────────────────────
		// Opening a trial-court case. The filer (attorney / pro se)
		// is the primary signer at Signatures[0]; a court_clerk who
		// accepts the filing cosigns intra-exchange. Mirrors the TN
		// Sup Ct's appellate_case_initiation shape. case_initiation is
		// the prereq ANCESTOR every case-lifecycle event requires
		// (motions.go) and has no prereq of its own (prerequisites.go).
		{
			EventType:           "case_initiation",
			RequiredSignerRoles: []string{"court_clerk"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},

		// ── §1 Genesis: counsel_appearance ──────────────────────
		// Per v1.8: defense_counsel / civil_attorney / prosecutor
		// file the appearance; court_clerk cosigns. bpr_number
		// (TN Board of Professional Responsibility) is the
		// attorney-licensing credential.
		{
			EventType: "counsel_appearance",
			AllowedFilerRoles: []schemas.FilerRole{
				schemas.FilerRoleDefenseCounsel,
				schemas.FilerRoleCivilAttorney,
				schemas.FilerRoleProsecutor,
			},
			RequiredSignerRoles: []string{"court_clerk"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
			RequiredCredentials: []string{"bpr_number"},
		},

		// motion_continuance      (§3G; defined in motions_3g.go)
		// motion_summary_judgment (§3B; defined in motions_3b.go)
		// motion_state_dismissal  (§3B; defined in motions_3b.go)

		// ── pleadings (non-motion) ──────────────────────────────
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

		// ── pure Signer-only events (no filer permitted) ─────────
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
		// Per v1.8 §12A: every appointment requires intra-
		// exchange cosignature from sitting Adjudicators within
		// the same exchange. The simplified role catalog has
		// one Adjudicator role (judge); MinSignerCosigners=2
		// means at least two sitting judges must cosign.
		{
			EventType:           "judicial_appointment",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "clerk_appointment",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "court_reporter_appointment",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},

		// ── cross-exchange events (IntraExchangeOnly=false) ──────
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

		// ── Issue #67 Part A — §6 Court Orders ──────────────────
		// Generic court-issued orders (scheduling, interlocutory,
		// protective, warrant). Every entry in this section:
		//   - Signed by a judge (RequiredSignerRoles=[judge]).
		//   - No filer permitted (these are pure Signer-only
		//     judicial acts; the courtroom clerk's role is the
		//     reduction-to-writing, not the legal act).
		//   - Intra-exchange (a TN judge cannot issue an order in
		//     a federal case; cross-exchange would require a
		//     transfer first).
		//   - MinSignerCosigners=1 (one Adjudicator's signature is
		//     authoritative on a single-judge bench; multi-panel
		//     courts can raise this in their bundle).
		{
			EventType:           "scheduling_order",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "interlocutory_order",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "protective_restraining_order",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "warrant_issuance_return",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},

		// ── Issue #67 Part B — §15 Schema Lifecycle ─────────────
		// Governance events that publish, adopt, amend, and
		// deprecate schemas. NETWORK-LEVEL (not case-bound), so:
		//   - RequiredSignerRoles=[judge] (Adjudicator-only;
		//     ministerial clerk-signing would weaken governance)
		//   - MinSignerCosigners=2 (two-judge minimum for any
		//     schema-level change — symmetric with judicial_
		//     appointment / clerk_appointment, the other two
		//     network-level events that require a 2-Adjudicator
		//     panel)
		//   - IntraExchangeOnly=true for publication / amendment /
		//     deprecation (a court's own schemas are governed by
		//     that court's judges)
		//   - IntraExchangeOnly=false for adoption (a court adopts
		//     another network's published schema; the cosignature
		//     can come from any acknowledging judge, with the
		//     adopting exchange identified in the payload).
		{
			EventType:           "schema_publication",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "schema_adoption",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   false, // adoption may reference cross-network publications
		},
		{
			EventType:           "schema_amendment",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "schema_deprecation",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},

		// ── Issue #67 Part C — §16 Network Topology critical 5 ───
		// Federation events: joining the network, mirroring,
		// revoking mirrors, forking, creating divisions.
		// All require senior approval (2-judge minimum); fork
		// requires the strictest 3-judge consensus.
		{
			EventType:           "anchor_registration",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "mirror_creation",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   false, // mirrors target external networks
		},
		{
			EventType:           "mirror_revocation",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   false,
		},
		{
			EventType:           "network_fork",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  3, // network fork is consensus-strict
			IntraExchangeOnly:   false,
		},
		{
			EventType:           "scope_division_creation",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},

		// ── Issue #67 Part D — §14 Crypto & Key Maintenance ─────
		// Continuity events. Routine rotation: 2-judge minimum
		// (institutional change). M-of-N escrow recovery: judge-
		// signed AND the M-of-N escrow shareholders cosign in the
		// payload (ParticipatingDIDs); the cosignature mix tier
		// 1 still requires a judge for log-level authorization.
		{
			EventType:           "institutional_key_rotation",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "mofn_escrow_recovery_execution",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  3, // recovery is consensus-strict
			IntraExchangeOnly:   true,
		},
	}
	// Append every §3A–§3I motion rule. Each motions_3X.go file
	// returns motionSpecs; motions.go converts them to the
	// canonical "filer + court_clerk cosign + bpr_number" shape.
	rules = append(rules, motionCosignatureRules()...)
	return rules
}

// MustCosignaturePolicy returns a policy populated with
// CosignatureRules or panics. Used by every TN county Bundle.
func MustCosignaturePolicy() *policy.InMemoryPolicy {
	p, err := policy.NewInMemoryPolicy(CosignatureRules())
	if err != nil {
		panic(fmt.Sprintf("tn/trial: cosignature policy invalid: %v", err))
	}
	return p
}
