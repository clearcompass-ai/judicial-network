/*
FILE PATH: deployments/tn/trial/prerequisites.go

DESCRIPTION:
    TN trial-court framework — prerequisite policy shared by
    every Tennessee county exchange. Lifted from
    deployments/davidson_county/rules/prerequisites.go.

    The 18 event_types match the cosignature policy's vocabulary
    plus two structural anchors (case_initiated, hearing) that
    are not subject to Filer cosignature.

    Categories:
      - case-lifecycle filings (motions, pleadings, accountings):
        require a case_initiated ancestor in the subtree.
      - judicial outcomes (verdict, final_judgment): require a
        responsive_pleading, motion_state_dismissal, or
        motion_summary_judgment in the subtree (some merits
        posture before judgment).
      - personnel events (judicial_appointment, clerk_appointment,
        court_reporter_appointment): require the primary signer
        to hold the matching authority scope.
      - cross-exchange events (case_transfer_*, relay_attestation):
        no prereqs — transfers are bootstrap-friendly.
      - transcript_publication: ADVISORY ancestor (the dictionary
        recommends but does not require a hearing event).

    NOTE: v1.8 vocabulary expansion (the ~50 §3A-§3I motion event
    types and the §11–§16 lifecycle events) lands in a follow-on
    commit. This file pins the current closed set; the cleanup
    pass adds the full v1.8 dictionary.

OVERVIEW:
    PrerequisiteRules        — map[event_type][]Prereq.
    MustPrerequisitePolicy   — convenience constructor (panics).

KEY DEPENDENCIES:
    - prerequisites.Prereq / prerequisites.NewInMemoryPolicy.
*/
package trial

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
)

// PrerequisiteRules returns the closed-set TN trial prerequisite
// vocabulary. Shared by every TN county exchange. Edit with
// care: changing this set changes the network's accept/reject
// contract for every TN trial court.
func PrerequisiteRules() map[string][]prerequisites.Prereq {
	caseInitAncestor := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"case_initiated"},
		Reason:           "every case-lifecycle event requires a case_initiated ancestor",
	}
	meritsPostureAncestor := prerequisites.Prereq{
		Mode: prerequisites.PrereqModeHard,
		RequiredAncestor: []string{
			"responsive_pleading",
			"motion_state_dismissal",
			"motion_summary_judgment",
		},
		Reason: "judgment requires a merits-posture event in the subtree",
	}
	hearingAdvisory := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeAdvisory,
		RequiredAncestor: []string{"hearing"},
		Reason:           "transcript_publication advisory: hearing should precede transcript",
	}

	return map[string][]prerequisites.Prereq{
		// ── attorney-driven filings ──────────────────────────────
		"motion_continuance":      {caseInitAncestor},
		"motion_summary_judgment": {caseInitAncestor},
		"responsive_pleading":     {caseInitAncestor},

		// ── prosecutor-driven ────────────────────────────────────
		"motion_state_dismissal": {caseInitAncestor},

		// ── fiduciary filings ────────────────────────────────────
		"fiduciary_accounting":    {caseInitAncestor},
		"asset_disposition_order": {caseInitAncestor},

		// ── guardian ad litem ────────────────────────────────────
		"appointment_guardian_ad_litem": {caseInitAncestor},

		// ── judicial outcomes (Hard merits-posture rule) ────────
		"verdict":        {caseInitAncestor, meritsPostureAncestor},
		"final_judgment": {caseInitAncestor, meritsPostureAncestor},

		// ── transcript_publication: Advisory hearing ancestor ───
		"transcript_publication": {caseInitAncestor, hearingAdvisory},

		// ── personnel events: authority-scope rules ─────────────
		"judicial_appointment": {{
			Mode:              prerequisites.PrereqModeHard,
			RequiredAuthority: "judicial_appointment_authority",
			Reason:            "judicial_appointment requires judicial_appointment_authority",
		}},
		"clerk_appointment": {{
			Mode:              prerequisites.PrereqModeHard,
			RequiredAuthority: "clerk_appointment_authority",
			Reason:            "clerk_appointment requires clerk_appointment_authority",
		}},
		"court_reporter_appointment": {{
			Mode:              prerequisites.PrereqModeHard,
			RequiredAuthority: "court_reporter_appointment_authority",
			Reason:            "court_reporter_appointment requires court_reporter_appointment_authority",
		}},

		// ── cross-exchange events: no prereqs ───────────────────
		"case_transfer_outbound": {},
		"case_transfer_inbound":  {},
		"relay_attestation":      {},

		// ── case bootstrap: anchor of the subtree, no prereq ────
		"case_initiated": {},

		// ── hearing: posture event, requires case_initiated ─────
		"hearing": {caseInitAncestor},
	}
}

// MustPrerequisitePolicy returns a policy populated with
// PrerequisiteRules or panics. Used by every TN county Bundle.
func MustPrerequisitePolicy() *prerequisites.InMemoryPolicy {
	p, err := prerequisites.NewInMemoryPolicy(PrerequisiteRules())
	if err != nil {
		panic(fmt.Sprintf("tn/trial: prereq policy invalid: %v", err))
	}
	return p
}
