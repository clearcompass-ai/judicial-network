/*
FILE PATH: deployments/tn/trial/prerequisites.go

DESCRIPTION:

	TN trial-court framework — prerequisite policy shared by
	every Tennessee county exchange. Lifted from
	internal/testfixtures/davidsonlegacy/prerequisites.go.

	The 18 event_types match the cosignature policy's vocabulary
	plus two structural anchors (case_initiation, hearing) that
	are not subject to Filer cosignature.

	Categories:
	  - case-lifecycle filings (motions, pleadings, accountings):
	    require a case_initiation ancestor in the subtree.
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

	prerequisites "github.com/clearcompass-ai/attesta-tools/libs/prereq"
)

// PrerequisiteRules returns the closed-set TN trial prerequisite
// vocabulary. Shared by every TN county exchange. Edit with
// care: changing this set changes the network's accept/reject
// contract for every TN trial court.
//
// caseInitAncestor (the shared Hard prereq used by every motion)
// lives in motions.go so the §3A–§3I motion files can reuse it
// without import gymnastics.
func PrerequisiteRules() map[string][]prerequisites.Prereq {
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
		RequiredAncestor: []string{"hearing_convened_concluded"},
		Reason:           "transcript_publication advisory: hearing should precede transcript",
	}

	rules := map[string][]prerequisites.Prereq{
		// ── §1 Genesis: counsel_appearance ──────────────────────
		// Hard: case_initiation. The Advisory binding_id-per-
		// represents check is enforced by the verifier-level
		// payload walk (the prereq Walker does not have a
		// per-payload "for each X in Y" primitive in v0.5.0;
		// the appearance entry's Hard prereq is the case root).
		"counsel_appearance": {caseInitAncestor},

		// motion_* prereqs live in motions_3X.go files via the
		// motionPrerequisiteRules() helper (merged below).

		// ── §2 Pleadings (non-motion) ───────────────────────────
		"responsive_pleading": {caseInitAncestor},

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
		"case_initiation": {},

		// ── hearing: posture event, requires case_initiation ─────
		"hearing_convened_concluded": {caseInitAncestor},

		// ── Issue #67 Part A — §6 Court Orders ──────────────────
		//
		// Each order's prereq mirrors dictionary §6:
		//
		//   scheduling_order             → Hard case_initiation
		//   protective_restraining_order → Hard case_initiation
		//   warrant_issuance_return      → Hard case_initiation
		//   interlocutory_order          → Hard prior motion_*
		//                                  (OR over the full §3A-3I
		//                                  motion catalog)
		"scheduling_order":             {caseInitAncestor},
		"protective_restraining_order": {caseInitAncestor},
		"warrant_issuance_return":      {caseInitAncestor},
		"interlocutory_order": {{
			Mode:             prerequisites.PrereqModeHard,
			RequiredAncestor: motionEventNames(),
			Reason:           "interlocutory_order rules on a prior motion (dictionary §6)",
		}},

		// ── Issue #67 Part B — §15 Schema Lifecycle ──────────────
		//
		// Per dictionary §15:
		//
		//   schema_publication  → origin event (no prereqs); a
		//                         versioned successor sets the
		//                         predecessor reference in the
		//                         payload (PredecessorPos), which
		//                         the verifier checks against the
		//                         log — not the prereq walker.
		//   schema_adoption     → Hard prior schema_publication
		//   schema_amendment    → Hard prior schema_publication
		//                         (for the predecessor)
		//   schema_deprecation  → Hard prior schema_publication
		//
		// schema_adoption / amendment / deprecation share the
		// SAME ancestor list (the prior schema_publication entry
		// on the log). One Prereq encodes that contract.
		"schema_publication": {},
		"schema_adoption": {{
			Mode:             prerequisites.PrereqModeHard,
			RequiredAncestor: []string{"schema_publication"},
			Reason:           "schema_adoption requires prior schema_publication of the target schema (dictionary §15)",
		}},
		"schema_amendment": {{
			Mode:             prerequisites.PrereqModeHard,
			RequiredAncestor: []string{"schema_publication"},
			Reason:           "schema_amendment requires prior schema_publication of the predecessor (dictionary §15)",
		}},
		"schema_deprecation": {{
			Mode:             prerequisites.PrereqModeHard,
			RequiredAncestor: []string{"schema_publication"},
			Reason:           "schema_deprecation requires prior schema_publication of the target (dictionary §15)",
		}},

		// ── Issue #67 Part C — §16 Network Topology critical 5 ──
		//
		// Per dictionary §16:
		//   anchor_registration:    origin event (no prereqs)
		//   network_fork:           origin event (no prereqs)
		//   mirror_creation:        Hard prior entry being
		//                           mirrored (delegation/schema)
		//   mirror_revocation:      Hard prior mirror_creation
		//   scope_division_creation: Hard prior exchange_onboarding
		//                            (the parent exchange must exist)
		//                            — until §11 lands we conservatively
		//                            require no prereq (origin-like)
		//                            so a court's first division can
		//                            land alongside its onboarding.
		"anchor_registration":     {},
		"network_fork":            {},
		"scope_division_creation": {},
		"mirror_creation": {{
			Mode: prerequisites.PrereqModeHard,
			RequiredAncestor: []string{
				"judicial_delegation",
				"schema_publication",
			},
			Reason: "mirror_creation requires prior entry being mirrored (delegation or schema, per dictionary §16)",
		}},
		"mirror_revocation": {{
			Mode:             prerequisites.PrereqModeHard,
			RequiredAncestor: []string{"mirror_creation"},
			Reason:           "mirror_revocation requires prior mirror_creation",
		}},
	}

	// Merge every §3A–§3I motion's prereqs (Hard case_initiation
	// ancestor + the section file's AdditionalPrereqs).
	for evt, prereqs := range motionPrerequisiteRules() {
		rules[evt] = prereqs
	}
	return rules
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
