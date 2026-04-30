/*
FILE PATH: deployments/tn/coa/prerequisites.go

DESCRIPTION:
    Tennessee Court of Appeals — prerequisite policy. Closed-set
    vocabulary + per-event prereq rules for the COA exchange.
    Vocabulary matches the cosignature policy (10 rules) so
    jurisdiction.Validate accepts the bundle at boot.

    Categories:
      - appellate root bootstrap (appellate_case_initiation):
        no Hard prereq; ADVISORY notice_of_appeal on the
        referenced trial root (cross-network — trial-side
        notice may not be visible yet when COA dockets the
        appeal; v1.8 §7B.1 calls this Advisory by design).
      - opinion events (appellate_opinion_publication,
        appellate_opinion_participation): require an
        appellate_case_initiation ancestor.
      - appellate_disposition: requires a merits-level opinion
        ancestor on this case root (v1.8 §7B.3).
      - remand_affirmance: ADVISORY notice_of_appeal (v1.8 §8).
      - personnel events: authority-scope rules.
      - topology events: no prereqs.

OVERVIEW:
    PrerequisiteRules        — map[event_type][]Prereq.
    MustPrerequisitePolicy   — convenience constructor (panics).

KEY DEPENDENCIES:
    - prerequisites.Prereq / prerequisites.NewInMemoryPolicy.
*/
package coa

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
)

// PrerequisiteRules returns the closed-set TN COA prerequisite
// vocabulary. 10 event types, matching the cosig fixture.
func PrerequisiteRules() map[string][]prerequisites.Prereq {
	noticeOfAppealAdvisory := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeAdvisory,
		RequiredAncestor: []string{"notice_of_appeal"},
		Reason:           "appellate root advisory: notice_of_appeal on trial side may not yet be visible (v1.8 §7B.1)",
	}
	appellateRootHard := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"appellate_case_initiation"},
		Reason:           "appellate event requires an appellate_case_initiation ancestor on this case root",
	}
	meritsOpinionHard := prerequisites.Prereq{
		Mode: prerequisites.PrereqModeHard,
		// v1.8 §7B.3 — disposition requires a merits-level
		// opinion (majority, plurality, per_curiam, memorandum).
		// We approximate via "publication of any opinion" plus
		// a vocabulary check at the verifier; the exact merits-
		// type filter belongs in the AppellateVocabulary
		// payload check, not the prereq walker.
		RequiredAncestor: []string{"appellate_opinion_publication"},
		Reason:           "appellate_disposition requires a merits-level appellate_opinion_publication on this case root",
	}

	return map[string][]prerequisites.Prereq{
		// ── appellate root bootstrap ────────────────────────────
		"appellate_case_initiation": {noticeOfAppealAdvisory},

		// ── opinion events ──────────────────────────────────────
		"appellate_opinion_publication":   {appellateRootHard},
		"appellate_opinion_participation": {appellateRootHard},

		// ── disposition: requires a merits opinion ──────────────
		"appellate_disposition": {appellateRootHard, meritsOpinionHard},

		// ── cross-network: remand back to trial ─────────────────
		// notice_of_appeal Advisory per v1.8 §8 — appellate
		// dispositions may legitimately arrive before the trial-
		// side notice_of_appeal is fully docketed.
		"remand_affirmance": {{
			Mode:             prerequisites.PrereqModeAdvisory,
			RequiredAncestor: []string{"notice_of_appeal"},
			Reason:           "remand_affirmance advisory: notice_of_appeal on trial side may not yet be visible (v1.8 §8)",
		}},

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

		// ── topology events: no prereqs ─────────────────────────
		"case_transfer_inbound":  {},
		"case_transfer_outbound": {},
		"relay_attestation":      {},
	}
}

// MustPrerequisitePolicy returns a policy populated with
// PrerequisiteRules or panics.
func MustPrerequisitePolicy() *prerequisites.InMemoryPolicy {
	p, err := prerequisites.NewInMemoryPolicy(PrerequisiteRules())
	if err != nil {
		panic(fmt.Sprintf("tn/coa: prereq policy invalid: %v", err))
	}
	return p
}
