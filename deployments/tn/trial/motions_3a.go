/*
FILE PATH: deployments/tn/trial/motions_3a.go

DESCRIPTION:
    v1.8 §3A — Jurisdictional & Pleading Motions. Nine event
    types covering TRCP/TRCrP Rule 12 challenges, Bill of
    Particulars, and Rule 15 amendments, plus the catch-all.

    All §3A motions share the §3 default cosig shape (filer +
    court_clerk cosign + bpr_number) and the Hard case_initiated
    ancestor prereq — no §3A motion has additional prereqs
    beyond the default per v1.8.

    The Filer set varies by motion:
      - Defense / civil + (sometimes) prosecutor for civil-side
        challenges (jurisdiction, process defects, failure to
        state claim, Rule 12.05 more definite, Rule 15 amend).
      - Defense + prosecutor for criminal-side challenges
        (charging defect, no probable cause).
      - Defense / civil for the strike motion (TRCP 12.06).

    Catch-all (motion_pleading_general) carries the same shape
    plus CustomTitleRequired=true.
*/
package trial

import "github.com/clearcompass-ai/judicial-network/schemas"

// motions3A returns the v1.8 §3A pleading motions.
func motions3A() []motionSpec {
	defenseCivil := []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleCivilAttorney,
	}
	defensePros := []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleProsecutor,
	}
	allAdvocates := []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleCivilAttorney,
		schemas.FilerRoleProsecutor,
	}

	return []motionSpec{
		// TRCP 12.02(1)–(3): subject matter, personal,
		// or geographic-venue jurisdiction.
		{
			EventType:     "motion_dismiss_jurisdiction",
			AllowedFilers: defenseCivil,
		},
		// TRCP 12.02(4)–(5): insufficiency of process / service.
		{
			EventType:     "motion_dismiss_process_defects",
			AllowedFilers: defenseCivil,
		},
		// TRCP 12.02(6): no legal remedy on the alleged facts.
		{
			EventType:     "motion_dismiss_failure_to_state_claim",
			AllowedFilers: defenseCivil,
		},
		// Criminal: defect in institution of prosecution / fatal
		// error in indictment, presentment, or information.
		{
			EventType:     "motion_dismiss_charging_defect",
			AllowedFilers: defensePros,
		},
		// General Sessions criminal preliminary hearing oral
		// motion to dismiss before bind-over to Grand Jury.
		{
			EventType:     "motion_dismiss_no_probable_cause",
			AllowedFilers: defensePros,
		},
		// TRCP 12.05 / TRCrP 7(c): more definite statement /
		// Bill of Particulars.
		{
			EventType:     "motion_more_definite_statement",
			AllowedFilers: allAdvocates,
		},
		// TRCP 12.06: strike redundant, immaterial, impertinent,
		// or scandalous matter.
		{
			EventType:     "motion_to_strike",
			AllowedFilers: defenseCivil,
		},
		// TRCP 15: amend pleadings (claims, defenses, parties).
		{
			EventType:     "motion_amend_pleadings",
			AllowedFilers: allAdvocates,
		},
		// Catch-all (Appendix A): non-standard pleading motion.
		// custom_title required at the schema layer.
		{
			EventType:           "motion_pleading_general",
			AllowedFilers:       allAdvocates,
			CustomTitleRequired: true,
		},
	}
}
