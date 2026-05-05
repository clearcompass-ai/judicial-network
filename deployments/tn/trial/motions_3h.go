/*
FILE PATH: deployments/tn/trial/motions_3h.go

DESCRIPTION:

	v1.8 §3H — Post-Trial / Post-Conviction Motions. Eleven
	event types. All §3H motions require a prior verdict OR
	final_judgment (some require one specifically).

	The prereq Walker treats RequiredAncestor as a satisfy-any
	list — so a single Prereq with both "verdict" and
	"final_judgment" in RequiredAncestor satisfies "either" per
	v1.8 §3H semantics. Stricter "exactly verdict" or "exactly
	final_judgment" prereqs use a single-element list.

	§3H is the largest section. Each motion below carries the
	minimum Hard prereq that v1.8 specifies; time-bounded
	prereqs (e.g., motion_reduction_of_sentence's 120-day
	window) are documented in v1.8 but enforced by the time-
	bound module beyond the prereq Walker — the Walker only
	checks ancestor presence here.
*/
package trial

import (
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// motions3H returns the v1.8 §3H post-trial motions.
func motions3H() []motionSpec {
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
	defenseOnly := []schemas.FilerRole{schemas.FilerRoleDefenseCounsel}

	verdictOrFJ := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"verdict", "final_judgment"},
		Reason:           "§3H post-trial motion requires a prior verdict OR final_judgment on this case root",
	}
	finalJudgmentHard := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"final_judgment"},
		Reason:           "TRCP 59.04 / similar requires a prior final_judgment",
	}
	verdictHard := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"verdict"},
		Reason:           "post-verdict motion requires a prior verdict",
	}
	fjOrDefault := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"final_judgment", "default_judgment"},
		Reason:           "TRCP 55.02 / 60.02 requires a prior final_judgment or default_judgment",
	}

	return []motionSpec{
		// TRCP 59.01 / TRCrP 33.
		{
			EventType:         "motion_new_trial",
			AllowedFilers:     allAdvocates,
			AdditionalPrereqs: []prerequisites.Prereq{verdictOrFJ},
		},
		// TRCP 59.04.
		{
			EventType:         "motion_alter_amend_judgment",
			AllowedFilers:     defenseCivil,
			AdditionalPrereqs: []prerequisites.Prereq{finalJudgmentHard},
		},
		// TRCP 50.02 / TRCrP 29(c).
		{
			EventType:         "motion_renewed_directed_verdict_jnov",
			AllowedFilers:     allAdvocates,
			AdditionalPrereqs: []prerequisites.Prereq{verdictHard},
		},
		// TRCrP 34.
		{
			EventType:         "motion_arrest_of_judgment",
			AllowedFilers:     defensePros,
			AdditionalPrereqs: []prerequisites.Prereq{verdictOrFJ},
		},
		// TRCP 55.02 / 60.02.
		{
			EventType:         "motion_set_aside_relief_from_judgment",
			AllowedFilers:     defenseCivil,
			AdditionalPrereqs: []prerequisites.Prereq{fjOrDefault},
		},
		// TRCrP 35: 120-day window.
		{
			EventType:         "motion_reduction_of_sentence",
			AllowedFilers:     defenseOnly,
			AdditionalPrereqs: []prerequisites.Prereq{finalJudgmentHard},
		},
		// TRCrP 36.1.
		{
			EventType:         "motion_correct_illegal_sentence",
			AllowedFilers:     defenseOnly,
			AdditionalPrereqs: []prerequisites.Prereq{finalJudgmentHard},
		},
		// TRCP 54.04: discretionary costs (civil prevailing party).
		{
			EventType: "motion_discretionary_costs",
			AllowedFilers: []schemas.FilerRole{
				schemas.FilerRoleCivilAttorney,
			},
			AdditionalPrereqs: []prerequisites.Prereq{finalJudgmentHard},
		},
		// T.C.A. § 40-26-105: coram nobis (1-year SOL; trial only).
		{
			EventType:         "petition_coram_nobis",
			AllowedFilers:     defenseOnly,
			AdditionalPrereqs: []prerequisites.Prereq{finalJudgmentHard},
		},
		// T.C.A. § 40-30-101.
		{
			EventType:         "petition_post_conviction_relief",
			AllowedFilers:     defenseOnly,
			AdditionalPrereqs: []prerequisites.Prereq{finalJudgmentHard},
		},
		// Catch-all (Appendix A).
		{
			EventType:           "motion_post_trial_general",
			AllowedFilers:       allAdvocates,
			AdditionalPrereqs:   []prerequisites.Prereq{verdictOrFJ},
			CustomTitleRequired: true,
		},
	}
}
