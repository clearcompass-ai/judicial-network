/*
FILE PATH: deployments/tn/trial/motions_3b.go

DESCRIPTION:
    v1.8 §3B — Dispositive & Summary Motions. Six event types
    that resolve a case as a matter of law without a merits
    trial.

    Prereq variations beyond the §3 default (Hard case_initiated):
      motion_judgment_on_pleadings  Hard responsive_pleading
                                    (pleadings closed)
      motion_default_judgment       Hard party_binding for the
                                    non-responding party
      every other motion            no additional prereqs

    Filer set varies:
      motion_summary_judgment / motion_judgment_on_pleadings —
        defense+civil (a civil dispositive motion)
      motion_default_judgment —
        defense+civil (the moving plaintiff has civil_attorney;
        a defaulting defendant scenario; either side can move
        for default if the other failed to respond)
      motion_state_dismissal / motion_dismiss_unnecessary_delay —
        prosecutor-only (criminal-side)
      motion_dispositive_general (catch-all) —
        all advocates
*/
package trial

import (
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// motions3B returns the v1.8 §3B dispositive motions.
func motions3B() []motionSpec {
	defenseCivil := []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleCivilAttorney,
	}
	prosOnly := []schemas.FilerRole{schemas.FilerRoleProsecutor}
	allAdvocates := []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleCivilAttorney,
		schemas.FilerRoleProsecutor,
	}

	pleadingsClosed := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"responsive_pleading"},
		Reason:           "motion_judgment_on_pleadings requires pleadings closed (TRCP 12.03)",
	}
	nonRespondingParty := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"party_binding"},
		Reason:           "motion_default_judgment requires party_binding for the non-responding party (TRCP 55)",
	}

	return []motionSpec{
		// TRCP 56.04: no genuine dispute of material fact.
		{
			EventType:     "motion_summary_judgment",
			AllowedFilers: defenseCivil,
		},
		// TRCP 12.03: judgment on the pleadings.
		{
			EventType:         "motion_judgment_on_pleadings",
			AllowedFilers:     defenseCivil,
			AdditionalPrereqs: []prerequisites.Prereq{pleadingsClosed},
		},
		// TRCP 55: opposing party failed to respond.
		{
			EventType:         "motion_default_judgment",
			AllowedFilers:     defenseCivil,
			AdditionalPrereqs: []prerequisites.Prereq{nonRespondingParty},
		},
		// TRCrP 48: prosecutor drops criminal charges.
		{
			EventType:     "motion_state_dismissal",
			AllowedFilers: prosOnly,
		},
		// Speedy-trial / prosecutorial delay dismissal.
		{
			EventType:     "motion_dismiss_unnecessary_delay",
			AllowedFilers: prosOnly,
		},
		// Catch-all (Appendix A).
		{
			EventType:           "motion_dispositive_general",
			AllowedFilers:       allAdvocates,
			CustomTitleRequired: true,
		},
	}
}
