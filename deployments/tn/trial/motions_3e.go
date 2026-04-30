/*
FILE PATH: deployments/tn/trial/motions_3e.go

DESCRIPTION:
    v1.8 §3E — Trial-Prep & Evidentiary Motions. Five event
    types covering pre-trial evidentiary practice. All §3E
    motions follow the §3 default (Hard case_initiated only).

    Filer set:
      motion_in_limine                       all advocates (civil + criminal)
      motion_suppress                        defense + prosecutor (criminal)
      motion_judicial_notice                 all advocates (TRE 201)
      motion_special_jury_instructions       all advocates (TRCP 51 / TRCrP 30)
      motion_competency_evaluation           defense + prosecutor (criminal)
*/
package trial

import "github.com/clearcompass-ai/judicial-network/schemas"

// motions3E returns the v1.8 §3E trial-prep motions.
func motions3E() []motionSpec {
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
		// Preemptively excludes prejudicial / irrelevant evidence.
		{EventType: "motion_in_limine", AllowedFilers: allAdvocates},
		// Criminal: 4th/5th/6th Amendment exclusion.
		{EventType: "motion_suppress", AllowedFilers: defensePros},
		// TRE 201: ask judge to take judicial notice of a fact.
		{EventType: "motion_judicial_notice", AllowedFilers: allAdvocates},
		// TRCP 51 / TRCrP 30: customized jury instructions.
		{EventType: "motion_special_jury_instructions", AllowedFilers: allAdvocates},
		// TRCrP 8.06: defendant competency to stand trial.
		{EventType: "motion_competency_evaluation", AllowedFilers: defensePros},
	}
}
