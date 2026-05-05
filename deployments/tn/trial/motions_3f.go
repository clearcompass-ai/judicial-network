/*
FILE PATH: deployments/tn/trial/motions_3f.go

DESCRIPTION:

	v1.8 §3F — In-Trial Dispositive Motions. Three event types
	that resolve a case mid-trial. All carry the same Advisory
	hearing_convened_concluded prereq (trial-in-progress
	indicator); the prereq is Advisory because not every TN
	deployment writes hearing_convened_concluded reliably mid-
	trial.

	No catch-all in §3F per v1.8.

	Filer set:
	  motion_directed_verdict     defense + civil (civil)
	  motion_judgment_acquittal   defense + prosecutor (criminal)
	  motion_mistrial             all advocates
*/
package trial

import (
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// motions3F returns the v1.8 §3F in-trial dispositive motions.
func motions3F() []motionSpec {
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

	hearingAdvisory := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeAdvisory,
		RequiredAncestor: []string{"hearing_convened_concluded"},
		Reason:           "advisory: §3F motions are filed mid-trial; hearing_convened_concluded should appear",
	}

	return []motionSpec{
		// TRCP 50: civil mid-trial directed verdict.
		{
			EventType:         "motion_directed_verdict",
			AllowedFilers:     defenseCivil,
			AdditionalPrereqs: []prerequisites.Prereq{hearingAdvisory},
		},
		// TRCrP 29: criminal mid-trial judgment of acquittal.
		{
			EventType:         "motion_judgment_acquittal",
			AllowedFilers:     defensePros,
			AdditionalPrereqs: []prerequisites.Prereq{hearingAdvisory},
		},
		// Mistrial — fatal incurable error / extreme prejudice.
		{
			EventType:         "motion_mistrial",
			AllowedFilers:     allAdvocates,
			AdditionalPrereqs: []prerequisites.Prereq{hearingAdvisory},
		},
	}
}
