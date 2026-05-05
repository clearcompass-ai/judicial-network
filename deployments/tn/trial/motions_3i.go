/*
FILE PATH: deployments/tn/trial/motions_3i.go

DESCRIPTION:

	v1.8 §3I — Appellate Bridge Motions. Three event types
	that arrange interlocutory or post-judgment appellate review.
	No catch-all in §3I per v1.8.

	Prereqs:
	  motion_interlocutory_appeal             Hard interlocutory_order
	  motion_extraordinary_appeal             §3 default only
	  motion_stay_of_execution_pending_appeal Hard notice_of_appeal

	Filer set: all advocates for every §3I motion (every party
	can move for appellate bridge relief).
*/
package trial

import (
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// motions3I returns the v1.8 §3I appellate-bridge motions.
func motions3I() []motionSpec {
	allAdvocates := []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleCivilAttorney,
		schemas.FilerRoleProsecutor,
	}

	interlocutoryHard := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"interlocutory_order"},
		Reason:           "TRAP 9 interlocutory appeal requires the ruling sought to be appealed",
	}
	noticeOfAppealHard := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"notice_of_appeal"},
		Reason:           "TRCP 62 / TRAP 7 stay pending appeal requires notice_of_appeal",
	}

	return []motionSpec{
		// TRAP 9: trial-judge permission for interlocutory appeal.
		{
			EventType:         "motion_interlocutory_appeal",
			AllowedFilers:     allAdvocates,
			AdditionalPrereqs: []prerequisites.Prereq{interlocutoryHard},
		},
		// TRAP 10: direct request to appellate court.
		{
			EventType:     "motion_extraordinary_appeal",
			AllowedFilers: allAdvocates,
		},
		// TRCP 62 / TRAP 7: stay pending appeal.
		{
			EventType:         "motion_stay_of_execution_pending_appeal",
			AllowedFilers:     allAdvocates,
			AdditionalPrereqs: []prerequisites.Prereq{noticeOfAppealHard},
		},
	}
}
