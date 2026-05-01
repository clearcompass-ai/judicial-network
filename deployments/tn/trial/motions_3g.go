/*
FILE PATH: deployments/tn/trial/motions_3g.go

DESCRIPTION:
    v1.8 §3G — Docket Management & Procedural Logistics. Nine
    event types (8 + 1 catch-all).

    Prereq variations beyond §3 default:
      motion_continuance              Advisory scheduling_order
      motion_substitution_parties     Hard party_binding
      motion_withdraw_counsel         Hard counsel_appearance
      motion_disqualification_recusal Hard judicial_assignment
      others                          §3 default only

    Filer set varies by motion; see per-motion notes.
*/
package trial

import (
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// motions3G returns the v1.8 §3G docket-management motions.
func motions3G() []motionSpec {
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

	scheduleAdvisory := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeAdvisory,
		RequiredAncestor: []string{"scheduling_order"},
		Reason:           "advisory: scheduling_order should set the date being moved (TRCP)",
	}
	partyBindingHard := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"party_binding"},
		Reason:           "motion_substitution_parties requires party_binding for the party being substituted (TRCP 25.01)",
	}
	counselAppearanceHard := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"counsel_appearance"},
		Reason:           "motion_withdraw_counsel requires the requesting attorney's counsel_appearance",
	}
	judicialAssignmentHard := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"judicial_assignment"},
		Reason:           "motion_disqualification_recusal requires judicial_assignment for the targeted Adjudicator (TSCR 10B)",
	}

	return []motionSpec{
		// Continuance: delay a hearing or trial date.
		{
			EventType:         "motion_continuance",
			AllowedFilers:     allAdvocates,
			AdditionalPrereqs: []prerequisites.Prereq{scheduleAdvisory},
		},
		// Consolidation/severance: TRCP 42 / TRCrP 14.
		{EventType: "motion_consolidation_severance", AllowedFilers: allAdvocates},
		// Substitution: TRCP 25.01.
		{
			EventType:         "motion_substitution_parties",
			AllowedFilers:     defenseCivil,
			AdditionalPrereqs: []prerequisites.Prereq{partyBindingHard},
		},
		// Change of venue: TRCrP 21.
		{EventType: "motion_change_of_venue", AllowedFilers: defensePros},
		// Withdraw counsel.
		{
			EventType:         "motion_withdraw_counsel",
			AllowedFilers:     allAdvocates,
			AdditionalPrereqs: []prerequisites.Prereq{counselAppearanceHard},
		},
		// Disqualification / recusal: TSCR 10B.
		{
			EventType:         "motion_disqualification_recusal",
			AllowedFilers:     allAdvocates,
			AdditionalPrereqs: []prerequisites.Prereq{judicialAssignmentHard},
		},
		// Juvenile transfer / DJJ custody.
		{EventType: "motion_juvenile_transfer_custody", AllowedFilers: defensePros},
		// Bond modification (criminal pre-trial).
		{EventType: "motion_bond_modification", AllowedFilers: defensePros},
		// Catch-all (Appendix A).
		{
			EventType:           "motion_procedural_general",
			AllowedFilers:       allAdvocates,
			CustomTitleRequired: true,
		},
	}
}
