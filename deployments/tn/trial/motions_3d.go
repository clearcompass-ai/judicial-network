/*
FILE PATH: deployments/tn/trial/motions_3d.go

DESCRIPTION:

	v1.8 §3D — Discovery, Spoliation & Protection. Seven event
	types covering TRCP 36 / 37 discovery enforcement, TRCP 26
	protective orders, TRCP 45 subpoena practice, plus the
	catch-all.

	Prereq variations beyond the §3 default (Hard case_initiated):
	  motion_compel_discovery       Advisory discovery_filing
	                                (the request that wasn't
	                                answered)
	  motion_discovery_sanctions    Hard interlocutory_order
	                                (granting discovery — the
	                                order alleged to have been
	                                violated)
	  motion_deem_facts_admitted    Advisory discovery_filing
	                                (the Requests for Admission
	                                that weren't responded to)

	Filer set: all advocates for every §3D motion (criminal +
	civil discovery practice both apply).
*/
package trial

import (
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// motions3D returns the v1.8 §3D discovery motions.
func motions3D() []motionSpec {
	allAdvocates := []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleCivilAttorney,
		schemas.FilerRoleProsecutor,
	}

	discoveryFilingAdvisory := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeAdvisory,
		RequiredAncestor: []string{"discovery_filing"},
		Reason:           "advisory: the request that was not adequately answered should appear on the case root",
	}
	interlocutoryOrderHard := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"interlocutory_order"},
		Reason:           "motion_discovery_sanctions requires a prior discovery-compelling interlocutory_order (TRCP 37.02)",
	}

	return []motionSpec{
		// TRCP 37.01 / TRCrP 16: compel discovery.
		{
			EventType:         "motion_compel_discovery",
			AllowedFilers:     allAdvocates,
			AdditionalPrereqs: []prerequisites.Prereq{discoveryFilingAdvisory},
		},
		// TRCP 37.02: sanctions for failure to obey a discovery order.
		{
			EventType:         "motion_discovery_sanctions",
			AllowedFilers:     allAdvocates,
			AdditionalPrereqs: []prerequisites.Prereq{interlocutoryOrderHard},
		},
		// TRCP 34A.02: spoliation sanctions.
		{
			EventType:     "motion_spoliation_sanctions",
			AllowedFilers: allAdvocates,
		},
		// TRCP 36: deem facts admitted.
		{
			EventType:         "motion_deem_facts_admitted",
			AllowedFilers:     allAdvocates,
			AdditionalPrereqs: []prerequisites.Prereq{discoveryFilingAdvisory},
		},
		// TRCP 26.03: protective order.
		{
			EventType:     "motion_protective_order",
			AllowedFilers: allAdvocates,
		},
		// TRCP 45.02: quash subpoena.
		{
			EventType:     "motion_quash_subpoena",
			AllowedFilers: allAdvocates,
		},
		// Catch-all (Appendix A).
		{
			EventType:           "motion_discovery_general",
			AllowedFilers:       allAdvocates,
			CustomTitleRequired: true,
		},
	}
}
