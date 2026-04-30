/*
FILE PATH: deployments/tn/trial/motions_3c.go

DESCRIPTION:
    v1.8 §3C — Equitable, Provisional & Class Remedies. Four
    event types covering TRCP 65 injunctions, asset attachment,
    TRCP 23 class certification, and the catch-all.

    All §3C motions follow the §3 default: Hard case_initiated
    ancestor only; no additional prereqs.

    Filer set:
      motion_tro_preliminary_injunction — civil-side primarily,
        but prosecutor-permitted for asset-freeze actions in
        criminal/civil-forfeiture cases.
      motion_attachment_receivership — civil-side + prosecutor
        (forfeiture proceedings).
      motion_class_certification — civil_attorney only (class
        actions are a civil-procedure construct; defense_counsel
        does not typically move for class cert; prosecutor
        never).
      motion_equitable_general — all advocates, catch-all.
*/
package trial

import "github.com/clearcompass-ai/judicial-network/schemas"

// motions3C returns the v1.8 §3C equitable motions.
func motions3C() []motionSpec {
	defenseCivil := []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleCivilAttorney,
	}
	civilOnly := []schemas.FilerRole{
		schemas.FilerRoleCivilAttorney,
	}
	allAdvocates := []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleCivilAttorney,
		schemas.FilerRoleProsecutor,
	}

	return []motionSpec{
		// TRCP 65: TRO / preliminary injunction.
		{
			EventType:     "motion_tro_preliminary_injunction",
			AllowedFilers: allAdvocates,
		},
		// Attachment / receivership of property during litigation.
		{
			EventType:     "motion_attachment_receivership",
			AllowedFilers: allAdvocates,
		},
		// TRCP 23.03: certify a lawsuit as a class action.
		{
			EventType:     "motion_class_certification",
			AllowedFilers: civilOnly,
		},
		// Catch-all (Appendix A).
		{
			EventType:           "motion_equitable_general",
			AllowedFilers:       defenseCivil,
			CustomTitleRequired: true,
		},
	}
}
