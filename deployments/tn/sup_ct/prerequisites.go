/*
FILE PATH: deployments/tn/sup_ct/prerequisites.go

DESCRIPTION:
    Tennessee Supreme Court — prerequisite policy. Vocabulary
    matches the cosignature fixture (11 events) so
    jurisdiction.Validate accepts the Bundle at boot.

    Categories:
      Appellate root        Advisory notice_of_appeal (race
                            tolerance for cross-network events).
      Opinion / participation Hard appellate_root ancestor.
      Disposition           Hard appellate_root + Hard merits
                            opinion ancestor.
      Remand                Advisory notice_of_appeal.
      Revocation (§12C)     Hard appointment ancestor — the
                            Signer being revoked must already
                            hold authority. Cross-exchange.
      Personnel             Authority-scope rules (Hard).
      Topology              No prereqs.
*/
package sup_ct

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
)

// PrerequisiteRules returns the closed-set TN Sup Ct
// prerequisite vocabulary.
func PrerequisiteRules() map[string][]prerequisites.Prereq {
	noticeOfAppealAdvisory := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeAdvisory,
		RequiredAncestor: []string{"notice_of_appeal"},
		Reason:           "appellate root advisory: notice_of_appeal on lower-court side may not yet be visible",
	}
	appellateRootHard := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"appellate_case_initiation"},
		Reason:           "appellate event requires an appellate_case_initiation ancestor on this case root",
	}
	meritsOpinionHard := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"appellate_opinion_publication"},
		Reason:           "appellate_disposition requires a merits-level appellate_opinion_publication on this case root",
	}
	appointmentAncestorHard := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"judicial_appointment"},
		Reason:           "authority_revocation_disciplinary requires a prior appointment for the Signer being revoked (v1.8 §12C)",
	}

	return map[string][]prerequisites.Prereq{
		"appellate_case_initiation":       {noticeOfAppealAdvisory},
		"appellate_opinion_publication":   {appellateRootHard},
		"appellate_opinion_participation": {appellateRootHard},
		"appellate_disposition":           {appellateRootHard, meritsOpinionHard},
		"remand_affirmance": {{
			Mode:             prerequisites.PrereqModeAdvisory,
			RequiredAncestor: []string{"notice_of_appeal"},
			Reason:           "remand_affirmance advisory: notice_of_appeal on lower-court side may not yet be visible",
		}},

		// §12C cross-exchange revocation. The walker enforces only
		// the local "appointment ancestor" check; the cosig
		// fixture enforces the cross-exchange Justice quorum.
		"authority_revocation_disciplinary": {appointmentAncestorHard},

		// Personnel events at the Sup Ct.
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

		// Topology events: no prereqs.
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
		panic(fmt.Sprintf("tn/sup_ct: prereq policy invalid: %v", err))
	}
	return p
}
