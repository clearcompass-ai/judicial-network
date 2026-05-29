/*
FILE PATH: deployments/frameworks/clerk_base/prerequisites.go

DESCRIPTION:

	Prerequisite policy for clerk events. Minimal today: most
	clerk events stand alone (a marriage_license_issued has no
	required ancestor). The handful with real prerequisites are
	declared here.

	# Reusable across states

	The same prerequisite rules apply to TN County Clerks, CA
	Court Executive Officers, and federal District Court Clerks.
	State-specific variations would land in state_profile
	overlays — not in this file.
*/
package clerk_base

import (
	prerequisites "github.com/clearcompass-ai/attesta-tools/libs/prereq"
)

// MustPrerequisitePolicy returns the clerk-event prerequisite policy.
//
// Most clerk events stand alone (a marriage_license issuance has no
// required ancestor) so the rule list is empty TODAY. But the Bundle
// validator (jurisdiction.Validate) requires the prerequisite policy's
// vocabulary to match the cosignature mix's event_type set, so we
// register every clerk event_type here with NO rules attached.
//
// When real prereq rules land (e.g. marriage_license_returned must
// reference the issued license), the rule replaces the empty slice
// for that event type.
func MustPrerequisitePolicy() prerequisites.Policy {
	rulesByEvent := make(map[string][]prerequisites.Prereq, len(AllEventTypes()))
	for _, evt := range AllEventTypes() {
		rulesByEvent[evt] = nil
	}
	p, err := prerequisites.NewInMemoryPolicy(rulesByEvent)
	if err != nil {
		panic("clerk_base: prerequisite policy: " + err.Error())
	}
	return p
}
