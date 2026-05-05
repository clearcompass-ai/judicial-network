/*
FILE PATH: deployments/TEMPLATE/rules/prerequisites.go

DESCRIPTION:

	TEMPLATE deployment — prerequisite policy skeleton. The
	skeleton ships ONE event_type (`case_initiated`) — the
	universal bootstrap event with no prereqs — to satisfy
	jurisdiction.Validate's vocabulary cross-check against the
	cosignature mix.

	Real deployments expand to cover their full vocabulary:
	motions (with case_initiated ancestor), judicial outcomes
	(with merits-posture rules), personnel events (with
	authority-scope rules), etc. See deployments/tn/trial/
	prerequisites.go for an 18-event TN trial reference and
	deployments/tn/coa/prerequisites.go for a 10-event TN COA
	reference.

OVERVIEW:

	PrerequisiteRules        — map[event_type][]Prereq.
	MustPrerequisitePolicy   — convenience constructor (panics).
*/
package rules

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
)

// PrerequisiteRules returns the TEMPLATE skeleton vocabulary.
// One event (case_initiated) with no prereqs — the universal
// case-root anchor.
func PrerequisiteRules() map[string][]prerequisites.Prereq {
	return map[string][]prerequisites.Prereq{
		"case_initiated": {},
	}
}

// MustPrerequisitePolicy returns a policy populated with
// PrerequisiteRules or panics.
func MustPrerequisitePolicy() *prerequisites.InMemoryPolicy {
	p, err := prerequisites.NewInMemoryPolicy(PrerequisiteRules())
	if err != nil {
		panic(fmt.Sprintf("TEMPLATE/rules: prereq policy invalid: %v", err))
	}
	return p
}
