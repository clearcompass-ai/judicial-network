/*
FILE PATH: deployments/TEMPLATE/rules/cosignature_mix.go

DESCRIPTION:

	TEMPLATE deployment — cosignature-mix policy skeleton. The
	skeleton ships ONE rule for `case_initiated` (the only event
	every Bundle must accept) — the minimum needed for
	jurisdiction.Validate to pass.

	Real deployments expand to cover their full event vocabulary:
	motions, judicial outcomes, personnel events, etc. See
	deployments/tn/trial/cosignature_mix.go for a 16-rule TN trial
	reference and deployments/tn/coa/cosignature_mix.go for a 10-
	rule TN COA reference.

OVERVIEW:

	CosignatureRules         — slice of CosignatureRule.
	MustCosignaturePolicy    — convenience constructor (panics).
*/
package rules

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/policy"
)

// CosignatureRules returns the TEMPLATE cosig fixture. ONE rule
// for the universally required `case_initiated` event; replace
// with your jurisdiction's actual policy.
func CosignatureRules() []policy.CosignatureRule {
	return []policy.CosignatureRule{
		{
			EventType:           "case_initiated",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
	}
}

// MustCosignaturePolicy returns a policy populated with
// CosignatureRules or panics.
func MustCosignaturePolicy() *policy.InMemoryPolicy {
	p, err := policy.NewInMemoryPolicy(CosignatureRules())
	if err != nil {
		panic(fmt.Sprintf("TEMPLATE/rules: cosignature policy invalid: %v", err))
	}
	return p
}
