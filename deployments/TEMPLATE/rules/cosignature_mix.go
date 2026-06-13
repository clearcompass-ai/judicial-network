/*
FILE PATH: deployments/TEMPLATE/rules/cosignature_mix.go

DESCRIPTION:

	TEMPLATE deployment — cosignature-mix policy skeleton. The
	skeleton ships ONE rule for `case_initiation` (the only event
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

	"github.com/baseproof/tooling/libs/policy"

	"github.com/clearcompass-ai/judicial-network/deployments/platformkinds"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// CosignatureRules returns the TEMPLATE cosig fixture. ONE rule
// for the universally required `case_initiation` event; replace
// with your jurisdiction's actual policy.
func CosignatureRules() []policy.CosignatureRule {
	rules := []policy.CosignatureRule{
		{
			EventType:           "case_initiation",
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
	}

	// ── PLATFORM REGISTRY KINDS (rc10) — shared mixes ─────────────
	rules = append(rules, platformkinds.CosignatureRules()...)
	return rules
}

// MustCosignaturePolicy returns a policy populated with
// CosignatureRules or panics.
func MustCosignaturePolicy() *policy.InMemoryPolicy {
	p, err := policy.NewInMemoryPolicy(CosignatureRules(), policy.WithKnownFilerRoles(schemas.KnownFilerRoles()...))
	if err != nil {
		panic(fmt.Sprintf("TEMPLATE/rules: cosignature policy invalid: %v", err))
	}
	return p
}
