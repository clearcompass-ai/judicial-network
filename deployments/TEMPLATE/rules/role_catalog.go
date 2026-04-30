/*
FILE PATH: deployments/TEMPLATE/rules/role_catalog.go

DESCRIPTION:
    TEMPLATE deployment — Signer role catalog skeleton. Copy
    this file (and its siblings in this directory) into a new
    deployments/<framework>/<court>/rules/ tree, then customize
    the role definitions for the target jurisdiction.

    The skeleton ships ONE role (`judge`) — the minimum needed
    for jurisdiction.Validate to accept the Bundle. Real
    deployments expand this to the appropriate set of Signer
    roles for their jurisdiction.

    See deployments/tn/trial/role_catalog.go for a 3-role TN
    trial reference and deployments/tn/coa/role_catalog.go for
    a 3-role TN COA reference.

OVERVIEW:
    Roles            — slice of Role definitions.
    MustRoleCatalog  — convenience constructor (panics on error).
*/
package rules

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// Roles returns the TEMPLATE deployment's role catalog. The
// skeleton has ONE role (`judge`); real deployments expand.
func Roles() []schemas.Role {
	year := 365 * 24 * time.Hour
	return []schemas.Role{
		{
			Name:            "judge",
			Actor:           schemas.ActorSigner,
			Description:     "TEMPLATE judge role — replace this catalog with your jurisdiction's actual Signer roles.",
			MaxDuration:     8 * year,
			DefaultDuration: 4 * year,
			AllowedScope: []string{
				"case_filing",
				"case_decision",
			},
			DefaultScope: []string{
				"case_filing",
				"case_decision",
			},
			DelegableBy:    nil,
			DelegableScope: nil,
		},
	}
}

// MustRoleCatalog returns a catalog populated with Roles or
// panics.
func MustRoleCatalog() *schemas.InMemoryCatalog {
	c, err := schemas.NewInMemoryCatalog(Roles())
	if err != nil {
		panic(fmt.Sprintf("TEMPLATE/rules: role catalog invalid: %v", err))
	}
	return c
}
