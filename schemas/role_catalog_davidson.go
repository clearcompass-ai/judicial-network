/*
FILE PATH: schemas/role_catalog_davidson.go

DESCRIPTION:
    Reference role catalog for the Davidson County deployment.
    Production deployments load their own catalog file but typically
    start from this template. Tests exercise the four-hop hierarchy:

      institutional_did ── grants ──> chief_justice (depth 0→1)
      chief_justice     ── grants ──> judge (depth 1→2)
      judge             ── grants ──> court_clerk (depth 2→3)
      judge             ── grants ──> deputy_judge (depth 2→3)
      court_clerk       ── grants ──> court_staff (depth 3→4)

    Scope tokens follow the convention "verb:object", e.g.
    "case_filing", "invite:judge", "revoke:any".

OVERVIEW:
    DavidsonRoles      — slice of Role definitions.
    MustDavidsonCatalog — convenience constructor (panics on error).
*/
package schemas

import (
	"fmt"
	"time"
)

// DavidsonRoles is the reference role catalog for the Davidson County
// deployment.
func DavidsonRoles() []Role {
	day := 24 * time.Hour
	year := 365 * day
	return []Role{
		{
			Name:            "chief_justice",
			Description:     "Top-of-chain authority for the court. Granted only by the institutional DID's Authority_Set.",
			MaxDuration:     8 * year,
			DefaultDuration: 4 * year,
			AllowedScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:judge",
				"invite:court_clerk",
				"invite:deputy_judge",
				"revoke:any",
				"administrative",
			},
			DefaultScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:judge",
				"invite:court_clerk",
				"invite:deputy_judge",
				"revoke:any",
				"administrative",
			},
			DelegableBy: nil, // institutional DID only
			DelegableScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:judge",
				"invite:court_clerk",
				"invite:deputy_judge",
				"revoke:any",
				"administrative",
			},
		},
		{
			Name:            "judge",
			Description:     "Sitting judge. Issues case decisions and may delegate to a clerk or deputy.",
			MaxDuration:     8 * year,
			DefaultDuration: 4 * year,
			AllowedScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:court_clerk",
				"invite:deputy_judge",
				"revoke:downstream",
			},
			DefaultScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
			},
			DelegableBy: []string{"chief_justice"},
			DelegableScope: []string{
				"case_filing",
				"docket_management",
				"invite:court_clerk",
				"invite:deputy_judge",
				"revoke:downstream",
			},
		},
		{
			Name:            "deputy_judge",
			Description:     "Deputy judge sitting for the granter. Decisions are valid for the granter's term.",
			MaxDuration:     2 * year,
			DefaultDuration: year,
			AllowedScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
			},
			DefaultScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
			},
			DelegableBy:    []string{"judge"},
			DelegableScope: nil, // deputies cannot re-delegate
		},
		{
			Name:            "court_clerk",
			Description:     "Court clerk. Files cases and manages the docket but does not issue decisions.",
			MaxDuration:     4 * year,
			DefaultDuration: 2 * year,
			AllowedScope: []string{
				"case_filing",
				"docket_management",
				"invite:court_staff",
			},
			DefaultScope: []string{
				"case_filing",
				"docket_management",
			},
			DelegableBy: []string{"chief_justice", "judge"},
			DelegableScope: []string{
				"case_filing",
				"docket_management",
				"invite:court_staff",
			},
		},
		{
			Name:            "court_staff",
			Description:     "Court staff. Limited filing access. Cannot delegate.",
			MaxDuration:     2 * year,
			DefaultDuration: year,
			AllowedScope: []string{
				"case_filing",
			},
			DefaultScope: []string{
				"case_filing",
			},
			DelegableBy:    []string{"court_clerk"},
			DelegableScope: nil,
		},
	}
}

// MustDavidsonCatalog returns a catalog populated with DavidsonRoles
// or panics. Convenience for tests and the default boot path.
func MustDavidsonCatalog() *InMemoryCatalog {
	c, err := NewInMemoryCatalog(DavidsonRoles())
	if err != nil {
		panic(fmt.Sprintf("schemas/role_catalog: Davidson fixture invalid: %v", err))
	}
	return c
}
