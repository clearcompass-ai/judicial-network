/*
FILE PATH: internal/testfixtures/davidsonlegacy/role_catalog.go

DESCRIPTION:

	Test-only fixture preserving the legacy 6-role Davidson
	hierarchy. NOT a production deployment — production TN
	counties use deployments/tn/counties/<county>/, which
	composes from the simplified 3-role tn/trial framework
	(judge / court_clerk / court_reporter).

	This fixture exists solely to back the multi-hop delegation-
	chain contract tests (depth=3 happy path, depth>3 rejection,
	ValidateGrant rejection-path coverage) that the simplified
	catalog cannot model. The 6-role hierarchy here is the
	original v1.6 Davidson catalog verbatim.

	Hierarchy:

	  institutional_did ── grants ──> chief_justice (depth 0→1)
	  chief_justice     ── grants ──> judge (depth 1→2)
	  chief_justice     ── grants ──> court_reporter (depth 1→2)
	  judge             ── grants ──> court_clerk (depth 2→3)
	  judge             ── grants ──> deputy_judge (depth 2→3)
	  court_clerk       ── grants ──> court_staff (depth 3→4)

	Scope tokens follow the convention "verb:object", e.g.
	"case_filing", "invite:judge", "revoke:any",
	"transcript_publication".

OVERVIEW:

	Roles            — slice of Role definitions.
	MustRoleCatalog  — convenience constructor (panics on error).

KEY DEPENDENCIES:
  - schemas.Role / schemas.NewInMemoryCatalog (core types).
*/
package davidsonlegacy

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// Roles is the legacy 6-role Davidson catalog, preserved as a
// test fixture for multi-hop delegation-chain contract tests.
// Production code uses deployments/tn/counties/davidson, which
// composes from the simplified 3-role tn/trial framework.
func Roles() []schemas.Role {
	day := 24 * time.Hour
	year := 365 * day
	return []schemas.Role{
		{
			Name:            "chief_justice",
			Actor:           schemas.ActorSigner,
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
				"invite:court_reporter",
				"revoke:any",
				"administrative",
				"transcript_publication",
			},
			DefaultScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:judge",
				"invite:court_clerk",
				"invite:deputy_judge",
				"invite:court_reporter",
				"revoke:any",
				"administrative",
			},
			DelegableBy: nil,
			DelegableScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:judge",
				"invite:court_clerk",
				"invite:deputy_judge",
				"invite:court_reporter",
				"revoke:any",
				"administrative",
				"transcript_publication",
			},
		},
		{
			Name:            "judge",
			Actor:           schemas.ActorSigner,
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
			Actor:           schemas.ActorSigner,
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
			DelegableScope: nil,
		},
		{
			Name:            "court_clerk",
			Actor:           schemas.ActorSigner,
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
			Actor:           schemas.ActorSigner,
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
		{
			Name:            "court_reporter",
			Actor:           schemas.ActorSigner,
			Description:     "Court reporter. Specialized cryptographic key used strictly to publish, encrypt, and sign certified hearing and trial transcripts.",
			MaxDuration:     4 * year,
			DefaultDuration: 2 * year,
			AllowedScope: []string{
				"transcript_publication",
			},
			DefaultScope: []string{
				"transcript_publication",
			},
			DelegableBy:    []string{"chief_justice"},
			DelegableScope: nil,
		},
	}
}

// MustRoleCatalog returns a catalog populated with Roles or panics.
// Convenience for tests and the default boot path.
func MustRoleCatalog() *schemas.InMemoryCatalog {
	c, err := schemas.NewInMemoryCatalog(Roles())
	if err != nil {
		panic(fmt.Sprintf("internal/testfixtures/davidsonlegacy: role catalog invalid: %v", err))
	}
	return c
}
