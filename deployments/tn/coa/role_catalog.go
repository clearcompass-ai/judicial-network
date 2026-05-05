/*
FILE PATH: deployments/tn/coa/role_catalog.go

DESCRIPTION:

	Tennessee Court of Appeals — Signer role catalog. The TN
	COA is a single statewide intermediate appellate exchange
	(ExchangeDID = did:web:state:tn:coa). Per v1.8, opinions
	are issued by three-judge panels; the catalog enumerates
	the Signer roles that hold keys at the COA exchange.

	Role hierarchy (3 roles after Clerk/Deputy-Clerk merge):

	  institutional_did ── grants ──> chief_judge (depth 0→1)
	  chief_judge       ── grants ──> judge (depth 1→2)
	  chief_judge       ── grants ──> court_clerk (depth 1→2)

	Scope tokens at the COA differ from trial:
	  - opinion_publication   — author opinions, mint opinion_id
	  - opinion_participation — record per-judge role on opinion
	  - disposition_issuance  — record panel disposition
	  - case_filing           — clerk lifecycle (appellate_case_init,
	                            remand_affirmance)
	  - docket_management     — clerk routine

OVERVIEW:

	Roles            — slice of Role definitions (3 roles).
	MustRoleCatalog  — convenience constructor (panics on error).

KEY DEPENDENCIES:
  - schemas.Role / schemas.NewInMemoryCatalog (core types).
*/
package coa

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// Roles is the TN Court of Appeals reference role catalog.
// Three Signer roles: chief_judge (presiding), judge, court_clerk.
// Deputy-Clerk merges into court_clerk per the simplification
// directive — the cryptographic surface is identical and the
// HR distinction does not need to live on the log.
func Roles() []schemas.Role {
	day := 24 * time.Hour
	year := 365 * day
	return []schemas.Role{
		{
			Name:            "chief_judge",
			Actor:           schemas.ActorSigner,
			Description:     "Presiding Judge of the Tennessee Court of Appeals. Top-of-chain authority for the appellate exchange. Granted only by the institutional DID's Authority_Set.",
			MaxDuration:     8 * year,
			DefaultDuration: 4 * year,
			AllowedScope: []string{
				"opinion_publication",
				"opinion_participation",
				"disposition_issuance",
				"case_filing",
				"docket_management",
				"invite:judge",
				"invite:court_clerk",
				"revoke:any",
				"administrative",
			},
			DefaultScope: []string{
				"opinion_publication",
				"opinion_participation",
				"disposition_issuance",
				"docket_management",
				"invite:judge",
				"invite:court_clerk",
				"revoke:any",
				"administrative",
			},
			DelegableBy: nil,
			DelegableScope: []string{
				"opinion_publication",
				"opinion_participation",
				"disposition_issuance",
				"case_filing",
				"docket_management",
				"invite:judge",
				"invite:court_clerk",
				"revoke:any",
				"administrative",
			},
		},
		{
			Name:            "judge",
			Actor:           schemas.ActorSigner,
			Description:     "Sitting Tennessee Court of Appeals judge. Authors opinions, participates in panels, signs disposition events.",
			MaxDuration:     8 * year,
			DefaultDuration: 4 * year,
			AllowedScope: []string{
				"opinion_publication",
				"opinion_participation",
				"disposition_issuance",
			},
			DefaultScope: []string{
				"opinion_publication",
				"opinion_participation",
				"disposition_issuance",
			},
			DelegableBy:    []string{"chief_judge"},
			DelegableScope: nil,
		},
		{
			Name:            "court_clerk",
			Actor:           schemas.ActorSigner,
			Description:     "Court of Appeals clerk. Files appellate cases (appellate_case_initiation), records remand_affirmance, manages the appellate docket. Subsumes deputy-clerk distinction.",
			MaxDuration:     4 * year,
			DefaultDuration: 2 * year,
			AllowedScope: []string{
				"case_filing",
				"docket_management",
			},
			DefaultScope: []string{
				"case_filing",
				"docket_management",
			},
			DelegableBy: []string{"chief_judge"},
			DelegableScope: []string{
				"case_filing",
				"docket_management",
			},
		},
	}
}

// MustRoleCatalog returns a catalog populated with Roles or
// panics. Used by the COA Bundle as the underlying RoleCatalog.
func MustRoleCatalog() *schemas.InMemoryCatalog {
	c, err := schemas.NewInMemoryCatalog(Roles())
	if err != nil {
		panic(fmt.Sprintf("tn/coa: role catalog invalid: %v", err))
	}
	return c
}
