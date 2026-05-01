/*
FILE PATH: deployments/tn/sup_ct/role_catalog.go

DESCRIPTION:
    Tennessee Supreme Court — Signer role catalog. The TN Sup
    Ct is a single statewide highest-appellate exchange
    (ExchangeDID = did:web:state:tn:sc). Five sitting Justices;
    one Chief Justice elected from among them.

    Role hierarchy:
      institutional_did ── grants ──> chief_justice (depth 0→1)
      chief_justice     ── grants ──> justice (depth 1→2)
      chief_justice     ── grants ──> court_clerk (depth 1→2)

    Differs from TN COA's chief_judge / judge naming because TN
    Supreme Court uses "Justice" (the appellate practitioner-
    rank distinction in TN). Same shape, different vocabulary.
*/
package sup_ct

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// Roles is the TN Supreme Court reference role catalog. Three
// Signer roles: chief_justice, justice, court_clerk.
func Roles() []schemas.Role {
	day := 24 * time.Hour
	year := 365 * day
	return []schemas.Role{
		{
			Name:            "chief_justice",
			Actor:           schemas.ActorSigner,
			Description:     "Chief Justice of the Tennessee Supreme Court. Top-of-chain authority for the Sup Ct exchange.",
			MaxDuration:     8 * year,
			DefaultDuration: 4 * year,
			AllowedScope: []string{
				"opinion_publication",
				"opinion_participation",
				"disposition_issuance",
				"case_filing",
				"docket_management",
				"invite:justice",
				"invite:court_clerk",
				"revoke:any",
				"administrative",
			},
			DefaultScope: []string{
				"opinion_publication",
				"opinion_participation",
				"disposition_issuance",
				"docket_management",
				"invite:justice",
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
				"invite:justice",
				"invite:court_clerk",
				"revoke:any",
				"administrative",
			},
		},
		{
			Name:            "justice",
			Actor:           schemas.ActorSigner,
			Description:     "Sitting Justice of the Tennessee Supreme Court. Authors opinions, participates in en-banc panels, signs disposition events. Cross-exchange revocations require cosignature from sitting Justices.",
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
			DelegableBy:    []string{"chief_justice"},
			DelegableScope: nil,
		},
		{
			Name:            "court_clerk",
			Actor:           schemas.ActorSigner,
			Description:     "Tennessee Supreme Court clerk. Files Sup Ct case roots, records dispositions, and manages the appellate docket.",
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
			DelegableBy: []string{"chief_justice"},
			DelegableScope: []string{
				"case_filing",
				"docket_management",
			},
		},
	}
}

// MustRoleCatalog returns a catalog populated with Roles or
// panics.
func MustRoleCatalog() *schemas.InMemoryCatalog {
	c, err := schemas.NewInMemoryCatalog(Roles())
	if err != nil {
		panic(fmt.Sprintf("tn/sup_ct: role catalog invalid: %v", err))
	}
	return c
}
