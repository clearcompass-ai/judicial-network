/*
FILE PATH: deployments/tn/trial/role_catalog.go

DESCRIPTION:

	TN trial-court framework — Signer role catalog shared by
	every Tennessee county exchange (Davidson, Shelby, Knox,
	Hamilton, …). Each county composes its Bundle from this
	framework plus its own ExchangeDID; the role definitions
	are identical across counties.

	Three Signer roles per the v1.8 Authority Summary:

	  institutional_did ── grants ──> judge          (depth 0→1)
	  judge             ── grants ──> court_clerk    (depth 1→2)
	  judge             ── grants ──> court_reporter (depth 1→2)

	Adjudicator subtypes (Magistrate, Chancellor, Justice) are
	modeled as scope+division concerns inside the `judge` role,
	not as separate role names. Clerk and Deputy Clerk collapse
	to a single `court_clerk` — the cryptographic surface is
	identical, deputy is an HR distinction the log does not need
	to record.

	Scope tokens follow the convention "verb:object", e.g.
	"case_filing", "invite:court_clerk", "revoke:downstream",
	"transcript_publication".

OVERVIEW:

	Roles            — slice of Role definitions (3 roles).
	MustRoleCatalog  — convenience constructor (panics on error).

KEY DEPENDENCIES:
  - schemas.Role / schemas.NewInMemoryCatalog (core types).
*/
package trial

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// Roles is the TN trial-court reference role catalog. Three
// Signer roles cover every event the trial framework records.
func Roles() []schemas.Role {
	day := 24 * time.Hour
	year := 365 * day
	return []schemas.Role{
		{
			Name:            "judge",
			Actor:           schemas.ActorSigner,
			Description:     "Sitting trial-court judge. Top-of-chain authority within the exchange. Granted only by the institutional DID's Authority_Set. Scope covers case decisions and delegation to clerks and court reporters.",
			MaxDuration:     8 * year,
			DefaultDuration: 4 * year,
			AllowedScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:court_clerk",
				"invite:court_reporter",
				"revoke:downstream",
				"administrative",
				"transcript_publication",
			},
			DefaultScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:court_clerk",
				"invite:court_reporter",
				"revoke:downstream",
				"administrative",
			},
			DelegableBy: nil,
			DelegableScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:court_clerk",
				"invite:court_reporter",
				"revoke:downstream",
				"administrative",
				"transcript_publication",
			},
		},
		{
			Name:            "court_clerk",
			Actor:           schemas.ActorSigner,
			Description:     "Court clerk. Files cases and manages the docket; cosigner for filer-driven motions; does not issue case decisions. Subsumes the deputy-clerk distinction (no separate deputy_clerk role).",
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
			DelegableBy: []string{"judge"},
			DelegableScope: []string{
				"case_filing",
				"docket_management",
			},
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
			DelegableBy:    []string{"judge"},
			DelegableScope: nil,
		},
	}
}

// MustRoleCatalog returns a catalog populated with Roles or
// panics. Convenience for tests and the default boot path. Used
// by every TN county Bundle as the underlying RoleCatalog.
func MustRoleCatalog() *schemas.InMemoryCatalog {
	c, err := schemas.NewInMemoryCatalog(Roles())
	if err != nil {
		panic(fmt.Sprintf("tn/trial: role catalog invalid: %v", err))
	}
	return c
}
