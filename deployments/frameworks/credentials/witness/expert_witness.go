/*
FILE PATH: deployments/frameworks/credentials/witness/expert_witness.go

DESCRIPTION:

	Expert-witness credential class — the framework's proof that
	non-attorney credentials extend the same Credential interface.

	An expert witness's qualification is DOMAIN-specific (medical,
	forensic, financial, ballistic). The Expert() constructor takes
	the domain so each domain is its own scoped Credential with its
	own ID. Court bundles that admit expert-witness testimony list
	the specific domains they accept via ConditionalCredentials in
	the composer.Spec — e.g. a Davidson Criminal Court might require
	credentials.witness.Expert("forensic") on a forensic_testimony
	event_type but not on a generic motion filing.

	# Why this lives in the framework today, before any court binds it

	The user's explicit requirement: "In future we might have witness
	of certain type be validated — ensure it is reusable." Landing
	the witness category alongside the attorney category at the same
	abstraction level proves the credentials/ package is genuinely
	agnostic to credential type. When a court actually requires expert
	witness validation, it adds the credential to its Spec; no
	framework change.

	Today's validators are format-only. Tomorrow's call the relevant
	state credentialing body (medical boards, forensic
	accrediting bodies, etc.) — same swap pattern as the attorney
	credentials.
*/
package witness

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
)

var domainFormat = regexp.MustCompile(`^[a-z][a-z0-9_]{1,30}$`)

// Expert returns an expert-witness credential for the given domain
// scoped to the given state. Domain MUST match [a-z][a-z0-9_]{1,30}
// to keep the credential ID predictable.
//
// Examples:
//
//	witness.Expert("medical",   credentials.Jurisdiction{State: "CA"})
//	witness.Expert("forensic",  credentials.Jurisdiction{State: "TN"})
//	witness.Expert("ballistic", credentials.Jurisdiction{Federal: true})
//
// A court that admits expert testimony on multiple domains lists
// multiple Expert() entries in its ConditionalCredentials.
func Expert(domain string, j credentials.Jurisdiction) credentials.Credential {
	if !domainFormat.MatchString(domain) {
		// Fail loud at construction time — a malformed domain would
		// silently never match.
		panic(fmt.Sprintf("witness.Expert: invalid domain %q (must match %s)",
			domain, domainFormat))
	}
	scope := j.State
	if j.Federal {
		scope = "fed"
	}
	id := fmt.Sprintf("%s_expert_%s", scope, domain)
	return &credentials.Baseline{
		CredentialID: id,
		Cat:          credentials.CategoryExpertWitness,
		Iss:          fmt.Sprintf("%s expert-witness certifying body (%s)", strings.ToUpper(scope), domain),
		J:            j,
		Desc:         fmt.Sprintf("Expert witness in %s, recognized in %s. Bound by courts that admit testimony in this domain.", domain, scope),
		ValidatorImpl: func(_ context.Context, _ string) (bool, error) {
			// Placeholder: format-only check is unsuitable for real
			// expert credentials. The real validator queries the
			// jurisdiction's credentialing body. Today returns true
			// for non-empty values; bundles that need real validation
			// MUST replace this until the resolver is wired.
			return true, nil
		},
	}
}

// CourtInterpreter returns a court-interpreter credential for the
// given language scoped to the given state. Mirrors Expert(); proves
// the witness category accommodates more than expert testimony.
func CourtInterpreter(language string, j credentials.Jurisdiction) credentials.Credential {
	if !domainFormat.MatchString(language) {
		panic(fmt.Sprintf("witness.CourtInterpreter: invalid language %q", language))
	}
	scope := j.State
	if j.Federal {
		scope = "fed"
	}
	id := fmt.Sprintf("%s_court_interpreter_%s", scope, language)
	return &credentials.Baseline{
		CredentialID: id,
		Cat:          credentials.CategoryCourtInterpreter,
		Iss:          fmt.Sprintf("%s court-certified interpreter program", strings.ToUpper(scope)),
		J:            j,
		Desc:         fmt.Sprintf("Court-certified %s interpreter in %s", language, scope),
		ValidatorImpl: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
	}
}
