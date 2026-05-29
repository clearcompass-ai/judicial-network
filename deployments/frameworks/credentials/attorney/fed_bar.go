/*
FILE PATH: deployments/frameworks/credentials/attorney/fed_bar.go

DESCRIPTION:

	Federal bar admission — the credential class binding attorney
	filings in federal courts (District, Circuit, SCOTUS) to a
	court-specific admission record.

	Unlike state bars, federal admission is GRANTED PER COURT: an
	attorney is admitted to the bar of the US District Court for the
	Middle District of Tennessee SEPARATELY from the bar of the
	Ninth Circuit, and admission to the SCOTUS bar is a distinct
	credential again. The Fed_BarFor() constructor takes the court
	DID so each admission is its own scoped Credential.

	Today's validator is format-only; tomorrow's swaps in PACER /
	per-court attorney directories.
*/
package attorney

import (
	"context"
	"fmt"
	"regexp"

	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
)

// fedBarAdmissionFormat is the placeholder format check; real federal
// admissions are alphanumeric per-court identifiers, varying by court.
var fedBarAdmissionFormat = regexp.MustCompile(`^[A-Za-z0-9_-]{3,32}$`)

// Fed_BarFor returns the federal-court bar admission credential scoped
// to the given court DID. Federal admissions are per-court, so each
// court that requires the credential supplies its own DID — the
// returned Credential's Jurisdiction.CourtScope is set accordingly.
//
// Example:
//
//	districtMidTN := "did:web:fed:district:tn_middle"
//	cred := attorney.Fed_BarFor(districtMidTN)
//	// cred.ID() = "fed_bar_admission:did:web:fed:district:tn_middle"
//
// The composer threads cred.ID() into cosignature rules, so two
// federal courts in the same network bind to DIFFERENT credential
// classes even though both are "federal bar admissions" by category.
func Fed_BarFor(courtDID string) credentials.Credential {
	return &credentials.Baseline{
		CredentialID: fmt.Sprintf("fed_bar_admission:%s", courtDID),
		Cat:          credentials.CategoryAttorneyBar,
		Iss:          fmt.Sprintf("Court bar of %s", courtDID),
		J: credentials.Jurisdiction{
			Federal:    true,
			CourtScope: courtDID,
		},
		Desc: fmt.Sprintf("Federal bar admission to the court at %s — separate from any other federal-court admission", courtDID),
		ValidatorImpl: func(_ context.Context, value string) (bool, error) {
			return fedBarAdmissionFormat.MatchString(value), nil
		},
	}
}

// SCOTUS_Bar returns the SCOTUS bar admission credential. SCOTUS
// admission is its own distinct class — Fed_BarFor("did:web:fed:scotus:us")
// works too, but SCOTUS_Bar() is the named convenience used by the
// SCOTUS bundle's RequiredCredentials list.
func SCOTUS_Bar() credentials.Credential {
	return Fed_BarFor("did:web:fed:scotus:us")
}
