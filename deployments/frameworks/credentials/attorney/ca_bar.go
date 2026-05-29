/*
FILE PATH: deployments/frameworks/credentials/attorney/ca_bar.go

DESCRIPTION:

	State Bar of California number — the credential class binding
	attorney filings in CA Superior, Court of Appeal, and Supreme
	Court to a verifiable license registry.

	CA Bar numbers are 6-digit sequential integers (~360,000 issued).
	Today's validator is format-only; tomorrow's swaps in the State
	Bar's published attorney lookup
	(https://apps.calbar.ca.gov/attorney/Licensee/AdvancedSearch).
*/
package attorney

import (
	"context"
	"regexp"

	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
)

var caBarNumberFormat = regexp.MustCompile(`^[0-9]{4,7}$`)

// CA_Bar returns the State Bar of California credential. Bound by
// every CA Superior Court, Court of Appeal division, and the CA
// Supreme Court.
func CA_Bar() credentials.Credential {
	return &credentials.Baseline{
		CredentialID: "ca_bar_number",
		Cat:          credentials.CategoryAttorneyBar,
		Iss:          "State Bar of California",
		J:            credentials.Jurisdiction{State: "CA"},
		Desc:         "CA attorney license issued by the State Bar of California; verify at https://apps.calbar.ca.gov/attorney/Licensee/AdvancedSearch",
		ValidatorImpl: func(_ context.Context, value string) (bool, error) {
			return caBarNumberFormat.MatchString(value), nil
		},
	}
}
