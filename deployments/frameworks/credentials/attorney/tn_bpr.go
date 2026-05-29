/*
FILE PATH: deployments/frameworks/credentials/attorney/tn_bpr.go

DESCRIPTION:

	Tennessee Board of Professional Responsibility (BPR) number — the
	credential class binding attorney filings in TN trial + appellate
	courts to a verifiable license registry.

	# Validator implementation

	Today: format check only (BPR numbers are 5-digit zero-padded
	integers in TN's current scheme; the Board occasionally widens
	this — the format check is conservative).

	Tomorrow: registry lookup against the BPR's published directory
	(https://www.tnbpr.org/AttorneyDirectory). When that resolver
	lands, ValidatorImpl swaps; the credential ID and all bundles
	binding it stay unchanged.
*/
package attorney

import (
	"context"
	"regexp"

	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
)

// tnBPRNumberFormat matches the current TN BPR scheme: a 4-7 digit
// number (the BPR has issued ~30,000 numbers; the range is bounded).
// Conservative — rejects letters and punctuation but admits any
// plausible-length numeric.
var tnBPRNumberFormat = regexp.MustCompile(`^[0-9]{4,7}$`)

// TN_BPR returns the TN Board of Professional Responsibility credential.
// Bound by Davidson Circuit, Knox Chancery, every TN trial-court division
// and every TN appellate court.
func TN_BPR() credentials.Credential {
	return &credentials.Baseline{
		CredentialID: "tn_bpr_number",
		Cat:          credentials.CategoryAttorneyBar,
		Iss:          "Tennessee Board of Professional Responsibility",
		J:            credentials.Jurisdiction{State: "TN"},
		Desc:         "TN attorney license issued by the Board of Professional Responsibility; verify at https://www.tnbpr.org/AttorneyDirectory",
		ValidatorImpl: func(_ context.Context, value string) (bool, error) {
			return tnBPRNumberFormat.MatchString(value), nil
		},
	}
}
