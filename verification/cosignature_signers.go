/*
FILE PATH: verification/cosignature_signers.go

DESCRIPTION:

	Helper for cosignature_check.go: walks the entry's signatures,
	excludes the primary signer (Signatures[0]) and the filer's own
	signature (capacity.DID), looks each up via RoleResolver to
	learn their Signer role + exchange, and reports back a
	SignerCosigner slice plus a verdict for the
	rule.MinSignerCosigners + rule.IntraExchangeOnly checks.

	Why not inline in cosignature_check.go: that file already
	handles the multi-step pipeline; the per-cosigner walk is its
	own concern. Splitting keeps both files under the line cap and
	each readable on its own.

OVERVIEW:

	collectSignerCosigners — walks signatures, returns
	                         ([]SignerCosigner, CosignatureRejection, reason).

KEY DEPENDENCIES:
  - verification.RoleResolver (DID → role + exchange).
  - policy.CosignatureRule (RequiredSignerRoles, MinSignerCosigners,
    IntraExchangeOnly).
*/
package verification

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// collectSignerCosigners walks entry.Signatures and accumulates
// the Signer cosigners (i.e., not the primary signer at [0] and
// not the filer at capacity.DID — both are accounted for
// separately). Returns the cosigner detail list plus a verdict.
//
// The verdict is CosigOK when:
//   - count of cosigners with role in rule.RequiredSignerRoles
//     is >= rule.EffectiveMinCosigners()
//   - if rule.IntraExchangeOnly: every counted cosigner's exchange
//     matches exchangeDID.
func collectSignerCosigners(
	sigs []envelope.Signature,
	cap *schemas.FiledByCapacity,
	rule *policy.CosignatureRule,
	resolver RoleResolver,
	exchangeDID string,
) ([]SignerCosigner, CosignatureRejection, string) {
	if len(sigs) == 0 {
		return nil, CosigRejectInsufficientSigners, "entry has no signatures"
	}
	// Primary signer at sigs[0] is handled by AuthorityResolver,
	// not by this cosignature check.
	filerDID := ""
	if cap != nil {
		filerDID = cap.DID
	}

	cosigners := make([]SignerCosigner, 0, len(sigs))
	matched := 0
	for i, s := range sigs {
		if i == 0 {
			continue // primary handled by AuthorityResolver, not here
		}
		// The filer's own signature is the attestation, not a
		// Signer cosignature.
		if s.SignerDID == filerDID {
			continue
		}
		entry, err := resolver.LookupRole(s.SignerDID)
		if err != nil {
			// Unknown DID — could be a Signer not yet in this
			// resolver's record (e.g., a payload's
			// signed_by_capacities block didn't list them), or
			// something stranger. Surface it with empty role so
			// the audit log shows it; do not count it toward the
			// threshold.
			if !errors.Is(err, ErrSignerUnknown) {
				// Genuine resolver error — surface it.
				return cosigners, CosigRejectInsufficientSigners,
					fmt.Sprintf("resolver error for %s: %v", s.SignerDID, err)
			}
			cosigners = append(cosigners, SignerCosigner{
				DID:          s.SignerDID,
				Role:         "",
				Exchange:     "",
				InAllowedSet: false,
			})
			continue
		}
		inSet := rule.PermitsSignerRole(entry.Role)
		cosigners = append(cosigners, SignerCosigner{
			DID:          s.SignerDID,
			Role:         entry.Role,
			Exchange:     entry.Exchange,
			InAllowedSet: inSet,
		})
		if !inSet {
			continue
		}
		if rule.IntraExchangeOnly && entry.Exchange != exchangeDID {
			continue
		}
		matched++
	}

	if matched < rule.EffectiveMinCosigners() {
		// Surface intra-exchange mismatches separately when they
		// are the cause: if some in-set cosigners exist but were
		// excluded for cross-exchange, it's an exchange mismatch.
		if rule.IntraExchangeOnly {
			for _, c := range cosigners {
				if c.InAllowedSet && c.Exchange != "" && c.Exchange != exchangeDID {
					return cosigners, CosigRejectExchangeMismatch,
						fmt.Sprintf("cosigner %s role=%q is from exchange %q; rule requires exchange %q",
							c.DID, c.Role, c.Exchange, exchangeDID)
				}
			}
		}
		return cosigners, CosigRejectInsufficientSigners,
			fmt.Sprintf("found %d Signer cosigner(s) in RequiredSignerRoles=%v; need %d",
				matched, rule.RequiredSignerRoles, rule.EffectiveMinCosigners())
	}
	return cosigners, CosigOK, ""
}
