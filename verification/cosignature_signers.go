/*
FILE PATH: verification/cosignature_signers.go

DESCRIPTION:
    Helper for cosignature_check.go: walks the entry's signatures,
    excludes the primary signer (Signatures[0]) and the filer's own
    signature (capacity.DID), looks each up in the OfficerRegistry
    to learn their ActorSigner role + exchange, and reports back
    a SignerCosigner slice plus a verdict for the
    rule.MinSignerCosigners + rule.IntraExchangeOnly checks.

    Why not inline in cosignature_check.go: that file already
    handles the multi-step pipeline; the per-cosigner walk is its
    own concern. Splitting keeps both files under the line cap and
    each readable on its own.

OVERVIEW:
    collectSignerCosigners — walks signatures, returns
                             ([]SignerCosigner, CosignatureRejection, reason).

KEY DEPENDENCIES:
    - directory.Registry (DID → Officer record).
    - policy.CosignatureRule (RequiredSignerRoles, MinSignerCosigners,
      IntraExchangeOnly).
*/
package verification

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/directory"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// collectSignerCosigners walks entry.Signatures and accumulates
// the ActorSigner cosigners (i.e., not the primary signer at [0]
// and not the filer at capacity.DID — both are accounted for
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
	registry directory.Registry,
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
		// Tier 1 cosignature.
		if s.SignerDID == filerDID {
			continue
		}
		officer, err := registry.Lookup(s.SignerDID)
		if err != nil {
			// Unknown DID — could be a Tier 1 actor not yet in
			// our registry, or something stranger. Surface it as
			// a cosigner with empty role so the audit log shows
			// it; do not count it toward the threshold.
			cosigners = append(cosigners, SignerCosigner{
				DID:          s.SignerDID,
				Role:         "",
				Exchange:     "",
				InAllowedSet: false,
			})
			continue
		}
		exchange := officer.DelegationRef.LogDID
		inSet := rule.PermitsSignerRole(officer.Role)
		cosigners = append(cosigners, SignerCosigner{
			DID:          s.SignerDID,
			Role:         officer.Role,
			Exchange:     exchange,
			InAllowedSet: inSet,
		})
		if !inSet {
			continue
		}
		if rule.IntraExchangeOnly && exchange != exchangeDID {
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
			fmt.Sprintf("found %d ActorSigner cosigner(s) in RequiredSignerRoles=%v; need %d",
				matched, rule.RequiredSignerRoles, rule.EffectiveMinCosigners())
	}
	return cosigners, CosigOK, ""
}
