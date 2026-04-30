/*
FILE PATH: deployments/tn/sup_ct/cosignature_mix.go

DESCRIPTION:
    Tennessee Supreme Court — cosignature-mix policy. Same
    appellate event family as TN COA, plus a CROSS-EXCHANGE rule
    that demonstrates v1.8 §12C's authority_revocation_disciplinary
    can flow from TN Sup Ct → a TN trial county exchange (e.g.,
    Davidson) when a sitting trial judge must be removed for cause.

    Cross-exchange revocation rule shape (v0.7.0 production:
    item L from the v0.5.0 closure deferral):

      authority_revocation_disciplinary:
        RequiredSignerRoles: [justice]
        MinSignerCosigners:  3              (5 sitting Justices;
                                              majority=3)
        IntraExchangeOnly:   FALSE          (the revoked Signer's
                                              ExchangeDID points
                                              to a trial county)

    The rule references the closed-set v1.8 §12C event_type so
    the verifier accepts a TN trial-court Signer-revocation entry
    cosigned by ≥3 TN Sup Ct Justices.
*/
package sup_ct

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/policy"
)

// CosignatureRules is the TN Supreme Court cosig fixture.
func CosignatureRules() []policy.CosignatureRule {
	return []policy.CosignatureRule{
		// ── appellate case lifecycle (mirror of TN COA) ─────────
		{
			EventType:           "appellate_case_initiation",
			RequiredSignerRoles: []string{"court_clerk"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "appellate_opinion_publication",
			RequiredSignerRoles: []string{"justice", "chief_justice"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "appellate_opinion_participation",
			RequiredSignerRoles: []string{"justice", "chief_justice"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			// En-banc disposition: 5 Justices; majority cosignature.
			EventType:           "appellate_disposition",
			RequiredSignerRoles: []string{"justice", "chief_justice"},
			MinSignerCosigners:  3,
			IntraExchangeOnly:   true,
		},

		// ── cross-network: remand back to lower court ───────────
		{
			EventType:           "remand_affirmance",
			RequiredSignerRoles: []string{"court_clerk", "justice", "chief_justice"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   false,
		},

		// ── §12C cross-exchange disciplinary revocation ─────────
		// THE v0.7.0 production rule: TN Sup Ct can revoke a
		// trial-court Signer's authority via majority Justice
		// cosignature. IntraExchangeOnly=false because the
		// revoked Signer's ExchangeDID points to a different
		// (trial) court. The verifier confirms the revocation
		// entry is cosigned by ≥3 TN Sup Ct Justices.
		{
			EventType:           "authority_revocation_disciplinary",
			RequiredSignerRoles: []string{"justice", "chief_justice"},
			MinSignerCosigners:  3,
			IntraExchangeOnly:   false,
		},

		// ── personnel events at the TN Sup Ct ───────────────────
		{
			EventType:           "judicial_appointment",
			RequiredSignerRoles: []string{"justice", "chief_justice"},
			MinSignerCosigners:  3,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "clerk_appointment",
			RequiredSignerRoles: []string{"justice", "chief_justice"},
			MinSignerCosigners:  3,
			IntraExchangeOnly:   true,
		},

		// ── cross-exchange topology ─────────────────────────────
		{
			EventType:           "case_transfer_inbound",
			RequiredSignerRoles: []string{"court_clerk", "justice"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   false,
		},
		{
			EventType:           "case_transfer_outbound",
			RequiredSignerRoles: []string{"court_clerk", "justice"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   false,
		},
		{
			EventType:           "relay_attestation",
			RequiredSignerRoles: []string{"court_clerk", "justice"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   false,
		},
	}
}

// MustCosignaturePolicy returns a policy populated with
// CosignatureRules or panics.
func MustCosignaturePolicy() *policy.InMemoryPolicy {
	p, err := policy.NewInMemoryPolicy(CosignatureRules())
	if err != nil {
		panic(fmt.Sprintf("tn/sup_ct: cosignature policy invalid: %v", err))
	}
	return p
}
