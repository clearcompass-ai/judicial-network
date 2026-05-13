/*
FILE PATH: schemas/attestation_policies.go

DESCRIPTION:

	Named AttestationPolicies declared on judicial-network schemas
	(v1.3.0 wire field SchemaParameters.AttestationPolicies). Schemas
	expose these slots so entries can adopt one of them by setting
	ControlHeader.AttestationPolicyName = "<name>". The ledger's
	admission gate runs attestation.VerifyEntryAttestationPolicy
	automatically when both conditions are met; schemas without
	policies declared (and entries without AttestationPolicyName) are
	a no-op.

	# SCOPE — declaration only, no enforcement

	This file produces the JSON wire shape of each policy. It does
	NOT enforce K-of-N at write time — that's the ledger's
	admission gate (ledger PR-E, self-gating). It does NOT enforce
	on read either — verification/attestation_policy_resolver.go is
	the read-side bridge that runs the SDK composite from a JN HTTP
	context.

	Every policy here is Required=false. Schemas opt INTO hard
	reject explicitly via schema amendment; "schema declares a
	policy" should never accidentally lock out otherwise-valid
	entries that don't reference it. SignerConstraint is empty by
	default — deployments restrict attestor authority via schema
	amendment when they need to.

	# CANONICAL JSON SHAPE

	Per types/attestation_policy_json.go, each policy serializes as:

	  {
	    "name":              "<identifier>",
	    "min_attestors":     <int>,
	    "window_seconds":    <int64>,
	    "required":          false,
	    "signer_constraint": {}
	  }

	The SDK's schema.JSONParameterExtractor reads the
	"attestation_policies" key on the schema entry's Domain Payload
	and decodes the slice via AttestationPolicy.UnmarshalJSON.

KEY DEPENDENCIES:
  - attesta v1.3.0 types.SchemaParameters.AttestationPolicies (wire)
  - attesta v1.3.0 types.AttestationPolicy.MarshalJSON (round-trip
    pin in test)
*/
package schemas

import "time"

// Policy names declared on each JN schema. Centralised so callers
// (HTTP request validation, audit tooling) can reference them by
// stable identifier rather than string-literal duplication.
const (
	// PolicyCivilPanelReview — used when a civil case is referred
	// to a multi-judge panel (consolidation, complex class actions).
	// 2 attestors within 30 days; informational unless schema is
	// amended to Required=true.
	PolicyCivilPanelReview = "civil_panel_review"

	// PolicyCriminalSeniorJudgeConcurrence — used when a criminal
	// matter (capital, multi-defendant, complex) carries a
	// concurrence by a senior judge. 1 attestor within 14 days.
	PolicyCriminalSeniorJudgeConcurrence = "criminal_senior_judge_concurrence"

	// PolicyDelegationBoardConcurrence — used when a delegation
	// issuance requires concurrence from the Board of Judges. 2
	// attestors within 72 hours.
	PolicyDelegationBoardConcurrence = "delegation_board_concurrence"

	// PolicySealingOrderConcurrence — used when a sealing order
	// requires a second-judge concurrence beyond the issuing
	// judge's signature. 1 attestor within 7 days.
	PolicySealingOrderConcurrence = "sealing_order_concurrence"

	// PolicyAppellatePanelConcurrence — used for en-banc / 3-judge
	// panel concurrence on opinion publication. 2 attestors within
	// 30 days (i.e. 1 primary author + 2 panel attesters).
	PolicyAppellatePanelConcurrence = "appellate_panel_concurrence"

	// PolicyAppellateDispositionConcurrence — appellate disposition
	// (affirm / reverse / remand / dismiss) carries the same panel
	// shape as opinion publication; declared on the disposition
	// schema so the disposition entry can adopt the policy
	// independently of the opinion publication.
	PolicyAppellateDispositionConcurrence = "appellate_disposition_concurrence"

	// PolicyFamilyCasePanelReview — used when a contested family
	// matter (custody, sealed adoption) is referred to a panel.
	// 2 attestors within 30 days.
	PolicyFamilyCasePanelReview = "family_case_panel_review"

	// PolicyJuvenileCaseConcurrence — used when a juvenile matter
	// carries a senior-magistrate concurrence (e.g., placement
	// orders, detention). 1 attestor within 14 days.
	PolicyJuvenileCaseConcurrence = "juvenile_case_concurrence"

	// PolicyEvidenceChainOfCustody — used when an evidence artifact
	// requires a chain-of-custody attestation (typically by the
	// court clerk + the lodging officer). 1 attestor within 30
	// days; informational by default.
	PolicyEvidenceChainOfCustody = "evidence_chain_of_custody"

	// PolicyCounselAppearanceClerkConcurrence — counsel appearance
	// entries typically require the clerk to cosign. 1 attestor
	// within 24 hours of the appearance.
	PolicyCounselAppearanceClerkConcurrence = "counsel_appearance_clerk_concurrence"

	// PolicyPartyBindingSealAuthority — sealed party bindings
	// (protected populations: juveniles, victims) require sealing-
	// authority concurrence beyond the clerk's primary signature.
	// 1 attestor within 7 days.
	PolicyPartyBindingSealAuthority = "party_binding_seal_authority"

	// PolicyJudicialSuccessionConcurrence — scoped judicial
	// succession requires concurrence from the incoming judicial
	// officer in addition to the outgoing one (both signers). 1
	// attestor within 7 days.
	PolicyJudicialSuccessionConcurrence = "judicial_succession_concurrence"

	// PolicyJudicialRevocationBoardConcurrence — delegation
	// revocation typically requires Board concurrence parallel to
	// issuance. 2 attestors within 72 hours.
	PolicyJudicialRevocationBoardConcurrence = "judicial_revocation_board_concurrence"
)

// attestationPolicyJSON is the wire shape of a single
// types.AttestationPolicy, matching the SDK's MarshalJSON
// (types/attestation_policy_json.go). Declared here so we can
// produce the canonical JSON without depending on the SDK's
// marshaler (the SDK's marshaler rejects invalid policies via
// Validate; producing raw maps gives us byte-stable output for
// any input we choose).
//
// signer_constraint is emitted as an empty object — domain-level
// constraint (allowlist of attestor DIDs, scope filter) is added
// per-deployment by amending the schema.
type attestationPolicyJSON struct {
	Name             string            `json:"name"`
	MinAttestors     int               `json:"min_attestors"`
	WindowSeconds    int64             `json:"window_seconds"`
	Required         bool              `json:"required"`
	SignerConstraint map[string]string `json:"signer_constraint"`
}

func policy(name string, minAttestors int, window time.Duration) attestationPolicyJSON {
	return attestationPolicyJSON{
		Name:             name,
		MinAttestors:     minAttestors,
		WindowSeconds:    int64(window / time.Second),
		Required:         false,
		SignerConstraint: map[string]string{},
	}
}

// civilCasePolicies returns the AttestationPolicies declared on
// tn-civil-case-v1. Currently one: civil_panel_review.
func civilCasePolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicyCivilPanelReview, 2, 30*24*time.Hour),
	}
}

// criminalCasePolicies returns the AttestationPolicies declared on
// tn-criminal-case-v1.
func criminalCasePolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicyCriminalSeniorJudgeConcurrence, 1, 14*24*time.Hour),
	}
}

// judicialDelegationPolicies returns the AttestationPolicies declared
// on judicial-delegation-v1.
func judicialDelegationPolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicyDelegationBoardConcurrence, 2, 72*time.Hour),
	}
}

// sealingOrderPolicies returns the AttestationPolicies declared on
// tn-sealing-order-v1.
func sealingOrderPolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicySealingOrderConcurrence, 1, 7*24*time.Hour),
	}
}

// appellateOpinionPolicies returns the AttestationPolicies declared
// on tn-appellate-opinion-publication-v1.
func appellateOpinionPolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicyAppellatePanelConcurrence, 2, 30*24*time.Hour),
	}
}

// appellateDispositionPolicies returns the AttestationPolicies
// declared on tn-appellate-disposition-v1.
func appellateDispositionPolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicyAppellateDispositionConcurrence, 2, 30*24*time.Hour),
	}
}

// familyCasePolicies returns the AttestationPolicies declared on
// tn-family-case-v1.
func familyCasePolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicyFamilyCasePanelReview, 2, 30*24*time.Hour),
	}
}

// juvenileCasePolicies returns the AttestationPolicies declared on
// tn-juvenile-case-v1.
func juvenileCasePolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicyJuvenileCaseConcurrence, 1, 14*24*time.Hour),
	}
}

// evidenceArtifactPolicies returns the AttestationPolicies declared
// on tn-evidence-artifact-v1.
func evidenceArtifactPolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicyEvidenceChainOfCustody, 1, 30*24*time.Hour),
	}
}

// counselAppearancePolicies returns the AttestationPolicies
// declared on tn-counsel-appearance-v1.
func counselAppearancePolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicyCounselAppearanceClerkConcurrence, 1, 24*time.Hour),
	}
}

// partyBindingSealedPolicies returns the AttestationPolicies
// declared on tn-party-binding-sealed-v1.
func partyBindingSealedPolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicyPartyBindingSealAuthority, 1, 7*24*time.Hour),
	}
}

// judicialSuccessionPolicies returns the AttestationPolicies
// declared on judicial-succession-v1.
func judicialSuccessionPolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicyJudicialSuccessionConcurrence, 1, 7*24*time.Hour),
	}
}

// judicialRevocationPolicies returns the AttestationPolicies
// declared on judicial-revocation-v1.
func judicialRevocationPolicies() []attestationPolicyJSON {
	return []attestationPolicyJSON{
		policy(PolicyJudicialRevocationBoardConcurrence, 2, 72*time.Hour),
	}
}
