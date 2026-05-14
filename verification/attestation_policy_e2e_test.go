/*
FILE PATH: verification/attestation_policy_e2e_test.go

DESCRIPTION:

	End-to-end integration test crossing the v1.3.0 producer and
	consumer surfaces. The two are unit-tested independently —
	schemas/attestation_policies_test.go (producer) and
	attestation_policy_resolver_test.go (consumer) — but the
	independence creates a drift window: a refactor that breaks the
	contract between them (wire-key rename, policy-shape change)
	passes the unit suites but fails in production.

	This test pins the full path: a schema declared via
	Default*Params() round-trips through the SDK extractor; an
	entry built with AttestationPolicyName via the JN builder
	helper carries the name on its header; the resolver picks the
	policy from the schema by that name. If any layer drifts, this
	test catches it.

	The five walkthrough policies + 4 additional schemas wired in
	PR E and PR F are spot-checked. The unit suites already pin
	per-schema behaviour; this file pins the cross-surface
	composition.
*/
package verification

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/schema"

	jnschemas "github.com/clearcompass-ai/judicial-network/schemas"
)

// e2eCase pins one (schema, policy-name, expected-K) triple.
type e2eCase struct {
	schemaName  string
	paramsBytes []byte
	policyName  string
	wantK       int
}

// TestE2E_AttestationPolicy_AllWalkthroughSchemas pins every
// AttestationPolicy-bearing JN schema's full cross-surface path:
// (1) Default<Schema>Params produces wire bytes that the SDK
// extractor parses without error; (2) an envelope built with
// AttestationPolicyName matching one of the declared policy
// names round-trips through the resolver and returns a policy
// whose MinAttestors matches what schemas/attestation_policies.go
// declared.
//
// Walking every schema here means any cross-surface drift — wire
// key rename, policy shape break, helper signature change —
// surfaces in one place, in test, before deployment.
func TestE2E_AttestationPolicy_AllWalkthroughSchemas(t *testing.T) {
	cases := []e2eCase{
		// PR E (1/2) schemas
		{"civil_case", jnschemas.DefaultCivilCaseParams(),
			jnschemas.PolicyCivilPanelReview, 2},
		{"criminal_case", jnschemas.DefaultCriminalCaseParams(),
			jnschemas.PolicyCriminalSeniorJudgeConcurrence, 1},
		{"judicial_delegation", jnschemas.DefaultJudicialDelegationParams(),
			jnschemas.PolicyDelegationBoardConcurrence, 2},
		{"sealing_order", jnschemas.DefaultSealingOrderParams(),
			jnschemas.PolicySealingOrderConcurrence, 1},
		{"appellate_opinion_publication", jnschemas.DefaultOpinionPublicationParams(),
			jnschemas.PolicyAppellatePanelConcurrence, 2},

		// PR F schemas (added for walkthrough completeness)
		{"appellate_disposition", jnschemas.DefaultDispositionParams(),
			jnschemas.PolicyAppellateDispositionConcurrence, 2},
		{"family_case", jnschemas.DefaultFamilyCaseParams(),
			jnschemas.PolicyFamilyCasePanelReview, 2},
		{"juvenile_case", jnschemas.DefaultJuvenileCaseParams(),
			jnschemas.PolicyJuvenileCaseConcurrence, 1},
		{"evidence_artifact", jnschemas.DefaultEvidenceArtifactParams(),
			jnschemas.PolicyEvidenceChainOfCustody, 1},
		{"counsel_appearance", jnschemas.DefaultCounselAppearanceParams(),
			jnschemas.PolicyCounselAppearanceClerkConcurrence, 1},
		{"party_binding_sealed", jnschemas.DefaultPartyBindingSealedParams(),
			jnschemas.PolicyPartyBindingSealAuthority, 1},
		{"judicial_succession", jnschemas.DefaultJudicialSuccessionParams(),
			jnschemas.PolicyJudicialSuccessionConcurrence, 1},
		{"judicial_revocation", jnschemas.DefaultJudicialRevocationParams(),
			jnschemas.PolicyJudicialRevocationBoardConcurrence, 2},
	}

	for _, c := range cases {
		t.Run(c.schemaName, func(t *testing.T) {
			// Layer 1: schema bytes → SDK SchemaParameters
			schemaEntry := &envelope.Entry{DomainPayload: c.paramsBytes}
			extractor := schema.NewJSONParameterExtractor()
			params, err := extractor.Extract(schemaEntry)
			if err != nil {
				t.Fatalf("schema extractor: %v", err)
			}
			if len(params.AttestationPolicies) == 0 {
				t.Fatalf("%s: extractor reported zero policies; want at least one",
					c.schemaName)
			}

			// Layer 2: build an unsigned entry and apply the policy
			// name via the JN builder helper.
			entry := &envelope.Entry{Header: envelope.ControlHeader{}}
			jnschemas.SetAttestationPolicy(entry, &c.policyName)
			if entry.Header.AttestationPolicyName == nil {
				t.Fatal("SetAttestationPolicy left header nil")
			}
			if got := *entry.Header.AttestationPolicyName; got != c.policyName {
				t.Errorf("AttestationPolicyName = %q, want %q",
					got, c.policyName)
			}

			// Layer 3: resolver finds the policy from the schema
			// by the name the entry header carries.
			policy, err := ResolveEntryAttestationPolicy(entry, params)
			if err != nil {
				t.Fatalf("ResolveEntryAttestationPolicy: %v", err)
			}
			if policy == nil {
				t.Fatal("resolver returned nil policy on a matched name")
			}
			if policy.Name != c.policyName {
				t.Errorf("policy.Name = %q, want %q",
					policy.Name, c.policyName)
			}
			if policy.MinAttestors != c.wantK {
				t.Errorf("policy.MinAttestors = %d, want %d",
					policy.MinAttestors, c.wantK)
			}
			if policy.Required {
				t.Errorf("policy.Required = true on first-declaration policy (should opt INTO hard reject explicitly)")
			}
		})
	}
}

// TestE2E_AttestationPolicy_NameNotFound exercises the negative
// path: an entry references a policy name that the schema does
// NOT declare. The resolver must surface the ErrPolicyNameNotFound
// sentinel so admission can reject deterministically.
func TestE2E_AttestationPolicy_NameNotFound(t *testing.T) {
	schemaEntry := &envelope.Entry{DomainPayload: jnschemas.DefaultCivilCaseParams()}
	params, err := schema.NewJSONParameterExtractor().Extract(schemaEntry)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	// Civil case schema declares PolicyCivilPanelReview but NOT a
	// "ghost" policy — picking a name no schema declares forces
	// the resolver to surface the not-found sentinel.
	bogusName := "ghost_policy_does_not_exist"
	entry := &envelope.Entry{Header: envelope.ControlHeader{}}
	jnschemas.SetAttestationPolicy(entry, &bogusName)

	_, err = ResolveEntryAttestationPolicy(entry, params)
	if err == nil {
		t.Fatal("expected error for bogus policy name; got nil")
	}
	if !errors.Is(err, ErrPolicyNameNotFound) {
		t.Errorf("err = %v, want errors.Is(ErrPolicyNameNotFound)", err)
	}
}

// TestE2E_AttestationPolicy_NoNameAdoption exercises the "no
// policy adopted" path: an entry without AttestationPolicyName
// must return ErrPolicyNotAdopted from the resolver, signalling
// the caller that the entry's primary signature alone is the
// authority (no K-of-N gate).
func TestE2E_AttestationPolicy_NoNameAdoption(t *testing.T) {
	schemaEntry := &envelope.Entry{DomainPayload: jnschemas.DefaultCivilCaseParams()}
	params, err := schema.NewJSONParameterExtractor().Extract(schemaEntry)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	// Entry built without setting AttestationPolicyName.
	entry := &envelope.Entry{Header: envelope.ControlHeader{}}

	_, err = ResolveEntryAttestationPolicy(entry, params)
	if err == nil {
		t.Fatal("expected ErrPolicyNotAdopted; got nil")
	}
	if !errors.Is(err, ErrPolicyNotAdopted) {
		t.Errorf("err = %v, want errors.Is(ErrPolicyNotAdopted)", err)
	}
}
