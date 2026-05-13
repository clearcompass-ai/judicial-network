/*
FILE PATH: schemas/attestation_policies_test.go

DESCRIPTION:

	Round-trip tests for the v1.3.0 SchemaParameters.AttestationPolicies
	wire-field declarations. For each of the five JN schemas with
	declared policies, this test:

	  1. Calls Default<Schema>Params() to produce the canonical
	     parameters JSON bytes.
	  2. Feeds those bytes through schema.NewJSONParameterExtractor
	     (the SDK extractor that ledger PR-E and JN's
	     verification/attestation_policy_resolver.go both consume).
	  3. Confirms the resulting SchemaParameters.AttestationPolicies
	     contains the expected named policy(s).
	  4. Confirms each policy's K, Window, and Required fields
	     match the schemas/attestation_policies.go declaration.

	If the SDK ever changes the wire shape, this test FAILS at the
	JN build and pins the regression before deployment.
*/
package schemas

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/schema"
)

// Manually pin each schema's expected policy. If we change
// schemas/attestation_policies.go, this table changes too — the
// duplication is the point: stop accidental drift in either file.
type expectedPolicy struct {
	name         string
	minAttestors int
	window       time.Duration
}

func TestCivilCaseAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "civil_case", DefaultCivilCaseParams(), []expectedPolicy{
		{PolicyCivilPanelReview, 2, 30 * 24 * time.Hour},
	})
}

func TestCriminalCaseAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "criminal_case", DefaultCriminalCaseParams(), []expectedPolicy{
		{PolicyCriminalSeniorJudgeConcurrence, 1, 14 * 24 * time.Hour},
	})
}

func TestJudicialDelegationAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "judicial_delegation", DefaultJudicialDelegationParams(), []expectedPolicy{
		{PolicyDelegationBoardConcurrence, 2, 72 * time.Hour},
	})
}

func TestSealingOrderAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "sealing_order", DefaultSealingOrderParams(), []expectedPolicy{
		{PolicySealingOrderConcurrence, 1, 7 * 24 * time.Hour},
	})
}

func TestAppellateOpinionAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "appellate_opinion_publication", DefaultOpinionPublicationParams(), []expectedPolicy{
		{PolicyAppellatePanelConcurrence, 2, 30 * 24 * time.Hour},
	})
}

func TestAppellateDispositionAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "appellate_disposition", DefaultDispositionParams(), []expectedPolicy{
		{PolicyAppellateDispositionConcurrence, 2, 30 * 24 * time.Hour},
	})
}

func TestFamilyCaseAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "family_case", DefaultFamilyCaseParams(), []expectedPolicy{
		{PolicyFamilyCasePanelReview, 2, 30 * 24 * time.Hour},
	})
}

func TestJuvenileCaseAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "juvenile_case", DefaultJuvenileCaseParams(), []expectedPolicy{
		{PolicyJuvenileCaseConcurrence, 1, 14 * 24 * time.Hour},
	})
}

func TestEvidenceArtifactAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "evidence_artifact", DefaultEvidenceArtifactParams(), []expectedPolicy{
		{PolicyEvidenceChainOfCustody, 1, 30 * 24 * time.Hour},
	})
}

func TestCounselAppearanceAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "counsel_appearance", DefaultCounselAppearanceParams(), []expectedPolicy{
		{PolicyCounselAppearanceClerkConcurrence, 1, 24 * time.Hour},
	})
}

func TestPartyBindingSealedAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "party_binding_sealed", DefaultPartyBindingSealedParams(), []expectedPolicy{
		{PolicyPartyBindingSealAuthority, 1, 7 * 24 * time.Hour},
	})
}

func TestJudicialSuccessionAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "judicial_succession", DefaultJudicialSuccessionParams(), []expectedPolicy{
		{PolicyJudicialSuccessionConcurrence, 1, 7 * 24 * time.Hour},
	})
}

func TestJudicialRevocationAttestationPolicies_RoundTrip(t *testing.T) {
	assertPolicies(t, "judicial_revocation", DefaultJudicialRevocationParams(), []expectedPolicy{
		{PolicyJudicialRevocationBoardConcurrence, 2, 72 * time.Hour},
	})
}

// assertPolicies runs the SDK extractor and compares the decoded
// policies against expected. Every policy declared in this file is
// Required=false at first declaration (see
// schemas/attestation_policies.go); the test pins that invariant.
func assertPolicies(t *testing.T, name string, paramsBytes []byte, expected []expectedPolicy) {
	t.Helper()
	entry := &envelope.Entry{DomainPayload: paramsBytes}
	ex := schema.NewJSONParameterExtractor()
	got, err := ex.Extract(entry)
	if err != nil {
		t.Fatalf("%s: extractor.Extract: %v", name, err)
	}
	if len(got.AttestationPolicies) != len(expected) {
		t.Fatalf("%s: got %d policies, want %d",
			name, len(got.AttestationPolicies), len(expected))
	}
	for i, want := range expected {
		got := got.AttestationPolicies[i]
		if got.Name != want.name {
			t.Errorf("%s policy[%d].Name = %q, want %q",
				name, i, got.Name, want.name)
		}
		if got.MinAttestors != want.minAttestors {
			t.Errorf("%s policy[%d].MinAttestors = %d, want %d",
				name, i, got.MinAttestors, want.minAttestors)
		}
		if got.Window != want.window {
			t.Errorf("%s policy[%d].Window = %v, want %v",
				name, i, got.Window, want.window)
		}
		if got.Required {
			t.Errorf("%s policy[%d].Required = true, want false (declared opt-in only)",
				name, i)
		}
	}
}

// TestEmptyParams_NoPoliciesExtracted pins the SDK's documented
// behavior that a schema without an attestation_policies key
// extracts to a nil AttestationPolicies slice. Useful as a control
// for the round-trip tests above: if this fails, the SDK has
// changed Extract's defaulting and the round-trip tests' assertions
// no longer measure what they claim to.
func TestEmptyParams_NoPoliciesExtracted(t *testing.T) {
	raw := []byte(`{"activation_delay": 0, "migration_policy": "amendment"}`)
	entry := &envelope.Entry{DomainPayload: raw}
	ex := schema.NewJSONParameterExtractor()
	got, err := ex.Extract(entry)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got.AttestationPolicies != nil {
		t.Errorf("empty schema produced %d policies, want nil",
			len(got.AttestationPolicies))
	}
}
