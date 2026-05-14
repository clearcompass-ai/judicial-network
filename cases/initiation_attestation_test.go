/*
FILE PATH: cases/initiation_attestation_test.go

DESCRIPTION:

	End-to-end pickup tests confirming that InitiateCase threads
	the InitiationConfig.AttestationPolicyName field to the
	envelope's ControlHeader.AttestationPolicyName. The schemas-
	side helper has its own unit tests in schemas/; this file pins
	the wire path so a future refactor that removes the
	SetAttestationPolicy call surfaces in the cases package's own
	test surface.
*/
package cases

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// TestInitiateCase_AttestationPolicy_Applied — when the config
// carries a non-nil non-empty AttestationPolicyName, the built
// entry's ControlHeader carries it.
func TestInitiateCase_AttestationPolicy_Applied(t *testing.T) {
	name := schemas.PolicyCriminalSeniorJudgeConcurrence
	result, err := InitiateCase(InitiationConfig{
		Destination:           "did:web:exchange.test",
		SignerDID:             courtDID,
		DocketNumber:          "2027-CR-1001",
		CaseType:              "criminal",
		FiledDate:             "2027-03-15",
		AttestationPolicyName: &name,
	})
	if err != nil {
		t.Fatalf("InitiateCase: %v", err)
	}
	if result.Entry.Header.AttestationPolicyName == nil {
		t.Fatalf("AttestationPolicyName = nil, want %q", name)
	}
	if got := *result.Entry.Header.AttestationPolicyName; got != name {
		t.Errorf("AttestationPolicyName = %q, want %q", got, name)
	}
}

// TestInitiateCase_AttestationPolicy_NotSet — when config does NOT
// supply an AttestationPolicyName (nil), the entry header stays
// byte-stable (nil). Confirms the no-policy path is unaffected by
// the new wiring.
func TestInitiateCase_AttestationPolicy_NotSet(t *testing.T) {
	result, err := InitiateCase(InitiationConfig{
		Destination:  "did:web:exchange.test",
		SignerDID:    courtDID,
		DocketNumber: "2027-CV-1002",
		CaseType:     "civil",
		FiledDate:    "2027-03-15",
	})
	if err != nil {
		t.Fatalf("InitiateCase: %v", err)
	}
	if result.Entry.Header.AttestationPolicyName != nil {
		t.Errorf("AttestationPolicyName = %q on no-policy config, want nil",
			*result.Entry.Header.AttestationPolicyName)
	}
}
