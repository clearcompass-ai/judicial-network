package scenario

import (
	"encoding/json"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	davidsondep "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// seededDavidson builds the Davidson registry and runs the officer seeder, so
// the generated cases' cosigners carry on-log delegation_refs.
func seededDavidson(t *testing.T) *Registry {
	t.Helper()
	reg, _ := seedFixture(t, DavidsonCounty(), trial.MustRoleCatalog())
	return reg
}

// TestGenerateCases_Davidson pins the structural shape of 100 generated cases:
// unique dockets, a clerk primary + a distinct clerk cosigner of the same
// court, a case_initiation event_type, a signed_by_capacities block carrying the
// cosigner's on-log delegation, and real randomization across divisions/types.
func TestGenerateCases_Davidson(t *testing.T) {
	reg := seededDavidson(t)
	plans, err := GenerateCases(reg, 100, testSeed)
	if err != nil {
		t.Fatalf("GenerateCases: %v", err)
	}
	if len(plans) != 100 {
		t.Fatalf("want 100 cases, got %d", len(plans))
	}

	dockets := map[string]bool{}
	specialties := map[string]bool{}
	caseTypes := map[string]bool{}
	for _, pc := range plans {
		if dockets[pc.DocketNumber] {
			t.Errorf("duplicate docket %q", pc.DocketNumber)
		}
		dockets[pc.DocketNumber] = true
		specialties[pc.Specialty] = true
		caseTypes[pc.CaseType] = true

		if pc.Primary.Kind != KindClerk || pc.Cosigner.Kind != KindClerk {
			t.Errorf("%s: signers must be clerks, got %s/%s", pc.DocketNumber, pc.Primary.Kind, pc.Cosigner.Kind)
		}
		if pc.Primary.DID == pc.Cosigner.DID {
			t.Errorf("%s: primary and cosigner must differ", pc.DocketNumber)
		}
		if pc.Primary.Court != pc.Cosigner.Court {
			t.Errorf("%s: primary court %q != cosigner court %q", pc.DocketNumber, pc.Primary.Court, pc.Cosigner.Court)
		}

		assertCaseInitiationPayload(t, pc)
	}

	if len(specialties) < 2 {
		t.Errorf("expected cases across multiple divisions, saw specialties %v", keys(specialties))
	}
	if len(caseTypes) < 3 {
		t.Errorf("expected varied case types, saw %v", keys(caseTypes))
	}
}

// assertCaseInitiationPayload checks the on-log payload the verifier reads.
func assertCaseInitiationPayload(t *testing.T, pc *PlannedCase) {
	t.Helper()
	var p struct {
		EventType    string `json:"event_type"`
		DocketNumber string `json:"docket_number"`
		Status       string `json:"status"`
	}
	if err := json.Unmarshal(pc.Entry.DomainPayload, &p); err != nil {
		t.Fatalf("%s: payload not JSON: %v", pc.DocketNumber, err)
	}
	if p.EventType != "case_initiation" {
		t.Errorf("%s: event_type = %q, want case_initiation", pc.DocketNumber, p.EventType)
	}
	if p.DocketNumber != pc.DocketNumber || p.Status != "active" {
		t.Errorf("%s: payload docket/status drift: %q/%q", pc.DocketNumber, p.DocketNumber, p.Status)
	}
	caps, present, err := schemas.ExtractSignedByCapacities(pc.Entry.DomainPayload)
	if err != nil || !present || len(caps) != 1 {
		t.Fatalf("%s: signed_by_capacities missing/invalid (present=%v err=%v n=%d)", pc.DocketNumber, present, err, len(caps))
	}
	sbc := caps[0]
	if sbc.DID != pc.Cosigner.DID || sbc.Role != "court_clerk" || sbc.Exchange != davidsondep.ExchangeDID {
		t.Errorf("%s: cosigner capacity drift: %+v", pc.DocketNumber, sbc)
	}
	if sbc.DelegationRef == nil {
		t.Errorf("%s: cosigner capacity missing on-log delegation_ref (seed must run first)", pc.DocketNumber)
	}
}

// TestGenerateCases_PassesCosignatureGate proves the generated construction
// satisfies the REAL tn/trial case_initiation cosignature rule: a clerk primary
// + one intra-exchange court_clerk cosigner. CheckCosignature is the role /
// threshold verifier (crypto is a separate layer), so SignerDID-only signatures
// exercise exactly the surface under test.
func TestGenerateCases_PassesCosignatureGate(t *testing.T) {
	reg := seededDavidson(t)
	plans, err := GenerateCases(reg, 5, testSeed)
	if err != nil {
		t.Fatalf("GenerateCases: %v", err)
	}
	pol := trial.MustCosignaturePolicy()
	pc := plans[0]
	pc.Entry.Signatures = []envelope.Signature{
		{SignerDID: pc.Primary.DID},
		{SignerDID: pc.Cosigner.DID},
	}

	// Happy path: the cosigner is a court_clerk of the Davidson exchange.
	ok := verification.NewMapRoleResolver().
		Bind(pc.Cosigner.DID, "court_clerk", davidsondep.ExchangeDID)
	v := verification.CheckCosignature(pc.Entry, pol, ok, davidsondep.ExchangeDID)
	if !v.OK {
		t.Fatalf("case_initiation should pass the cosignature gate, got %s: %s", v.Rejection, v.Reason)
	}

	// Negative: if the lone cosigner is not a court_clerk, the rule fails.
	notClerk := verification.NewMapRoleResolver().
		Bind(pc.Cosigner.DID, "judge", davidsondep.ExchangeDID)
	v2 := verification.CheckCosignature(pc.Entry, pol, notClerk, davidsondep.ExchangeDID)
	if v2.OK || v2.Rejection != verification.CosigRejectInsufficientSigners {
		t.Errorf("a non-clerk cosigner must fail insufficient_signers, got OK=%v rej=%s", v2.OK, v2.Rejection)
	}
}

// TestGenerateCases_Deterministic: same (registry, n, seed) ⇒ identical dockets
// and signing clerks.
func TestGenerateCases_Deterministic(t *testing.T) {
	a, err := GenerateCases(seededDavidson(t), 50, testSeed)
	if err != nil {
		t.Fatalf("GenerateCases a: %v", err)
	}
	b, err := GenerateCases(seededDavidson(t), 50, testSeed)
	if err != nil {
		t.Fatalf("GenerateCases b: %v", err)
	}
	for i := range a {
		if a[i].DocketNumber != b[i].DocketNumber ||
			a[i].Primary.DID != b[i].Primary.DID ||
			a[i].Cosigner.DID != b[i].Cosigner.DID {
			t.Fatalf("case %d not deterministic: %q(%s/%s) vs %q(%s/%s)", i,
				a[i].DocketNumber, a[i].Primary.DID, a[i].Cosigner.DID,
				b[i].DocketNumber, b[i].Primary.DID, b[i].Cosigner.DID)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
