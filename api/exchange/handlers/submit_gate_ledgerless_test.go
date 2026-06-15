package handlers

import (
	"context"
	"testing"

	davidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
)

// TestBundleSubmitGate_LedgerLess_FailsClosed (#124 D9): a gate with NO Authority
// wired (ledger-less boot) substitutes jurisdiction.NoAuthorityChainResolver
// (submit_gate.go:147), so a cosigner CLAIM can never be verified — it is dropped
// and the multi-sig requirement fails CLOSED. Never admit on an unverifiable claim.
//
// Distinct from TestBundleSubmitGate_CaseInitiation_SelfAssertedClerk_RejectedG19,
// which injects an explicit non-nil always-reject Authority (backsNobody{}); this
// exercises the Authority==nil substitution branch that ledger-less boot hits.
func TestBundleSubmitGate_LedgerLess_FailsClosed(t *testing.T) {
	reg := davidsonRegistry(t)
	b := gateBytes(t, atyDID, map[string]any{
		"event_type": "case_initiation",
		"signed_by_capacities": []map[string]any{
			{
				"did": clerkDID, "role": "court_clerk", "exchange": davidson.ExchangeDID,
				"delegation_ref": map[string]any{"log_did": davidson.ExchangeDID, "sequence": 9},
			},
		},
	}, clerkDID)

	// Authority nil AND Resolver nil → the gate substitutes
	// NoAuthorityChainResolver: the clerk claim is unverifiable → dropped →
	// quorum unmet → insufficient_signers.
	rej := (&BundleSubmitGate{Registry: reg}).Admit(context.Background(), b)
	if rej == nil || rej.Code != "insufficient_signers" {
		t.Fatalf("ledger-less gate must fail closed on an unverifiable cosigner claim, got %+v", rej)
	}
}
