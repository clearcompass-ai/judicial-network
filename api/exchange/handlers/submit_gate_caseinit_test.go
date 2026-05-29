/*
FILE PATH: api/exchange/handlers/submit_gate_caseinit_test.go

DESCRIPTION:

	End-to-end coverage for the now-wired SubmitGate on the
	case_initiation genesis event, against the REAL Davidson County
	Bundle (deployments/tn/counties/davidson → tn/trial policy).
	Proves two fixes together:

	  - the cosignature policy declares case_initiation (tn/trial),
	  - the gate derives a per-entry PayloadRoleResolver from the
	    entry's signed_by_capacities block (no off-log registry),

	so a case opened by the cases.InitiateCase builder with a
	declared + actually-signing court_clerk cosigner is ADMITTED,
	while the failure shapes (no cosigner, no event_type, cross-
	exchange clerk, malformed capacities) are each REJECTED with the
	expected closed-set code.

	Signatures here carry a registered AlgoID + dummy bytes: the
	submit gate verifies cosignature ROLE-MIX (CheckCosignature),
	not signature cryptography — that is the ledger's admission job.
*/
package handlers

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"

	"github.com/clearcompass-ai/judicial-network/cases"
	davidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

const (
	atyDID   = "did:key:zATTORNEY"
	clerkDID = "did:key:zCOURTCLERK"
)

func davidsonRegistry(t *testing.T) *jurisdiction.Registry {
	t.Helper()
	reg := jurisdiction.NewRegistry()
	if err := reg.Register(davidson.MustBundle()); err != nil {
		t.Fatalf("register davidson: %v", err)
	}
	reg.Freeze()
	return reg
}

func dummySig(did string) envelope.Signature {
	return envelope.Signature{SignerDID: did, AlgoID: envelope.SigAlgoEd25519, Bytes: make([]byte, 64)}
}

// gateBytes builds a serialized entry with filerDID as the primary
// signer at Signatures[0] plus the listed cosigners, carrying the
// given domain payload. The header is a real validated RootEntity
// header from the builder (the gate reads only payload + signatures
// + destination), keeping the test focused on gate behavior.
func gateBytes(t *testing.T, filerDID string, payload map[string]any, cosignerDIDs ...string) []byte {
	t.Helper()
	tmpl, err := cases.InitiateCase(cases.InitiationConfig{
		Destination:  davidson.ExchangeDID,
		SignerDID:    filerDID,
		DocketNumber: "tmpl",
		CaseType:     "civil",
		FiledDate:    "2027-01-01",
	})
	if err != nil {
		t.Fatalf("template build: %v", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	sigs := []envelope.Signature{dummySig(filerDID)}
	for _, c := range cosignerDIDs {
		sigs = append(sigs, dummySig(c))
	}
	entry, err := envelope.NewEntry(tmpl.Entry.Header, body, sigs)
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	b, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return b
}

// ─── happy path: real builder output → wired gate → admit ──────────

func TestBundleSubmitGate_CaseInitiation_BuilderEndToEnd(t *testing.T) {
	reg := davidsonRegistry(t)
	clerk := schemas.SignedByCapacity{DID: clerkDID, Role: "court_clerk", Exchange: davidson.ExchangeDID}
	built, err := cases.InitiateCase(cases.InitiationConfig{
		Destination:  davidson.ExchangeDID,
		SignerDID:    atyDID,
		DocketNumber: "2027-CR-7",
		CaseType:     "criminal",
		FiledDate:    "2027-03-15",
		Cosigners:    []schemas.SignedByCapacity{clerk},
	})
	if err != nil {
		t.Fatalf("InitiateCase: %v", err)
	}
	entry, err := envelope.NewEntry(built.Entry.Header, built.Entry.DomainPayload,
		[]envelope.Signature{dummySig(atyDID), dummySig(clerkDID)})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	b, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	gate := &BundleSubmitGate{Registry: reg}
	if rej := gate.Admit(b); rej != nil {
		t.Fatalf("expected admit, got code=%q reason=%q", rej.Code, rej.Reason)
	}
}

// ─── rejection shapes ──────────────────────────────────────────────

func TestBundleSubmitGate_CaseInitiation_NoCosigner_Rejected(t *testing.T) {
	reg := davidsonRegistry(t)
	// event_type present, but only the filer signs (no court_clerk).
	b := gateBytes(t, atyDID, map[string]any{
		"event_type":    "case_initiation",
		"docket_number": "2027-CR-8",
	})
	rej := (&BundleSubmitGate{Registry: reg}).Admit(b)
	if rej == nil || rej.Code != string("insufficient_signers") {
		t.Fatalf("want insufficient_signers, got %+v", rej)
	}
}

func TestBundleSubmitGate_CaseInitiation_NoEventType_Rejected(t *testing.T) {
	reg := davidsonRegistry(t)
	b := gateBytes(t, atyDID, map[string]any{"docket_number": "2027-CR-9"}, clerkDID)
	rej := (&BundleSubmitGate{Registry: reg}).Admit(b)
	if rej == nil || rej.Code != "missing_event_type" {
		t.Fatalf("want missing_event_type, got %+v", rej)
	}
}

func TestBundleSubmitGate_CaseInitiation_CrossExchangeClerk_Rejected(t *testing.T) {
	reg := davidsonRegistry(t)
	// Clerk signs and is declared, but belongs to a different exchange.
	b := gateBytes(t, atyDID, map[string]any{
		"event_type": "case_initiation",
		"signed_by_capacities": []map[string]any{
			{"did": clerkDID, "role": "court_clerk", "exchange": "did:web:state:tn:shelby"},
		},
	}, clerkDID)
	rej := (&BundleSubmitGate{Registry: reg}).Admit(b)
	if rej == nil || rej.Code != "exchange_mismatch" {
		t.Fatalf("want exchange_mismatch, got %+v", rej)
	}
}

func TestBundleSubmitGate_CaseInitiation_MalformedCapacities_Rejected(t *testing.T) {
	reg := davidsonRegistry(t)
	// signed_by_capacities present but not an array → resolver build fails.
	b := gateBytes(t, atyDID, map[string]any{
		"event_type":           "case_initiation",
		"signed_by_capacities": "not-an-array",
	}, clerkDID)
	rej := (&BundleSubmitGate{Registry: reg}).Admit(b)
	if rej == nil || rej.Code != "malformed_capacities" {
		t.Fatalf("want malformed_capacities, got %+v", rej)
	}
}

func TestBundleSubmitGate_UnknownExchange_Rejected(t *testing.T) {
	// Empty registry → davidson destination is unknown.
	reg := jurisdiction.NewRegistry()
	reg.Freeze()
	b := gateBytes(t, atyDID, map[string]any{"event_type": "case_initiation"}, clerkDID)
	rej := (&BundleSubmitGate{Registry: reg}).Admit(b)
	if rej == nil || rej.Code != "unknown_exchange" {
		t.Fatalf("want unknown_exchange, got %+v", rej)
	}
}
