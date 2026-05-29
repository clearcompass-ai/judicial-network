/*
FILE PATH: cases/initiation_eventtype_test.go

DESCRIPTION:

	Pins the cosignature-gate contract for InitiateCase: every
	case_initiation entry MUST carry event_type="case_initiation" in
	its domain payload (the closed-set Event Dictionary key the
	submit gate reads), and InitiationConfig.Cosigners MUST surface
	in the payload's signed_by_capacities block so the destination's
	cosignature policy is verifiable. Without event_type the now-wired
	gate rejects with missing_event_type; without the declared
	court_clerk cosigner it rejects with insufficient_signers.
*/
package cases

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

func TestInitiateCase_EmitsEventType(t *testing.T) {
	result, err := InitiateCase(InitiationConfig{
		Destination:  "did:web:state:tn:davidson",
		SignerDID:    courtDID,
		DocketNumber: "2027-CR-2001",
		CaseType:     "criminal",
		FiledDate:    "2027-03-15",
	})
	if err != nil {
		t.Fatalf("InitiateCase: %v", err)
	}
	var p struct {
		EventType string `json:"event_type"`
	}
	if err := json.Unmarshal(result.Entry.DomainPayload, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if p.EventType != "case_initiation" {
		t.Errorf("event_type = %q, want case_initiation", p.EventType)
	}
}

// event_type must be authoritative: an ExtraPayload key of the same
// name cannot clobber the load-bearing value.
func TestInitiateCase_EventTypeNotClobberable(t *testing.T) {
	result, err := InitiateCase(InitiationConfig{
		Destination:  "did:web:state:tn:davidson",
		SignerDID:    courtDID,
		DocketNumber: "2027-CR-2004",
		CaseType:     "criminal",
		FiledDate:    "2027-03-15",
		ExtraPayload: map[string]interface{}{"event_type": "wizard_event"},
	})
	if err != nil {
		t.Fatalf("InitiateCase: %v", err)
	}
	var p struct {
		EventType string `json:"event_type"`
	}
	if err := json.Unmarshal(result.Entry.DomainPayload, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if p.EventType != "case_initiation" {
		t.Errorf("event_type = %q, ExtraPayload must not clobber it", p.EventType)
	}
}

func TestInitiateCase_EmitsSignedByCapacities(t *testing.T) {
	clerk := schemas.SignedByCapacity{
		DID:      "did:key:zClerk",
		Role:     "court_clerk",
		Exchange: "did:web:state:tn:davidson",
	}
	result, err := InitiateCase(InitiationConfig{
		Destination:  "did:web:state:tn:davidson",
		SignerDID:    courtDID,
		DocketNumber: "2027-CV-2002",
		CaseType:     "civil",
		FiledDate:    "2027-03-15",
		Cosigners:    []schemas.SignedByCapacity{clerk},
	})
	if err != nil {
		t.Fatalf("InitiateCase: %v", err)
	}
	caps, present, err := schemas.ExtractSignedByCapacities(result.Entry.DomainPayload)
	if err != nil || !present {
		t.Fatalf("ExtractSignedByCapacities: present=%v err=%v", present, err)
	}
	if len(caps) != 1 || caps[0].DID != clerk.DID || caps[0].Role != "court_clerk" ||
		caps[0].Exchange != clerk.Exchange {
		t.Errorf("signed_by_capacities drift: %+v", caps)
	}
}

// No Cosigners → no signed_by_capacities key (the block is omitted,
// not emitted empty).
func TestInitiateCase_NoCosigners_NoCapacityBlock(t *testing.T) {
	result, err := InitiateCase(InitiationConfig{
		Destination:  "did:web:state:tn:davidson",
		SignerDID:    courtDID,
		DocketNumber: "2027-CV-2005",
		CaseType:     "civil",
		FiledDate:    "2027-03-15",
	})
	if err != nil {
		t.Fatalf("InitiateCase: %v", err)
	}
	_, present, err := schemas.ExtractSignedByCapacities(result.Entry.DomainPayload)
	if err != nil {
		t.Fatalf("ExtractSignedByCapacities: %v", err)
	}
	if present {
		t.Error("expected no signed_by_capacities block when Cosigners is empty")
	}
}

func TestInitiateCase_RejectsInvalidCosigner(t *testing.T) {
	_, err := InitiateCase(InitiationConfig{
		Destination:  "did:web:state:tn:davidson",
		SignerDID:    courtDID,
		DocketNumber: "2027-CV-2003",
		CaseType:     "civil",
		FiledDate:    "2027-03-15",
		Cosigners:    []schemas.SignedByCapacity{{DID: "did:key:zClerk"}}, // missing role + exchange
	})
	if err == nil {
		t.Fatal("expected error for cosigner missing role/exchange")
	}
}
