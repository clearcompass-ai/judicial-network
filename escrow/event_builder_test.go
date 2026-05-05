/*
FILE PATH: escrow/event_builder_test.go

DESCRIPTION:

	Direct unit pin for the JN-side escrow wrappers around the SDK
	recovery primitives. The HTTP handlers in api/judicial/escrow.go
	exercise the same code path through the wire layer; tests here
	fail-fast on misconfiguration before any HTTP plumbing is
	involved.
*/
package escrow

import (
	"testing"
)

const (
	tDestination       = "did:web:state:tn:davidson"
	tCourtDID          = "did:web:state:tn:davidson"
	tFailedExchangeDID = "did:web:state:tn:davidson:exchange-2025"
	tNewExchangeDID    = "did:web:state:tn:davidson:exchange-2026"
	tSignerDID         = "did:web:state:tn:davidson:judge-mcclendon"
)

// ─────────────────────────────────────────────────────────────────────
// BuildRecoveryRequest
// ─────────────────────────────────────────────────────────────────────

func TestBuildRecoveryRequest_RejectsMissingDIDs(t *testing.T) {
	cases := []RecoveryInitiateConfig{
		{Destination: tDestination, FailedExchangeDID: tFailedExchangeDID, NewExchangeDID: tNewExchangeDID},
		{Destination: tDestination, CourtDID: tCourtDID, NewExchangeDID: tNewExchangeDID},
		{Destination: tDestination, CourtDID: tCourtDID, FailedExchangeDID: tFailedExchangeDID},
	}
	for i, cfg := range cases {
		if _, err := BuildRecoveryRequest(cfg); err == nil {
			t.Errorf("case %d should reject — missing one of the required DIDs", i)
		}
	}
}

func TestBuildRecoveryRequest_HappyPath(t *testing.T) {
	res, err := BuildRecoveryRequest(RecoveryInitiateConfig{
		Destination:       tDestination,
		CourtDID:          tCourtDID,
		FailedExchangeDID: tFailedExchangeDID,
		NewExchangeDID:    tNewExchangeDID,
	})
	if err != nil {
		t.Fatalf("BuildRecoveryRequest: %v", err)
	}
	if res == nil || res.RequestEntry == nil {
		t.Fatal("RequestEntry must be non-nil on happy path")
	}
	if res.RequestEntry.Header.SignerDID != tNewExchangeDID {
		t.Errorf("SignerDID = %q, want %q (recovery-request signed by new exchange)",
			res.RequestEntry.Header.SignerDID, tNewExchangeDID)
	}
	if res.RequestEntry.Header.Destination != tDestination {
		t.Errorf("Destination = %q, want %q",
			res.RequestEntry.Header.Destination, tDestination)
	}
}

func TestBuildRecoveryRequest_BadEscrowPackageCID(t *testing.T) {
	_, err := BuildRecoveryRequest(RecoveryInitiateConfig{
		Destination:       tDestination,
		CourtDID:          tCourtDID,
		FailedExchangeDID: tFailedExchangeDID,
		NewExchangeDID:    tNewExchangeDID,
		EscrowPackageCID:  "not-a-valid-cid",
	})
	if err == nil {
		t.Error("expected error for malformed escrow_package_cid")
	}
}

// ─────────────────────────────────────────────────────────────────────
// BuildMigrationRecord
// ─────────────────────────────────────────────────────────────────────

func TestBuildMigrationRecord_RejectsMissingSigner(t *testing.T) {
	if _, err := BuildMigrationRecord(MigrationRecordConfig{
		Destination:       tDestination,
		CourtDID:          tCourtDID,
		FailedExchangeDID: tFailedExchangeDID,
		NewExchangeDID:    tNewExchangeDID,
	}); err == nil {
		t.Error("BuildMigrationRecord MUST reject empty SignerDID")
	}
}

func TestBuildMigrationRecord_HappyPath(t *testing.T) {
	entry, err := BuildMigrationRecord(MigrationRecordConfig{
		Destination:       tDestination,
		SignerDID:         tSignerDID,
		CourtDID:          tCourtDID,
		FailedExchangeDID: tFailedExchangeDID,
		NewExchangeDID:    tNewExchangeDID,
		RecoveryThreshold: 3,
		TriggerCount:      2,
	})
	if err != nil {
		t.Fatalf("BuildMigrationRecord: %v", err)
	}
	if entry.Header.SignerDID != tSignerDID {
		t.Errorf("SignerDID = %q, want %q", entry.Header.SignerDID, tSignerDID)
	}
}
