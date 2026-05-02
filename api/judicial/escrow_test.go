/*
FILE PATH: api/judicial/escrow_test.go

DESCRIPTION:
    Validation contracts for the escrow recovery handlers. Pinned:

      Wired routes:
        - 401 on no caller
        - 400 on missing required fields
        - 200 on happy path; BuildResponse shape returned

      501 stubs:
        - 401 on no caller (the auth gate runs first)
        - 501 with operational-reasoning substring on authenticated
          calls (table-driven, mirrors the C6 stub harness)

    The full happy-path correctness (the SDK actually building a
    valid recovery-request entry) is pinned by SDK and migration
    tests; this file proves the HTTP wiring + auth gating only.
*/
package judicial

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	escrowDestination = "did:web:state:tn:davidson"
	escrowCourtDID    = "did:web:state:tn:davidson"
	escrowFailedDID   = "did:web:state:tn:davidson:exchange-2025"
	escrowNewDID      = "did:web:state:tn:davidson:exchange-2026"
)

// ─────────────────────────────────────────────────────────────────────
// initiate-recovery
// ─────────────────────────────────────────────────────────────────────

func TestEscrowInitiate_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, escrowInitiateRequest{
		Destination:       escrowDestination,
		CourtDID:          escrowCourtDID,
		FailedExchangeDID: escrowFailedDID,
		NewExchangeDID:    escrowNewDID,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/escrow/recovery/initiate", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestEscrowInitiate_MissingFields_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, escrowInitiateRequest{Destination: escrowDestination})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/escrow/recovery/initiate", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestEscrowInitiate_HappyPath_200(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, escrowInitiateRequest{
		Destination:       escrowDestination,
		CourtDID:          escrowCourtDID,
		FailedExchangeDID: escrowFailedDID,
		NewExchangeDID:    escrowNewDID,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/escrow/recovery/initiate", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBuildResponse(t, rec.Body.Bytes())
	if resp.SigningPayload == "" {
		t.Error("signing_payload empty")
	}
	if resp.Header == nil || resp.Header.SignerDID != escrowNewDID {
		t.Errorf("Header.SignerDID = %v, want %q (recovery request signed by new exchange)",
			resp.Header, escrowNewDID)
	}
}

// ─────────────────────────────────────────────────────────────────────
// migration-record
// ─────────────────────────────────────────────────────────────────────

func TestEscrowMigrationRecord_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, escrowMigrationRecordRequest{
		Destination:       escrowDestination,
		FailedExchangeDID: escrowFailedDID,
		NewExchangeDID:    escrowNewDID,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/escrow/migration/record", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestEscrowMigrationRecord_MissingFields_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, escrowMigrationRecordRequest{Destination: escrowDestination})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/escrow/migration/record", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestEscrowMigrationRecord_HappyPath_200(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, escrowMigrationRecordRequest{
		Destination:       escrowDestination,
		CourtDID:          escrowCourtDID,
		FailedExchangeDID: escrowFailedDID,
		NewExchangeDID:    escrowNewDID,
		RecoveryThreshold: 3,
		TriggerCount:      2,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/escrow/migration/record", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────
// 501 stubs — table-driven (matches C6 pattern)
// ─────────────────────────────────────────────────────────────────────

var escrowStubRoutes = []struct {
	path string
	hint string
}{
	{"/v1/judicial/escrow/recovery/collect-share",
		"per-recovery state across N share submissions"},
	{"/v1/judicial/escrow/recovery/execute",
		"32-byte MasterKey material"},
	{"/v1/judicial/escrow/arbitration/evaluate",
		"resolved EntryWithMetadata fixtures"},
}

func TestEscrowStubs_NoCaller_401(t *testing.T) {
	for _, tc := range escrowStubRoutes {
		t.Run(tc.path, func(t *testing.T) {
			h := newTestHandler(Dependencies{})
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
		})
	}
}

func TestEscrowStubs_NotImplemented_WithReason(t *testing.T) {
	for _, tc := range escrowStubRoutes {
		t.Run(tc.path, func(t *testing.T) {
			withCaller(t, testJudge)
			h := newTestHandler(Dependencies{})
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tc.path,
				strings.NewReader("{}"))
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotImplemented {
				t.Errorf("status = %d, want 501", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tc.hint) {
				t.Errorf("body should mention %q (operational reasoning); got %s",
					tc.hint, rec.Body.String())
			}
		})
	}
}
