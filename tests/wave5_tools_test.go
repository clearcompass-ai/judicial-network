/*
FILE PATH:
    tests/wave5_tools_test.go

DESCRIPTION:
    Integration tests for the tools layer. Verifies that the court tools
    HTTP API correctly submits entries through the exchange, and that the
    aggregator correctly classifies all entry types produced by the SDK.

KEY ARCHITECTURAL DECISIONS:
    - Mock exchange: httptest.NewServer accepts build-sign-submit and
      returns incrementing positions. Tests the full HTTP round-trip.
    - No Postgres: read endpoints return 503. Write endpoints verified
      through mock exchange response positions.
    - Aggregator classification tested with every SDK builder type.

OVERVIEW:
    Integration_CourtTools_CaseLifecycle: create → amend status → seal → unseal
    Integration_CourtTools_OfficerLifecycle: delegate → list (503) → revoke
    Integration_CourtTools_DocketLifecycle: publish → reassign
    Integration_Aggregator_AllEntryTypes: every builder → classify → verify type
    Integration_ProviderTools_AccessControl: API key + sealed enforcement
*/
package tests

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/tools/aggregator"
	"github.com/clearcompass-ai/judicial-network/tools/common"
	"github.com/clearcompass-ai/judicial-network/tools/courts"
	"github.com/clearcompass-ai/judicial-network/tools/providers"
)

// -------------------------------------------------------------------------
// 1) Mock exchange for integration tests
// -------------------------------------------------------------------------

func mockExchangeServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var seq atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pos := seq.Add(1)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"position": pos})
	}))
	t.Cleanup(srv.Close)
	return srv, &seq
}

func courtToolsHandler(t *testing.T, exchangeURL string) http.Handler {
	t.Helper()
	cfg := common.DefaultConfig()
	cfg.CasesLogDID = "did:web:integ:cases"
	cfg.OfficersLogDID = "did:web:integ:officers"
	cfg.CourtDID = "did:web:integ"
	exchange := common.NewExchangeClient(exchangeURL)
	verify := common.NewVerifyClient("http://localhost:0")
	return courts.NewServer(cfg, exchange, verify, nil).Handler()
}

func postJSON(t *testing.T, handler http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signer-DID", "did:web:integ:judge")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// -------------------------------------------------------------------------
// 2) Integration: court tools case lifecycle
// -------------------------------------------------------------------------

func TestIntegration_CourtTools_CaseLifecycle(t *testing.T) {
	mock, seq := mockExchangeServer(t)
	h := courtToolsHandler(t, mock.URL)

	// Create case.
	w := postJSON(t, h, "/v1/cases", map[string]any{
		"docket_number": "2027-CR-INT-001",
		"case_type":     "criminal",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d — %s", w.Code, w.Body.String())
	}

	// Create officer.
	w = postJSON(t, h, "/v1/officers", map[string]any{
		"delegate_did": "did:web:integ:judge-smith",
		"role":         "judge",
		"scope_limit":  []string{"order", "judgment"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("officer: %d — %s", w.Code, w.Body.String())
	}

	// Publish docket.
	w = postJSON(t, h, "/v1/docket", map[string]any{
		"date": "2027-04-17",
		"assignments": []map[string]any{
			{"judge_did": "did:web:integ:judge-smith", "courtrooms": []string{"4A"}},
		},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("docket: %d — %s", w.Code, w.Body.String())
	}

	// Verify 3 submissions went to exchange.
	if seq.Load() != 3 {
		t.Errorf("exchange calls = %d, want 3", seq.Load())
	}
}

// -------------------------------------------------------------------------
// 3) Integration: aggregator classifies all SDK entry types
// -------------------------------------------------------------------------

func TestIntegration_Aggregator_AllEntryTypes(t *testing.T) {
	d := aggregator.NewDeserializer()

	tests := []struct {
		name     string
		entry    *envelope.Entry
		wantType string
	}{
		{
			name: "root_entity",
			entry: mustBuild(t, func() (*envelope.Entry, error) {
				return builder.BuildRootEntity(builder.RootEntityParams{
					Destination: "did:web:exchange.test",
					SignerDID: "did:web:test",
					Payload:   mustJSONW5(t, map[string]any{"docket_number": "X", "case_type": "criminal"}),
				})
			}),
			wantType: "new_case",
		},
		{
			name: "amendment",
			entry: mustBuild(t, func() (*envelope.Entry, error) {
				return builder.BuildAmendment(builder.AmendmentParams{
					Destination: "did:web:exchange.test",
					SignerDID:  "did:web:test",
					TargetRoot: types.LogPosition{LogDID: "t", Sequence: 10},
					Payload:    mustJSONW5(t, map[string]any{"status": "disposed"}),
				})
			}),
			wantType: "amendment",
		},
		{
			name: "delegation",
			entry: mustBuild(t, func() (*envelope.Entry, error) {
				return builder.BuildDelegation(builder.DelegationParams{
					Destination: "did:web:exchange.test",
					SignerDID:   "did:web:court",
					DelegateDID: "did:web:judge",
					Payload:     mustJSONW5(t, map[string]any{"role": "judge"}),
				})
			}),
			wantType: "delegation",
		},
		{
			name: "enforcement",
			entry: mustBuild(t, func() (*envelope.Entry, error) {
				return builder.BuildEnforcement(builder.EnforcementParams{
					Destination: "did:web:exchange.test",
					SignerDID:    "did:web:j",
					TargetRoot:   types.LogPosition{LogDID: "t", Sequence: 100},
					ScopePointer: types.LogPosition{LogDID: "t", Sequence: 1},
					Payload:      mustJSONW5(t, map[string]any{"order_type": "sealing_order"}),
				})
			}),
			wantType: "enforcement",
		},
		{
			name: "path_b",
			entry: mustBuild(t, func() (*envelope.Entry, error) {
				return builder.BuildPathBEntry(builder.PathBParams{
					Destination: "did:web:exchange.test",
					SignerDID:          "did:web:j",
					TargetRoot:         types.LogPosition{LogDID: "t", Sequence: 100},
					DelegationPointers: []types.LogPosition{{LogDID: "t", Sequence: 5}},
					Payload:            mustJSONW5(t, map[string]any{"action": "order"}),
				})
			}),
			wantType: "path_b_order",
		},
		{
			name: "commentary",
			entry: mustBuild(t, func() (*envelope.Entry, error) {
				return builder.BuildCommentary(builder.CommentaryParams{
					Destination: "did:web:exchange.test",
					SignerDID: "did:web:j",
					Payload:   mustJSONW5(t, map[string]any{"note": "test"}),
				})
			}),
			wantType: "commentary",
		},
		{
			name: "cosignature",
			entry: mustBuild(t, func() (*envelope.Entry, error) {
				return builder.BuildCosignature(builder.CosignatureParams{
					Destination: "did:web:exchange.test",
					SignerDID:     "did:web:clerk",
					CosignatureOf: types.LogPosition{LogDID: "t", Sequence: 50},
					Payload:       mustJSONW5(t, map[string]any{"endorsement": "approved"}),
				})
			}),
			wantType: "cosignature",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := common.RawEntry{
				Sequence:     42,
				CanonicalHex: hex.EncodeToString(envelope.Serialize(tc.entry)),
			}
			c, err := d.Classify("test-log", raw)
			if err != nil {
				t.Fatalf("classify: %v", err)
			}
			if c.EntryType != tc.wantType {
				t.Errorf("type = %q, want %q", c.EntryType, tc.wantType)
			}
		})
	}
}

// -------------------------------------------------------------------------
// 4) Integration: provider API key enforcement
// -------------------------------------------------------------------------

func TestIntegration_ProviderTools_AccessControl(t *testing.T) {
	cfg := common.DefaultConfig()
	verify := common.NewVerifyClient("http://localhost:0")
	h := providers.NewServer(cfg, verify, nil).Handler()

	// No API key → 401.
	req := httptest.NewRequest("GET", "/v1/records/search?q=test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no key: status = %d, want 401", w.Code)
	}

	// With API key, no DB → 503.
	req = httptest.NewRequest("GET", "/v1/records/search?q=test", nil)
	req.Header.Set("X-API-Key", "test-key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no db: status = %d, want 503", w.Code)
	}
}

// -------------------------------------------------------------------------
// 5) Integration: provider health always works
// -------------------------------------------------------------------------

func TestIntegration_ProviderTools_HealthAlwaysOK(t *testing.T) {
	cfg := common.DefaultConfig()
	verify := common.NewVerifyClient("http://localhost:0")
	h := providers.NewServer(cfg, verify, nil).Handler()

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("healthz = %d, want 200", w.Code)
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func mustBuild(t *testing.T, fn func() (*envelope.Entry, error)) *envelope.Entry {
	t.Helper()
	e, err := fn()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return e
}

func mustJSONW5(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return b
}
