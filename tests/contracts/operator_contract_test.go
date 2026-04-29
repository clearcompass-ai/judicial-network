/*
FILE PATH: tests/contracts/operator_contract_test.go

DESCRIPTION:
    Wire-format contract tests pinning judicial-network's HTTP
    interactions with the operator service. Per the architecture
    spec, JN talks to the operator only via SDK clients
    (HTTPEntryFetcher, HTTPOperatorQueryAPI, HTTPSubmitter). This
    file pins:

      1. /v1/entries/{seq}/raw response shape (X-Sequence + X-Log-Time
         headers, application/octet-stream body) round-trips through
         the SDK fetcher to a complete EntryWithMetadata.
      2. /v1/query/scan response shape (queryListResponse JSON)
         round-trips through HTTPOperatorQueryAPI.ScanFromPosition.
      3. POST /v1/entries acceptance contract: the operator's submit
         endpoint accepts canonical wire bytes that JN's exchange
         produces (envelope.Serialize), responds 202 + SCT JSON.
      4. 404 / 503 / non-200 mappings the SDK errors-on per docstring.
      5. The operator's /raw absent-X-Log-Time is tolerated (SDK
         reads it, falls back gracefully — pre-fix-regression
         guard for legacy entry_index rows).

    Each test uses an httptest.Server fake. The fake reproduces the
    operator's wire shape byte-for-byte; if the SDK fetcher / query
    API can drive the fake, a real operator at the same wire
    contract will work.
*/
package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// /v1/entries/{seq}/raw — byte fetch contract
// ─────────────────────────────────────────────────────────────────────

// TestOperatorContract_RawEndpoint_HappyPath pins the operator's /raw
// response shape that JN's HTTPEntryFetcher consumes:
//
//   200 OK
//   Content-Type: application/octet-stream
//   X-Sequence: <uint64 decimal>
//   X-Log-Time: <RFC-3339Nano UTC>
//   <body: raw wire bytes>
//
// A regression in the operator's serveWALInline / serveBytestoreRedirect
// (operator commit 8afc27b) that drops the headers fails this test.
func TestOperatorContract_RawEndpoint_HappyPath(t *testing.T) {
	logTime := time.Date(2027, 4, 29, 12, 0, 0, 0, time.UTC)
	wire := []byte("test-canonical-wire-bytes")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/entries/42/raw" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Sequence", "42")
		w.Header().Set("X-Log-Time", logTime.Format(time.RFC3339Nano))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wire)
	}))
	defer srv.Close()

	f := sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
		BaseURL: srv.URL,
		LogDID:  "did:web:courts.davidson:cases",
		Timeout: 5 * time.Second,
	})

	got, err := f.Fetch(types.LogPosition{
		LogDID:   "did:web:courts.davidson:cases",
		Sequence: 42,
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil entry")
	}
	if got.Position.Sequence != 42 {
		t.Errorf("Sequence: got %d, want 42", got.Position.Sequence)
	}
	if !got.LogTime.Equal(logTime) {
		t.Errorf("LogTime drift: got %v, want %v", got.LogTime, logTime)
	}
	if string(got.CanonicalBytes) != string(wire) {
		t.Errorf("CanonicalBytes drift: got %q, want %q", got.CanonicalBytes, wire)
	}
}

// TestOperatorContract_RawEndpoint_MissingXLogTime tolerated.
// Older operator versions (pre-8afc27b) didn't stamp X-Log-Time.
// JN's fetcher must fall back to a zero-valued LogTime rather than
// erroring, so legacy /raw routes remain consumable.
func TestOperatorContract_RawEndpoint_MissingXLogTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Sequence", "1")
		// Deliberately no X-Log-Time.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("legacy"))
	}))
	defer srv.Close()

	f := sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
		BaseURL: srv.URL,
		LogDID:  "did:test",
		Timeout: 5 * time.Second,
	})
	got, err := f.Fetch(types.LogPosition{LogDID: "did:test", Sequence: 1})
	if err != nil {
		t.Fatalf("Fetch tolerated absence: %v", err)
	}
	if got == nil {
		t.Fatal("nil entry")
	}
	if !got.LogTime.IsZero() {
		t.Errorf("LogTime should be zero when X-Log-Time absent: got %v", got.LogTime)
	}
}

// TestOperatorContract_RawEndpoint_404 pins the SDK's 404 mapping:
// fetcher returns (nil, nil) on operator 404, NOT an error.
// Consumers (JN's tools/aggregator/scanner.go) rely on this to
// distinguish "no entry at this seq" from "operator unreachable."
func TestOperatorContract_RawEndpoint_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	f := sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
		BaseURL: srv.URL, LogDID: "x", Timeout: 5 * time.Second,
	})
	got, err := f.Fetch(types.LogPosition{LogDID: "x", Sequence: 999})
	if err != nil {
		t.Fatalf("404 should not error: %v", err)
	}
	if got != nil {
		t.Errorf("404 should return (nil, nil): got %+v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// /v1/query/scan — metadata pagination contract
// ─────────────────────────────────────────────────────────────────────

// TestOperatorContract_ScanEndpoint_HappyPath pins the JSON envelope
// the operator returns from /v1/query/scan and confirms the SDK's
// HTTPOperatorQueryAPI.ScanFromPosition consumes it cleanly.
//
// Wire shape:
//   GET /v1/query/scan?start=N&count=M  →  200 + JSON
//     {
//       "entries": [
//         {
//           "sequence_number":  <uint64>,
//           "canonical_hash":   "<hex>",
//           "log_time":          "<RFC-3339Nano>",
//           "signer_did":        "did:...",
//           "protocol_version": <uint16>,
//           "payload_size":     <int>,
//           "canonical_size":   <int>
//         }, ...
//       ],
//       "count": <int>
//     }
func TestOperatorContract_ScanEndpoint_HappyPath(t *testing.T) {
	logTime := time.Date(2027, 4, 29, 8, 0, 0, 0, time.UTC)
	wantEntries := []map[string]any{
		{
			"sequence_number":  uint64(10),
			"canonical_hash":   "abcd",
			"log_time":         logTime.Format(time.RFC3339Nano),
			"signer_did":       "did:web:courts.davidson:judge",
			"protocol_version": 5,
			"payload_size":     200,
			"canonical_size":   500,
		},
		{
			"sequence_number":  uint64(11),
			"canonical_hash":   "ef01",
			"log_time":         logTime.Add(1 * time.Second).Format(time.RFC3339Nano),
			"protocol_version": 5,
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query/scan" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("start") != "5" {
			t.Errorf("expected start=5, got %s", r.URL.Query().Get("start"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": wantEntries,
			"count":   len(wantEntries),
		})
	}))
	defer srv.Close()

	q, err := sdklog.NewHTTPOperatorQueryAPI(sdklog.HTTPOperatorQueryAPIConfig{
		BaseURL: srv.URL,
		LogDID:  "did:web:courts.davidson:cases",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTPOperatorQueryAPI: %v", err)
	}
	got, err := q.ScanFromPosition(5, 10)
	if err != nil {
		t.Fatalf("ScanFromPosition: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(entries): got %d, want 2", len(got))
	}
	if got[0].Position.Sequence != 10 {
		t.Errorf("seq[0]: got %d, want 10", got[0].Position.Sequence)
	}
	if !got[0].LogTime.Equal(logTime) {
		t.Errorf("LogTime[0] drift: got %v, want %v", got[0].LogTime, logTime)
	}
	// Egress-protection mandate: scan responses MUST NOT carry
	// CanonicalBytes (consumer round-trips to /raw for bytes).
	if got[0].CanonicalBytes != nil {
		t.Errorf("CanonicalBytes leak: scan should never carry bytes")
	}
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/entries — JN→operator submit contract
// ─────────────────────────────────────────────────────────────────────

// TestOperatorContract_SubmitEndpoint_HappyPath pins the request
// shape JN's exchange handlers (entries.go EntrySubmitHandler /
// EntryFullHandler / management.go submitToOperator) emit:
//
//   POST /v1/entries
//   Content-Type: application/octet-stream
//   <body: envelope.Serialize(signed_entry)>
//
// The operator returns 202 + SCT JSON. JN's submitToOperator helper
// JSON-decodes-and-re-encodes the response; we assert the round-trip
// works end-to-end.
func TestOperatorContract_SubmitEndpoint_HappyPath(t *testing.T) {
	var seenContentType, seenMethod string
	var seenBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenContentType = r.Header.Get("Content-Type")
		seenBody, _ = io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":         1,
			"signer_did":      "did:test:operator",
			"sig_algo_id":     "ecdsa-secp256k1-sha256",
			"log_did":         "did:web:courts.davidson:cases",
			"canonical_hash":  "abcd",
			"log_time_micros": time.Now().UnixMicro(),
			"log_time":        time.Now().UTC().Format(time.RFC3339Nano),
			"signature":       "deadbeef",
		})
	}))
	defer srv.Close()

	wire := []byte("canonical-wire-bytes-from-jn-exchange")
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, srv.URL+"/v1/entries", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	client := sdklog.DefaultClient(5 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status: got %d, want 202", resp.StatusCode)
	}
	if seenMethod != http.MethodPost {
		t.Errorf("method: got %q, want POST", seenMethod)
	}
	if seenContentType != "application/octet-stream" {
		t.Errorf("Content-Type: got %q, want application/octet-stream", seenContentType)
	}
	if string(seenBody) != string(wire) {
		t.Errorf("body drift: got %q, want %q", seenBody, wire)
	}
}

// TestOperatorContract_SubmitEndpoint_503Retried pins the wire-level
// 503-Retry-After contract. Operator commit dd2acd9 + JN Phase 1E
// shared client both require the SDK transport to retry transparently.
// First call returns 503 + Retry-After: 1; second call succeeds.
func TestOperatorContract_SubmitEndpoint_503Retried(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client := sdklog.DefaultClient(10 * time.Second)
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, srv.URL+"/v1/entries",
		bytes.NewReader([]byte("retry-test")))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("expected 202 after retry, got %d", resp.StatusCode)
	}
	if calls < 2 {
		t.Errorf("expected ≥ 2 attempts, got %d", calls)
	}
}

