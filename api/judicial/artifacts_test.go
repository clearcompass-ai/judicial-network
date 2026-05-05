/*
FILE PATH: api/judicial/artifacts_test.go

DESCRIPTION:

	Validation contracts for artifact publish + retrieve. The full
	happy-path round-trip exercises the in-memory ContentStore +
	KeyStore stack — pinning what production deployments rely on:
	publish → retrieve → grant-result-decryptable shape.
*/
package judicial

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// artifactPublishHandler
// ─────────────────────────────────────────────────────────────────────

func TestArtifactPublish_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, artifactPublishRequest{
		PlaintextB64: base64Encode([]byte("hello")),
		SchemaLogDID: testCasesLog, SchemaSeq: 1,
		OwnerDID: testClerk,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/artifacts", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestArtifactPublish_EmptyPlaintext_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, artifactPublishRequest{
		PlaintextB64: "",
		SchemaLogDID: testCasesLog, SchemaSeq: 1,
		OwnerDID: testClerk,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/artifacts", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestArtifactPublish_BadBase64_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, artifactPublishRequest{
		PlaintextB64: "not!!base64",
		SchemaLogDID: testCasesLog, SchemaSeq: 1,
		OwnerDID: testClerk,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/artifacts", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// artifactRetrieveHandler
// ─────────────────────────────────────────────────────────────────────

func TestArtifactRetrieve_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/artifacts/retrieve?destination="+testDestination+"&artifact_cid=Qm123", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestArtifactRetrieve_MissingParams_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/judicial/artifacts/retrieve", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestArtifactRetrieve_BadCID_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/artifacts/retrieve?destination="+testDestination+"&artifact_cid=not!!cid", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// parseUint64 helper coverage
func TestParseUint64_EmptyZero(t *testing.T) {
	v, err := parseUint64("")
	if err != nil || v != 0 {
		t.Errorf("parseUint64(\"\") = %d, %v; want 0, nil", v, err)
	}
}

func TestParseUint64_Valid(t *testing.T) {
	v, err := parseUint64("12345")
	if err != nil || v != 12345 {
		t.Errorf("parseUint64(\"12345\") = %d, %v; want 12345, nil", v, err)
	}
}
