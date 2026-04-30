/*
FILE PATH: api/exchange/handlers/submit_gate_functional_test.go

DESCRIPTION:
    Functional integration tests for the SubmitGate, exercised
    through EntrySubmitHandler.ServeHTTP. Cover the four
    user-visible scenarios:

      1. Pre-3E.4 backward compat — when SubmitGate is nil, the
         handler is a pure proxy. Existing test exercises this;
         here we re-confirm the proxy stays untouched.
      2. Stub gate accepts → request reaches the operator.
      3. Stub gate rejects → handler returns 403 with the gate's
         Code in the body.
      4. Stub gate handles deserialize errors gracefully on
         malformed bodies → 400.
*/
package handlers

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// makeSubmitDeps wires a Dependencies with a stub gate and a
// throwaway operator endpoint that the test fakes via
// httptest.Server. Returns the handler + the operator's
// requested-url channel so tests can assert on forwarding.
func makeSubmitDeps(t *testing.T, gate SubmitGater) (*EntrySubmitHandler, *httptest.Server, chan string) {
	t.Helper()
	hits := make(chan string, 4)
	op := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hits <- string(body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"accepted":true}`))
	}))
	deps := &Dependencies{OperatorEndpoint: op.URL, SubmitGate: gate}
	return NewEntrySubmitHandler(deps), op, hits
}

// opaqueBytes returns bytes the stub gate ignores entirely.
// Stub gates don't deserialize — the gate contract is "the gate
// owns deserialization." Production BundleSubmitGate runs
// envelope.Deserialize internally and returns deserialize_failed
// on garbage, exercised in TestSubmit_GateMalformedBody_400.
func opaqueBytes() []byte {
	return []byte("opaque bytes — stub gate ignores them; production BundleSubmitGate would Deserialize")
}

// ─── pre-3E.4 backward compat: nil gate forwards proxy ────────────

func TestSubmit_NoGate_ProxiesToOperator(t *testing.T) {
	h, op, hits := makeSubmitDeps(t, nil)
	defer op.Close()

	body := []byte("any opaque bytes — gate skipped because nil")
	req := httptest.NewRequest(http.MethodPost,
		"/v1/entries/submit", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	select {
	case got := <-hits:
		if got != string(body) {
			t.Errorf("body forwarded drift: got %q want %q", got, string(body))
		}
	default:
		t.Error("operator did not receive the forwarded body")
	}
}

// ─── gate accepts → request reaches operator ─────────────────────

func TestSubmit_GateAccepts_ForwardsToOperator(t *testing.T) {
	h, op, hits := makeSubmitDeps(t, stubGater{rej: nil})
	defer op.Close()

	body := opaqueBytes()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/entries/submit", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("accept path status: want 200, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	select {
	case <-hits:
	default:
		t.Error("operator should have received the forwarded entry")
	}
}

// ─── gate rejects → 403 with code in body ─────────────────────────

func TestSubmit_GateRejects_403WithCode(t *testing.T) {
	rej := &Rejection{Code: "unknown_event_type", Reason: "wizard_motion"}
	h, op, hits := makeSubmitDeps(t, stubGater{rej: rej})
	defer op.Close()

	body := opaqueBytes()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/entries/submit", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("reject path status: want 403, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unknown_event_type") {
		t.Errorf("rejection Code missing from response body: %s", rec.Body.String())
	}
	select {
	case <-hits:
		t.Error("operator must NOT receive a rejected entry")
	default:
	}
}

// ─── gate skipped on malformed body → 400 ─────────────────────────

func TestSubmit_GateMalformedBody_400(t *testing.T) {
	// Real BundleSubmitGate fails deserialize on garbage bytes.
	// We exercise the handler's error path by giving the stub
	// gate non-Deserialize-able input.
	gate := &BundleSubmitGate{}
	h, op, _ := makeSubmitDeps(t, gate)
	defer op.Close()

	req := httptest.NewRequest(http.MethodPost,
		"/v1/entries/submit", bytes.NewReader([]byte("not an envelope")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("malformed body status: want 400, got %d", rec.Code)
	}
}
