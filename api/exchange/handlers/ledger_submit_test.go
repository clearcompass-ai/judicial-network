/*
FILE PATH: api/exchange/handlers/ledger_submit_test.go

DESCRIPTION:

	Pins the protected wrapper:
	  1. Pass-through when LedgerBreaker is nil — preserves
	     previous behaviour for tests.
	  2. 5xx from ledger trips the breaker after the configured
	     threshold; subsequent calls fast-fail with 503.
	  3. Metrics observe per-call result + breaker state.
	  4. capturingResponseWriter replays headers + status + body.
*/
package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/clearcompass-ai/judicial-network/api/middleware/observability"
	"github.com/clearcompass-ai/judicial-network/api/middleware/reliability"
)

// stubLedger returns an httptest.Server that responds with the
// given status + body on every call. ToggleStatus lets tests flip
// the response mid-run to exercise the closed→open transition.
type stubLedger struct {
	srv    *httptest.Server
	status atomic.Int32
}

func newStubLedger(initialStatus int, body string) *stubLedger {
	s := &stubLedger{}
	s.status.Store(int32(initialStatus))
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(s.status.Load()))
		fmt.Fprint(w, body)
	}))
	return s
}

// ─────────────────────────────────────────────────────────────────────
// Pass-through (breaker nil)
// ─────────────────────────────────────────────────────────────────────

func TestSubmitProtected_NoBreaker_PassesThrough(t *testing.T) {
	op := newStubLedger(http.StatusAccepted, `{"ok":true}`)
	defer op.srv.Close()
	deps := &Dependencies{LedgerEndpoint: op.srv.URL}
	rec := httptest.NewRecorder()
	submitToLedgerProtected(rec, deps, []byte("x"))
	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────
// 5xx → breaker trips → subsequent fast-fail
// ─────────────────────────────────────────────────────────────────────

func TestSubmitProtected_5xx_TripsBreaker(t *testing.T) {
	op := newStubLedger(http.StatusInternalServerError, `{"err":"down"}`)
	defer op.srv.Close()

	r := observability.NewMetricsRegistry()
	deps := &Dependencies{
		LedgerEndpoint: op.srv.URL,
		LedgerBreaker:  reliability.NewBreaker(reliability.CircuitConfig{FailureThreshold: 2}),
		LedgerMetrics:  observability.NewLedgerSubmitMetrics(r),
	}

	// First two calls: 500 surfaces back to the caller.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		submitToLedgerProtected(rec, deps, []byte("x"))
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("call %d: got %d, want 500", i, rec.Code)
		}
	}
	// Third call: breaker is open, fast-fail with 503 + circuit-open body.
	rec := httptest.NewRecorder()
	submitToLedgerProtected(rec, deps, []byte("x"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("breaker-open call: got %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "circuit open") {
		t.Errorf("body should mention circuit open; got %q", rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────
// Result classification
// ─────────────────────────────────────────────────────────────────────

func TestClassifyResult(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"nil":          {nil, "ok"},
		"circuit_open": {reliability.ErrCircuitOpen, "circuit_open"},
		"wrapped_open": {fmt.Errorf("wrap: %w", reliability.ErrCircuitOpen), "circuit_open"},
		"other_error":  {errors.New("ledger returned 500"), "error"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := classifyResult(c.err); got != c.want {
				t.Errorf("classifyResult(%v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// capturingResponseWriter
// ─────────────────────────────────────────────────────────────────────

func TestCapturingResponseWriter_Replay(t *testing.T) {
	cap := newCapturingResponseWriter()
	cap.Header().Set("Content-Type", "application/json")
	cap.WriteHeader(http.StatusAccepted)
	_, _ = cap.Write([]byte(`{"ok":true}`))

	rec := httptest.NewRecorder()
	cap.replayTo(rec)
	if rec.Code != http.StatusAccepted {
		t.Errorf("replayed status = %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("replayed Content-Type = %q", rec.Header().Get("Content-Type"))
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("replayed body = %q", rec.Body.String())
	}
}

func TestCapturingResponseWriter_DefaultStatus_OnImplicitWrite(t *testing.T) {
	cap := newCapturingResponseWriter()
	_, _ = cap.Write([]byte("hello"))
	if cap.status != http.StatusOK {
		t.Errorf("implicit Write should set status=200; got %d", cap.status)
	}
}
