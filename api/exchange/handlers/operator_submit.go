/*
FILE PATH: api/exchange/handlers/operator_submit.go

DESCRIPTION:
    Operator-submit protection wrapper. Wraps submitToOperator (in
    management.go) with two pieces of Phase 14/15 wiring:

      1. reliability.Breaker (Phase 14) — fast-fails when the
         operator is down. Without this, every queued submit
         waits its full 30s timeout against an unresponsive
         operator; at 1000 TPS that's an OOM in seconds.

      2. observability.OperatorSubmitMetrics (Phase 15) — records
         per-submit latency, result class, and breaker state so
         operator-side regressions are visible from the JN
         binary's /metrics output.

    The wrapper is opt-in via Dependencies.OperatorBreaker +
    .OperatorMetrics. Both nil → fall through to bare
    submitToOperator (preserves the current single-tenant /
    test-mode behavior).

    Wire shape preserved
    ────────────────────
    submitToOperator stays as-is (writes to ResponseWriter,
    includes the SDK's RetryAfterRoundTripper for 503/Retry-After
    handling). The protected wrapper drives it through a
    capturingResponseWriter so the breaker can observe pass/fail
    without losing the response body the underlying handler is
    expected to relay back to the caller.
*/
package handlers

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/middleware/reliability"
)

// submitToOperatorProtected runs submitToOperator inside the
// configured circuit breaker + records observability metrics.
// When deps.OperatorBreaker is nil it falls through to bare
// submitToOperator — preserving pre-Phase-3 behavior for tests +
// dev deploys that don't configure the breaker.
func submitToOperatorProtected(w http.ResponseWriter, deps *Dependencies, signed []byte) {
	if deps.OperatorBreaker == nil {
		submitToOperator(w, deps.OperatorEndpoint, signed)
		return
	}

	cap := newCapturingResponseWriter()
	start := time.Now()
	err := deps.OperatorBreaker.Call(func() error {
		submitToOperator(cap, deps.OperatorEndpoint, signed)
		// 5xx from the operator counts as a breaker-trippable
		// failure. 4xx is the caller's problem and does NOT
		// trip the breaker (the operator is healthy; the request
		// was bad).
		if cap.status >= 500 {
			return fmt.Errorf("operator returned %d", cap.status)
		}
		return nil
	})

	result := classifyResult(err)
	if deps.OperatorMetrics != nil {
		deps.OperatorMetrics.Observe(
			time.Since(start).Seconds(),
			result,
			deps.OperatorBreaker.State(),
		)
	}

	if errors.Is(err, reliability.ErrCircuitOpen) {
		// Breaker is open — fast-fail with 503. Don't replay
		// cap (it never ran the inner submit).
		http.Error(w, `{"error":"operator circuit open; retry later"}`,
			http.StatusServiceUnavailable)
		return
	}
	cap.replayTo(w)
}

func classifyResult(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, reliability.ErrCircuitOpen) {
		return "circuit_open"
	}
	return "error"
}

// capturingResponseWriter buffers everything submitToOperator
// writes so the protected wrapper can inspect status (for breaker
// fail/pass classification) before replaying to the real
// http.ResponseWriter. Implementation is deliberately small —
// status + headers + body buffer. No chunked-encoding complexity
// because submitToOperator's response is a single small JSON
// document.
type capturingResponseWriter struct {
	status  int
	header  http.Header
	body    bytes.Buffer
	written bool
}

func newCapturingResponseWriter() *capturingResponseWriter {
	return &capturingResponseWriter{header: http.Header{}}
}

func (c *capturingResponseWriter) Header() http.Header {
	return c.header
}

func (c *capturingResponseWriter) WriteHeader(code int) {
	if c.written {
		return
	}
	c.status = code
	c.written = true
}

func (c *capturingResponseWriter) Write(b []byte) (int, error) {
	if !c.written {
		c.WriteHeader(http.StatusOK)
	}
	return c.body.Write(b)
}

// replayTo writes the captured headers, status, and body to the
// real ResponseWriter in the correct order. Idempotent if the
// caller never wrote anything (the zero status maps to 200 OK).
func (c *capturingResponseWriter) replayTo(w http.ResponseWriter) {
	for k, vs := range c.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if c.status != 0 {
		w.WriteHeader(c.status)
	}
	if c.body.Len() > 0 {
		_, _ = w.Write(c.body.Bytes())
	}
}
