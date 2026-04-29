/*
FILE PATH: api/exchange/middleware/freshness.go

DESCRIPTION:
    HTTP middleware that gates exchange endpoints on the signed entry's
    freshness — the time between the entry's EventTime and the
    server's wall-clock at admission. Uses the SDK's
    exchange/policy.CheckFreshness primitive; this middleware adapts
    it to net/http and lets each route declare which validity tempo it
    accepts.

KEY ARCHITECTURAL DECISIONS:
    - Three named tempos per ortholog-sdk/APPLY-destination-binding.md:
        TempoAutomated   — 60s   (machine-to-machine, witnesses, anchors)
        TempoInteractive — 5min  (clerks, administrators)
        TempoDeliberative — 30min (deliberative judicial signings)
      The SDK's hard 1-hour ceiling (MaxFreshnessTolerance) is
      preserved by composition: this middleware only ever passes one
      of the three named tempos to CheckFreshness, never an
      arbitrary duration.
    - The middleware is content-aware: it deserializes the request
      body once via envelope.Deserialize, runs the freshness check,
      and re-injects the bytes via a wrapping io.ReadCloser so the
      downstream handler reads the same bytes verbatim. No payload
      copy beyond what the framework already does.
    - Fail-closed JSON 400 with a stable error code:
        freshness_stale     — entry is older than the tempo allows
        freshness_future    — entry's EventTime exceeds the
                              CheckFreshness future-tolerance
        freshness_malformed — body is not a deserializable entry
        freshness_misconfig — programmer passed an out-of-band tempo
    - Clock injection: NowFunc field defaults to time.Now().UTC().
      Tests pin the clock; production never overrides.
    - The middleware does NOT mutate Header.EventTime, NOT cache the
      decision, and NOT silently downgrade. A rejected request never
      reaches the wrapped handler.

KEY DEPENDENCIES:
    - ortholog-sdk/exchange/policy: CheckFreshness, FreshnessAutomated,
      FreshnessInteractive, FreshnessDeliberative, MaxFreshnessTolerance,
      and the typed errors.
    - ortholog-sdk/core/envelope: Deserialize.
*/
package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"
)

// Tempo is a named-tier freshness window. The set is closed; new
// tiers go through the SDK's policy package, not the consumer.
type Tempo int

const (
	// TempoAutomated maps to FreshnessAutomated (60s).
	TempoAutomated Tempo = iota + 1
	// TempoInteractive maps to FreshnessInteractive (5min).
	TempoInteractive
	// TempoDeliberative maps to FreshnessDeliberative (30min).
	TempoDeliberative
)

// String returns the tempo name as it appears in audit logs and
// error responses.
func (t Tempo) String() string {
	switch t {
	case TempoAutomated:
		return "automated"
	case TempoInteractive:
		return "interactive"
	case TempoDeliberative:
		return "deliberative"
	default:
		return "unknown"
	}
}

// duration maps the named tempo to the SDK's policy constant. Any
// new tempo MUST be added here AND in (*Tempo).String above —
// programmer error otherwise.
func (t Tempo) duration() (time.Duration, bool) {
	switch t {
	case TempoAutomated:
		return policy.FreshnessAutomated, true
	case TempoInteractive:
		return policy.FreshnessInteractive, true
	case TempoDeliberative:
		return policy.FreshnessDeliberative, true
	default:
		return 0, false
	}
}

// FreshnessConfig parameterizes a single endpoint's freshness gate.
type FreshnessConfig struct {
	// Tempo selects the validity window for this endpoint.
	Tempo Tempo
	// NowFunc returns the server's clock. nil → time.Now().UTC().
	// Tests inject a deterministic clock here.
	NowFunc func() time.Time
}

// rejectionCode classifies a freshness rejection so monitoring and
// audit pipelines can key off a stable enum.
type rejectionCode string

const (
	codeStale     rejectionCode = "freshness_stale"
	codeFuture    rejectionCode = "freshness_future"
	codeMalformed rejectionCode = "freshness_malformed"
	codeMisconfig rejectionCode = "freshness_misconfig"
)

// rejectionBody is the JSON shape returned on rejection. Stable
// across releases; new fields are additive.
type rejectionBody struct {
	Error      string `json:"error"`
	Code       string `json:"code"`
	Tempo      string `json:"tempo,omitempty"`
	Tolerance  string `json:"tolerance_seconds,omitempty"`
}

// New returns an http.Handler that runs the freshness gate then
// delegates to next. The wrapped request's body has the same bytes
// the original carried — Deserialize-then-rewind is transparent to
// the downstream handler.
func New(cfg FreshnessConfig, next http.Handler) http.Handler {
	if next == nil {
		panic("middleware/freshness: nil next handler")
	}
	tolerance, ok := cfg.Tempo.duration()
	if !ok {
		// Returning a panicking handler at construction time is the
		// right disposition for a programmer-supplied unknown tempo —
		// the request lifecycle should never see this error.
		panic(fmt.Sprintf("middleware/freshness: unknown tempo %d", cfg.Tempo))
	}
	now := cfg.NowFunc
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeRejection(w, http.StatusBadRequest, rejectionBody{
				Error: fmt.Sprintf("read body: %v", err),
				Code:  string(codeMalformed),
				Tempo: cfg.Tempo.String(),
			})
			return
		}
		_ = r.Body.Close()

		entry, err := envelope.Deserialize(body)
		if err != nil {
			writeRejection(w, http.StatusBadRequest, rejectionBody{
				Error: fmt.Sprintf("deserialize: %v", err),
				Code:  string(codeMalformed),
				Tempo: cfg.Tempo.String(),
			})
			return
		}

		if err := policy.CheckFreshness(entry, now(), tolerance); err != nil {
			code := classifyFreshnessError(err)
			writeRejection(w, http.StatusBadRequest, rejectionBody{
				Error:     err.Error(),
				Code:      string(code),
				Tempo:     cfg.Tempo.String(),
				Tolerance: tolerance.String(),
			})
			return
		}

		// Restore body for downstream handlers.
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

// classifyFreshnessError maps the SDK's typed errors to our stable
// rejection-code enum. Anything we cannot classify becomes
// codeMisconfig — surfacing to operators as a programmer bug rather
// than a request-side fault.
func classifyFreshnessError(err error) rejectionCode {
	switch {
	case errors.Is(err, policy.ErrEntryStale):
		return codeStale
	case errors.Is(err, policy.ErrEntryFuture):
		return codeFuture
	case errors.Is(err, policy.ErrEntryNil),
		errors.Is(err, policy.ErrToleranceZero),
		errors.Is(err, policy.ErrToleranceTooLarge):
		return codeMisconfig
	default:
		return codeMisconfig
	}
}

// writeRejection emits the canonical 4xx JSON body. Sets
// Content-Type, then status, then writes — order matters for
// net/http's auto Content-Length handling.
func writeRejection(w http.ResponseWriter, status int, body rejectionBody) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
