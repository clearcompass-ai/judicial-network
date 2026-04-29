/*
FILE PATH: api/exchange/middleware/freshness_test.go

COVERAGE:
    Every code path in freshness.go: tempo→duration mapping, all
    three named tempos, rejection classification (stale, future,
    malformed, misconfig), body re-injection, downstream-handler
    isolation, and the panic-on-misconfig contract.
*/
package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"

	"github.com/clearcompass-ai/judicial-network/internal/testutil"
)

// ─── Helpers ────────────────────────────────────────────────────────

func mkSignedEntryAt(t *testing.T, eventTime int64) []byte {
	t.Helper()
	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:exchange.test",
		SignerDID:   "did:web:courts.test.gov",
		Payload:     []byte(`{"k":"v"}`),
		EventTime:   eventTime,
	})
	if err != nil {
		t.Fatalf("BuildRootEntity: %v", err)
	}
	signed := testutil.SignEntry(t, entry, testutil.GenerateSigningKey(t))
	return envelope.Serialize(signed)
}

func passThrough() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, r.Body) // echo body so the test can verify re-injection
	})
}

// ─── Tempo string + duration mapping ────────────────────────────────

func TestTempo_StringAndDuration(t *testing.T) {
	cases := []struct {
		t    Tempo
		name string
		dur  time.Duration
	}{
		{TempoAutomated, "automated", policy.FreshnessAutomated},
		{TempoInteractive, "interactive", policy.FreshnessInteractive},
		{TempoDeliberative, "deliberative", policy.FreshnessDeliberative},
	}
	for _, c := range cases {
		if c.t.String() != c.name {
			t.Errorf("String() = %q, want %q", c.t.String(), c.name)
		}
		got, ok := c.t.duration()
		if !ok || got != c.dur {
			t.Errorf("duration() for %s = (%v,%v), want (%v,true)", c.name, got, ok, c.dur)
		}
	}
	// Unknown tempo:
	if Tempo(99).String() != "unknown" {
		t.Error("unknown tempo should stringify as 'unknown'")
	}
	if _, ok := Tempo(99).duration(); ok {
		t.Error("unknown tempo must not map to a duration")
	}
}

// ─── Happy path: fresh entry passes ─────────────────────────────────

func TestNew_FreshEntry_Passes(t *testing.T) {
	now := time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)
	body := mkSignedEntryAt(t, now.UnixMicro()) // EventTime = now

	h := New(FreshnessConfig{
		Tempo:   TempoInteractive,
		NowFunc: func() time.Time { return now },
	}, passThrough())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(body))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	// Echo body should match — middleware must re-inject bytes verbatim.
	if !bytes.Equal(w.Body.Bytes(), body) {
		t.Errorf("downstream did not receive exact body bytes")
	}
}

// ─── Stale entry rejected with code freshness_stale ────────────────

func TestNew_StaleEntry_RejectedAsStale(t *testing.T) {
	now := time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)
	old := now.Add(-2 * policy.FreshnessAutomated) // way past 60s
	body := mkSignedEntryAt(t, old.UnixMicro())

	h := New(FreshnessConfig{
		Tempo:   TempoAutomated,
		NowFunc: func() time.Time { return now },
	}, passThrough())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(body))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	var rb rejectionBody
	if err := json.Unmarshal(w.Body.Bytes(), &rb); err != nil {
		t.Fatalf("parse rejection: %v", err)
	}
	if rb.Code != string(codeStale) {
		t.Errorf("Code = %q, want %q", rb.Code, codeStale)
	}
	if rb.Tempo != "automated" {
		t.Errorf("Tempo = %q", rb.Tempo)
	}
	if !strings.Contains(rb.Tolerance, "1m") && !strings.Contains(rb.Tolerance, "60s") {
		t.Errorf("Tolerance = %q (want ~60s)", rb.Tolerance)
	}
}

// ─── Future entry rejected with code freshness_future ──────────────

func TestNew_FutureEntry_RejectedAsFuture(t *testing.T) {
	now := time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)
	future := now.Add(10 * time.Minute) // beyond any reasonable skew
	body := mkSignedEntryAt(t, future.UnixMicro())

	h := New(FreshnessConfig{
		Tempo:   TempoAutomated,
		NowFunc: func() time.Time { return now },
	}, passThrough())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(body))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", w.Code)
	}
	var rb rejectionBody
	_ = json.Unmarshal(w.Body.Bytes(), &rb)
	if rb.Code != string(codeFuture) {
		t.Errorf("Code = %q, want %q", rb.Code, codeFuture)
	}
}

// ─── Malformed entry rejected with code freshness_malformed ────────

func TestNew_MalformedEntry_RejectedAsMalformed(t *testing.T) {
	h := New(FreshnessConfig{
		Tempo: TempoAutomated,
	}, passThrough())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader([]byte("garbage")))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", w.Code)
	}
	var rb rejectionBody
	_ = json.Unmarshal(w.Body.Bytes(), &rb)
	if rb.Code != string(codeMalformed) {
		t.Errorf("Code = %q, want %q", rb.Code, codeMalformed)
	}
}

// ─── Body read error → malformed ────────────────────────────────────

type erroringReader struct{}

func (erroringReader) Read([]byte) (int, error)    { return 0, io.ErrUnexpectedEOF }
func (erroringReader) Close() error                { return nil }

func TestNew_BodyReadError_RejectedAsMalformed(t *testing.T) {
	h := New(FreshnessConfig{Tempo: TempoAutomated}, passThrough())
	r := httptest.NewRequest(http.MethodPost, "/v1/entries", nil)
	r.Body = erroringReader{}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", w.Code)
	}
	var rb rejectionBody
	_ = json.Unmarshal(w.Body.Bytes(), &rb)
	if rb.Code != string(codeMalformed) {
		t.Errorf("Code = %q", rb.Code)
	}
}

// ─── Default NowFunc is time.Now().UTC() ───────────────────────────

func TestNew_NilNowFunc_UsesWallClock(t *testing.T) {
	body := mkSignedEntryAt(t, time.Now().UTC().UnixMicro())
	h := New(FreshnessConfig{Tempo: TempoInteractive}, passThrough())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(body))
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ─── classifyFreshnessError covers every typed branch ──────────────

func TestClassifyFreshnessError_AllTypedErrors(t *testing.T) {
	cases := []struct {
		err  error
		want rejectionCode
	}{
		{policy.ErrEntryStale, codeStale},
		{policy.ErrEntryFuture, codeFuture},
		{policy.ErrEntryNil, codeMisconfig},
		{policy.ErrToleranceZero, codeMisconfig},
		{policy.ErrToleranceTooLarge, codeMisconfig},
	}
	for _, c := range cases {
		if got := classifyFreshnessError(c.err); got != c.want {
			t.Errorf("classify(%v) = %q, want %q", c.err, got, c.want)
		}
	}
	// Unknown error → misconfig.
	if got := classifyFreshnessError(io.EOF); got != codeMisconfig {
		t.Errorf("classify(unknown) = %q, want %q", got, codeMisconfig)
	}
}

// ─── Misconfig: panic on unknown tempo ─────────────────────────────

func TestNew_UnknownTempo_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on unknown tempo")
		}
	}()
	_ = New(FreshnessConfig{Tempo: Tempo(99)}, passThrough())
}

func TestNew_NilNext_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil next handler")
		}
	}()
	_ = New(FreshnessConfig{Tempo: TempoAutomated}, nil)
}

// ─── Downstream isolation: rejected request never calls next ───────

func TestNew_Rejected_NeverCallsNext(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	h := New(FreshnessConfig{Tempo: TempoAutomated}, next)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader([]byte("garbage")))
	h.ServeHTTP(w, r)
	if called {
		t.Error("downstream handler must NOT be called on rejection")
	}
}
