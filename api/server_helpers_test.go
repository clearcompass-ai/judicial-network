/*
FILE PATH: api/server_helpers_test.go

DESCRIPTION:

	Smoke tests for the  composer-side reliability wiring.
	The reliability primitives have unit tests in
	api/middleware/reliability/; tests here pin that NewServer
	actually applies them to /v1/* routes.

	Pinned:
	  1. Default Config (no rate limit, default 1 MiB body, no
	     timeout) accepts a normal request — backward compat.
	  2. Tiny GlobalBurst trips a 429 after the burst is exhausted.
	  3. MaxBodyBytes set tight rejects an oversized body with 413.
	  4. /healthz is NEVER wrapped — must remain reachable even
	     when other routes are rate-limited / size-capped.
*/
package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestComposerReliability_DefaultConfig_AcceptsNormalRequest(t *testing.T) {
	srv := mustComposer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/verify/origin/did:web:x/100", nil)
	srv.Handler().ServeHTTP(rec, req)
	// We don't assert a specific status — the verification handler
	// will 404 on the empty LogQueries map. The signal here is
	// "the request reached the handler", which means none of the
	// reliability wrappers blocked it.
	if rec.Code == http.StatusTooManyRequests {
		t.Error("default config should not rate-limit normal requests")
	}
	if rec.Code == http.StatusRequestEntityTooLarge {
		t.Error("default config should not 413 a body-less request")
	}
}

func TestComposerReliability_GlobalRateLimit_429sPastBurst(t *testing.T) {
	srv, err := NewServer(Config{
		Addr:        ":0",
		GlobalRPS:   0.0001, // sustained ~0; bucket only refills 1 every ~3h
		GlobalBurst: 2,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	h := srv.Handler()

	hit := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/verify/origin/did:web:x/1", nil)
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// First 2 requests pass the global limiter (each route shares
	// the same global bucket). The 3rd MUST 429.
	if hit() == http.StatusTooManyRequests {
		t.Error("first request should pass the global limiter (burst=2)")
	}
	if hit() == http.StatusTooManyRequests {
		t.Error("second request should pass the global limiter (burst=2)")
	}
	if got := hit(); got != http.StatusTooManyRequests {
		t.Errorf("third request: got %d, want 429 (burst exhausted)", got)
	}
}

func TestComposerReliability_MaxBodyBytes_413sOversize(t *testing.T) {
	srv, err := NewServer(Config{
		Addr:         ":0",
		MaxBodyBytes: 64, // tiny cap to trip easily
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	rec := httptest.NewRecorder()
	body := bytes.NewReader([]byte(strings.Repeat("y", 1024)))
	req := httptest.NewRequest(http.MethodPost, "/v1/entries/build", body)
	req.ContentLength = 1024
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: got %d, want 413", rec.Code)
	}
}

func TestComposerReliability_HealthzNotWrapped(t *testing.T) {
	srv, err := NewServer(Config{
		Addr:        ":0",
		GlobalRPS:   0.0001,
		GlobalBurst: 1, // every route except /healthz is hard-rate-limited
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Burn the bucket on /v1/*.
	_ = func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/verify/origin/did:web:x/1", nil)
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}()
	// /healthz MUST still be 200 — liveness probes never get
	// rate-limited.
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("healthz iter %d: got %d, want 200 (must not be rate-limited)", i, rec.Code)
		}
	}
}
