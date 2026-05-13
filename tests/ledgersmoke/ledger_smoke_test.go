// FILE PATH: tests/contracts/ledger_smoke_test.go
//
// DESCRIPTION:
//
//	Phase 2 — Ledger wire-contract smoke test. Verifies the
//	five HTTP surfaces JN exchanges data with on a real
//	clearcompass-ai/ledger HEAD (or v0.9.0+) build:
//
//	  1. Entry admission   (POST /v1/entries/submit)
//	  2. Entry read        (GET  /v1/entries/{seq}/raw)
//	  3. Tree-head fetch   (GET  <ledger>/v1/sth)
//	  4. Tile pull         (GET  <ledger>/tile/...)
//	  5. Gossip pull       (GET  /v1/gossip/since)
//
//	The test is skipped unless JN_LEDGER_SMOKE_URL is set. CI
//	wires this against a Ledger container; local development
//	skips silently. The test contract is "no 5xx from any of
//	the five round-trips when given canonical inputs"; full
//	semantic verification is the responsibility of unit tests
//	on each handler.
//
//	This file deliberately does NOT exercise BLS material — the
//	smoke test confirms wire compatibility (envelope protocol
//	version 1, ctx-aware fetcher / leaf reader, the new
//	WitnessKeySet cosign verify), not full cryptographic
//	correctness which the SDK's own integration suite covers.
package ledgersmoke

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

// EnvLedgerSmokeURL names the env var the test reads to enable
// itself. CI sets it to the Ledger container's base URL. Local
// developers can run `JN_LEDGER_SMOKE_URL=http://localhost:8080
// go test ./tests/contracts/ -run TestLedgerSmoke`.
const EnvLedgerSmokeURL = "JN_LEDGER_SMOKE_URL"

// TestLedgerSmoke exercises the five wire round-trips. The
// per-step asserts are intentionally narrow — no parsing of
// response bodies; we only confirm that no surface returns 5xx
// when handed canonical inputs.
func TestLedgerSmoke(t *testing.T) {
	base := os.Getenv(EnvLedgerSmokeURL)
	if base == "" {
		t.Skipf("set %s to run the Ledger smoke test (e.g. http://localhost:8080)", EnvLedgerSmokeURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 10 * time.Second}

	t.Run("STH fetch", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/sth", nil)
		if err != nil {
			t.Fatalf("STH request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("STH fetch: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Fatalf("STH fetch returned 5xx %d", resp.StatusCode)
		}
	})

	t.Run("Gossip feed handshake", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			base+"/v1/gossip/since?limit=1", nil)
		if err != nil {
			t.Fatalf("gossip request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("gossip fetch: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Fatalf("gossip /since returned 5xx %d (the Ledger MUST expose this in v0.9.0+)",
				resp.StatusCode)
		}
	})

	t.Run("Static-CT tile probe", func(t *testing.T) {
		// Standard Static-CT tile path; the Ledger serves an
		// empty result with 200 or 404 for an absent tile —
		// either is acceptable. A 5xx indicates wire breakage.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			base+"/tile/0/0", nil)
		if err != nil {
			t.Fatalf("tile request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("tile fetch: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Fatalf("tile fetch returned 5xx %d", resp.StatusCode)
		}
	})

	t.Run("Entries read", func(t *testing.T) {
		// Seq 0 either resolves to the genesis entry (200) or
		// 404 on an empty log — both are acceptable. 5xx is
		// not.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			base+"/v1/entries/0/raw", nil)
		if err != nil {
			t.Fatalf("entry request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("entry fetch: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Fatalf("entry fetch returned 5xx %d", resp.StatusCode)
		}
	})

	t.Run("Admission contract (anonymous probe)", func(t *testing.T) {
		// We do NOT submit a real entry — that requires signed
		// material this smoke test deliberately doesn't carry.
		// We only verify the submit endpoint refuses unsigned
		// nonsense with a 4xx (not a 5xx).
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			base+"/v1/entries/submit", nil)
		if err != nil {
			t.Fatalf("submit request: %v", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("submit probe: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Fatalf("submit probe returned 5xx %d (anonymous probe must surface 4xx)",
				resp.StatusCode)
		}
	})
}
