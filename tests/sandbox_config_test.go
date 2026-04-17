//go:build sandbox

package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// ═════════════════════════════════════════════════════════════════════
// Sandbox config — single source for all Wave 4 tests
// ═════════════════════════════════════════════════════════════════════

// SandboxConfig holds all endpoint URLs for the dev sandbox.
// Set via environment variables or defaults to localhost.
type SandboxConfig struct {
	OperatorURL      string // Tessera operator: POST /v1/entries, GET /v1/entries/{seq}
	ArtifactStoreURL string // Artifact store: POST /v1/artifacts, GET /v1/artifacts/resolve
	ExchangeURL      string // Exchange: POST /v1/build-sign-submit, key management
	VerificationURL  string // Our verification API: GET /v1/verify/*
	CourtDID         string // Court DID for test court
	OfficersLogDID   string
	CasesLogDID      string
	PartiesLogDID    string

	// Second court — cross-court tests run only when these are set.
	Court2OperatorURL    string
	Court2ExchangeURL    string
	Court2DID            string
	Court2OfficersLogDID string
	Court2CasesLogDID    string
	Court2PartiesLogDID  string

	// Shared anchor — required for cross-court proofs.
	AnchorLogDID    string
	AnchorOperatorURL string
}

func loadSandboxConfig() SandboxConfig {
	return SandboxConfig{
		OperatorURL:      envOr("SANDBOX_OPERATOR_URL", "http://localhost:8001"),
		ArtifactStoreURL: envOr("SANDBOX_ARTIFACT_STORE_URL", "http://localhost:8002"),
		ExchangeURL:      envOr("SANDBOX_EXCHANGE_URL", "http://localhost:8003"),
		VerificationURL:  envOr("SANDBOX_VERIFICATION_URL", "http://localhost:8080"),
		CourtDID:         envOr("SANDBOX_COURT_DID", "did:web:courts.sandbox.gov"),
		OfficersLogDID:   envOr("SANDBOX_OFFICERS_LOG", "did:web:courts.sandbox.gov:officers"),
		CasesLogDID:      envOr("SANDBOX_CASES_LOG", "did:web:courts.sandbox.gov:cases"),
		PartiesLogDID:    envOr("SANDBOX_PARTIES_LOG", "did:web:courts.sandbox.gov:parties"),

		Court2OperatorURL:    os.Getenv("SANDBOX_COURT2_OPERATOR_URL"),
		Court2ExchangeURL:    os.Getenv("SANDBOX_COURT2_EXCHANGE_URL"),
		Court2DID:            os.Getenv("SANDBOX_COURT2_DID"),
		Court2OfficersLogDID: os.Getenv("SANDBOX_COURT2_OFFICERS_LOG"),
		Court2CasesLogDID:    os.Getenv("SANDBOX_COURT2_CASES_LOG"),
		Court2PartiesLogDID:  os.Getenv("SANDBOX_COURT2_PARTIES_LOG"),

		AnchorLogDID:      os.Getenv("SANDBOX_ANCHOR_LOG_DID"),
		AnchorOperatorURL: os.Getenv("SANDBOX_ANCHOR_OPERATOR_URL"),
	}
}

// HasSecondCourt returns true when a second court is fully configured.
func (c SandboxConfig) HasSecondCourt() bool {
	return c.Court2OperatorURL != "" &&
		c.Court2ExchangeURL != "" &&
		c.Court2DID != "" &&
		c.Court2CasesLogDID != "" &&
		c.AnchorLogDID != "" &&
		c.AnchorOperatorURL != ""
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ═════════════════════════════════════════════════════════════════════
// HTTP helpers — submit, fetch, verify
// ═════════════════════════════════════════════════════════════════════

var sandboxClient = &http.Client{Timeout: 30 * time.Second}

// submitEntry sends a build-sign-submit request to the exchange.
// Returns the operator's response (includes log position).
func submitEntry(t *testing.T, cfg SandboxConfig, req map[string]any) map[string]any {
	t.Helper()
	return submitEntryTo(t, cfg.ExchangeURL, req)
}

// submitEntryTo sends to a specific exchange URL (for multi-court tests).
func submitEntryTo(t *testing.T, exchangeURL string, req map[string]any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(req)

	resp, err := sandboxClient.Post(
		exchangeURL+"/v1/build-sign-submit",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("submit entry: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("submit entry: HTTP %d: %s", resp.StatusCode, respBody)
	}

	var result map[string]any
	json.Unmarshal(respBody, &result)
	return result
}

// fetchEntryFrom reads an entry from a specific operator URL.
func fetchEntryFrom(t *testing.T, operatorURL string, seq uint64) map[string]any {
	t.Helper()
	url := fmt.Sprintf("%s/v1/entries/%d", operatorURL, seq)

	resp, err := sandboxClient.Get(url)
	if err != nil {
		t.Fatalf("fetch entry %d: %v", seq, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch entry %d: HTTP %d: %s", seq, resp.StatusCode, body)
	}

	var result map[string]any
	json.Unmarshal(body, &result)
	return result
}

// fetchEntry reads an entry from the primary operator by sequence number.
func fetchEntry(t *testing.T, cfg SandboxConfig, seq uint64) map[string]any {
	t.Helper()
	return fetchEntryFrom(t, cfg.OperatorURL, seq)
}

// verifyOrigin calls GET /v1/verify/origin/{logID}/{pos}.
func verifyOrigin(t *testing.T, cfg SandboxConfig, logID string, pos uint64) map[string]any {
	t.Helper()
	url := fmt.Sprintf("%s/v1/verify/origin/%s/%d", cfg.VerificationURL, logID, pos)
	return httpGET(t, url)
}

// verifyAuthority calls GET /v1/verify/authority/{logID}/{pos}.
func verifyAuthority(t *testing.T, cfg SandboxConfig, logID string, pos uint64) map[string]any {
	t.Helper()
	url := fmt.Sprintf("%s/v1/verify/authority/%s/%d", cfg.VerificationURL, logID, pos)
	return httpGET(t, url)
}

// verifyDelegation calls GET /v1/verify/delegation/{logID}/{pos}.
func verifyDelegation(t *testing.T, cfg SandboxConfig, logID string, pos uint64) map[string]any {
	t.Helper()
	url := fmt.Sprintf("%s/v1/verify/delegation/%s/%d", cfg.VerificationURL, logID, pos)
	return httpGET(t, url)
}

// verifyBatch calls GET /v1/verify/batch/{logID}/{positions}.
func verifyBatch(t *testing.T, cfg SandboxConfig, logID, positions string) map[string]any {
	t.Helper()
	url := fmt.Sprintf("%s/v1/verify/batch/%s/%s", cfg.VerificationURL, logID, positions)
	return httpGET(t, url)
}

// verifyCrossLog calls POST /v1/verify/cross-log.
func verifyCrossLog(t *testing.T, cfg SandboxConfig, body map[string]any) map[string]any {
	t.Helper()
	return httpPOST(t, cfg.VerificationURL+"/v1/verify/cross-log", body)
}

// verifyFraudProof calls POST /v1/verify/fraud-proof.
func verifyFraudProof(t *testing.T, cfg SandboxConfig, body map[string]any) map[string]any {
	t.Helper()
	return httpPOST(t, cfg.VerificationURL+"/v1/verify/fraud-proof", body)
}

// pushArtifact uploads ciphertext to the artifact store.
func pushArtifact(t *testing.T, cfg SandboxConfig, ciphertext []byte, cidStr string) {
	t.Helper()
	req, _ := http.NewRequest("POST", cfg.ArtifactStoreURL+"/v1/artifacts", bytes.NewReader(ciphertext))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Artifact-CID", cidStr)

	resp, err := sandboxClient.Do(req)
	if err != nil {
		t.Fatalf("push artifact: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("push artifact: HTTP %d: %s", resp.StatusCode, body)
	}
}

// fetchArtifact retrieves ciphertext from the artifact store.
func fetchArtifact(t *testing.T, cfg SandboxConfig, cidStr string) []byte {
	t.Helper()
	url := fmt.Sprintf("%s/v1/artifacts/%s", cfg.ArtifactStoreURL, cidStr)

	resp, err := sandboxClient.Get(url)
	if err != nil {
		t.Fatalf("fetch artifact: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch artifact %s: HTTP %d: %s", cidStr, resp.StatusCode, body)
	}
	return body
}

// healthCheck verifies a service is reachable.
func healthCheck(t *testing.T, baseURL string) {
	t.Helper()
	resp, err := sandboxClient.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("health check %s: %v", baseURL, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health check %s: HTTP %d", baseURL, resp.StatusCode)
	}
}

func httpGET(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := sandboxClient.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(body, &result)
	result["_status_code"] = float64(resp.StatusCode)
	return result
}

func httpPOST(t *testing.T, url string, payload map[string]any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(payload)
	resp, err := sandboxClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(respBody, &result)
	result["_status_code"] = float64(resp.StatusCode)
	return result
}
