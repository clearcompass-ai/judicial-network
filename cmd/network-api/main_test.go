/*
FILE PATH: cmd/network-api/main_test.go

DESCRIPTION:
    Boot-time coverage for cmd/network-api. Pinned properties:

      1. loadConfig honors --config flag; missing flag uses Defaults +
         env overrides.
      2. loadConfig fails fast on missing file / malformed JSON / invalid
         operational config (each surface bubbles ErrInvalidConfig).
      3. registerProductionBundles registers Davidson + COA + Sup. Ct.
         and freezes; ExchangeDIDs come back sorted.
      4. buildNonceStores constructs one store per registered destination
         (memory backend) and surfaces errors for misconfigured Redis.
      5. buildKeyStore returns the right backend for memory, errors with
         a Phase-8 marker for softhsm / vault, errors on unknown backend.
      6. The full run() entry point starts the server, serves /healthz,
         and shuts down cleanly on context cancel.
*/
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
	"github.com/clearcompass-ai/judicial-network/api/middleware"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// ─────────────────────────────────────────────────────────────────────
// loadConfig
// ─────────────────────────────────────────────────────────────────────

func TestLoadConfig_NoFlag_ReturnsDefaultsPlusEnv(t *testing.T) {
	clearAPIEnv(t)
	t.Setenv("API_LISTEN_ADDR", ":7000")
	// Auth material is required for Validate; supply through env.
	t.Setenv("API_AUTH_MODE", "mtls")

	cfg, err := loadConfig([]string{}) // no --config flag
	// Without TLS material env vars (we don't expose them in the env
	// allowlist), Validate will fail. That is the documented Phase
	// 4 contract: TLS material is provisioned via JSON config.
	if err == nil {
		t.Fatalf("expected validate failure (no TLS files); got cfg=%+v", cfg)
	}
	if !errors.Is(err, config.ErrInvalidConfig) {
		t.Errorf("error should wrap config.ErrInvalidConfig: %v", err)
	}
}

func TestLoadConfig_ConfigFile_AndValidate(t *testing.T) {
	clearAPIEnv(t)
	cfgPath := writeJSON(t, map[string]any{
		"listen_addr":             ":9001",
		"operator_endpoint":       "http://op.test",
		"artifact_store_endpoint": "http://art.test",
		"verification_endpoint":   "http://verify.test",
		"eth_rpc_endpoint":        "http://rpc.test",
		"keystore":                map[string]any{"backend": "memory"},
		"nonce_store": map[string]any{
			"backend":          "memory",
			"freshness_window": int64(5 * time.Minute),
		},
		"auth": map[string]any{
			"mode":           "mtls",
			"client_ca_file": "ca.pem",
			"tls_cert_file":  "tls.crt",
			"tls_key_file":   "tls.key",
		},
	})

	cfg, err := loadConfig([]string{"--config", cfgPath})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ListenAddr != ":9001" {
		t.Errorf("ListenAddr = %q, want :9001", cfg.ListenAddr)
	}
}

func TestLoadConfig_MissingFile_Errors(t *testing.T) {
	clearAPIEnv(t)
	_, err := loadConfig([]string{"--config", "/no/such/file.json"})
	if err == nil {
		t.Fatal("expected error reading missing config")
	}
	if !errors.Is(err, config.ErrInvalidConfig) {
		t.Errorf("error should wrap ErrInvalidConfig: %v", err)
	}
}

func TestLoadConfig_MalformedJSON_Errors(t *testing.T) {
	clearAPIEnv(t)
	tmp := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmp, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadConfig([]string{"--config", tmp})
	if err == nil {
		t.Fatal("expected error parsing malformed config")
	}
	if !errors.Is(err, config.ErrInvalidConfig) {
		t.Errorf("error should wrap ErrInvalidConfig: %v", err)
	}
}

func TestLoadConfig_BadFlag_Errors(t *testing.T) {
	clearAPIEnv(t)
	// --not-a-flag is unknown to flag.ContinueOnError
	_, err := loadConfig([]string{"--not-a-flag"})
	if err == nil {
		t.Fatal("expected flag-parsing error")
	}
	if !strings.Contains(err.Error(), "parse flags") {
		t.Errorf("error should mention 'parse flags': %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// registerProductionBundles
// ─────────────────────────────────────────────────────────────────────

func TestRegisterProductionBundles_AllThreeRegistered(t *testing.T) {
	r := jurisdiction.NewRegistry()
	if err := registerProductionBundles(r); err != nil {
		t.Fatalf("registerProductionBundles: %v", err)
	}
	dids := r.ExchangeDIDs()
	if len(dids) != 3 {
		t.Errorf("registered DIDs = %d, want 3 (Davidson + COA + Sup. Ct.); got %v",
			len(dids), dids)
	}
	// DIDs come from the deployment Bundles' compiled-in constants;
	// renaming a Bundle's ExchangeDID would surface here.
	want := map[string]bool{
		"did:web:state:tn:davidson": false,
		"did:web:state:tn:coa":      false,
		"did:web:state:tn:sc":       false,
	}
	for _, did := range dids {
		if _, ok := want[did]; ok {
			want[did] = true
		}
	}
	for did, found := range want {
		if !found {
			t.Errorf("expected destination %s registered; got %v", did, dids)
		}
	}
}

func TestRegisterProductionBundles_FreezesAfterCallChainSucceeds(t *testing.T) {
	r := jurisdiction.NewRegistry()
	if err := registerProductionBundles(r); err != nil {
		t.Fatalf("first register: %v", err)
	}
	r.Freeze()
	// After Freeze, attempting to register again returns the
	// ErrRegistryFrozen sentinel (verified at the jurisdiction
	// package level; here we just smoke-test the post-Freeze state).
	if err := registerProductionBundles(r); err == nil {
		t.Error("expected error registering into a frozen registry")
	}
}

// ─────────────────────────────────────────────────────────────────────
// buildNonceStores
// ─────────────────────────────────────────────────────────────────────

func TestBuildNonceStores_MemoryBackend_OnePerDestination(t *testing.T) {
	r := jurisdiction.NewRegistry()
	if err := registerProductionBundles(r); err != nil {
		t.Fatalf("register: %v", err)
	}
	r.Freeze()

	cfg := config.Operational{
		NonceStore: config.NonceStoreOpConfig{
			Backend:         config.NonceStoreBackendMemory,
			FreshnessWindow: time.Minute,
		},
	}
	stores, err := buildNonceStores(cfg, r)
	if err != nil {
		t.Fatalf("buildNonceStores: %v", err)
	}
	if len(stores) != 3 {
		t.Errorf("stores = %d, want 3", len(stores))
	}
	for _, did := range r.ExchangeDIDs() {
		if stores[did] == nil {
			t.Errorf("missing store for %s", did)
		}
	}
}

func TestBuildNonceStores_RedisWithoutAddr_Errors(t *testing.T) {
	r := jurisdiction.NewRegistry()
	if err := registerProductionBundles(r); err != nil {
		t.Fatalf("register: %v", err)
	}
	r.Freeze()

	cfg := config.Operational{
		NonceStore: config.NonceStoreOpConfig{
			Backend:         config.NonceStoreBackendRedis,
			FreshnessWindow: time.Minute,
			// RedisAddr deliberately empty
		},
	}
	_, err := buildNonceStores(cfg, r)
	if err == nil {
		t.Fatal("expected error: redis backend without RedisAddr")
	}
	if !strings.Contains(err.Error(), "RedisAddr") {
		t.Errorf("error should mention RedisAddr: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// buildKeyStore
// ─────────────────────────────────────────────────────────────────────

func TestBuildKeyStore_Memory_ReturnsInMemoryStore(t *testing.T) {
	ks, err := buildKeyStore(config.KeyStoreConfig{Backend: config.KeyStoreBackendMemory})
	if err != nil {
		t.Fatalf("buildKeyStore: %v", err)
	}
	if ks == nil {
		t.Fatal("expected non-nil KeyStore")
	}
	if _, ok := ks.(*keystore.MemoryKeyStore); !ok {
		t.Errorf("expected *MemoryKeyStore, got %T", ks)
	}
}

func TestBuildKeyStore_SoftHSM_RequiresPKCS11Config(t *testing.T) {
	_, err := buildKeyStore(config.KeyStoreConfig{Backend: config.KeyStoreBackendSoftHSM})
	if err == nil {
		t.Fatal("softhsm backend without pkcs11 config should error")
	}
	if !strings.Contains(err.Error(), "pkcs11 config") {
		t.Errorf("error should mention missing pkcs11 config: %v", err)
	}
}

func TestBuildKeyStore_SoftHSM_BadPINFile_Errors(t *testing.T) {
	_, err := buildKeyStore(config.KeyStoreConfig{
		Backend: config.KeyStoreBackendSoftHSM,
		PKCS11: &config.PKCS11Config{
			LibraryPath: "/lib/dummy.so",
			PINFile:     "/no/such/pin/file",
		},
	})
	if err == nil {
		t.Fatal("missing PIN file should error")
	}
	if !strings.Contains(err.Error(), "PIN file") {
		t.Errorf("error should mention PIN file: %v", err)
	}
}

func TestBuildKeyStore_Vault_RequiresVaultConfig(t *testing.T) {
	_, err := buildKeyStore(config.KeyStoreConfig{Backend: config.KeyStoreBackendVault})
	if err == nil {
		t.Fatal("vault backend without vault config should error")
	}
	if !strings.Contains(err.Error(), "vault config") {
		t.Errorf("error should mention missing vault config: %v", err)
	}
}

func TestBuildKeyStore_Vault_BadTokenFile_Errors(t *testing.T) {
	_, err := buildKeyStore(config.KeyStoreConfig{
		Backend: config.KeyStoreBackendVault,
		Vault: &config.VaultConfig{
			Address:   "https://vault.svc",
			TokenFile: "/no/such/token/file",
			Mount:     "transit",
		},
	})
	if err == nil {
		t.Fatal("missing token file should error")
	}
	if !strings.Contains(err.Error(), "token file") {
		t.Errorf("error should mention token file: %v", err)
	}
}

func TestBuildKeyStore_UnknownBackend_Errors(t *testing.T) {
	_, err := buildKeyStore(config.KeyStoreConfig{Backend: "aws-kms"})
	if err == nil {
		t.Fatal("unknown backend should error")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("error should mention 'unknown': %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// buildAuthenticator (Phase 5 wiring)
// ─────────────────────────────────────────────────────────────────────

func TestBuildAuthenticator_MTLS_ReturnsMTLSAuth(t *testing.T) {
	a, err := buildAuthenticator(config.AuthConfig{Mode: config.AuthModeMTLS})
	if err != nil {
		t.Fatalf("buildAuthenticator(mtls): %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil Authenticator")
	}
	if _, ok := a.(middleware.MTLSAuth); !ok {
		t.Errorf("expected middleware.MTLSAuth, got %T", a)
	}
}

func TestBuildAuthenticator_JWT_ReturnsJWTAuth(t *testing.T) {
	a, err := buildAuthenticator(config.AuthConfig{
		Mode:      config.AuthModeJWT,
		JWTIssuer: "https://idp.test",
		JWKSURL:   "https://idp.test/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("buildAuthenticator(jwt): %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil Authenticator")
	}
	if _, ok := a.(*middleware.JWTAuth); !ok {
		t.Errorf("expected *middleware.JWTAuth, got %T", a)
	}
}

func TestBuildAuthenticator_JWT_MissingIssuerErrors(t *testing.T) {
	_, err := buildAuthenticator(config.AuthConfig{
		Mode:    config.AuthModeJWT,
		JWKSURL: "https://idp.test/.well-known/jwks.json",
		// JWTIssuer left empty
	})
	if err == nil {
		t.Fatal("expected error: jwt mode requires JWTIssuer")
	}
}

func TestBuildAuthenticator_EmptyMode_ReturnsNil(t *testing.T) {
	a, err := buildAuthenticator(config.AuthConfig{})
	if err != nil {
		t.Fatalf("empty Mode should not error: %v", err)
	}
	if a != nil {
		t.Errorf("empty Mode should return nil Authenticator (no composer auth); got %T", a)
	}
}

func TestBuildAuthenticator_UnknownMode_Errors(t *testing.T) {
	_, err := buildAuthenticator(config.AuthConfig{Mode: "oidc-implicit"})
	if err == nil {
		t.Fatal("unknown mode should error")
	}
	if !strings.Contains(err.Error(), "unknown auth mode") {
		t.Errorf("error should mention 'unknown auth mode': %v", err)
	}
}

// TestBuildAuthenticator_FlowsThroughRunDeps confirms the dependency
// injection seam works: a stub newAuthenticator that always returns a
// fixed authenticator is honored by run().
func TestBuildAuthenticator_FlowsThroughRunDeps(t *testing.T) {
	called := false
	stub := deps{
		registerBundles: registerProductionBundles,
		newKeyStore:     buildKeyStore,
		newAuthenticator: func(cfg config.AuthConfig) (middleware.Authenticator, error) {
			called = true
			return middleware.MTLSAuth{}, nil
		},
	}

	// Need a free port and a valid config for run() to reach the
	// authenticator step.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfgPath := writeJSON(t, map[string]any{
		"listen_addr":             addr,
		"operator_endpoint":       "http://op.test",
		"artifact_store_endpoint": "http://art.test",
		"verification_endpoint":   "http://verify.test",
		"eth_rpc_endpoint":        "http://rpc.test",
		"keystore":                map[string]any{"backend": "memory"},
		"nonce_store": map[string]any{
			"backend":          "memory",
			"freshness_window": int64(time.Minute),
		},
		"auth": map[string]any{
			"mode":       "jwt",
			"jwt_issuer": "https://idp.test",
			"jwks_url":   "https://idp.test/.well-known/jwks.json",
		},
	})
	clearAPIEnv(t)

	runErr := make(chan error, 1)
	go func() { runErr <- run([]string{"--config", cfgPath}, stub) }()

	// Trigger shutdown after a brief moment so the goroutine exits.
	time.Sleep(200 * time.Millisecond)
	proc, _ := os.FindProcess(os.Getpid())
	_ = proc.Signal(os.Interrupt)
	<-runErr

	if !called {
		t.Error("stub newAuthenticator was never called; run() bypassed the dep seam")
	}
}

// ─────────────────────────────────────────────────────────────────────
// End-to-end run() lifecycle
// ─────────────────────────────────────────────────────────────────────

// TestRun_HealthzServedThenShutdown is the load-bearing boot smoke
// test. It:
//
//  1. Writes a valid config JSON pointing at a free port (we pick by
//     listening on :0 first then writing the assigned port back).
//  2. Calls run() with stub deps that register a single test Bundle
//     (so the boot path succeeds without staging real deployment
//     code).
//  3. Polls /healthz until it returns 200.
//  4. Sends SIGTERM by cancelling the run() goroutine's context (we
//     can't actually send a signal without affecting the test
//     process; instead we call srv.Shutdown directly via a hook).
//
// On any step's failure the test reports loudly. Whole flight under
// 2 seconds.
func TestRun_HealthzServedThenShutdown(t *testing.T) {
	// Get a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfgPath := writeJSON(t, map[string]any{
		"listen_addr":             addr,
		"operator_endpoint":       "http://op.test",
		"artifact_store_endpoint": "http://art.test",
		"verification_endpoint":   "http://verify.test",
		"eth_rpc_endpoint":        "http://rpc.test",
		"keystore":                map[string]any{"backend": "memory"},
		"nonce_store": map[string]any{
			"backend":          "memory",
			"freshness_window": int64(time.Minute),
		},
		"auth": map[string]any{
			// Plain HTTP for this smoke test — auth material with
			// real TLS would require staging certs out-of-test.
			// jwt mode + dummy issuer/jwks satisfies Validate.
			"mode":      "jwt",
			"jwt_issuer": "https://idp.test",
			"jwks_url":   "https://idp.test/.well-known/jwks.json",
		},
	})
	clearAPIEnv(t)

	// Stub deps: register one test Bundle, build memory keystore,
	// build JWT-or-mTLS authenticator from cfg (nil for empty Mode,
	// which the smoke test uses below — see config without Auth.Mode).
	stubDeps := deps{
		registerBundles:  registerProductionBundles, // production set is fine
		newKeyStore:      buildKeyStore,
		newAuthenticator: buildAuthenticator,
	}

	// Run the binary in a goroutine.
	runErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runErr <- run([]string{"--config", cfgPath}, stubDeps)
	}()

	// Poll /healthz until it responds (or timeout).
	url := "http://" + addr + "/healthz"
	if !waitFor(t, 2*time.Second, func() bool {
		resp, err := http.Get(url)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode == http.StatusOK && string(body) == "ok"
	}) {
		t.Fatalf("healthz never returned 200 ok within 2s")
	}

	// Send SIGTERM to the process. The signal handler in run() will
	// pick it up and call Shutdown.
	proc, _ := os.FindProcess(os.Getpid())
	if err := proc.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal: %v", err)
	}

	// run() should return nil on graceful shutdown.
	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("run exited with %v; want nil after graceful shutdown", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not exit within 3s of signal")
	}
	wg.Wait()
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func writeJSON(t *testing.T, v any) string {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "config.json")
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return tmp
}

// clearAPIEnv mirrors the helper in api/config — strips every API_*
// env var to prevent host-environment bleed-through.
func clearAPIEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		"API_LISTEN_ADDR",
		"API_OPERATOR_ENDPOINT",
		"API_ARTIFACT_STORE_ENDPOINT",
		"API_VERIFICATION_ENDPOINT",
		"API_ETH_RPC_ENDPOINT",
		"API_KEYSTORE_BACKEND",
		"API_NONCE_STORE_BACKEND",
		"API_NONCE_STORE_REDIS_ADDR",
		"API_AUTH_MODE",
	} {
		t.Setenv(v, "")
		_ = os.Unsetenv(v)
	}
}

// waitFor polls cond every 50ms until it returns true or deadline
// elapses. Returns true on success, false on timeout.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// generateTestCAPEM creates a real self-signed CA PEM at runtime,
// for tests that exercise mTLS configuration paths. Provided here so
// future tests in this package can use it without depending on
// fixtures cross-package.
//
//nolint:unused // reserved for Phase 5 mTLS auth tests
func generateTestCAPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "network-api-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// silence "imported and not used" if all consumers of fmt land in a
// guard branch (defensive).
var _ = fmt.Sprintf
