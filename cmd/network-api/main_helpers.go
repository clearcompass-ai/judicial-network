/*
FILE PATH: cmd/network-api/main_helpers.go

DESCRIPTION:

	Boot-time helpers split out of main.go to keep that file focused
	on the run() / main() control flow. Owns:

	  - registerProductionBundles : compile-in deployment Bundles
	  - buildNonceStores          : per-destination NonceStore map
	  - buildKeyStore             : memory / softhsm / vault selector
	  - buildAuthenticator        : mTLS / JWT / none selector

	Each helper is independently testable and replaced by a stub in
	main_test.go via the deps struct.
*/
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq" // postgres driver for the durable gossip store

	middleware "github.com/clearcompass-ai/attesta-tools/libs/httpmw"
	"github.com/clearcompass-ai/attesta-tools/libs/httpmw/observability"
	"github.com/clearcompass-ai/attesta-tools/libs/keystore"
	pkcs11ks "github.com/clearcompass-ai/attesta-tools/libs/keystore/pkcs11"
	vaultks "github.com/clearcompass-ai/attesta-tools/libs/keystore/vault"
	sdkauth "github.com/clearcompass-ai/attesta/exchange/auth"
	"github.com/clearcompass-ai/judicial-network/api/config"
	auth "github.com/clearcompass-ai/judicial-network/api/exchange/auth/v2"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"

	"github.com/clearcompass-ai/judicial-network/deployments/registry"
	tncoa "github.com/clearcompass-ai/judicial-network/deployments/tn/coa"
	tndavidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
)

// registerProductionBundles loads every JN deployment Bundle from the
// declarative registry (deployments/registry/) and registers it.
//
// The registry is the single source of truth for which courts exist
// across TN, CA, and the federal hierarchy. Adding a new state or new
// court = adding a Spec entry in deployments/registry/<state>.go; no
// change to this function.
//
// Two legacy single-DID bundles (Davidson umbrella + TN COA umbrella)
// are registered alongside the registry-loaded bundles. These exist
// for backward compatibility with end-to-end tests that hardcode
// did:web:state:tn:davidson and did:web:state:tn:coa as targets; the
// registry provides finer-grained division-level DIDs on top. Both
// can coexist because the DIDs don't collide.
//
// Network isolation is NOT enforced at registry time — the registry
// is a catalog of destination policies, identical across every JN
// binary. Per-network isolation lives at the ledger boundary: the
// network-api binds to one ledger (LEDGER_ENDPOINT); the ledger
// validates that an entry's destination is under its own network_id
// (see attesta/exchange/admission). The e2e provisioner brings up
// multiple JN binaries sharing this same registry; cross-network
// admission is enforced downstream.
func registerProductionBundles(r *jurisdiction.Registry) error {
	// Legacy umbrella DIDs preserved for backward-compat with
	// existing end-to-end tests. The framework's division-level
	// DIDs (registered below by registry.LoadInto) are the new
	// canonical entries.
	for _, factory := range []func() jurisdiction.Bundle{
		tndavidson.MustBundle, // did:web:state:tn:davidson (umbrella)
		tncoa.MustBundle,      // did:web:state:tn:coa     (umbrella)
	} {
		b := factory()
		if err := r.Register(b); err != nil {
			return fmt.Errorf("register %s: %w", b.ExchangeDID(), err)
		}
	}
	// Framework-loaded bundles: 7 Federal + 49 TN + 7 CA (see
	// deployments/registry/registry_test.go for the count pin).
	return registry.LoadInto(r)
}

// buildNonceStores constructs one sdkauth.NonceStore per
// registered destination DID. The resulting map is keyed by
// destination so the v2 auth middleware can look up the right
// store per request from Request.Destination.
//
// Returned errors propagate verbatim so the binary fails loud on
// missing Redis address / invalid backend / etc.
//
// v2 NOTE: the pre-v2 freshness window is GONE — wall-clock
// freshness is now folded into the SDK envelope's
// IssuedAt/ExpiresAt + the SDK's MaxValidityWindow ceiling (1h),
// checked inside sdkauth.VerifyRequest. The NonceStore is replay
// defense only.
func buildNonceStores(cfg config.Operational, r *jurisdiction.Registry) (map[string]sdkauth.NonceStore, error) {
	nonceCfg := auth.NonceStoreConfig{
		Backend:        auth.NonceStoreBackend(cfg.NonceStore.Backend),
		RedisAddr:      cfg.NonceStore.RedisAddr,
		RedisPassword:  cfg.NonceStore.RedisPassword,
		RedisDB:        cfg.NonceStore.RedisDB,
		RedisKeyPrefix: cfg.NonceStore.RedisKeyPrefix,
	}

	out := make(map[string]sdkauth.NonceStore, r.Len())
	for _, did := range r.ExchangeDIDs() {
		s, err := nonceCfg.BuildForExchange(did)
		if err != nil {
			return nil, fmt.Errorf("nonce store for %s: %w", did, err)
		}
		out[did] = s
	}
	return out, nil
}

// buildKeyStore returns a keystore.KeyStore for the configured
// backend.  wires SoftHSM (PKCS#11) and Vault Transit native
// alongside the in-memory dev path. The PKCS#11 backend compiles in
// only with -tags pkcs11; the no-cgo build target returns
// pkcs11.ErrNotBuilt, surfaced here so ledgers see a clear message.
func buildKeyStore(cfg config.KeyStoreConfig) (keystore.KeyStore, error) {
	switch cfg.Backend {
	case config.KeyStoreBackendMemory:
		return keystore.NewMemoryKeyStore(), nil

	case config.KeyStoreBackendSoftHSM:
		if cfg.PKCS11 == nil {
			return nil, fmt.Errorf("keystore: softhsm requires pkcs11 config")
		}
		pin, err := pkcs11ks.LoadPINFile(cfg.PKCS11.PINFile)
		if err != nil {
			return nil, fmt.Errorf("keystore: softhsm: %w", err)
		}
		return pkcs11ks.New(pkcs11ks.Config{
			LibraryPath: cfg.PKCS11.LibraryPath,
			SlotID:      cfg.PKCS11.SlotID,
			PIN:         pin,
			TokenLabel:  cfg.PKCS11.TokenLabel,
		})

	case config.KeyStoreBackendVault:
		if cfg.Vault == nil {
			return nil, fmt.Errorf("keystore: vault requires vault config")
		}
		token, err := vaultks.LoadTokenFile(cfg.Vault.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("keystore: vault: %w", err)
		}
		return vaultks.New(vaultks.Config{
			Address: cfg.Vault.Address,
			Token:   token,
			Mount:   cfg.Vault.Mount,
		})

	default:
		return nil, fmt.Errorf("keystore: unknown backend %q", cfg.Backend)
	}
}

// ledgerProbeClient builds the HTTP client probeLedgerReachable uses at boot.
// It MUST honor the same TLS posture as the rest of the JN→ledger leg, or the
// boot probe fails against an HTTPS ledger that presents a privately-signed cert
// (a bare http.Client verifies against the SYSTEM roots and rejects the run CA):
//
//   - http endpoint                  → plain client (plaintext / dev).
//   - https + client cert+key        → mTLS (present the cert; pin LedgerCAFile).
//   - https + CA only (open HTTPS)    → server-verify (pin LedgerCAFile, no cert).
//   - https + no CA                   → system roots (public-PKI ledger).
//
// Verification is never skipped (no InsecureSkipVerify).
func ledgerProbeClient(cfg config.Operational) (*http.Client, error) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.LedgerEndpoint)), "https://") {
		return &http.Client{Timeout: 3 * time.Second}, nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if cfg.LedgerCAFile != "" {
		caPEM, err := os.ReadFile(cfg.LedgerCAFile)
		if err != nil {
			return nil, fmt.Errorf("read ledger CA %q: %w", cfg.LedgerCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("ledger CA %q contains no parseable certificates", cfg.LedgerCAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.LedgerCertFile != "" && cfg.LedgerKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.LedgerCertFile, cfg.LedgerKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load ledger client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// probeLedgerReachable enforces the JN's hard dependency on the ledger:
// the network is an AUDITOR of a ledger and has no purpose without one, so
// network-api refuses to start unless the ledger answers GET /healthz at
// boot. It retries briefly to tolerate a ledger that is still coming up,
// then fails with a directive error. /readyz keeps the dependency honest
// after boot; this keeps it honest AT boot.
func probeLedgerReachable(ctx context.Context, cfg config.Operational) error {
	url := cfg.LedgerEndpoint + "/healthz"
	client, err := ledgerProbeClient(cfg)
	if err != nil {
		return fmt.Errorf("ledger probe: build client: %w", err)
	}
	const attempts = 5
	var lastErr error
	for i := 1; i <= attempts; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("ledger probe: build request: %w", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode/100 == 2 {
				return nil
			}
			lastErr = fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
		} else {
			lastErr = err
		}
		if i < attempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	return fmt.Errorf("ledger not reachable at %s after %d attempts: %w; "+
		"the JN is an auditor of the ledger and will not start without one "+
		"(bring it up first: cd ../ledger && ./scripts/run-local.sh up)",
		url, attempts, lastErr)
}

// buildReadyzChecks builds the composer's /readyz check list.
// Includes ledger + artifact-store HTTP reachability when their
// respective endpoints are configured. An unset endpoint is
// silently skipped — the composer's /readyz returns 200 only
// when EVERY configured check passes; missing checks neither
// pass nor fail. With the artifact store left out (empty endpoint),
// readiness gates on the ledger alone.
//
// readyzClient threads the binary's hoisted outbound *http.Client so
// the probe shares the operator-chosen mTLS posture (libs/v1.29.0
// CheckHTTPGet panics on nil to prevent silent demotion). When no
// ledger cert/key is configured (dev / pre-cert deploys pointing at
// plaintext), the hoisted client is nil and we fall back to
// http.DefaultClient — matching the deployment's plaintext mode.
func buildReadyzChecks(cfg config.Operational, readyzClient *http.Client) []observability.ReadyCheck {
	if readyzClient == nil {
		readyzClient = http.DefaultClient
	}
	var checks []observability.ReadyCheck
	if cfg.LedgerEndpoint != "" {
		checks = append(checks, observability.CheckHTTPGet(
			"ledger", cfg.LedgerEndpoint+"/healthz", readyzClient))
	}
	if cfg.ArtifactStoreEndpoint != "" {
		checks = append(checks, observability.CheckHTTPGet(
			"artifact_store", cfg.ArtifactStoreEndpoint+"/healthz", readyzClient))
	}
	return checks
}

// buildAuthenticator constructs the composer-level Authenticator from
// cfg.Mode. Returns:
//
//	mtls → middleware.MTLSAuth{} (composer's listener already verifies
//	       the cert chain when ClientCAFile is set; this middleware
//	       lifts the SAN URI DID into request context).
//	jwt  → *middleware.JWTAuth fetched against cfg.JWKSURL using the
//	       supplied hoisted outbound client (libs/v1.29.0 JWTConfig
//	       rejects a nil Client to prevent silent demotion from the
//	       operator-chosen mTLS posture).
//	""   → nil, nil (no auth; dev / single-process deployments).
//
// Any other Mode value is a config-validation failure and never
// reaches here — config.Validate rejects unknown modes at boot.
func buildAuthenticator(cfg config.AuthConfig, jwksClient *http.Client) (middleware.Authenticator, error) {
	switch cfg.Mode {
	case config.AuthModeMTLS:
		return middleware.MTLSAuth{}, nil
	case config.AuthModeJWT:
		if jwksClient == nil {
			jwksClient = http.DefaultClient
		}
		return middleware.NewJWTAuth(middleware.JWTConfig{
			Issuer:  cfg.JWTIssuer,
			JWKSURL: cfg.JWKSURL,
			Client:  jwksClient,
		})
	case "":
		return nil, nil
	default:
		return nil, fmt.Errorf("authenticator: unknown auth mode %q", cfg.Mode)
	}
}

// Custody (the durable gossip.Store + the serve feed) belongs to the external
// auditor, not the JN enforcer (Separation of Duties). buildGossipStore +
// buildGossipFeed were removed in Phase B — the JN hosts neither.

// requireLedgerMTLS enforces the secure-by-default JN→ledger edge: an HTTPS ledger
// endpoint MUST be reached with a client cert (the ledger edge mandates mTLS),
// unless allowPlaintext opts out (TLS-terminating proxy / loopback-dev). A
// plaintext (http) or empty endpoint imposes no requirement. Pure — unit-tested.
func requireLedgerMTLS(endpoint, certFile, keyFile string, allowPlaintext, allowSelfSigned bool, caFile string) error {
	if allowPlaintext || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(endpoint)), "https://") {
		return nil
	}
	// Open-HTTPS opt-in (zero-trust): the ledger serves reads openly and gates
	// writes on the in-body G5 signature, so the JN may verify the ledger's
	// privately-signed/self-signed cert against a pinned CA and present no client
	// cert. The CA is REQUIRED — verification is never skipped.
	if allowSelfSigned {
		if caFile == "" {
			return fmt.Errorf("API_LEDGER_ALLOW_SELF_SIGNED is set but API_LEDGER_CA_FILE is empty: " +
				"a self-signed ledger cert must be pinned to a CA (verification is never skipped)")
		}
		return nil
	}
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("API_LEDGER_ENDPOINT is https but no client cert configured: " +
			"set API_LEDGER_CERT_FILE + API_LEDGER_KEY_FILE (mTLS), or " +
			"API_LEDGER_ALLOW_SELF_SIGNED=true + API_LEDGER_CA_FILE (open HTTPS to a privately-signed ledger), or " +
			"API_LEDGER_ALLOW_PLAINTEXT=true (TLS-terminating-proxy / loopback)")
	}
	return nil
}
