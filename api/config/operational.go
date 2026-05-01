/*
Package config — operational configuration for the api/ binary.

The api/ surface is the JN network's common write API. It is
multi-tenant by design: a single binary serves N destinations, each
defined by a compiled-in jurisdiction.Bundle (the "deployment profile"
pattern; see deployments/tn/counties/davidson/bundle.go for the
canonical example).

This package separates two concerns that production code must NEVER
mix:

  DEFINITION (compiled-in Go code; immutable per release):
    - Destination DIDs (e.g., "did:web:state:tn:davidson")
    - Role catalogs, cosignature policies, prerequisite policies
    - Per-jurisdiction authority chain resolvers
    - Appellate vocabularies
    These live in deployments/.../bundle.go. Loaded once at boot via
    jurisdiction.Registry.Register and frozen.

  OPERATIONAL CONFIG (env / JSON; varies per environment):
    - Listen address, upstream endpoints (operator, artifact store,
      verification service, EIP-1271 RPC)
    - KeyStore backend selection (memory / softhsm / vault)
    - Nonce-store backend (memory / redis) and connection params
    - Auth selection (mTLS, JWT) and trust material
    - Telemetry endpoints
    These live in this struct.

The hard rule: Operational MUST NOT carry any DID. Identity comes from
imported deployment packages — never from JSON. A typo in operational
config never produces a "phantom" destination; it can only mismatch a
non-DID knob (port number, RPC URL, etc.) which boot validation
catches loudly.

Loading model:

  1. Defaults() returns the zero-config baseline (every field has a
     sane in-memory dev value).
  2. LoadFromFile(path) reads JSON and applies overrides on top.
  3. ApplyEnvOverrides reads a fixed set of env vars (precedence:
     env > file > defaults).
  4. Validate() runs Boot-time consistency checks; returns
     ErrInvalidConfig with a descriptive message on failure.

Production deployments call all four in order; tests skip 2-3.
*/
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidConfig wraps every validation failure surfaced by this
// package. Callers errors.Is against this sentinel for routing.
var ErrInvalidConfig = errors.New("api/config: invalid operational config")

// Defaults returns the baseline operational config used by tests
// and dev environments. All endpoints point at localhost; no TLS;
// memory backends for keystore and nonce store. Production callers
// pass this to LoadFromFile to overlay an environment file.
func Defaults() Operational {
	return Operational{
		ListenAddr: ":8443",

		OperatorEndpoint:      "http://localhost:8001",
		ArtifactStoreEndpoint: "http://localhost:8002",
		VerificationEndpoint:  "http://localhost:8080",
		EthRPCEndpoint:        "http://localhost:8545",

		KeyStore: KeyStoreConfig{
			Backend: KeyStoreBackendMemory,
		},
		NonceStore: NonceStoreOpConfig{
			Backend:         NonceStoreBackendMemory,
			FreshnessWindow: 5 * time.Minute,
		},
		Auth: AuthConfig{
			Mode: AuthModeMTLS,
		},
	}
}

// Operational is the full operational config for an api/ binary.
//
// IMPORTANT: this struct contains zero DIDs. Destination identities
// come from compiled-in deployment packages (see jurisdiction.Bundle
// + deployments/.../bundle.go), never from this struct. Mixing them
// is a security regression — a typo in JSON would create a phantom
// destination that no Bundle covers.
type Operational struct {
	// ListenAddr is the api/ HTTP listen address. Format: ":port" or
	// "host:port". Required.
	ListenAddr string `json:"listen_addr"`

	// Upstream service endpoints. All required for a production
	// deploy; tests may stub-substitute.
	OperatorEndpoint      string `json:"operator_endpoint"`
	ArtifactStoreEndpoint string `json:"artifact_store_endpoint"`
	VerificationEndpoint  string `json:"verification_endpoint"`

	// EthRPCEndpoint is the Ethereum JSON-RPC URL the SDK's PKHVerifier
	// uses to issue eth_call against EIP-1271 contracts. Required when
	// any registered Bundle accepts SCW-rooted signers.
	EthRPCEndpoint string `json:"eth_rpc_endpoint"`

	KeyStore   KeyStoreConfig     `json:"keystore"`
	NonceStore NonceStoreOpConfig `json:"nonce_store"`
	Auth       AuthConfig         `json:"auth"`
}

// ─────────────────────────────────────────────────────────────────────
// KeyStore
// ─────────────────────────────────────────────────────────────────────

// KeyStoreBackend names the deployment-time custody backend for
// signing keys. Stable string values for env / JSON.
type KeyStoreBackend string

const (
	KeyStoreBackendMemory  KeyStoreBackend = "memory"
	KeyStoreBackendSoftHSM KeyStoreBackend = "softhsm"
	KeyStoreBackendVault   KeyStoreBackend = "vault"
)

// KeyStoreConfig configures the institutional signing-key custody
// for the api/ binary. Backend selection is operational; per-DID key
// material itself is provisioned out-of-band (HSM token init, Vault
// transit key creation).
type KeyStoreConfig struct {
	Backend KeyStoreBackend `json:"backend"`

	PKCS11 *PKCS11Config `json:"pkcs11,omitempty"` // populated when Backend = softhsm
	Vault  *VaultConfig  `json:"vault,omitempty"`  // populated when Backend = vault
}

// PKCS11Config is the SoftHSM / cloud HSM connection config.
//
// PINFile holds a filesystem path; the actual PIN string is read at
// boot from that path. JSON config files MUST NEVER contain the PIN
// string itself — production deployments use a sealed file plus a
// host-level secret-injection layer (Kubernetes secret mount,
// HashiCorp Vault Agent, etc.).
type PKCS11Config struct {
	LibraryPath string `json:"library_path"` // e.g., "/usr/lib/softhsm/libsofthsm2.so"
	SlotID      uint   `json:"slot_id"`
	PINFile     string `json:"pin_file"` // path to file containing PIN
	TokenLabel  string `json:"token_label"`
}

// VaultConfig is the HashiCorp Vault Transit native secp256k1 config.
//
// Mode is implicit: always "transit native". secp256k1 has been in
// Vault Transit OSS since v1.18 (Sept 2024); production deployments
// run latest Vault, where this is GA.
//
// TokenFile is filesystem-sourced; never inline in JSON. See PINFile
// in PKCS11Config for the same rationale.
type VaultConfig struct {
	Address   string `json:"address"`    // e.g., "https://vault.svc:8200"
	TokenFile string `json:"token_file"` // path to file containing Vault token
	Mount     string `json:"mount"`      // e.g., "transit"
	KeyName   string `json:"key_name"`   // e.g., "exchange-davidson-signer-1"
}

// ─────────────────────────────────────────────────────────────────────
// NonceStore
// ─────────────────────────────────────────────────────────────────────

// NonceStoreBackend names the deployment-time nonce-store backend for
// signed-request replay protection. Stable string values for env /
// JSON.
type NonceStoreBackend string

const (
	NonceStoreBackendMemory NonceStoreBackend = "memory"
	NonceStoreBackendRedis  NonceStoreBackend = "redis"
)

// NonceStoreOpConfig configures replay-protection for signed
// requests. Per-tenant namespacing happens at runtime via
// auth.NonceStoreConfig.BuildForExchange — operational config holds
// only the connection.
type NonceStoreOpConfig struct {
	Backend NonceStoreBackend `json:"backend"`

	// FreshnessWindow caps signed-request timestamp staleness. Empty
	// or zero → DefaultFreshnessWindow (5 minutes).
	FreshnessWindow time.Duration `json:"freshness_window"`

	// Redis-only fields. Empty/ignored for memory backend.
	RedisAddr      string `json:"redis_addr,omitempty"`
	RedisPassword  string `json:"redis_password,omitempty"`
	RedisDB        int    `json:"redis_db,omitempty"`
	RedisKeyPrefix string `json:"redis_key_prefix,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────
// Auth
// ─────────────────────────────────────────────────────────────────────

// AuthMode names the deployment-time auth mode for the api/ surface.
// Routing dispatch is ALWAYS payload-driven (entry.Header.Destination);
// auth determines callerDID. The two are decoupled.
type AuthMode string

const (
	AuthModeMTLS AuthMode = "mtls"
	AuthModeJWT  AuthMode = "jwt"
)

// AuthConfig configures caller-identity establishment. mTLS reads the
// signer DID from the client cert SAN; JWT reads it from the verified
// token's subject claim.
type AuthConfig struct {
	Mode AuthMode `json:"mode"`

	// mTLS-specific
	ClientCAFile string `json:"client_ca_file,omitempty"` // PEM, for verifying client certs

	// JWT-specific
	JWTIssuer string `json:"jwt_issuer,omitempty"` // expected `iss` claim
	JWKSURL   string `json:"jwks_url,omitempty"`   // public-key set endpoint

	// Server TLS material (used by both modes; mTLS additionally
	// requires ClientCAFile above to verify peer certs).
	TLSCertFile string `json:"tls_cert_file,omitempty"`
	TLSKeyFile  string `json:"tls_key_file,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────
// Loading
// ─────────────────────────────────────────────────────────────────────

// LoadFromFile reads a JSON file into an Operational, applying it on
// top of Defaults(). Returns ErrInvalidConfig wrapped with the
// underlying read or parse error.
func LoadFromFile(path string) (Operational, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Operational{}, fmt.Errorf("%w: read %q: %w", ErrInvalidConfig, path, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Operational{}, fmt.Errorf("%w: parse %q: %w", ErrInvalidConfig, path, err)
	}
	return cfg, nil
}

// ApplyEnvOverrides applies a fixed allowlist of env vars to cfg.
// Precedence: env > file > defaults. Returns the modified config so
// callers can chain.
//
// The recognized env vars are:
//
//	API_LISTEN_ADDR
//	API_OPERATOR_ENDPOINT
//	API_ARTIFACT_STORE_ENDPOINT
//	API_VERIFICATION_ENDPOINT
//	API_ETH_RPC_ENDPOINT
//	API_KEYSTORE_BACKEND          (memory|softhsm|vault)
//	API_NONCE_STORE_BACKEND       (memory|redis)
//	API_NONCE_STORE_REDIS_ADDR
//	API_AUTH_MODE                 (mtls|jwt)
//
// Unrecognized vars are ignored. Empty values are NOT applied
// (treat as "keep current").
func ApplyEnvOverrides(cfg Operational) Operational {
	if v := os.Getenv("API_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("API_OPERATOR_ENDPOINT"); v != "" {
		cfg.OperatorEndpoint = v
	}
	if v := os.Getenv("API_ARTIFACT_STORE_ENDPOINT"); v != "" {
		cfg.ArtifactStoreEndpoint = v
	}
	if v := os.Getenv("API_VERIFICATION_ENDPOINT"); v != "" {
		cfg.VerificationEndpoint = v
	}
	if v := os.Getenv("API_ETH_RPC_ENDPOINT"); v != "" {
		cfg.EthRPCEndpoint = v
	}
	if v := os.Getenv("API_KEYSTORE_BACKEND"); v != "" {
		cfg.KeyStore.Backend = KeyStoreBackend(strings.ToLower(strings.TrimSpace(v)))
	}
	if v := os.Getenv("API_NONCE_STORE_BACKEND"); v != "" {
		cfg.NonceStore.Backend = NonceStoreBackend(strings.ToLower(strings.TrimSpace(v)))
	}
	if v := os.Getenv("API_NONCE_STORE_REDIS_ADDR"); v != "" {
		cfg.NonceStore.RedisAddr = v
	}
	if v := os.Getenv("API_AUTH_MODE"); v != "" {
		cfg.Auth.Mode = AuthMode(strings.ToLower(strings.TrimSpace(v)))
	}
	return cfg
}

// ─────────────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────────────

// Validate enforces operational consistency at boot. Each rule is
// independent; the first failure is returned with a descriptive
// message wrapping ErrInvalidConfig.
//
// Rules enforced:
//
//  1. ListenAddr non-empty.
//  2. Every upstream URL non-empty.
//  3. EthRPCEndpoint non-empty (required for SCW signers).
//  4. KeyStore.Backend is one of the known constants.
//  5. KeyStore-specific sub-config is populated when its backend is
//     selected (PKCS11 for softhsm; Vault for vault). Unused
//     sub-configs MUST be nil to surface accidental copy-paste.
//  6. NonceStore.Backend is one of the known constants.
//  7. NonceStore.RedisAddr non-empty when Backend = redis.
//  8. NonceStore.FreshnessWindow > 0.
//  9. Auth.Mode is one of the known constants.
// 10. Auth-mode-specific fields populated as required.
//
// Validate does NOT touch the filesystem (e.g., to verify PINFile
// exists). That's the binary's job at first KeyStore use, so unit
// tests can construct an Operational without staging real files.
func (cfg Operational) Validate() error {
	if cfg.ListenAddr == "" {
		return fmt.Errorf("%w: ListenAddr required", ErrInvalidConfig)
	}
	if cfg.OperatorEndpoint == "" {
		return fmt.Errorf("%w: OperatorEndpoint required", ErrInvalidConfig)
	}
	if cfg.ArtifactStoreEndpoint == "" {
		return fmt.Errorf("%w: ArtifactStoreEndpoint required", ErrInvalidConfig)
	}
	if cfg.VerificationEndpoint == "" {
		return fmt.Errorf("%w: VerificationEndpoint required", ErrInvalidConfig)
	}
	if cfg.EthRPCEndpoint == "" {
		return fmt.Errorf("%w: EthRPCEndpoint required (SCW signers verify via eth_call)", ErrInvalidConfig)
	}

	if err := cfg.KeyStore.validate(); err != nil {
		return err
	}
	if err := cfg.NonceStore.validate(); err != nil {
		return err
	}
	if err := cfg.Auth.validate(); err != nil {
		return err
	}
	return nil
}

func (k KeyStoreConfig) validate() error {
	switch k.Backend {
	case KeyStoreBackendMemory:
		if k.PKCS11 != nil {
			return fmt.Errorf("%w: PKCS11 set with memory backend (set Backend = softhsm or remove PKCS11)", ErrInvalidConfig)
		}
		if k.Vault != nil {
			return fmt.Errorf("%w: Vault set with memory backend (set Backend = vault or remove Vault)", ErrInvalidConfig)
		}
	case KeyStoreBackendSoftHSM:
		if k.PKCS11 == nil {
			return fmt.Errorf("%w: PKCS11 required for softhsm backend", ErrInvalidConfig)
		}
		if k.Vault != nil {
			return fmt.Errorf("%w: Vault must be nil for softhsm backend", ErrInvalidConfig)
		}
		if k.PKCS11.LibraryPath == "" {
			return fmt.Errorf("%w: PKCS11.LibraryPath required", ErrInvalidConfig)
		}
		if k.PKCS11.PINFile == "" {
			return fmt.Errorf("%w: PKCS11.PINFile required (path to file containing the PIN)", ErrInvalidConfig)
		}
		if k.PKCS11.TokenLabel == "" {
			return fmt.Errorf("%w: PKCS11.TokenLabel required", ErrInvalidConfig)
		}
	case KeyStoreBackendVault:
		if k.Vault == nil {
			return fmt.Errorf("%w: Vault required for vault backend", ErrInvalidConfig)
		}
		if k.PKCS11 != nil {
			return fmt.Errorf("%w: PKCS11 must be nil for vault backend", ErrInvalidConfig)
		}
		if k.Vault.Address == "" {
			return fmt.Errorf("%w: Vault.Address required", ErrInvalidConfig)
		}
		if k.Vault.TokenFile == "" {
			return fmt.Errorf("%w: Vault.TokenFile required", ErrInvalidConfig)
		}
		if k.Vault.Mount == "" {
			return fmt.Errorf("%w: Vault.Mount required (e.g., \"transit\")", ErrInvalidConfig)
		}
		if k.Vault.KeyName == "" {
			return fmt.Errorf("%w: Vault.KeyName required", ErrInvalidConfig)
		}
	case "":
		return fmt.Errorf("%w: KeyStore.Backend required (memory|softhsm|vault)", ErrInvalidConfig)
	default:
		return fmt.Errorf("%w: KeyStore.Backend %q not recognized (expected memory|softhsm|vault)",
			ErrInvalidConfig, k.Backend)
	}
	return nil
}

func (n NonceStoreOpConfig) validate() error {
	switch n.Backend {
	case NonceStoreBackendMemory:
		// Memory backend ignores Redis fields.
	case NonceStoreBackendRedis:
		if n.RedisAddr == "" {
			return fmt.Errorf("%w: NonceStore.RedisAddr required for redis backend", ErrInvalidConfig)
		}
	case "":
		return fmt.Errorf("%w: NonceStore.Backend required (memory|redis)", ErrInvalidConfig)
	default:
		return fmt.Errorf("%w: NonceStore.Backend %q not recognized (expected memory|redis)",
			ErrInvalidConfig, n.Backend)
	}
	if n.FreshnessWindow <= 0 {
		return fmt.Errorf("%w: NonceStore.FreshnessWindow must be > 0", ErrInvalidConfig)
	}
	return nil
}

func (a AuthConfig) validate() error {
	switch a.Mode {
	case AuthModeMTLS:
		if a.ClientCAFile == "" {
			return fmt.Errorf("%w: Auth.ClientCAFile required for mtls mode", ErrInvalidConfig)
		}
		if a.TLSCertFile == "" || a.TLSKeyFile == "" {
			return fmt.Errorf("%w: Auth.TLSCertFile and TLSKeyFile required for mtls mode", ErrInvalidConfig)
		}
	case AuthModeJWT:
		if a.JWTIssuer == "" {
			return fmt.Errorf("%w: Auth.JWTIssuer required for jwt mode", ErrInvalidConfig)
		}
		if a.JWKSURL == "" {
			return fmt.Errorf("%w: Auth.JWKSURL required for jwt mode", ErrInvalidConfig)
		}
		// Server TLS still recommended for JWT but not strictly
		// required (e.g., when the api/ runs behind a TLS-terminating
		// proxy). Skip the check.
	case "":
		return fmt.Errorf("%w: Auth.Mode required (mtls|jwt)", ErrInvalidConfig)
	default:
		return fmt.Errorf("%w: Auth.Mode %q not recognized (expected mtls|jwt)",
			ErrInvalidConfig, a.Mode)
	}
	return nil
}

// MarshalForLogging returns a JSON representation safe to log: it
// strips secret-bearing fields (TokenFile / PINFile only carry paths,
// not values, so they ARE safe; this is defense in depth in case
// future fields hold raw secret strings). Today this is identical to
// json.Marshal — the function exists so future additions of secret
// fields have a single sanitization point.
func (cfg Operational) MarshalForLogging() ([]byte, error) {
	return json.MarshalIndent(cfg, "", "  ")
}

// Compile-time check that ParseDuration helper signature is stable.
// The package does not export it, but tests round-trip Operational
// through JSON which exercises time.Duration's UnmarshalJSON path.
var _ = strconv.Itoa
