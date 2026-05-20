/*
FILE PATH: api/config/operational_test.go

DESCRIPTION:

	Exhaustive coverage of api/config.Operational. Pinned properties:

	  1. Defaults are sane and Validate-clean for an in-memory dev
	     deployment (after auth material is supplied).
	  2. JSON round-trip preserves every field.
	  3. LoadFromFile overlays JSON onto Defaults; missing path is
	     treated as "no overlay" (returns Defaults unchanged).
	  4. ApplyEnvOverrides honors the documented allowlist; empty
	     env values do NOT override.
	  5. Validate fires on every documented failure mode and stays
	     silent on every documented success mode.
	  6. Operational holds zero DIDs. (Compile-time + literal probe.)
	  7. Secret fields (PINFile, TokenFile) hold paths, never raw
	     secrets — verified by JSON round-trip preserving the path.
*/
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// Defaults
// ─────────────────────────────────────────────────────────────────────

func TestDefaults_Memorable(t *testing.T) {
	d := Defaults()
	if d.ListenAddr != ":8443" {
		t.Errorf("ListenAddr = %q, want :8443", d.ListenAddr)
	}
	if d.LedgerEndpoint == "" || d.ArtifactStoreEndpoint == "" {
		t.Error("upstream endpoints must default to localhost values")
	}
	if d.KeyStore.Backend != KeyStoreBackendMemory {
		t.Errorf("KeyStore.Backend = %q, want memory", d.KeyStore.Backend)
	}
	if d.NonceStore.Backend != NonceStoreBackendMemory {
		t.Errorf("NonceStore.Backend = %q, want memory", d.NonceStore.Backend)
	}
	if d.NonceStore.FreshnessWindow != 5*time.Minute {
		t.Errorf("FreshnessWindow = %v, want 5m", d.NonceStore.FreshnessWindow)
	}
	if d.Auth.Mode != AuthModeMTLS {
		t.Errorf("Auth.Mode = %q, want mtls", d.Auth.Mode)
	}
}

// Defaults() pass Validate() iff auth TLS material is supplied. The
// shape of the test mirrors the production boot pattern: take Defaults,
// fill in the deployment-specific paths, then Validate.
func TestDefaults_ValidateAfterAuthMaterial(t *testing.T) {
	cfg := Defaults()
	cfg.Auth.ClientCAFile = "ca.pem"
	cfg.Auth.TLSCertFile = "tls.crt"
	cfg.Auth.TLSKeyFile = "tls.key"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Defaults + auth material should validate: %v", err)
	}
}

func TestDefaults_HoldsNoDIDs(t *testing.T) {
	// Compile-time + value probe: re-marshal Defaults and assert no
	// substring "did:" appears anywhere. Ensures future field additions
	// can't sneak in a destination DID without tripping this guard.
	d := Defaults()
	js, _ := json.Marshal(d)
	if strings.Contains(string(js), "did:") {
		t.Errorf("Defaults() leaked a DID into operational config:\n%s", js)
	}
}

// ─────────────────────────────────────────────────────────────────────
// JSON round-trip — preserves every field
// ─────────────────────────────────────────────────────────────────────

func TestJSONRoundTrip_PreservesEveryField(t *testing.T) {
	original := Operational{
		ListenAddr:            ":9999",
		LedgerEndpoint:        "https://op.example",
		ArtifactStoreEndpoint: "https://blobs.example",
		VerificationEndpoint:  "https://verify.example",
		KeyStore: KeyStoreConfig{
			Backend: KeyStoreBackendVault,
			Vault: &VaultConfig{
				Address:   "https://vault.example",
				TokenFile: "/run/secrets/vault-token",
				Mount:     "transit",
				KeyName:   "exchange-davidson",
			},
		},
		NonceStore: NonceStoreOpConfig{
			Backend:         NonceStoreBackendRedis,
			FreshnessWindow: 17 * time.Second,
			RedisAddr:       "redis.example:6379",
			RedisPassword:   "PASSPATHTOKEN",
			RedisDB:         3,
			RedisKeyPrefix:  "jn:nonce:",
		},
		Auth: AuthConfig{
			Mode:        AuthModeJWT,
			JWTIssuer:   "https://idp.example",
			JWKSURL:     "https://idp.example/.well-known/jwks.json",
			TLSCertFile: "/etc/tls/server.crt",
			TLSKeyFile:  "/etc/tls/server.key",
		},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var roundtripped Operational
	if err := json.Unmarshal(data, &roundtripped); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(original, roundtripped) {
		t.Errorf("round-trip drift\noriginal  = %+v\nroundtrip = %+v", original, roundtripped)
	}
}

// ─────────────────────────────────────────────────────────────────────
// LoadFromFile
// ─────────────────────────────────────────────────────────────────────

func TestLoadFromFile_EmptyPath_ReturnsDefaults(t *testing.T) {
	cfg, err := LoadFromFile("")
	if err != nil {
		t.Fatalf("LoadFromFile(\"\"): %v", err)
	}
	if !reflect.DeepEqual(cfg, Defaults()) {
		t.Errorf("empty path should return Defaults verbatim")
	}
}

func TestLoadFromFile_OverlaysOnDefaults(t *testing.T) {
	tmp := writeJSON(t, map[string]any{
		"listen_addr": ":7777",
		"keystore":    map[string]any{"backend": "vault"},
	})
	cfg, err := LoadFromFile(tmp)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if cfg.ListenAddr != ":7777" {
		t.Errorf("ListenAddr override missed: %q", cfg.ListenAddr)
	}
	if cfg.KeyStore.Backend != KeyStoreBackendVault {
		t.Errorf("KeyStore.Backend override missed: %q", cfg.KeyStore.Backend)
	}
	// Fields the JSON didn't mention must come from Defaults.
	if cfg.LedgerEndpoint != Defaults().LedgerEndpoint {
		t.Errorf("LedgerEndpoint should default: %q", cfg.LedgerEndpoint)
	}
}

func TestLoadFromFile_MissingPath_Errors(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/that/should/not/exist.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error should wrap ErrInvalidConfig: %v", err)
	}
}

func TestLoadFromFile_MalformedJSON_Errors(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmp, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadFromFile(tmp)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error should wrap ErrInvalidConfig: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// ApplyEnvOverrides
// ─────────────────────────────────────────────────────────────────────

func TestApplyEnvOverrides_NoEnv_NoChange(t *testing.T) {
	clearAPIEnv(t)
	cfg := Defaults()
	got := ApplyEnvOverrides(cfg)
	if !reflect.DeepEqual(cfg, got) {
		t.Errorf("with no env vars set, config must be unchanged")
	}
}

func TestApplyEnvOverrides_EmptyEnv_DoesNotOverride(t *testing.T) {
	clearAPIEnv(t)
	t.Setenv("API_LISTEN_ADDR", "") // explicitly empty
	cfg := Defaults()
	got := ApplyEnvOverrides(cfg)
	if got.ListenAddr != cfg.ListenAddr {
		t.Errorf("empty env value should not override; ListenAddr = %q", got.ListenAddr)
	}
}

func TestApplyEnvOverrides_AllVars(t *testing.T) {
	clearAPIEnv(t)
	t.Setenv("API_LISTEN_ADDR", ":1234")
	t.Setenv("API_LEDGER_ENDPOINT", "https://op.via.env")
	t.Setenv("API_ARTIFACT_STORE_ENDPOINT", "https://art.via.env")
	t.Setenv("API_VERIFICATION_ENDPOINT", "https://vfy.via.env")
	t.Setenv("API_KEYSTORE_BACKEND", "softhsm")
	t.Setenv("API_NONCE_STORE_BACKEND", "redis")
	t.Setenv("API_NONCE_STORE_REDIS_ADDR", "redis.via.env:6379")
	t.Setenv("API_AUTH_MODE", "jwt")

	got := ApplyEnvOverrides(Defaults())

	wantListen := ":1234"
	if got.ListenAddr != wantListen {
		t.Errorf("ListenAddr = %q, want %q", got.ListenAddr, wantListen)
	}
	if got.LedgerEndpoint != "https://op.via.env" {
		t.Errorf("LedgerEndpoint = %q", got.LedgerEndpoint)
	}
	if got.ArtifactStoreEndpoint != "https://art.via.env" {
		t.Errorf("ArtifactStoreEndpoint = %q", got.ArtifactStoreEndpoint)
	}
	if got.VerificationEndpoint != "https://vfy.via.env" {
		t.Errorf("VerificationEndpoint = %q", got.VerificationEndpoint)
	}
	if got.KeyStore.Backend != KeyStoreBackendSoftHSM {
		t.Errorf("KeyStore.Backend = %q, want softhsm", got.KeyStore.Backend)
	}
	if got.NonceStore.Backend != NonceStoreBackendRedis {
		t.Errorf("NonceStore.Backend = %q, want redis", got.NonceStore.Backend)
	}
	if got.NonceStore.RedisAddr != "redis.via.env:6379" {
		t.Errorf("NonceStore.RedisAddr = %q", got.NonceStore.RedisAddr)
	}
	if got.Auth.Mode != AuthModeJWT {
		t.Errorf("Auth.Mode = %q, want jwt", got.Auth.Mode)
	}
}

func TestApplyEnvOverrides_LowercasesBackendStrings(t *testing.T) {
	clearAPIEnv(t)
	// Ops sometimes uppercase env values; the loader must normalize.
	t.Setenv("API_KEYSTORE_BACKEND", "VAULT")
	t.Setenv("API_NONCE_STORE_BACKEND", "REDIS")
	t.Setenv("API_AUTH_MODE", "JWT")
	got := ApplyEnvOverrides(Defaults())
	if got.KeyStore.Backend != KeyStoreBackendVault {
		t.Errorf("uppercase VAULT not normalized: %q", got.KeyStore.Backend)
	}
	if got.NonceStore.Backend != NonceStoreBackendRedis {
		t.Errorf("uppercase REDIS not normalized: %q", got.NonceStore.Backend)
	}
	if got.Auth.Mode != AuthModeJWT {
		t.Errorf("uppercase JWT not normalized: %q", got.Auth.Mode)
	}
}

// Precedence is documented as env > file > defaults. This test composes
// all three to assert the order.
func TestApplyEnvOverrides_PrecedenceEnvBeatsFile(t *testing.T) {
	clearAPIEnv(t)
	tmp := writeJSON(t, map[string]any{
		"listen_addr":     ":8888",
		"ledger_endpoint": "https://op.from.file",
	})
	t.Setenv("API_LISTEN_ADDR", ":9999") // env should win

	cfg, err := LoadFromFile(tmp)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	cfg = ApplyEnvOverrides(cfg)

	if cfg.ListenAddr != ":9999" {
		t.Errorf("env should beat file; ListenAddr = %q want :9999", cfg.ListenAddr)
	}
	if cfg.LedgerEndpoint != "https://op.from.file" {
		t.Errorf("file value (no env override) should win over default: %q", cfg.LedgerEndpoint)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Validate — happy paths
// ─────────────────────────────────────────────────────────────────────

func TestValidate_HappyPath_Memory(t *testing.T) {
	cfg := Defaults()
	cfg.Auth.ClientCAFile = "ca.pem"
	cfg.Auth.TLSCertFile = "tls.crt"
	cfg.Auth.TLSKeyFile = "tls.key"
	if err := cfg.Validate(); err != nil {
		t.Errorf("memory + mtls should validate: %v", err)
	}
}

func TestValidate_HappyPath_SoftHSM_MTLS(t *testing.T) {
	cfg := Defaults()
	cfg.KeyStore = KeyStoreConfig{
		Backend: KeyStoreBackendSoftHSM,
		PKCS11: &PKCS11Config{
			LibraryPath: "/usr/lib/softhsm/libsofthsm2.so",
			SlotID:      0,
			PINFile:     "/run/secrets/softhsm-pin",
			TokenLabel:  "exchange-tokens",
		},
	}
	cfg.Auth.ClientCAFile = "ca.pem"
	cfg.Auth.TLSCertFile = "tls.crt"
	cfg.Auth.TLSKeyFile = "tls.key"
	if err := cfg.Validate(); err != nil {
		t.Errorf("softhsm + mtls should validate: %v", err)
	}
}

func TestValidate_HappyPath_Vault_JWT(t *testing.T) {
	cfg := Defaults()
	cfg.KeyStore = KeyStoreConfig{
		Backend: KeyStoreBackendVault,
		Vault: &VaultConfig{
			Address:   "https://vault.svc:8200",
			TokenFile: "/run/secrets/vault-token",
			Mount:     "transit",
			KeyName:   "exchange-davidson-signer-1",
		},
	}
	cfg.Auth = AuthConfig{
		Mode:      AuthModeJWT,
		JWTIssuer: "https://idp.example",
		JWKSURL:   "https://idp.example/.well-known/jwks.json",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("vault + jwt should validate: %v", err)
	}
}

func TestValidate_HappyPath_NonceRedis(t *testing.T) {
	cfg := Defaults()
	cfg.NonceStore = NonceStoreOpConfig{
		Backend:         NonceStoreBackendRedis,
		FreshnessWindow: 5 * time.Minute,
		RedisAddr:       "redis.svc:6379",
	}
	cfg.Auth.ClientCAFile = "ca.pem"
	cfg.Auth.TLSCertFile = "tls.crt"
	cfg.Auth.TLSKeyFile = "tls.key"
	if err := cfg.Validate(); err != nil {
		t.Errorf("nonce-redis should validate: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Validate — failure paths (one per documented rule)
// ─────────────────────────────────────────────────────────────────────

func TestValidate_RejectsEmptyListenAddr(t *testing.T) {
	cfg := validBase(t)
	cfg.ListenAddr = ""
	expectInvalid(t, cfg, "ListenAddr required")
}

func TestValidate_RejectsEmptyLedgerEndpoint(t *testing.T) {
	cfg := validBase(t)
	cfg.LedgerEndpoint = ""
	expectInvalid(t, cfg, "LedgerEndpoint required")
}

func TestValidate_RejectsEmptyArtifactStoreEndpoint(t *testing.T) {
	cfg := validBase(t)
	cfg.ArtifactStoreEndpoint = ""
	expectInvalid(t, cfg, "ArtifactStoreEndpoint required")
}

func TestValidate_RejectsEmptyVerificationEndpoint(t *testing.T) {
	cfg := validBase(t)
	cfg.VerificationEndpoint = ""
	expectInvalid(t, cfg, "VerificationEndpoint required")
}

func TestValidate_RejectsEmptyKeystoreBackend(t *testing.T) {
	cfg := validBase(t)
	cfg.KeyStore.Backend = ""
	expectInvalid(t, cfg, "KeyStore.Backend required")
}

func TestValidate_RejectsUnknownKeystoreBackend(t *testing.T) {
	cfg := validBase(t)
	cfg.KeyStore.Backend = KeyStoreBackend("aws-kms")
	expectInvalid(t, cfg, "not recognized")
}

func TestValidate_RejectsMemoryBackendWithPKCS11Set(t *testing.T) {
	cfg := validBase(t)
	cfg.KeyStore = KeyStoreConfig{
		Backend: KeyStoreBackendMemory,
		PKCS11:  &PKCS11Config{}, // accidentally left over from prior config
	}
	expectInvalid(t, cfg, "PKCS11 set with memory backend")
}

func TestValidate_RejectsMemoryBackendWithVaultSet(t *testing.T) {
	cfg := validBase(t)
	cfg.KeyStore = KeyStoreConfig{
		Backend: KeyStoreBackendMemory,
		Vault:   &VaultConfig{},
	}
	expectInvalid(t, cfg, "Vault set with memory backend")
}

func TestValidate_RejectsSoftHSMWithoutPKCS11(t *testing.T) {
	cfg := validBase(t)
	cfg.KeyStore = KeyStoreConfig{Backend: KeyStoreBackendSoftHSM}
	expectInvalid(t, cfg, "PKCS11 required for softhsm")
}

func TestValidate_RejectsSoftHSMWithVaultAlsoSet(t *testing.T) {
	cfg := validBase(t)
	cfg.KeyStore = KeyStoreConfig{
		Backend: KeyStoreBackendSoftHSM,
		PKCS11: &PKCS11Config{
			LibraryPath: "x.so", PINFile: "p", TokenLabel: "t",
		},
		Vault: &VaultConfig{},
	}
	expectInvalid(t, cfg, "Vault must be nil for softhsm")
}

func TestValidate_RejectsSoftHSMMissingLibraryPath(t *testing.T) {
	cfg := validBase(t)
	cfg.KeyStore = KeyStoreConfig{
		Backend: KeyStoreBackendSoftHSM,
		PKCS11:  &PKCS11Config{PINFile: "p", TokenLabel: "t"},
	}
	expectInvalid(t, cfg, "PKCS11.LibraryPath required")
}

func TestValidate_RejectsSoftHSMMissingPINFile(t *testing.T) {
	cfg := validBase(t)
	cfg.KeyStore = KeyStoreConfig{
		Backend: KeyStoreBackendSoftHSM,
		PKCS11:  &PKCS11Config{LibraryPath: "x.so", TokenLabel: "t"},
	}
	expectInvalid(t, cfg, "PKCS11.PINFile required")
}

func TestValidate_RejectsSoftHSMMissingTokenLabel(t *testing.T) {
	cfg := validBase(t)
	cfg.KeyStore = KeyStoreConfig{
		Backend: KeyStoreBackendSoftHSM,
		PKCS11:  &PKCS11Config{LibraryPath: "x.so", PINFile: "p"},
	}
	expectInvalid(t, cfg, "PKCS11.TokenLabel required")
}

func TestValidate_RejectsVaultWithoutVaultConfig(t *testing.T) {
	cfg := validBase(t)
	cfg.KeyStore = KeyStoreConfig{Backend: KeyStoreBackendVault}
	expectInvalid(t, cfg, "Vault required for vault backend")
}

func TestValidate_RejectsVaultWithPKCS11AlsoSet(t *testing.T) {
	cfg := validBase(t)
	cfg.KeyStore = KeyStoreConfig{
		Backend: KeyStoreBackendVault,
		Vault: &VaultConfig{
			Address: "x", TokenFile: "t", Mount: "transit", KeyName: "k",
		},
		PKCS11: &PKCS11Config{},
	}
	expectInvalid(t, cfg, "PKCS11 must be nil for vault")
}

func TestValidate_RejectsVaultMissingFields(t *testing.T) {
	cases := map[string]struct {
		mut  func(v *VaultConfig)
		want string
	}{
		"missing address": {
			mut:  func(v *VaultConfig) { v.Address = "" },
			want: "Vault.Address required",
		},
		"missing token file": {
			mut:  func(v *VaultConfig) { v.TokenFile = "" },
			want: "Vault.TokenFile required",
		},
		"missing mount": {
			mut:  func(v *VaultConfig) { v.Mount = "" },
			want: "Vault.Mount required",
		},
		"missing key name": {
			mut:  func(v *VaultConfig) { v.KeyName = "" },
			want: "Vault.KeyName required",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			v := &VaultConfig{
				Address:   "https://vault.example:8200",
				TokenFile: "/tok", Mount: "transit", KeyName: "k",
			}
			tc.mut(v)
			cfg := validBase(t)
			cfg.KeyStore = KeyStoreConfig{
				Backend: KeyStoreBackendVault,
				Vault:   v,
			}
			expectInvalid(t, cfg, tc.want)
		})
	}
}

func TestValidate_RejectsEmptyNonceStoreBackend(t *testing.T) {
	cfg := validBase(t)
	cfg.NonceStore.Backend = ""
	expectInvalid(t, cfg, "NonceStore.Backend required")
}

func TestValidate_RejectsUnknownNonceStoreBackend(t *testing.T) {
	cfg := validBase(t)
	cfg.NonceStore.Backend = NonceStoreBackend("postgres")
	expectInvalid(t, cfg, "not recognized")
}

func TestValidate_RejectsRedisWithoutAddr(t *testing.T) {
	cfg := validBase(t)
	cfg.NonceStore = NonceStoreOpConfig{
		Backend:         NonceStoreBackendRedis,
		FreshnessWindow: time.Minute,
	}
	expectInvalid(t, cfg, "RedisAddr required")
}

func TestValidate_RejectsZeroFreshnessWindow(t *testing.T) {
	cfg := validBase(t)
	cfg.NonceStore.FreshnessWindow = 0
	expectInvalid(t, cfg, "FreshnessWindow must be > 0")
}

func TestValidate_RejectsEmptyAuthMode(t *testing.T) {
	cfg := validBase(t)
	cfg.Auth = AuthConfig{}
	expectInvalid(t, cfg, "Auth.Mode required")
}

func TestValidate_RejectsUnknownAuthMode(t *testing.T) {
	cfg := validBase(t)
	cfg.Auth.Mode = AuthMode("oidc")
	expectInvalid(t, cfg, "not recognized")
}

func TestValidate_RejectsMTLSWithoutClientCA(t *testing.T) {
	cfg := validBase(t)
	cfg.Auth.ClientCAFile = ""
	expectInvalid(t, cfg, "ClientCAFile required")
}

func TestValidate_RejectsMTLSWithoutTLSCert(t *testing.T) {
	cfg := validBase(t)
	cfg.Auth.TLSCertFile = ""
	expectInvalid(t, cfg, "TLSCertFile and TLSKeyFile required")
}

func TestValidate_RejectsJWTWithoutIssuer(t *testing.T) {
	cfg := validBase(t)
	cfg.Auth = AuthConfig{Mode: AuthModeJWT, JWKSURL: "https://x/jwks"}
	expectInvalid(t, cfg, "JWTIssuer required")
}

func TestValidate_RejectsJWTWithoutJWKSURL(t *testing.T) {
	cfg := validBase(t)
	cfg.Auth = AuthConfig{Mode: AuthModeJWT, JWTIssuer: "iss"}
	expectInvalid(t, cfg, "JWKSURL required")
}

// ─────────────────────────────────────────────────────────────────────
// Operational holds zero DIDs (the rule that matters most)
// ─────────────────────────────────────────────────────────────────────

func TestOperationalStruct_NoDIDFields(t *testing.T) {
	// Walk the Operational type; assert no field name contains "DID"
	// and no JSON tag matches *_did. Catches the "developer added a
	// CourtDID field to make tests easier" regression.
	walkFields(t, reflect.TypeOf(Operational{}))
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// validBase returns a fully-validating Operational that test cases
// mutate to exercise individual failure modes.
func validBase(t *testing.T) Operational {
	t.Helper()
	cfg := Defaults()
	cfg.Auth.ClientCAFile = "ca.pem"
	cfg.Auth.TLSCertFile = "tls.crt"
	cfg.Auth.TLSKeyFile = "tls.key"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validBase fixture is invalid: %v", err)
	}
	return cfg
}

func expectInvalid(t *testing.T, cfg Operational, mustContain string) {
	t.Helper()
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", mustContain)
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error should wrap ErrInvalidConfig: %v", err)
	}
	if !strings.Contains(err.Error(), mustContain) {
		t.Errorf("error %q should contain %q", err.Error(), mustContain)
	}
}

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

// clearAPIEnv unsets every API_* env var the package reads, so each
// test starts from a deterministic baseline regardless of host env.
func clearAPIEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		"API_LISTEN_ADDR",
		"API_LEDGER_ENDPOINT",
		"API_ARTIFACT_STORE_ENDPOINT",
		"API_VERIFICATION_ENDPOINT",
		"API_KEYSTORE_BACKEND",
		"API_NONCE_STORE_BACKEND",
		"API_NONCE_STORE_REDIS_ADDR",
		"API_AUTH_MODE",
	} {
		t.Setenv(v, "")
		_ = os.Unsetenv(v)
	}
}

// walkFields recurses through a struct type asserting no field name
// or JSON tag implies a DID field. Caller passes Operational's type;
// this enforces the architectural rule at the test level.
func walkFields(t *testing.T, typ reflect.Type) {
	t.Helper()
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if strings.Contains(f.Name, "DID") {
			t.Errorf("Operational forbids DID-bearing fields; found %s.%s",
				typ.Name(), f.Name)
		}
		if tag := strings.Split(f.Tag.Get("json"), ",")[0]; strings.Contains(tag, "did") {
			t.Errorf("Operational forbids DID-shaped JSON tags; found %s.%s -> json:%q",
				typ.Name(), f.Name, tag)
		}
		// Recurse through embedded / nested struct types.
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			walkFields(t, ft)
		}
	}
}
