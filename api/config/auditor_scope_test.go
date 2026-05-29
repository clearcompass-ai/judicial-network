/*
FILE PATH: api/config/auditor_scope_test.go

DESCRIPTION:

	D7 test additions for AuditorScopeConfig + URLDriftInterval.

	Lives in its own file (parallel to operational_test.go) so the
	v1.33.x adoption tests are co-located and the original test file
	stays focused on the pre-v1.33 surface.

	Pinned properties:
	  1. All four env vars apply cleanly.
	  2. Boot-fast-fail: Enforce=true with empty RegistryFile errors
	     with "silent scope-gate downgrade" — both at the unit level
	     (AuditorScopeConfig.validate) and the integration level
	     (Operational.Validate).
	  3. Enforce=true + RegistryFile set is the happy path.
	  4. Default (Enforce=false) never errors.
	  5. AmendmentFile is independently optional.
	  6. Malformed / negative URL drift durations are silently ignored
	     (preserving Defaults' 0, the documented "disabled" state).
*/
package config

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// clearAuditorScopeEnv unsets every env var the D7 surfaces read so
// each test starts from a deterministic baseline. Decoupled from the
// existing clearAPIEnv (which lives in operational_test.go) so this
// file is self-contained.
func clearAuditorScopeEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		"API_ENFORCE_SCOPES",
		"API_AUDITOR_REGISTRY_FILE",
		"API_AUDITOR_AMENDMENT_FILE",
		"API_URL_DRIFT_INTERVAL",
	} {
		t.Setenv(v, "")
		_ = os.Unsetenv(v)
	}
}

// ──────────────────────────────────────────────────────────────────
// ApplyEnvOverrides — AuditorScope + URLDriftInterval
// ──────────────────────────────────────────────────────────────────

func TestApplyEnvOverrides_AuditorScope(t *testing.T) {
	clearAuditorScopeEnv(t)
	t.Setenv("API_ENFORCE_SCOPES", "true")
	t.Setenv("API_AUDITOR_REGISTRY_FILE", "/mnt/auditor/registry.json")
	t.Setenv("API_AUDITOR_AMENDMENT_FILE", "/mnt/auditor/amendments.json")
	t.Setenv("API_URL_DRIFT_INTERVAL", "15m")

	got := ApplyEnvOverrides(Defaults())

	if !got.AuditorScope.Enforce {
		t.Error("AuditorScope.Enforce not set from env")
	}
	if got.AuditorScope.RegistryFile != "/mnt/auditor/registry.json" {
		t.Errorf("AuditorScope.RegistryFile = %q", got.AuditorScope.RegistryFile)
	}
	if got.AuditorScope.AmendmentFile != "/mnt/auditor/amendments.json" {
		t.Errorf("AuditorScope.AmendmentFile = %q", got.AuditorScope.AmendmentFile)
	}
	if got.URLDriftInterval != 15*time.Minute {
		t.Errorf("URLDriftInterval = %v, want 15m", got.URLDriftInterval)
	}
}

// URLDriftInterval silently ignores unparseable values — the override
// path's err==nil guard protects against a bad operator value disabling
// other valid overrides downstream.
func TestApplyEnvOverrides_URLDriftInterval_BadValue_Ignored(t *testing.T) {
	clearAuditorScopeEnv(t)
	t.Setenv("API_URL_DRIFT_INTERVAL", "not-a-duration")
	got := ApplyEnvOverrides(Defaults())
	if got.URLDriftInterval != 0 {
		t.Errorf("malformed duration should leave URLDriftInterval at 0; got %v",
			got.URLDriftInterval)
	}
}

// Negative durations are likewise ignored (the d > 0 guard).
func TestApplyEnvOverrides_URLDriftInterval_NegativeIgnored(t *testing.T) {
	clearAuditorScopeEnv(t)
	t.Setenv("API_URL_DRIFT_INTERVAL", "-5m")
	got := ApplyEnvOverrides(Defaults())
	if got.URLDriftInterval != 0 {
		t.Errorf("negative duration should leave URLDriftInterval at 0; got %v",
			got.URLDriftInterval)
	}
}

// ──────────────────────────────────────────────────────────────────
// AuditorScopeConfig.validate
// ──────────────────────────────────────────────────────────────────

// Boot-fast-fail rule: Enforce=true && RegistryFile=="" is a silent-
// downgrade hazard the validator must catch.
func TestAuditorScope_Validate_EnforceRequiresRegistry(t *testing.T) {
	cfg := AuditorScopeConfig{Enforce: true} // RegistryFile empty
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error: Enforce=true requires RegistryFile")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error should wrap ErrInvalidConfig: %v", err)
	}
	if !strings.Contains(err.Error(), "silent scope-gate downgrade") {
		t.Errorf("error should mention 'silent scope-gate downgrade': %v", err)
	}
}

// Validate also fires when wrapped through Operational.Validate so a
// bad AuditorScope rejects an otherwise valid cfg at the integration
// level (the actual boot pathway).
func TestValidate_AuditorScope_BootFastFail(t *testing.T) {
	cfg := Defaults()
	cfg.Auth.ClientCAFile = "ca.pem"
	cfg.Auth.TLSCertFile = "tls.crt"
	cfg.Auth.TLSKeyFile = "tls.key"
	// Inject a misconfigured scope on top of an otherwise valid base.
	cfg.AuditorScope = AuditorScopeConfig{Enforce: true}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected Validate() to fail on misconfigured AuditorScope")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error should wrap ErrInvalidConfig: %v", err)
	}
	if !strings.Contains(err.Error(), "silent scope-gate downgrade") {
		t.Errorf("error should mention 'silent scope-gate downgrade': %v", err)
	}
}

// Enforce + RegistryFile is the happy path.
func TestAuditorScope_Validate_EnforceWithRegistry_OK(t *testing.T) {
	cfg := AuditorScopeConfig{Enforce: true, RegistryFile: "/mnt/registry.json"}
	if err := cfg.validate(); err != nil {
		t.Errorf("unexpected validate error: %v", err)
	}
}

// Default (Enforce=false) never errors regardless of file presence.
func TestAuditorScope_Validate_DisabledNeverErrors(t *testing.T) {
	cfg := AuditorScopeConfig{Enforce: false} // no files set
	if err := cfg.validate(); err != nil {
		t.Errorf("disabled scope should not error: %v", err)
	}
}

// AmendmentFile is independently optional — Enforce=true with
// RegistryFile set but no amendments is the legal "no amendments yet"
// state (registry-only scope).
func TestAuditorScope_Validate_AmendmentFileOptional(t *testing.T) {
	cfg := AuditorScopeConfig{Enforce: true, RegistryFile: "/r.json"}
	if err := cfg.validate(); err != nil {
		t.Errorf("AmendmentFile empty should not error: %v", err)
	}
}
