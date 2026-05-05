/*
FILE PATH: tools/cmd/witness/config_test.go

DESCRIPTION:

	Pins LoadConfig + Validate:
	  1. Missing file path → clear error.
	  2. Malformed JSON → clear error.
	  3. Default poll interval applied when zero.
	  4. Validate enforces witness_did, witness_key_file, log_dids,
	     ledgers map populated, and ledger-per-log coverage.
*/
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeJSON(t *testing.T, m map[string]any) string {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "witness.json")
	data, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return tmp
}

func TestLoadConfig_MissingPath_Errors(t *testing.T) {
	if _, err := LoadConfig(""); err == nil {
		t.Error("expected error for empty path")
	}
}

func TestLoadConfig_BadJSON_Errors(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(tmp, []byte("{not json"), 0o600)
	if _, err := LoadConfig(tmp); err == nil {
		t.Error("expected parse error")
	}
}

func TestLoadConfig_AppliesDefaultPollInterval(t *testing.T) {
	path := writeJSON(t, map[string]any{
		"witness_did":      "did:web:w",
		"witness_key_file": "/etc/k",
		"log_dids":         []string{"did:web:x"},
		"ledgers":          map[string]string{"did:web:x": "http://op"},
	})
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("PollInterval = %v, want 5s default", cfg.PollInterval)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Validate
// ─────────────────────────────────────────────────────────────────────

func TestValidate_HappyPath(t *testing.T) {
	cfg := Config{
		WitnessDID:     "did:web:w",
		WitnessKeyFile: "/etc/k",
		LogDIDs:        []string{"did:web:x"},
		Ledgers:        map[string]string{"did:web:x": "http://op"},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissingFields(t *testing.T) {
	base := Config{
		WitnessDID:     "did:web:w",
		WitnessKeyFile: "/etc/k",
		LogDIDs:        []string{"did:web:x"},
		Ledgers:        map[string]string{"did:web:x": "http://op"},
	}
	cases := []struct {
		mod  func(*Config)
		want string
	}{
		{func(c *Config) { c.WitnessDID = "" }, "witness_did"},
		{func(c *Config) { c.WitnessKeyFile = "" }, "witness_key_file"},
		{func(c *Config) { c.LogDIDs = nil }, "log_did"},
		{func(c *Config) { c.Ledgers = nil }, "ledgers"},
	}
	for _, c := range cases {
		cfg := base
		c.mod(&cfg)
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("expected error containing %q, got %v", c.want, err)
		}
	}
}

func TestValidate_LogWithoutLedger(t *testing.T) {
	cfg := Config{
		WitnessDID:     "did:web:w",
		WitnessKeyFile: "/etc/k",
		LogDIDs:        []string{"did:web:x", "did:web:y"},
		Ledgers:        map[string]string{"did:web:x": "http://op"}, // y missing
	}
	if err := cfg.Validate(); err == nil ||
		!strings.Contains(err.Error(), "did:web:y") {
		t.Errorf("expected error mentioning unmapped log; got %v", err)
	}
}
