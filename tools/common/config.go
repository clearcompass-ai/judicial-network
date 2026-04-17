package common

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config holds all tools configuration. Loaded from JSON, overridable via env.
type Config struct {
	// Upstream services (domain layer — tools have no privilege over these).
	OperatorURL      string `json:"operator_url"`
	ArtifactStoreURL string `json:"artifact_store_url"`
	ExchangeURL      string `json:"exchange_url"`
	VerificationURL  string `json:"verification_url"`

	// Court identity.
	CourtDID       string `json:"court_did"`
	OfficersLogDID string `json:"officers_log"`
	CasesLogDID    string `json:"cases_log"`
	PartiesLogDID  string `json:"parties_log"`

	// Postgres (tools-local, NOT shared with domain).
	DatabaseURL string `json:"database_url"`

	// Server addresses.
	CourtToolsAddr    string `json:"court_tools_addr"`
	ProviderToolsAddr string `json:"provider_tools_addr"`

	// Aggregator settings.
	AggregatorPollInterval time.Duration `json:"aggregator_poll_interval"`
	AggregatorBatchSize    int           `json:"aggregator_batch_size"`

	// Auth.
	CourtSSOIssuer       string `json:"court_sso_issuer"`
	ProviderAPIKeyHeader string `json:"provider_api_key_header"`
}

// DefaultConfig returns a Config with sane defaults.
func DefaultConfig() Config {
	return Config{
		OperatorURL:            "http://localhost:8001",
		ArtifactStoreURL:       "http://localhost:8002",
		ExchangeURL:            "http://localhost:8003",
		VerificationURL:        "http://localhost:8080",
		CourtDID:               "did:web:courts.localhost",
		OfficersLogDID:         "did:web:courts.localhost:officers",
		CasesLogDID:            "did:web:courts.localhost:cases",
		PartiesLogDID:          "did:web:courts.localhost:parties",
		DatabaseURL:            "postgres://localhost:5432/court_tools?sslmode=disable",
		CourtToolsAddr:         ":8090",
		ProviderToolsAddr:      ":8091",
		AggregatorPollInterval: 5 * time.Second,
		AggregatorBatchSize:    100,
		ProviderAPIKeyHeader:   "X-API-Key",
	}
}

// LoadConfig reads a JSON config file and applies environment overrides.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("config: read %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}

	// Environment overrides take precedence.
	envOverride(&cfg.OperatorURL, "TOOLS_OPERATOR_URL")
	envOverride(&cfg.ArtifactStoreURL, "TOOLS_ARTIFACT_STORE_URL")
	envOverride(&cfg.ExchangeURL, "TOOLS_EXCHANGE_URL")
	envOverride(&cfg.VerificationURL, "TOOLS_VERIFICATION_URL")
	envOverride(&cfg.CourtDID, "TOOLS_COURT_DID")
	envOverride(&cfg.OfficersLogDID, "TOOLS_OFFICERS_LOG")
	envOverride(&cfg.CasesLogDID, "TOOLS_CASES_LOG")
	envOverride(&cfg.PartiesLogDID, "TOOLS_PARTIES_LOG")
	envOverride(&cfg.DatabaseURL, "TOOLS_DATABASE_URL")
	envOverride(&cfg.CourtToolsAddr, "TOOLS_COURT_ADDR")
	envOverride(&cfg.ProviderToolsAddr, "TOOLS_PROVIDER_ADDR")

	return cfg, nil
}

func envOverride(target *string, key string) {
	if v := os.Getenv(key); v != "" {
		*target = v
	}
}

// LogDIDs returns all three log DIDs for iteration.
func (c Config) LogDIDs() []string {
	return []string{c.OfficersLogDID, c.CasesLogDID, c.PartiesLogDID}
}
