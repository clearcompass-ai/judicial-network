/*
FILE PATH: tools/cmd/witness/config.go

DESCRIPTION:

	Witness daemon operational config. Separate from
	api/config.Operational because the witness daemon has no
	keystore / nonce-store / auth — its only dependencies are
	the witness BLS key and the ledger endpoints.

	On-disk shape (witness.json):

	  {
	    "witness_did":   "did:web:state:tn:witness:01",
	    "witness_key_file": "/etc/witness/bls.key",
	    "poll_interval": "5s",
	    "log_dids": [
	      "did:web:state:tn:davidson:cases",
	      "did:web:state:tn:davidson:officers"
	    ],
	    "ledgers": {
	      "did:web:state:tn:davidson:cases":    "https://ledger.davidson",
	      "did:web:state:tn:davidson:officers": "https://ledger.davidson"
	    }
	  }

	PEM-encoded BLS key file format is the SDK's
	crypto/signatures.GenerateBLSKey output. The daemon loads it
	once at boot and holds it for the process lifetime.
*/
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config is the witness daemon's on-disk config shape. Loaded from
// JSON via LoadConfig.
type Config struct {
	// WitnessDID is the daemon's identity. Used as the SignerDID on
	// emitted cosignatures so the ledger can route them to the
	// matching witness slot in its accepted-witness set.
	WitnessDID string `json:"witness_did"`

	// WitnessKeyFile is the filesystem path to the BLS private key
	// (PEM-encoded). Production deploys mount this from a sealed
	// secret store (Vault / k8s secret); the file MUST be 0600.
	WitnessKeyFile string `json:"witness_key_file"`

	// PollInterval is the gap between tree-head fetches per log.
	// Zero applies the documented default (5s).
	PollInterval time.Duration `json:"poll_interval,omitempty"`

	// LogDIDs is the set of logs this witness cosigns. Each must
	// have a matching entry in Ledgers.
	LogDIDs []string `json:"log_dids"`

	// Ledgers maps log DID → ledger base URL. The daemon polls
	// `<base>/v1/tree/head?log=<did>` per the SDK's TreeHeadClient
	// shape, then POSTs cosignatures to `<base>/v1/cosignatures`.
	Ledgers map[string]string `json:"ledgers"`
}

// LoadConfig reads + parses the JSON config file. Returns the zero
// Config + error on read / parse failure.
func LoadConfig(path string) (Config, error) {
	if path == "" {
		return Config{}, fmt.Errorf("witness: --config path required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("witness: read config %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("witness: parse config %q: %w", path, err)
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	return cfg, nil
}

// Validate enforces the boot-time invariants. Returns a clear
// error so misconfig fails fast with an actionable message.
func (c Config) Validate() error {
	if c.WitnessDID == "" {
		return fmt.Errorf("witness: witness_did required")
	}
	if c.WitnessKeyFile == "" {
		return fmt.Errorf("witness: witness_key_file required")
	}
	if len(c.LogDIDs) == 0 {
		return fmt.Errorf("witness: at least one log_did required")
	}
	if len(c.Ledgers) == 0 {
		return fmt.Errorf("witness: ledgers map cannot be empty")
	}
	for _, did := range c.LogDIDs {
		if _, ok := c.Ledgers[did]; !ok {
			return fmt.Errorf("witness: log_did %q has no ledger endpoint", did)
		}
	}
	return nil
}
