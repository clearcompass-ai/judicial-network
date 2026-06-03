package stack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/clearcompass-ai/judicial-network/e2e/dockerx"
)

// Checkpoint is the parsed /v1/tree/horizon (and /v1/tree/head) — snake_case JSON
// with hex roots and the per-witness cosignatures.
type Checkpoint struct {
	TreeSize    int    `json:"tree_size"`
	RootHash    string `json:"root_hash"`
	SMTRoot     string `json:"smt_root"`
	ReceiptRoot string `json:"receipt_root"`
	Signatures  []struct {
		PubKeyID  string `json:"pub_key_id"`
		SchemeTag int    `json:"scheme_tag"`
	} `json:"signatures"`
}

// FetchHorizon reads + parses the published, witness-cosigned horizon over open
// HTTPS (certsDir holds the run CA the probe pins to verify the ledger's server
// cert; no client cert is presented).
func FetchHorizon(certsDir string, port int) (Checkpoint, error) {
	return fetchCheckpoint(certsDir, fmt.Sprintf("https://localhost:%d/v1/tree/horizon", port))
}

// FetchHead reads + parses the latest committed head over open HTTPS (server-verify).
func FetchHead(certsDir string, port int) (Checkpoint, error) {
	return fetchCheckpoint(certsDir, fmt.Sprintf("https://localhost:%d/v1/tree/head", port))
}

func fetchCheckpoint(certsDir, url string) (Checkpoint, error) {
	body := ledgerBody(certsDir, url)
	var c Checkpoint
	if body == "" {
		return c, fmt.Errorf("empty response from %s", url)
	}
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		return c, fmt.Errorf("parse %s: %w", url, err)
	}
	return c, nil
}

// DistinctSigners is the number of UNIQUE cosigner pub_key_ids — equals
// len(Signatures) only when no witness signed twice.
func (c Checkpoint) DistinctSigners() int {
	set := make(map[string]bool, len(c.Signatures))
	for _, s := range c.Signatures {
		set[s.PubKeyID] = true
	}
	return len(set)
}

// SchemesAllECDSA reports whether every cosignature uses scheme_tag 1 (ECDSA).
func (c Checkpoint) SchemesAllECDSA() bool {
	for _, s := range c.Signatures {
		if s.SchemeTag != 1 {
			return false
		}
	}
	return true
}

// InspectOracle reads a backfill manifest and returns the leaf count and the number
// of DISTINCT 64-hex keys. distinct == leaves proves the oracle is not collapsed
// (the DeriveKey(seq 0) regression made every key identical).
func InspectOracle(manifestPath string) (leaves, distinct int, err error) {
	b, e := os.ReadFile(manifestPath)
	if e != nil {
		return 0, 0, e
	}
	var m BackfillStats
	if e := json.Unmarshal(b, &m); e != nil {
		return 0, 0, e
	}
	set := make(map[string]bool, len(m.Leaves))
	for _, l := range m.Leaves {
		if len(l.Key) == 64 {
			set[l.Key] = true
		}
	}
	return len(m.Leaves), len(set), nil
}

// ManifestPath is the oracle manifest for a target.
func (t Target) ManifestPath() string { return filepath.Join(t.FixturesDir, "backfill-manifest.json") }

// LedgerLog returns the ledger container's full log.
func LedgerLog(container string) string { return dockerx.Logs(container) }
