// Package topology loads the cross-network topology manifest the
// provisioner emits at .run/{id}/topology.json. The manifest is the
// single source of truth for which witness/auditor identities serve
// which networks — neither network's bootstrap document alone carries
// that linkage, so this package is the seam for every scenario that
// asserts on shared identities (e.g. "the same shared witness identity
// signs heads on both networks", "an auditor's gossip key matches
// across both networks").
package topology

import (
	"encoding/json"
	"fmt"
	"os"
)

// Manifest mirrors the topology manifest JSON the Go stack provisioner
// writes. Field tags match the manifest exactly so drift surfaces at
// decode time.
type Manifest struct {
	Networks          []NetworkView         `json:"networks"`
	WitnessIdentities []WitnessIdentityView `json:"witness_identities"`
	AuditorIdentities []AuditorIdentityView `json:"auditor_identities"`
}

// NetworkView is one network's resolved state (URLs, bootstrap path,
// witness+auditor lists in registration order).
type NetworkView struct {
	Name          string               `json:"name"`
	Display       string               `json:"display"`
	ExchangeDID   string               `json:"exchange_did"`
	LedgerURL     string               `json:"ledger_url"`
	AggregatorURL string               `json:"aggregator_url"`
	JNURL         string               `json:"jn_url"`
	BootstrapPath string               `json:"bootstrap_path"`
	K             int                  `json:"k"`
	NWitnesses    int                  `json:"n_witnesses"`
	NAuditors     int                  `json:"n_auditors"`
	Witnesses     []NetworkWitnessSlot `json:"witnesses"`
	Auditors      []NetworkAuditorSlot `json:"auditors"`
	Destinations  []string             `json:"destinations"`
}

// NetworkWitnessSlot is one witness in this network's set — its
// identity name (stable across networks), the DID it has in THIS
// network's bootstrap, its URL on the host, and whether it's shared.
type NetworkWitnessSlot struct {
	Identity string `json:"identity"`
	DID      string `json:"did"`
	URL      string `json:"url"`
	Shared   bool   `json:"shared"`
}

// NetworkAuditorSlot is one auditor in this network's fleet.
type NetworkAuditorSlot struct {
	Identity string `json:"identity"`
	URL      string `json:"url"`
	Shared   bool   `json:"shared"`
}

// WitnessIdentityView is the cross-network linkage for one witness
// identity: which networks it participates in and the DID it has in
// each. For a shared identity, DIDPerNetwork has two entries — the
// DIDs MUST be the same string (the SAME key produces the SAME DID),
// which is the heart of the shared-identity contract.
type WitnessIdentityView struct {
	Name          string            `json:"name"`
	Networks      []string          `json:"networks"`
	DIDPerNetwork map[string]string `json:"did_per_network"`
	Shared        bool              `json:"shared"`
}

// AuditorIdentityView is the cross-network linkage for one auditor
// identity.
type AuditorIdentityView struct {
	Name     string   `json:"name"`
	Networks []string `json:"networks"`
	Shared   bool     `json:"shared"`
}

// Load reads + parses the topology manifest at path. Returns an
// empty manifest with a nil error when the file doesn't exist — the
// harness gates on m.Loaded() so a bare `go test` without a stack
// up still passes the gate-on-pending tests.
func Load(path string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return m, fmt.Errorf("read topology %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("parse topology %s: %w", path, err)
	}
	return m, nil
}

// Loaded reports whether the manifest has at least one network — the
// gate harness tests use to know the topology is real.
func (m Manifest) Loaded() bool {
	return len(m.Networks) > 0
}

// Network returns the network view with the given name (e.g.
// "federal", "tn"), or nil if absent.
func (m Manifest) Network(name string) *NetworkView {
	for i := range m.Networks {
		if m.Networks[i].Name == name {
			return &m.Networks[i]
		}
	}
	return nil
}

// SharedWitnessIdentities returns every witness identity that
// participates in more than one network. Useful for cross-network
// referring scenarios: walk these, fetch each network's tree-head
// signatures, and assert the same identity's DID appears in both
// signature sets.
func (m Manifest) SharedWitnessIdentities() []WitnessIdentityView {
	var out []WitnessIdentityView
	for _, w := range m.WitnessIdentities {
		if w.Shared {
			out = append(out, w)
		}
	}
	return out
}

// SharedAuditorIdentities returns every auditor identity that
// participates in more than one network.
func (m Manifest) SharedAuditorIdentities() []AuditorIdentityView {
	var out []AuditorIdentityView
	for _, a := range m.AuditorIdentities {
		if a.Shared {
			out = append(out, a)
		}
	}
	return out
}
