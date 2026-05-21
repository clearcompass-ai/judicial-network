package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/clearcompass-ai/judicial-network/api/config"
)

// writeBootstrap writes a minimal bootstrap document. applyBootstrapDerivations
// reads only exchange_did + genesis_witness_set, so the rest is filler.
func writeBootstrap(t *testing.T, exchangeDID string, witnesses []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "network-bootstrap.json")
	doc := `{"protocol_version":"1","network_name":"test","exchange_did":"` + exchangeDID + `","genesis_witness_set":[`
	for i, w := range witnesses {
		if i > 0 {
			doc += ","
		}
		doc += `"` + w + `"`
	}
	doc += `],"genesis_tree_head":{"root_hash":"00","tree_size":0}}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The env-driven / k8s path: an operator turns on the auditor with toggles +
// K, and the witness set + gossip peer derive from the (mounted) bootstrap.
func TestApplyBootstrapDerivations_WitnessSetAndPeer(t *testing.T) {
	ws := []string{"did:key:w1", "did:key:w2", "did:key:w3", "did:key:w4", "did:key:w5"}
	cfg := config.Defaults()
	cfg.LedgerEndpoint = "http://localhost:8080"
	cfg.NetworkBootstrapFile = writeBootstrap(t, "did:web:state:tn:davidson", ws)
	cfg.Witness.QuorumK = 5
	cfg.GossipIngest.Enabled = true

	got, err := applyBootstrapDerivations(cfg)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	if len(got.Witness.Sets) != 1 {
		t.Fatalf("want 1 derived witness set, got %d", len(got.Witness.Sets))
	}
	set := got.Witness.Sets[0]
	if set.LogDID != "did:web:state:tn:davidson" || len(set.WitnessDIDs) != 5 || set.QuorumK != 5 {
		t.Errorf("derived set = %+v", set)
	}
	if len(got.GossipIngest.Peers) != 1 ||
		got.GossipIngest.Peers[0].LogDID != "did:web:state:tn:davidson" ||
		got.GossipIngest.Peers[0].BaseURL != "http://localhost:8080" {
		t.Errorf("derived peer = %+v", got.GossipIngest.Peers)
	}
}

func TestApplyBootstrapDerivations_ExplicitSetsNotOverridden(t *testing.T) {
	cfg := config.Defaults()
	cfg.NetworkBootstrapFile = writeBootstrap(t, "did:web:state:tn:davidson", []string{"did:key:w1", "did:key:w2"})
	cfg.Witness.QuorumK = 1
	cfg.Witness.Sets = []config.WitnessSetConfig{
		{LogDID: "did:web:other", WitnessDIDs: []string{"did:key:x"}, QuorumK: 1},
	}
	got, err := applyBootstrapDerivations(cfg)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got.Witness.Sets) != 1 || got.Witness.Sets[0].LogDID != "did:web:other" {
		t.Errorf("explicit Sets must not be overridden: %+v", got.Witness.Sets)
	}
}

func TestApplyBootstrapDerivations_QuorumExceedsN(t *testing.T) {
	cfg := config.Defaults()
	cfg.NetworkBootstrapFile = writeBootstrap(t, "did:web:state:tn:davidson", []string{"did:key:w1", "did:key:w2"})
	cfg.Witness.QuorumK = 5 // > N=2
	if _, err := applyBootstrapDerivations(cfg); err == nil {
		t.Fatal("expected error when QuorumK > N witnesses")
	}
}

func TestApplyBootstrapDerivations_NoopWhenNothingNeeded(t *testing.T) {
	cfg := config.Defaults() // no QuorumK, ingest disabled
	got, err := applyBootstrapDerivations(cfg)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got.Witness.Sets) != 0 || len(got.GossipIngest.Peers) != 0 {
		t.Errorf("nothing should be derived; got sets=%d peers=%d",
			len(got.Witness.Sets), len(got.GossipIngest.Peers))
	}
}
