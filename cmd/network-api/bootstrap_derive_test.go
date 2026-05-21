package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// The equivocation scanner audits the witness-set logs, which need not be JN
// court destinations (e.g. the ledger's own log DID from the bootstrap). They
// must still get a ledger endpoint, or the scanner fails "no ledger endpoint".
func TestLedgerEndpointMap_IncludesWitnessSetLogs(t *testing.T) {
	reg := jurisdiction.NewRegistry()
	if err := registerProductionBundles(reg); err != nil {
		t.Fatalf("register bundles: %v", err)
	}
	reg.Freeze()

	cfg := config.Defaults()
	cfg.LedgerEndpoint = "http://localhost:8080"
	cfg.Witness.Sets = []config.WitnessSetConfig{
		{LogDID: "did:attesta:standalone-witness:local", WitnessDIDs: []string{"did:key:w1"}, QuorumK: 1},
	}

	m := ledgerEndpointMap(cfg, reg)

	if m["did:attesta:standalone-witness:local"] != "http://localhost:8080" {
		t.Errorf("audited (non-court) log not mapped to the ledger: %v", m)
	}
	if m["did:web:state:tn:davidson"] != "http://localhost:8080" {
		t.Errorf("registered court destination not mapped: %v", m)
	}
}

// A per-log override wins over the default ledger endpoint.
func TestLedgerEndpointMap_PerLogOverride(t *testing.T) {
	reg := jurisdiction.NewRegistry()
	_ = registerProductionBundles(reg)
	reg.Freeze()

	cfg := config.Defaults()
	cfg.LedgerEndpoint = "http://localhost:8080"
	cfg.Witness.LedgerEndpoints = map[string]string{"did:attesta:other:log": "http://other:9090"}
	cfg.Witness.Sets = []config.WitnessSetConfig{
		{LogDID: "did:attesta:other:log", WitnessDIDs: []string{"did:key:w1"}, QuorumK: 1},
	}

	m := ledgerEndpointMap(cfg, reg)
	if m["did:attesta:other:log"] != "http://other:9090" {
		t.Errorf("per-log override ignored: %v", m)
	}
}

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
