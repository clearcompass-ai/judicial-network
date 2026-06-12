package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// The env-driven / k8s path (pin mode, DiscoverOriginator=false): an operator
// turns on the auditor with toggles + K, and the witness set + gossip peer
// derive from the (mounted) bootstrap, keyed by exchange_did verbatim.
func TestApplyBootstrapDerivations_WitnessSetAndPeer(t *testing.T) {
	ws := []string{"did:key:w1", "did:key:w2", "did:key:w3", "did:key:w4", "did:key:w5"}
	cfg := config.Defaults()
	cfg.LedgerEndpoint = "http://localhost:8080"
	cfg.NetworkBootstrapFile = writeFullBootstrap(t, "did:web:state:tn:davidson", ws)
	cfg.Witness.QuorumK = 3 // J4: must equal the constitutional majority(5)=3
	cfg.GossipIngest.Enabled = true
	cfg.GossipIngest.DiscoverOriginator = false // pin path: key by exchange_did

	got, err := applyBootstrapDerivations(context.Background(), cfg)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	if len(got.Witness.Sets) != 1 {
		t.Fatalf("want 1 derived witness set, got %d", len(got.Witness.Sets))
	}
	set := got.Witness.Sets[0]
	if set.LogDID != "did:web:state:tn:davidson" || len(set.WitnessDIDs) != 5 || set.QuorumK != 3 {
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
	cfg.NetworkBootstrapFile = writeFullBootstrap(t, "did:web:state:tn:davidson", []string{"did:key:w1", "did:key:w2"})
	cfg.Witness.QuorumK = 1
	cfg.Witness.Sets = []config.WitnessSetConfig{
		{LogDID: "did:web:other", WitnessDIDs: []string{"did:key:x"}, QuorumK: 1},
	}
	got, err := applyBootstrapDerivations(context.Background(), cfg)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got.Witness.Sets) != 1 || got.Witness.Sets[0].LogDID != "did:web:other" {
		t.Errorf("explicit Sets must not be overridden: %+v", got.Witness.Sets)
	}
}

func TestApplyBootstrapDerivations_QuorumExceedsN(t *testing.T) {
	cfg := config.Defaults()
	cfg.NetworkBootstrapFile = writeFullBootstrap(t, "did:web:state:tn:davidson", []string{"did:key:w1", "did:key:w2"})
	cfg.Witness.QuorumK = 5 // > N=2
	if _, err := applyBootstrapDerivations(context.Background(), cfg); err == nil {
		t.Fatal("expected error when QuorumK > N witnesses")
	}
}

func TestApplyBootstrapDerivations_NoopWhenNothingNeeded(t *testing.T) {
	cfg := config.Defaults() // no QuorumK, ingest disabled
	got, err := applyBootstrapDerivations(context.Background(), cfg)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got.Witness.Sets) != 0 || len(got.GossipIngest.Peers) != 0 {
		t.Errorf("nothing should be derived; got sets=%d peers=%d",
			len(got.Witness.Sets), len(got.GossipIngest.Peers))
	}
}

// TestApplyBootstrapDerivations_Discovery is the regression for the JN custody
// stall: STHs are originated under the ledger's operational did:key, so the
// derived witness set + peer must key on THAT (discovered from /v1/log-info),
// not exchange_did. Keying by exchange_did is what made gossipverify reject
// every event with "no witness set for source_log_did <did:key…>".
func TestApplyBootstrapDerivations_Discovery(t *testing.T) {
	const operatorDID = "did:key:zQ3shLEDGEROPERATIONALKEYxxxxxxxxxxxxxxxxxxxxx"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/log-info" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"log_did":    "did:web:state:tn:davidson",
			"ledger_did": operatorDID,
		})
	}))
	defer srv.Close()

	cfg := config.Defaults() // DiscoverOriginator defaults true
	cfg.LedgerEndpoint = srv.URL
	cfg.NetworkBootstrapFile = writeFullBootstrap(t, "did:web:state:tn:davidson",
		[]string{"did:key:w1", "did:key:w2", "did:key:w3"})
	cfg.Witness.QuorumK = 2 // J4: constitutional majority(3)=2
	cfg.GossipIngest.Enabled = true

	got, err := applyBootstrapDerivations(context.Background(), cfg)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if got.Witness.Sets[0].LogDID != operatorDID {
		t.Errorf("witness set must key on the discovered operational did:key, got %q", got.Witness.Sets[0].LogDID)
	}
	if got.GossipIngest.Peers[0].LogDID != operatorDID {
		t.Errorf("peer must key on the discovered operational did:key, got %q", got.GossipIngest.Peers[0].LogDID)
	}
}

// TestApplyBootstrapDerivations_DiscoveryUnreachable fails closed (does not
// hang) when the ledger never serves /v1/log-info; a short context bounds it.
func TestApplyBootstrapDerivations_DiscoveryUnreachable(t *testing.T) {
	cfg := config.Defaults()
	cfg.LedgerEndpoint = "http://127.0.0.1:0"
	cfg.NetworkBootstrapFile = writeFullBootstrap(t, "did:web:state:tn:davidson",
		[]string{"did:key:w1", "did:key:w2"})
	cfg.Witness.QuorumK = 2
	cfg.GossipIngest.Enabled = true

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := applyBootstrapDerivations(ctx, cfg); err == nil {
		t.Fatal("expected discovery against an unreachable ledger to fail")
	}
}
