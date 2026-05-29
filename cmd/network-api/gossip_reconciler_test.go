// buildGossipIngest multi-pipeline coverage.
//
// C-2 contract: when cfg.GossipIngest.PeerLogs is non-empty, the
// binary builds ONE parallel pipeline per foreign log on top of the
// home pipeline. Each foreign pipeline has its own NetworkID +
// witness set + GossipVerifier + Reconciler; all pipelines share
// the same TrustedHeadStore + HeadsJournal (LogDID-keyed, globally
// unique) so cross-log reads see a unified worldview.
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/did"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
)

// genWitnessDIDs returns n fresh did:key secp256k1 DIDs (the form
// gossipverify.NewWitnessSetRegistry / crosslog.BuildWitnessSetsECDSAOnly
// resolve via witness.KeysFromDIDs).
func genWitnessDIDs(t *testing.T, n int) []string {
	t.Helper()
	out := make([]string, n)
	for i := 0; i < n; i++ {
		kp, err := did.GenerateDIDKeySecp256k1()
		if err != nil {
			t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
		}
		out[i] = kp.DID
	}
	return out
}

// writeFullBootstrap writes a STRUCTURALLY COMPLETE bootstrap doc
// suitable for the NetworkID-deriving load path (loadNetworkID).
// writeBootstrap in bootstrap_derive_test.go writes the minimal
// (applyBootstrapDerivations-only) shape, which fails when fed
// through network.BootstrapDocument.IDs() — that path requires
// the full genesis admission/signature policy.
func writeFullBootstrap(t *testing.T, exchangeDID string, witnesses []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "network-bootstrap.json")
	doc := `{` +
		`"protocol_version":"attesta/v1",` +
		`"network_name":"test",` +
		`"exchange_did":"` + exchangeDID + `",` +
		`"genesis_witness_set":[`
	for i, w := range witnesses {
		if i > 0 {
			doc += `,`
		}
		doc += `"` + w + `"`
	}
	doc += `],` +
		`"genesis_tree_head":{"root_hash":"` + strings.Repeat("0", 64) + `","tree_size":0},` +
		`"genesis_admission_authorities":["0x00000000000000000000000000000000000000a1"],` +
		`"genesis_admission_policy":{"gating_required":true,"cost_mode":"uncharged"},` +
		`"genesis_signature_policy":{` +
		`"allowed_entry_sig_schemes":[1],` +
		`"allowed_cosign_scheme_tags":[1],` +
		`"min_signatures_per_entry":1` +
		`}` +
		`}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// minimalIngestCfg returns a config with everything buildGossipIngest
// needs (bootstrap path with valid DIDs, witness sets, peers) but no
// foreign PeerLogs. Caller mutates GossipIngest.PeerLogs to test the
// multi-network surface.
func minimalIngestCfg(t *testing.T) (config.Operational, []string) {
	t.Helper()

	homeWitnesses := genWitnessDIDs(t, 2)

	cfg := config.Defaults()
	cfg.LedgerEndpoint = "http://localhost:8080"
	cfg.NetworkBootstrapFile = writeFullBootstrap(t, "did:web:state:tn:davidson", homeWitnesses)
	cfg.Witness.QuorumK = 2
	cfg.Witness.Sets = []config.WitnessSetConfig{{
		LogDID:      "did:web:state:tn:davidson",
		WitnessDIDs: homeWitnesses,
		QuorumK:     2,
	}}
	cfg.GossipIngest.Enabled = true
	cfg.GossipIngest.Peers = []config.GossipPeerConfig{
		{LogDID: "did:web:state:tn:davidson", BaseURL: "http://localhost:8080"},
	}
	return cfg, homeWitnesses
}

// validPeerLog returns a structurally complete foreign-network
// PeerLogConfig. Helper writes a 64-hex NetworkID + the right
// number of did:key witnesses for the QuorumK.
func validForeignPeerLog(t *testing.T, did, networkID string) config.PeerLogConfig {
	t.Helper()
	return config.PeerLogConfig{
		LogDID:         did,
		NetworkID:      networkID,
		GossipEndpoint: "https://federal.example/v1/gossip",
		WitnessDIDs:    genWitnessDIDs(t, 3),
		QuorumK:        2,
	}
}

// TestBuildGossipIngest_Disabled_NoPipeline pins that the disabled
// case returns an empty pipelines struct with nothing to run.
func TestBuildGossipIngest_Disabled_NoPipeline(t *testing.T) {
	t.Parallel()
	cfg := config.Operational{}
	cfg.GossipIngest.Enabled = false

	pipelines, err := buildGossipIngest(cfg, &did.VerifierRegistry{}, judicial.Dependencies{}, nil)
	if err != nil {
		t.Fatalf("disabled ingest should not error: %v", err)
	}
	if len(pipelines.Pullers) != 0 {
		t.Errorf("Pullers len = %d, want 0 (ingest disabled)", len(pipelines.Pullers))
	}
	if pipelines.Heads != nil || pipelines.Journal != nil {
		t.Error("disabled ingest must not allocate Heads/Journal")
	}
}

// TestBuildGossipIngest_EnabledNoPeers_NoPipeline pins that the
// enabled-but-no-peers-or-peer-logs case is also a no-op.
func TestBuildGossipIngest_EnabledNoPeers_NoPipeline(t *testing.T) {
	t.Parallel()
	cfg := config.Operational{}
	cfg.GossipIngest.Enabled = true
	// No Peers, no PeerLogs.

	pipelines, err := buildGossipIngest(cfg, &did.VerifierRegistry{}, judicial.Dependencies{}, nil)
	if err != nil {
		t.Fatalf("no peers should not error: %v", err)
	}
	if len(pipelines.Pullers) != 0 {
		t.Errorf("Pullers len = %d, want 0 (no peers configured)", len(pipelines.Pullers))
	}
}

// TestBuildGossipIngest_HomeOnly_OnePipeline pins the v1.33 baseline:
// home Peers configured, no PeerLogs ⇒ exactly one pipeline (home).
func TestBuildGossipIngest_HomeOnly_OnePipeline(t *testing.T) {
	t.Parallel()
	cfg, _ := minimalIngestCfg(t)

	verifier, err := buildSignatureVerifier(cfg, stubResolver{})
	if err != nil {
		t.Fatalf("buildSignatureVerifier: %v", err)
	}

	pipelines, err := buildGossipIngest(cfg, verifier, judicial.Dependencies{}, nil)
	if err != nil {
		t.Fatalf("home-only buildGossipIngest: %v", err)
	}
	if len(pipelines.Pullers) != 1 {
		t.Errorf("Pullers len = %d, want 1 (home only)", len(pipelines.Pullers))
	}
	if pipelines.Heads == nil {
		t.Error("Heads must be non-nil when at least one pipeline runs")
	}
	if pipelines.Journal == nil {
		t.Error("Journal must be non-nil when at least one pipeline runs (v1.34 contract)")
	}
	if pipelines.HomeReconciler == nil {
		t.Error("HomeReconciler must be non-nil when a home pipeline runs")
	}
}

// TestBuildGossipIngest_TwoForeignNetworks_ThreePipelines pins the
// core C-2 contract: one home + two foreign PeerLogs ⇒ three
// pipelines, each with its own Verifier/Reconciler but ALL sharing
// the same Heads + Journal.
func TestBuildGossipIngest_TwoForeignNetworks_ThreePipelines(t *testing.T) {
	t.Parallel()
	cfg, _ := minimalIngestCfg(t)

	// Two foreign peer logs with distinct NetworkIDs.
	federalNetworkID := strings.Repeat("a", 64)
	gaNetworkID := strings.Repeat("b", 64)
	cfg.GossipIngest.PeerLogs = []config.PeerLogConfig{
		validForeignPeerLog(t, "did:web:federal-courts.example", federalNetworkID),
		validForeignPeerLog(t, "did:web:ga-courts.example", gaNetworkID),
	}

	verifier, err := buildSignatureVerifier(cfg, stubResolver{})
	if err != nil {
		t.Fatalf("buildSignatureVerifier: %v", err)
	}

	pipelines, err := buildGossipIngest(cfg, verifier, judicial.Dependencies{}, nil)
	if err != nil {
		t.Fatalf("multi-network buildGossipIngest: %v", err)
	}
	if got, want := len(pipelines.Pullers), 3; got != want {
		t.Errorf("Pullers len = %d, want %d (1 home + 2 foreign)", got, want)
	}
	if pipelines.Heads == nil || pipelines.Journal == nil {
		t.Error("Heads/Journal must be shared across all pipelines")
	}
}

// TestBuildGossipIngest_ForeignOnly_NoHome pins the cross-network-only
// deployment: no home peers, only foreign PeerLogs. Should still build
// one pipeline per foreign log (the JN can verify foreign-log
// references without subscribing to home gossip).
func TestBuildGossipIngest_ForeignOnly_NoHome(t *testing.T) {
	t.Parallel()
	cfg, _ := minimalIngestCfg(t)
	cfg.GossipIngest.Peers = nil // drop home peers
	cfg.GossipIngest.PeerLogs = []config.PeerLogConfig{
		validForeignPeerLog(t, "did:web:federal-courts.example", strings.Repeat("a", 64)),
	}

	verifier, err := buildSignatureVerifier(cfg, stubResolver{})
	if err != nil {
		t.Fatalf("buildSignatureVerifier: %v", err)
	}

	pipelines, err := buildGossipIngest(cfg, verifier, judicial.Dependencies{}, nil)
	if err != nil {
		t.Fatalf("foreign-only buildGossipIngest: %v", err)
	}
	if got, want := len(pipelines.Pullers), 1; got != want {
		t.Errorf("Pullers len = %d, want %d (foreign-only)", got, want)
	}
	if pipelines.HomeReconciler != nil {
		t.Error("HomeReconciler must be nil when no home peers are configured")
	}
}

// TestBuildGossipIngest_MalformedForeignNetworkID_Rejected pins
// fail-fast on a malformed foreign NetworkID. Config-validate
// catches the LENGTH/HEX-CHARS shape; this test pins the BOOT
// fast-fail when the bytes are structurally bad enough that
// cosign.NetworkIDFromWire rejects them (zero NetworkID).
func TestBuildGossipIngest_MalformedForeignNetworkID_Rejected(t *testing.T) {
	t.Parallel()
	cfg, _ := minimalIngestCfg(t)
	cfg.GossipIngest.PeerLogs = []config.PeerLogConfig{{
		LogDID:         "did:web:federal.example",
		NetworkID:      strings.Repeat("0", 64), // all-zero NetworkID is rejected by cosign
		GossipEndpoint: "https://federal.example/v1/gossip",
		WitnessDIDs:    genWitnessDIDs(t, 2),
		QuorumK:        2,
	}}

	verifier, err := buildSignatureVerifier(cfg, stubResolver{})
	if err != nil {
		t.Fatalf("buildSignatureVerifier: %v", err)
	}

	_, err = buildGossipIngest(cfg, verifier, judicial.Dependencies{}, nil)
	if err == nil {
		t.Fatal("malformed (all-zero) NetworkID must fail boot")
	}
	if !strings.Contains(err.Error(), "foreign pipeline") {
		t.Errorf("err = %q, want a 'foreign pipeline' diagnosis", err.Error())
	}
}

// TestBuildGossipIngest_EmptyBootstrap_Rejected pins fail-fast when
// ingest is enabled but no bootstrap file is configured.
func TestBuildGossipIngest_EmptyBootstrap_Rejected(t *testing.T) {
	t.Parallel()
	cfg := config.Operational{}
	cfg.GossipIngest.Enabled = true
	cfg.GossipIngest.Peers = []config.GossipPeerConfig{
		{LogDID: "did:web:peer", BaseURL: "http://peer"},
	}
	// NetworkBootstrapFile intentionally empty

	_, err := buildGossipIngest(cfg, &did.VerifierRegistry{}, judicial.Dependencies{}, nil)
	if err == nil {
		t.Fatal("ingest enabled with no bootstrap MUST error")
	}
	if !strings.Contains(err.Error(), "NetworkBootstrapFile") {
		t.Errorf("err = %q, want a 'NetworkBootstrapFile' diagnosis", err.Error())
	}
}

// TestBuildGossipIngest_NonRegistryVerifier_Rejected pins the
// compatibility contract: the signature verifier MUST be a
// *did.VerifierRegistry (the originator + signer paths need
// concrete access to the registry's resolver chain).
func TestBuildGossipIngest_NonRegistryVerifier_Rejected(t *testing.T) {
	t.Parallel()
	cfg, _ := minimalIngestCfg(t)

	_, err := buildGossipIngest(cfg, fakeVerifier{}, judicial.Dependencies{}, nil)
	if err == nil {
		t.Fatal("non-Registry verifier must fail boot")
	}
	if !strings.Contains(err.Error(), "VerifierRegistry") {
		t.Errorf("err = %q, want a 'VerifierRegistry' diagnosis", err.Error())
	}
}

// fakeVerifier is the wrong concrete type for the originator path —
// it satisfies attestation.SignatureVerifier but is NOT a
// *did.VerifierRegistry, so the gossip-ingest originator-verifier
// derivation must reject it.
type fakeVerifier struct{}

func (fakeVerifier) Verify(_ context.Context, _ string, _, _ []byte, _ uint16) error {
	return errors.New("nope")
}

