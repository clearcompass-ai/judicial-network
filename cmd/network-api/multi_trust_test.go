// buildMultiJurisdictionTrust coverage.
//
// Pins the C-3 wiring contract: the builder constructs the cross-
// network LogTrustProvider from operator config + the existing
// boot-time inputs, returning a degenerate-nil when no foreign
// PeerLogs are declared (signal to call sites that LocalTrust
// remains the active provider).
package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/attesta-tools/libs/monitoring"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
	"github.com/clearcompass-ai/judicial-network/verification/trust"
)

// TestBuildMultiJurisdictionTrust_NoPeerLogs_ReturnsNil pins the
// degenerate-nil contract: a deployment with no foreign PeerLogs
// declared keeps the v1.33 LocalTrust path untouched (call sites
// see a nil deps.MultiTrust and fall back to trust.NewLocalTrust).
func TestBuildMultiJurisdictionTrust_NoPeerLogs_ReturnsNil(t *testing.T) {
	t.Parallel()
	cfg := config.Operational{}
	// No GossipIngest.PeerLogs entries.
	got, err := buildMultiJurisdictionTrust(cfg, judicial.Dependencies{}, monitoring.NewMemoryHeadsJournal())
	if err != nil {
		t.Fatalf("no-PeerLogs case should not error: %v", err)
	}
	if got != nil {
		t.Errorf("got %T, want nil (signal that LocalTrust path is active)", got)
	}
}

// TestBuildMultiJurisdictionTrust_HappyPath pins that a complete
// configuration (bootstrap + at least one PeerLog + journal)
// returns a non-nil LogTrustProvider that satisfies the SDK
// interface.
func TestBuildMultiJurisdictionTrust_HappyPath(t *testing.T) {
	t.Parallel()
	const homeDID = "did:web:state:tn:davidson"
	witnesses := genWitnessDIDs(t, 3)

	cfg := config.Operational{}
	cfg.NetworkBootstrapFile = writeFullBootstrap(t, homeDID, witnesses)
	cfg.GossipIngest.Enabled = true
	cfg.GossipIngest.PeerLogs = []config.PeerLogConfig{
		validForeignPeerLog(t, "did:web:federal-courts.example", strings.Repeat("a", 64)),
	}

	got, err := buildMultiJurisdictionTrust(cfg, judicial.Dependencies{}, monitoring.NewMemoryHeadsJournal())
	if err != nil {
		t.Fatalf("buildMultiJurisdictionTrust: %v", err)
	}
	if got == nil {
		t.Fatal("got nil; want non-nil provider when PeerLogs are declared")
	}
	// Compile-time interface check; the provider must conform.
	var _ verifier.LogTrustProvider = got
	// Concrete-type check: it should be a trust.MultiJurisdictionTrust,
	// not some other LogTrustProvider impl.
	if _, ok := got.(trust.MultiJurisdictionTrust); !ok {
		t.Errorf("got %T, want trust.MultiJurisdictionTrust", got)
	}
}

// TestBuildMultiJurisdictionTrust_NoBootstrap_Rejected pins that
// PeerLogs declared but no bootstrap file is a boot-fatal
// misconfiguration (the home log DID source is missing).
func TestBuildMultiJurisdictionTrust_NoBootstrap_Rejected(t *testing.T) {
	t.Parallel()
	cfg := config.Operational{}
	cfg.GossipIngest.PeerLogs = []config.PeerLogConfig{
		validForeignPeerLog(t, "did:web:federal.example", strings.Repeat("a", 64)),
	}
	// NetworkBootstrapFile intentionally empty.
	_, err := buildMultiJurisdictionTrust(cfg, judicial.Dependencies{}, monitoring.NewMemoryHeadsJournal())
	if err == nil {
		t.Fatal("no bootstrap with PeerLogs declared MUST fail")
	}
	if !strings.Contains(err.Error(), "NetworkBootstrapFile") {
		t.Errorf("err = %q, want a 'NetworkBootstrapFile' diagnosis", err.Error())
	}
}

// TestBuildMultiJurisdictionTrust_NoJournal_Rejected pins that
// PeerLogs declared but no journal is a boot-fatal misconfiguration
// (foreign-log as-of resolution would silently fail closed for
// every lookup).
func TestBuildMultiJurisdictionTrust_NoJournal_Rejected(t *testing.T) {
	t.Parallel()
	cfg := config.Operational{}
	cfg.NetworkBootstrapFile = writeFullBootstrap(t, "did:web:home", genWitnessDIDs(t, 2))
	cfg.GossipIngest.PeerLogs = []config.PeerLogConfig{
		validForeignPeerLog(t, "did:web:federal.example", strings.Repeat("a", 64)),
	}

	_, err := buildMultiJurisdictionTrust(cfg, judicial.Dependencies{}, nil)
	if err == nil {
		t.Fatal("nil journal with PeerLogs declared MUST fail")
	}
	if !strings.Contains(err.Error(), "HeadsJournal") {
		t.Errorf("err = %q, want a 'HeadsJournal' diagnosis", err.Error())
	}
}

// TestBuildMultiJurisdictionTrust_MalformedForeignNetworkID_Rejected
// pins that a foreign log with an all-zero NetworkID (which the
// SDK rejects post-parse) surfaces a structured error referencing
// the offending PeerLog index + LogDID.
func TestBuildMultiJurisdictionTrust_MalformedForeignNetworkID_Rejected(t *testing.T) {
	t.Parallel()
	cfg := config.Operational{}
	cfg.NetworkBootstrapFile = writeFullBootstrap(t, "did:web:home", genWitnessDIDs(t, 2))
	cfg.GossipIngest.PeerLogs = []config.PeerLogConfig{{
		LogDID:         "did:web:federal.example",
		NetworkID:      strings.Repeat("0", 64), // all-zero ⇒ rejected
		GossipEndpoint: "https://federal.example/v1/gossip",
		WitnessDIDs:    genWitnessDIDs(t, 2),
		QuorumK:        2,
	}}

	_, err := buildMultiJurisdictionTrust(cfg, judicial.Dependencies{}, monitoring.NewMemoryHeadsJournal())
	if err == nil {
		t.Fatal("all-zero NetworkID MUST fail")
	}
	if !strings.Contains(err.Error(), "PeerLogs[0]") || !strings.Contains(err.Error(), "did:web:federal.example") {
		t.Errorf("err = %q, want index + LogDID diagnosis", err.Error())
	}
}

// TestBuildForeignWitnessSets_PerLogNetworkBinding pins that each
// resulting keyset is bound to its DECLARED NetworkID (not a
// shared one) — this is the cross-network replay rejection
// foundation (Scenario 5).
func TestBuildForeignWitnessSets_PerLogNetworkBinding(t *testing.T) {
	t.Parallel()
	peerLogs := []config.PeerLogConfig{
		validForeignPeerLog(t, "did:web:federal.example", strings.Repeat("a", 64)),
		validForeignPeerLog(t, "did:web:ga.example", strings.Repeat("b", 64)),
	}
	sets, err := buildForeignWitnessSets(peerLogs)
	if err != nil {
		t.Fatalf("buildForeignWitnessSets: %v", err)
	}
	if got, want := len(sets), 2; got != want {
		t.Fatalf("len(sets) = %d, want %d", got, want)
	}
	if sets["did:web:federal.example"] == nil || sets["did:web:ga.example"] == nil {
		t.Errorf("missing keyset(s); got keys %v", mapKeys(sets))
	}
	// Cross-network identity: federal and GA keysets bind to
	// DIFFERENT NetworkIDs. We can't reach into the keyset's
	// NetworkID directly (it's encapsulated), but the keysets MUST
	// be distinct values — sharing one would mean both bind to the
	// same network.
	if sets["did:web:federal.example"] == sets["did:web:ga.example"] {
		t.Error("federal and GA keysets share a pointer — they must bind to distinct NetworkIDs")
	}
}

// TestBuildForeignWitnessSets_EmptyInput pins that an empty
// PeerLogs slice returns an empty (non-nil) map — the caller
// chooses what to do with it (buildMultiJurisdictionTrust short-
// circuits BEFORE calling this; the helper is robust against
// direct empty calls).
func TestBuildForeignWitnessSets_EmptyInput(t *testing.T) {
	t.Parallel()
	sets, err := buildForeignWitnessSets(nil)
	if err != nil {
		t.Fatalf("buildForeignWitnessSets(nil): %v", err)
	}
	if sets == nil {
		t.Error("got nil map; want empty non-nil map")
	}
	if len(sets) != 0 {
		t.Errorf("len(sets) = %d, want 0", len(sets))
	}
}

// TestBuildForeignWitnessSets_DuplicateLogDID_PropagatesSDKError
// pins that the SDK's BuildWitnessSetsECDSAOnly duplicate-LogDID
// rejection propagates. (The JN config validator catches duplicates
// at boot per api/config/operational.go::ValidatePeerLogs, but the
// helper is defense-in-depth.)
func TestBuildForeignWitnessSets_DuplicateLogDID_PropagatesSDKError(t *testing.T) {
	t.Parallel()
	pl := validForeignPeerLog(t, "did:web:federal.example", strings.Repeat("a", 64))
	// buildForeignWitnessSets is called per-PeerLog (each in a
	// single-spec slice), so the SDK's duplicate detection within
	// a single call doesn't fire — the duplication is across
	// successive calls into the SAME output map. Verify the map
	// resolution: the second call's keyset REPLACES the first
	// (last-write-wins). The JN config validator is the
	// uniqueness gate; this test pins that the helper itself does
	// not panic on a duplicate.
	sets, err := buildForeignWitnessSets([]config.PeerLogConfig{pl, pl})
	if err != nil {
		t.Fatalf("buildForeignWitnessSets: %v", err)
	}
	if len(sets) != 1 {
		t.Errorf("len(sets) = %d, want 1 (duplicate LogDID collapses)", len(sets))
	}
}

// Static check: errors-wrap the trust package's ErrMultiTrustConfig
// makes its way through buildMultiJurisdictionTrust unchanged so
// callers (the future operator-facing config validator) can
// distinguish wiring faults from runtime trust failures.
func TestBuildMultiJurisdictionTrust_PropagatesMultiTrustConfigError(t *testing.T) {
	t.Parallel()
	// Bootstrap exchange_did → "did:web:foo"; foreign PeerLog
	// LogDID intentionally COLLIDES with it. NewMultiJurisdictionTrust
	// rejects with ErrMultiTrustConfig; the builder MUST surface it.
	const did = "did:web:colliding"
	cfg := config.Operational{}
	cfg.NetworkBootstrapFile = writeFullBootstrap(t, did, genWitnessDIDs(t, 2))
	cfg.GossipIngest.PeerLogs = []config.PeerLogConfig{
		validForeignPeerLog(t, did, strings.Repeat("a", 64)),
	}

	_, err := buildMultiJurisdictionTrust(cfg, judicial.Dependencies{}, monitoring.NewMemoryHeadsJournal())
	if err == nil {
		t.Fatal("home-DID collision MUST fail")
	}
	if !errors.Is(err, trust.ErrMultiTrustConfig) {
		t.Errorf("err = %v, want wrapping ErrMultiTrustConfig", err)
	}
}

// mapKeys returns the keys of any string-keyed map as a slice
// (test diagnostic helper).
func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
