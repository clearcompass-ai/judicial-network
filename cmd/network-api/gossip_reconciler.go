/*
FILE PATH: cmd/network-api/gossip_reconciler.go

DESCRIPTION:

	Composition root for the INBOUND gossip anti-entropy plane — the "Smart
	Edge" pull pipeline. Strings together the verify-only layers into one
	background worker:

	  peers.PeerPuller        pulls each peer's /v1/gossip/since feed (raw,
	                             untrusted SignedEvents)
	       │
	       ▼
	  gossipverify.GossipVerifier  Tier 1: gossip.Verify envelope authenticity
	                               Tier 2: findings router — embedded
	                               K-of-N / signer / merkle proof against
	                               JN-LOCAL trust roots (witness-set registry,
	                               the shared DID VerifierRegistry, trusted heads)
	       │
	       ▼
	  monitoring.Reconciler      advances JN's verified view: CosignedTreeHead →
	                             TrustedHeadStore; WitnessRotation → live trust root

	SEPARATION OF DUTIES: the JN is the ENFORCER, not the custodian. It
	re-verifies what it pulls (Alignment 6) and advances its own trusted view —
	it does NOT persist a gossip store, serve a feed, or slash. Custody of fraud
	evidence (the durable store + equivocation findings) belongs to the external
	auditor; the JN consumes that evidence by re-verifying it, identical to how
	the ledger treats it (detect/serve, never a synchronous control plane —
	Alignment 11).

	ZERO-TRUST: every trust input is JN-local. Witness sets come from
	Witness.Sets + NetworkBootstrapFile; the originator/signer verifier is the
	same DID VerifierRegistry the admission gate uses; peers contribute only
	bytes. Disabled deployments (no GossipIngest.Enabled / no peers) build
	nothing and return a nil puller.
*/
package main

import (
	"fmt"
	"log/slog"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/gossip"

	"github.com/clearcompass-ai/attesta-tools/libs/auditing/gossipverify"
	"github.com/clearcompass-ai/attesta-tools/libs/auditing/peers"
	"github.com/clearcompass-ai/attesta-tools/libs/monitoring"

	"github.com/clearcompass-ai/judicial-network/api/config"
)

// buildGossipIngest assembles the inbound, verify-only pull pipeline from
// operational config + the shared signature verifier. Returns (nil, nil) when
// ingest is disabled or no peers are configured. Returns an error only on a
// misconfiguration that should abort boot (enabled but no bootstrap/network
// identity, or a signature verifier that cannot back an originator check).
func buildGossipIngest(
	cfg config.Operational,
	sigVerifier attestation.SignatureVerifier,
	logger *slog.Logger,
) (*peers.PeerPuller, *monitoring.TrustedHeadStore, error) {
	if !cfg.GossipIngest.Enabled || len(cfg.GossipIngest.Peers) == 0 {
		return nil, nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.NetworkBootstrapFile == "" {
		return nil, nil, fmt.Errorf("gossip ingest enabled but NetworkBootstrapFile is empty (envelope + witness verification need the network ID)")
	}
	networkID, err := loadNetworkID(cfg.NetworkBootstrapFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load network id: %w", err)
	}
	witnessSets, err := buildWitnessSets(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("build witness sets: %w", err)
	}

	// The originator (envelope) + signer verifiers are the SAME DID
	// VerifierRegistry the admission gate uses — it already knows did:key /
	// did:web / did:pkh. gossip.NewDIDOriginatorVerifier needs the concrete
	// registry; the admission gate hands it back as the interface.
	registry, ok := sigVerifier.(*did.VerifierRegistry)
	if !ok {
		return nil, nil, fmt.Errorf("gossip ingest requires a *did.VerifierRegistry signature verifier, got %T", sigVerifier)
	}
	originator, err := gossip.NewDIDOriginatorVerifier(registry)
	if err != nil {
		return nil, nil, fmt.Errorf("originator verifier: %w", err)
	}

	witnessRegistry := gossipverify.NewWitnessSetRegistry(witnessSets, networkID)
	heads := monitoring.NewTrustedHeadStore(logger)

	// Cross-log inclusion (ClassMerkle) tile mirrors. Proofs replay against the
	// source log's TRUSTED head (heads, above), so a mirror is a data source,
	// not a trust root; empty config ⇒ those findings fail-closed.
	var tiles gossipverify.TileFetcherSource
	if len(cfg.GossipIngest.TileMirrors) > 0 {
		mirrors := make(map[string]string, len(cfg.GossipIngest.TileMirrors))
		for _, m := range cfg.GossipIngest.TileMirrors {
			mirrors[m.LogDID] = m.BaseURL
		}
		htm, terr := gossipverify.NewHTTPTileMirrors(mirrors, nil)
		if terr != nil {
			return nil, nil, fmt.Errorf("tile mirrors: %w", terr)
		}
		tiles = htm
	}

	verifier, err := gossipverify.NewGossipVerifier(gossipverify.GossipVerifierConfig{
		Originator:     originator,
		NetworkID:      networkID,
		WitnessSets:    witnessRegistry,
		SignerVerifier: registry,
		Heads:          heads,
		Tiles:          tiles,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("gossip verifier: %w", err)
	}

	reconciler, err := monitoring.NewReconciler(monitoring.ReconcilerConfig{
		Verifier: verifier,
		Heads:    heads,
		// No Store: the JN hosts no custody — verified evidence lives with the
		// auditor. No Equivocation responder: slashing/recording is the
		// auditor's custody role, not the enforcer's.
		// The witness-set registry IS the rotator: a Tier-2-verified
		// WitnessRotationFinding advances the live trust root (verify-before-
		// swap, standing quorum).
		Rotator: witnessRegistry,
		Logger:  logger,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("reconciler: %w", err)
	}

	feeds := make([]peers.PeerFeed, len(cfg.GossipIngest.Peers))
	for i, p := range cfg.GossipIngest.Peers {
		feeds[i] = peers.PeerFeed{LogDID: p.LogDID, BaseURL: p.BaseURL}
	}
	puller, err := peers.NewPeerPuller(peers.PeerPullerConfig{
		Peers:     feeds,
		Sink:      reconciler,
		Interval:  cfg.GossipIngest.PollInterval,
		PageLimit: cfg.GossipIngest.PageLimit,
		Logger:    logger,
	})
	if err != nil {
		return nil, nil, err
	}
	// heads is returned so the API server can surface the verify-only trusted
	// view read-only (GET /v1/judicial/monitoring/peer-consistency).
	return puller, heads, nil
}
