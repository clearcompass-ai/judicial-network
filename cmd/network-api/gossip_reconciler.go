/*
FILE PATH: cmd/network-api/gossip_reconciler.go

DESCRIPTION:

	Composition root for the INBOUND gossip anti-entropy plane — the "Smart
	Edge" pull pipeline. Strings together the three layers built across the
	repo into one background worker:

	  topology.PeerPuller        pulls each peer's /v1/gossip/since feed (raw,
	                             untrusted SignedEvents)
	       │
	       ▼
	  verification.GossipVerifier  Tier 1: gossip.Verify envelope authenticity
	                               Tier 2: judicialfindings router — embedded
	                               K-of-N / signer / merkle proof against
	                               JN-LOCAL trust roots (witness-set registry,
	                               the shared DID VerifierRegistry, trusted heads)
	       │
	       ▼
	  monitoring.Reconciler      dispatches the verified, typed finding to its
	                             enforcer (TrustedHeadStore, EquivocationResponder)

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

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/equivocation"
	"github.com/clearcompass-ai/judicial-network/monitoring"
	"github.com/clearcompass-ai/judicial-network/topology"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// buildGossipIngest assembles the inbound pull pipeline from operational
// config + the shared signature verifier. Returns (nil, nil) when ingest is
// disabled or no peers are configured. Returns an error only on a
// misconfiguration that should abort boot (enabled but no bootstrap/network
// identity, or a signature verifier that cannot back an originator check).
func buildGossipIngest(
	cfg config.Operational,
	sigVerifier attestation.SignatureVerifier,
	logger *slog.Logger,
) (*topology.PeerPuller, error) {
	if !cfg.GossipIngest.Enabled || len(cfg.GossipIngest.Peers) == 0 {
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.NetworkBootstrapFile == "" {
		return nil, fmt.Errorf("gossip ingest enabled but NetworkBootstrapFile is empty (envelope + witness verification need the network ID)")
	}
	networkID, err := loadNetworkID(cfg.NetworkBootstrapFile)
	if err != nil {
		return nil, fmt.Errorf("load network id: %w", err)
	}
	witnessSets, err := buildWitnessSets(cfg)
	if err != nil {
		return nil, fmt.Errorf("build witness sets: %w", err)
	}

	// The originator (envelope) + signer verifiers are the SAME DID
	// VerifierRegistry the admission gate uses — it already knows did:key /
	// did:web / did:pkh. gossip.NewDIDOriginatorVerifier needs the concrete
	// registry; the admission gate hands it back as the interface.
	registry, ok := sigVerifier.(*did.VerifierRegistry)
	if !ok {
		return nil, fmt.Errorf("gossip ingest requires a *did.VerifierRegistry signature verifier, got %T", sigVerifier)
	}
	originator, err := gossip.NewDIDOriginatorVerifier(registry)
	if err != nil {
		return nil, fmt.Errorf("originator verifier: %w", err)
	}

	witnessRegistry := verification.NewWitnessSetRegistry(witnessSets, networkID)
	heads := monitoring.NewTrustedHeadStore(logger)

	// Cross-log inclusion (ClassMerkle) tile mirrors. Proofs replay against the
	// source log's TRUSTED head (heads, above), so a mirror is a data source,
	// not a trust root; empty config ⇒ those findings fail-closed.
	var tiles verification.TileFetcherSource
	if len(cfg.GossipIngest.TileMirrors) > 0 {
		mirrors := make(map[string]string, len(cfg.GossipIngest.TileMirrors))
		for _, m := range cfg.GossipIngest.TileMirrors {
			mirrors[m.LogDID] = m.BaseURL
		}
		htm, terr := verification.NewHTTPTileMirrors(mirrors, nil)
		if terr != nil {
			return nil, fmt.Errorf("tile mirrors: %w", terr)
		}
		tiles = htm
	}

	verifier, err := verification.NewGossipVerifier(verification.GossipVerifierConfig{
		Originator:     originator,
		NetworkID:      networkID,
		WitnessSets:    witnessRegistry,
		SignerVerifier: registry,
		Heads:          heads,
		Tiles:          tiles,
	})
	if err != nil {
		return nil, fmt.Errorf("gossip verifier: %w", err)
	}

	// Equivocation responder requires witness sets to slash against. With none
	// configured, equivocation findings are still verified + logged by the
	// reconciler, just not slashed.
	var responder *monitoring.EquivocationResponder
	if len(witnessSets) > 0 {
		slasher, serr := equivocation.NewSlasher(equivocation.SlasherConfig{
			WitnessSets: witnessSets,
			Threshold:   cfg.GossipIngest.SlashThreshold,
			Logger:      logger,
		})
		if serr != nil {
			return nil, fmt.Errorf("slasher: %w", serr)
		}
		responder, err = monitoring.NewEquivocationResponder(slasher, logger)
		if err != nil {
			return nil, fmt.Errorf("equivocation responder: %w", err)
		}
	}

	reconciler, err := monitoring.NewReconciler(monitoring.ReconcilerConfig{
		Verifier:     verifier,
		Heads:        heads,
		Equivocation: responder,
		// The witness-set registry IS the rotator: a Tier-2-verified
		// WitnessRotationFinding advances the live trust root (verify-before-
		// swap, standing quorum). Without this, witness sets could never
		// rotate at runtime — the SDK rotation machinery would stay dormant.
		Rotator: witnessRegistry,
		Logger:  logger,
	})
	if err != nil {
		return nil, fmt.Errorf("reconciler: %w", err)
	}

	peers := make([]topology.PeerFeed, len(cfg.GossipIngest.Peers))
	for i, p := range cfg.GossipIngest.Peers {
		peers[i] = topology.PeerFeed{LogDID: p.LogDID, BaseURL: p.BaseURL}
	}
	return topology.NewPeerPuller(topology.PeerPullerConfig{
		Peers:     peers,
		Sink:      reconciler,
		Interval:  cfg.GossipIngest.PollInterval,
		PageLimit: cfg.GossipIngest.PageLimit,
		Logger:    logger,
	})
}
