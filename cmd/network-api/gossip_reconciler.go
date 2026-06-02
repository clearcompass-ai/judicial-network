/*
FILE PATH: cmd/network-api/gossip_reconciler.go

DESCRIPTION:

	Composition root for the INBOUND gossip anti-entropy plane — the "Smart
	Edge" pull pipeline. Strings together the verify-only layers into one
	background worker per gossip network:

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
	                             TrustedHeadStore + HeadsJournal;
	                             WitnessRotation → live trust root

	v1.34+ MULTI-NETWORK INGEST. The HOME pipeline (cfg.GossipIngest.Peers +
	cfg.NetworkBootstrapFile's NetworkID + Witness.Sets) runs as before. In
	addition, ONE PARALLEL pipeline is built per cfg.GossipIngest.PeerLogs
	entry — each foreign log carries its OWN NetworkID + witness set, so it
	needs its own GossipVerifier + Reconciler. All pipelines write into the
	SAME TrustedHeadStore + HeadsJournal (keyed by LogDID — globally unique),
	so cross-log reads (the C-3 MultiJurisdictionTrust LogTrustProvider) see
	one unified worldview regardless of which network a head came from.

	SEPARATION OF DUTIES: the JN is the ENFORCER, not the custodian. It
	re-verifies what it pulls (Alignment 6) and advances its own trusted view —
	it does NOT persist a gossip store, serve a feed, or slash. Custody of fraud
	evidence (the durable store + equivocation findings) belongs to the external
	auditor; the JN consumes that evidence by re-verifying it, identical to how
	the ledger treats it (detect/serve, never a synchronous control plane —
	Alignment 11). The HeadsJournal in this binary is the IN-MEMORY
	MemoryHeadsJournal — a process-local archive for as-of reads. The
	PostgresHeadsJournal that survives restarts lives with the auditor.

	ZERO-TRUST: every trust input is JN-local. Witness sets come from
	Witness.Sets + NetworkBootstrapFile (home) or PeerLogs[i].WitnessDIDs
	(foreign); the originator/signer verifier is the same DID VerifierRegistry
	the admission gate uses; peers contribute only bytes. Disabled deployments
	(no GossipIngest.Enabled / no peers / no peer logs) build nothing and
	return an empty pipeline.
*/
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/gossip"
	sdklog "github.com/clearcompass-ai/attesta/log"

	"github.com/clearcompass-ai/attesta-tools/libs/auditing/gossipverify"
	"github.com/clearcompass-ai/attesta-tools/libs/auditing/peers"
	"github.com/clearcompass-ai/attesta-tools/libs/crosslog"
	"github.com/clearcompass-ai/attesta-tools/libs/monitoring"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
)

// gossipIngestPipelines bundles the outputs of buildGossipIngest so main can
// run every puller in its own goroutine and surface the home-network
// Reconciler for SIGHUP-driven hot reloads. The TrustedHeadStore and
// HeadsJournal are SHARED across all pipelines (home + each foreign PeerLog)
// — both are keyed by LogDID, which is globally unique, so writes from
// different networks never collide.
type gossipIngestPipelines struct {
	// Pullers is the home-network puller (index 0) followed by one
	// puller per cfg.GossipIngest.PeerLogs entry, in declaration order.
	// nil / empty when ingest is disabled or has no peers.
	Pullers []*peers.PeerPuller

	// Heads is the shared in-memory trusted-head view across home +
	// foreign networks. Returned for the API server to surface read-
	// only via GET /v1/judicial/monitoring/peer-consistency.
	Heads *monitoring.TrustedHeadStore

	// Journal is the shared in-memory durable archive — every verified
	// CosignedTreeHeadFinding (home OR foreign network) fans out to this
	// journal via the Reconciler's Journal hook. Returned for the C-3
	// MultiJurisdictionTrust LogTrustProvider to resolve as-of heads.
	// nil ⇒ pipelines were not built (no ingest).
	Journal monitoring.HeadsJournal

	// HomeReconciler is the home-network reconciler. Returned so a SIGHUP
	// handler (D13, optional) can call RefreshRegistry()/RefreshAmendments()
	// to hot-reload the gate inputs. The PER-FOREIGN reconcilers are not
	// surfaced; the v1.33 scope gate applies to the home network only
	// (foreign-network auditor scopes are owned by the foreign network).
	HomeReconciler *monitoring.Reconciler
}

// buildGossipIngest assembles the inbound, verify-only pull pipeline(s) from
// operational config + the shared signature verifier. Returns an empty
// pipelines struct when ingest is disabled or no peers/peer-logs are
// configured. Returns an error only on a misconfiguration that should abort
// boot (enabled but no bootstrap/network identity, or a signature verifier
// that cannot back an originator check, or a malformed foreign-network
// NetworkID).
//
// judicialDeps threads the v1.33.x auditor-scope inputs (AuditorRegistry,
// AuditorAmendments, AuditorScopeAsOf) into the HOME Reconciler so a
// verified finding emitted by an out-of-scope auditor is rejected before
// it can advance JN's trusted view. nil slices leave the home reconciler in
// pre-v1.33 behaviour (every verified finding advances). Foreign-network
// reconcilers are not subject to the home-network's auditor-scope gate —
// each foreign network's authorities are owned by that network.
func buildGossipIngest(
	cfg config.Operational,
	sigVerifier attestation.SignatureVerifier,
	judicialDeps judicial.Dependencies,
	logger *slog.Logger,
) (gossipIngestPipelines, error) {
	if !cfg.GossipIngest.Enabled {
		return gossipIngestPipelines{}, nil
	}
	if len(cfg.GossipIngest.Peers) == 0 && len(cfg.GossipIngest.PeerLogs) == 0 {
		return gossipIngestPipelines{}, nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.NetworkBootstrapFile == "" {
		return gossipIngestPipelines{}, fmt.Errorf("gossip ingest enabled but NetworkBootstrapFile is empty (envelope + witness verification need the network ID)")
	}

	// The originator (envelope) + signer verifiers are the SAME DID
	// VerifierRegistry the admission gate uses — it already knows did:key /
	// did:web / did:pkh. The DID resolver is network-agnostic; the same
	// verifier serves home + every foreign pipeline.
	registry, ok := sigVerifier.(*did.VerifierRegistry)
	if !ok {
		return gossipIngestPipelines{}, fmt.Errorf("gossip ingest requires a *did.VerifierRegistry signature verifier, got %T", sigVerifier)
	}
	originator, err := gossip.NewDIDOriginatorVerifier(registry)
	if err != nil {
		return gossipIngestPipelines{}, fmt.Errorf("originator verifier: %w", err)
	}

	// SHARED state: one in-memory anchor + one in-memory journal across
	// home + every foreign pipeline. Each pipeline writes through both
	// via its own Reconciler (which is wired with both Heads and Journal
	// via libs/monitoring.ReconcilerConfig.Journal — the v1.34 fan-out
	// hook). Multi-log isolation in the journal is keyed by LogDID, so
	// cross-network writes do not collide.
	sharedHeads := monitoring.NewTrustedHeadStore(logger)
	sharedJournal := monitoring.NewMemoryHeadsJournal()

	pipelines := gossipIngestPipelines{
		Heads:   sharedHeads,
		Journal: sharedJournal,
	}

	// ── HOME pipeline ─────────────────────────────────────────────────
	if len(cfg.GossipIngest.Peers) > 0 {
		homePuller, homeReconciler, err := buildHomePipeline(
			cfg, originator, registry, sharedHeads, sharedJournal, judicialDeps, logger)
		if err != nil {
			return gossipIngestPipelines{}, fmt.Errorf("home pipeline: %w", err)
		}
		pipelines.Pullers = append(pipelines.Pullers, homePuller)
		pipelines.HomeReconciler = homeReconciler
	}

	// ── PER-FOREIGN PeerLog pipelines ────────────────────────────────
	// Each foreign log has its own NetworkID + witness set + GossipVerifier
	// + Reconciler. They share the same TrustedHeadStore + HeadsJournal as
	// the home pipeline so the C-3 LogTrustProvider gets a unified worldview.
	for i, peerLog := range cfg.GossipIngest.PeerLogs {
		foreignPuller, err := buildForeignPipeline(
			peerLog, cfg.GossipIngest, originator, registry, sharedHeads, sharedJournal, logger)
		if err != nil {
			return gossipIngestPipelines{}, fmt.Errorf("foreign pipeline %d (%s): %w", i, peerLog.LogDID, err)
		}
		pipelines.Pullers = append(pipelines.Pullers, foreignPuller)
	}

	return pipelines, nil
}

// buildHomePipeline assembles the HOME-network verify-and-reconcile chain:
// home NetworkID + home Witness.Sets + home Peers. The Reconciler is wired
// with the shared TrustedHeadStore AND shared HeadsJournal so every verified
// home-network cosigned head fans out to both stores.
func buildHomePipeline(
	cfg config.Operational,
	originator gossip.OriginatorVerifier,
	registry *did.VerifierRegistry,
	heads *monitoring.TrustedHeadStore,
	journal monitoring.HeadsJournal,
	judicialDeps judicial.Dependencies,
	logger *slog.Logger,
) (*peers.PeerPuller, *monitoring.Reconciler, error) {
	networkID, err := loadNetworkID(cfg.NetworkBootstrapFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load network id: %w", err)
	}
	witnessSets, err := buildWitnessSets(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("build witness sets: %w", err)
	}
	witnessRegistry := gossipverify.NewWitnessSetRegistry(witnessSets, networkID)

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

	// v1.33.x auditor-scope gate. nil registry leaves the reconciler in
	// pre-v1.33 behaviour (no scope check); cfg.Validate guarantees an
	// Enforce=true config arrives here with a populated registry slice.
	// AuditorScopeAsOf is the closure that resolves the as-of position
	// for scope merging at finding-handling time.
	reconciler, err := monitoring.NewReconciler(monitoring.ReconcilerConfig{
		Verifier: verifier,
		Heads:    heads,
		Journal:  journal,
		// No Store: the JN hosts no custody — verified evidence lives with the
		// auditor. No Equivocation responder: slashing/recording is the
		// auditor's custody role, not the enforcer's.
		// The witness-set registry IS the rotator: a Tier-2-verified
		// WitnessRotationFinding advances the live trust root (verify-before-
		// swap, standing quorum).
		Rotator:           witnessRegistry,
		Logger:            logger,
		AuditorRegistry:   judicialDeps.AuditorRegistry,
		AuditorAmendments: judicialDeps.AuditorAmendments,
		AuditorScopeAsOf:  judicialDeps.AuditorScopeAsOf,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("reconciler: %w", err)
	}

	feeds := make([]peers.PeerFeed, len(cfg.GossipIngest.Peers))
	for i, p := range cfg.GossipIngest.Peers {
		feeds[i] = peers.PeerFeed{LogDID: p.LogDID, BaseURL: p.BaseURL}
	}
	puller, err := peers.NewPeerPuller(peers.PeerPullerConfig{
		Peers:      feeds,
		Sink:       reconciler,
		Interval:   cfg.GossipIngest.PollInterval,
		PageLimit:  cfg.GossipIngest.PageLimit,
		Logger:     logger,
		HTTPClient: defaultIngestHTTPClient(),
	})
	if err != nil {
		return nil, nil, err
	}
	return puller, reconciler, nil
}

// defaultIngestHTTPClient returns the *http.Client every gossip puller
// uses to GET /v1/gossip/since on its peer feeds. The PeerPuller
// requires it (its v1.27.1 contract); a single shared client carries
// connection pooling across home + foreign pipelines.
//
// Production deployments that need mTLS for foreign endpoints will
// pin a per-pipeline client; today the same hardened default suffices
// (foreign-network gossip is verified end-to-end so the transport's
// authenticity is not a trust input).
func defaultIngestHTTPClient() *http.Client {
	return sdklog.DefaultClient(15*time.Second, nil)
}

// buildForeignPipeline assembles ONE foreign-network verify-and-reconcile
// chain for a single PeerLogConfig. The foreign NetworkID + witness DIDs
// + QuorumK come from the PeerLogConfig; everything else (originator
// verifier, signer verifier, shared TrustedHeadStore + HeadsJournal) is
// shared with the home pipeline. The foreign Reconciler does NOT install
// the home-network's auditor-scope gate — each foreign network's authorities
// are owned by that network.
//
// The puller pulls only ONE feed (peerLog.GossipEndpoint, keyed by
// peerLog.LogDID) — the foreign log's own gossip endpoint. Cross-network
// equivocation findings are still caught here: a fork detected by the
// shared journal's BurnTransition fails closed every subsequent
// VerifyCrossLogProof against that foreign LogDID (STRICT FAIL-CLOSED
// mandate from the 15-year zero-trust spec).
func buildForeignPipeline(
	peerLog config.PeerLogConfig,
	ingestCfg config.GossipIngestConfig,
	originator gossip.OriginatorVerifier,
	registry *did.VerifierRegistry,
	heads *monitoring.TrustedHeadStore,
	journal monitoring.HeadsJournal,
	logger *slog.Logger,
) (*peers.PeerPuller, error) {
	// Foreign NetworkID — 32 bytes / 64 hex chars (cfg.validate
	// guarantees the shape).
	foreignNetworkID, err := cosign.NetworkIDFromWire(peerLog.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("parse NetworkID: %w", err)
	}

	// Foreign witness set — KEY: peerLog.LogDID, VALUE: keyset bound to
	// the foreign NetworkID. The crosslog builder is domain-free; we
	// map the JN config into its neutral spec type.
	witnessSpec, err := witnessSpecWithBLS(peerLog.LogDID, peerLog.WitnessDIDs, peerLog.QuorumK, peerLog.WitnessDeclarationsFile, peerLog.AuthorizedBLSWitnessIDs)
	if err != nil {
		return nil, fmt.Errorf("source foreign BLS witnesses: %w", err)
	}
	keysets, err := crosslog.BuildWitnessSetsForPolicy(
		[]crosslog.WitnessSetSpec{witnessSpec},
		foreignNetworkID,
		peerLog.AllowedCosignSchemeTags,
	)
	if err != nil {
		return nil, fmt.Errorf("build foreign witness keyset: %w", err)
	}

	// Per-foreign WitnessSetRegistry. Cannot be shared with the home
	// pipeline — the registry is bound to ONE NetworkID at construction.
	foreignRegistry := gossipverify.NewWitnessSetRegistry(keysets, foreignNetworkID)

	// Foreign GossipVerifier. NetworkID, WitnessSets, and Heads are
	// foreign-specific; Originator + SignerVerifier are shared (DID
	// resolution is network-agnostic). No tile mirrors for foreign
	// pipelines yet (cross-network inclusion proof verification lands
	// in C-5).
	verifier, err := gossipverify.NewGossipVerifier(gossipverify.GossipVerifierConfig{
		Originator:     originator,
		NetworkID:      foreignNetworkID,
		WitnessSets:    foreignRegistry,
		SignerVerifier: registry,
		Heads:          heads,
	})
	if err != nil {
		return nil, fmt.Errorf("foreign gossip verifier: %w", err)
	}

	// Foreign Reconciler. Wired to the SHARED Heads + Journal so cross-
	// log reads see foreign heads. Rotator is the foreign WitnessSetRegistry
	// — a foreign log's witness-set rotation MUST verify-before-swap
	// against the FOREIGN current set, not the home set. No auditor-scope
	// gate (foreign network owns its authority graph).
	reconciler, err := monitoring.NewReconciler(monitoring.ReconcilerConfig{
		Verifier: verifier,
		Heads:    heads,
		Journal:  journal,
		Rotator:  foreignRegistry,
		Logger:   logger,
	})
	if err != nil {
		return nil, fmt.Errorf("foreign reconciler: %w", err)
	}

	// Per-foreign-log poll/page defaults. Zero values inherit the home
	// pipeline's GossipIngest-wide defaults; a foreign log can override
	// either via PeerLogConfig.{PollInterval, PageLimit}.
	pollInterval := peerLog.PollInterval
	if pollInterval == 0 {
		pollInterval = ingestCfg.PollInterval
	}
	pageLimit := peerLog.PageLimit
	if pageLimit == 0 {
		pageLimit = ingestCfg.PageLimit
	}

	puller, err := peers.NewPeerPuller(peers.PeerPullerConfig{
		Peers: []peers.PeerFeed{{
			LogDID:  peerLog.LogDID,
			BaseURL: peerLog.GossipEndpoint,
		}},
		Sink:       reconciler,
		Interval:   pollInterval,
		PageLimit:  pageLimit,
		Logger:     logger,
		HTTPClient: defaultIngestHTTPClient(),
	})
	if err != nil {
		return nil, fmt.Errorf("foreign puller: %w", err)
	}
	return puller, nil
}
