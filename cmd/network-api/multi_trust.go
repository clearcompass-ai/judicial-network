/*
FILE PATH: cmd/network-api/multi_trust.go

DESCRIPTION:

	buildMultiJurisdictionTrust composes the C-3 cross-network
	LogTrustProvider from boot-time inputs: the existing per-log
	(Fetcher, LeafReader) pair (wrapped as LocalTrust for the home
	dispatch), the home log DID (the bootstrap doc's ExchangeDID),
	the foreign witness keysets (one per cfg.GossipIngest.PeerLogs
	entry, each bound to its foreign NetworkID), and the shared
	HeadsJournal the C-2 multi-network ingest writes through.

	Returns (nil, nil) when no foreign PeerLogs are declared — the
	provider would then degenerate to a pure LocalTrust pass-through
	at every dispatch, and the existing call sites are byte-for-byte
	equivalent at AsOf{} via trust.NewLocalTrust(Fetcher, LeafReader).
	Wiring it as nil keeps the v1.33 single-network path untouched
	for deployments that have not yet declared peer logs (the C-4
	migration switches to deps.MultiTrust only when non-nil).

LIFECYCLE

	Construction order in main.go:

	  1. buildJudicialDeps   → deps.Fetcher, deps.LeafReader set
	  2. buildGossipIngest   → gossipPipelines.{Heads, Journal}
	  3. deps.HeadsJournal   = gossipPipelines.Journal
	  4. deps.MultiTrust     = buildMultiJurisdictionTrust(cfg, deps,
	                              gossipPipelines.Journal)  // HERE

	The provider must be built AFTER step 3 because it captures the
	journal pointer for as-of head resolution; the journal must be
	the SAME instance the gossip pipelines write through (else
	foreign reads would silently fail closed).

SECURITY POSTURE

	Witness keysets are built from JN-LOCAL operator config — never
	from peer-supplied bytes. Each foreign keyset binds to its
	declared NetworkID at construction time (the same NetworkID the
	C-2 foreign gossip pipeline's GossipVerifier binds its envelope
	+ cosign checks to). The provider's foreignSets map and the
	gossip ingest's WitnessSetRegistry are therefore the SAME crypto
	root in two places — both fail closed if the operator declares
	a wrong NetworkID.
*/
package main

import (
	"fmt"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/attesta-tools/libs/crosslog"
	"github.com/clearcompass-ai/attesta-tools/libs/monitoring"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
	"github.com/clearcompass-ai/judicial-network/verification/trust"
)

// buildMultiJurisdictionTrust constructs the C-3 cross-network
// LogTrustProvider. See file-level docstring for the lifecycle +
// security contract.
//
// Returns (nil, nil) when cfg.GossipIngest.PeerLogs is empty —
// signal to callers that the v1.33 single-network LocalTrust path
// remains the active trust provider at every call site (the C-4
// migration is a no-op in that case).
func buildMultiJurisdictionTrust(
	cfg config.Operational,
	deps judicial.Dependencies,
	journal monitoring.HeadsJournal,
) (verifier.LogTrustProvider, error) {
	// Single-network deployment → nothing for the provider to
	// dispatch on; LocalTrust is sufficient.
	if len(cfg.GossipIngest.PeerLogs) == 0 {
		return nil, nil
	}
	if cfg.NetworkBootstrapFile == "" {
		return nil, fmt.Errorf("MultiJurisdictionTrust: NetworkBootstrapFile required (home log DID source)")
	}
	if journal == nil {
		return nil, fmt.Errorf("MultiJurisdictionTrust: HeadsJournal required for foreign-log as-of resolution")
	}
	doc, err := loadBootstrapDoc(cfg.NetworkBootstrapFile)
	if err != nil {
		return nil, fmt.Errorf("MultiJurisdictionTrust: load bootstrap: %w", err)
	}
	homeLogDID := doc.ExchangeDID
	if homeLogDID == "" {
		return nil, fmt.Errorf("MultiJurisdictionTrust: bootstrap.ExchangeDID empty (cannot identify home log)")
	}

	foreignSets, err := buildForeignWitnessSets(cfg.GossipIngest.PeerLogs)
	if err != nil {
		return nil, err
	}

	local := trust.NewLocalTrust(deps.Fetcher, deps.LeafReader)
	prov, err := trust.NewMultiJurisdictionTrust(local, homeLogDID, foreignSets, journal)
	if err != nil {
		return nil, fmt.Errorf("MultiJurisdictionTrust: %w", err)
	}
	return prov, nil
}

// buildForeignWitnessSets resolves cfg.GossipIngest.PeerLogs into
// the foreign-log keyset map MultiJurisdictionTrust dispatches on.
// Each keyset binds to its declared FOREIGN NetworkID (the same
// binding the foreign gossip pipeline's GossipVerifier uses — one
// source of crypto truth).
//
// Failure modes (all boot-fatal):
//   - malformed PeerLog NetworkID (cosign.NetworkIDFromWire rejects)
//   - crosslog.BuildWitnessSetsECDSAOnly rejects (bad witness DID,
//     duplicate, K > N, etc.)
func buildForeignWitnessSets(peerLogs []config.PeerLogConfig) (map[string]*cosign.WitnessKeySet, error) {
	out := make(map[string]*cosign.WitnessKeySet, len(peerLogs))
	for i, pl := range peerLogs {
		nid, err := cosign.NetworkIDFromWire(pl.NetworkID)
		if err != nil {
			return nil, fmt.Errorf("MultiJurisdictionTrust: PeerLogs[%d] (%s).NetworkID: %w", i, pl.LogDID, err)
		}
		keysets, err := crosslog.BuildWitnessSetsECDSAOnly(
			[]crosslog.WitnessSetSpec{{
				LogDID:      pl.LogDID,
				WitnessDIDs: pl.WitnessDIDs,
				QuorumK:     pl.QuorumK,
			}},
			nid,
		)
		if err != nil {
			return nil, fmt.Errorf("MultiJurisdictionTrust: PeerLogs[%d] (%s) build keyset: %w", i, pl.LogDID, err)
		}
		out[pl.LogDID] = keysets[pl.LogDID]
	}
	return out, nil
}
