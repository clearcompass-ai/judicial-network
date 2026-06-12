// FILE PATH: cmd/network-api/era_wiring.go
//
// FED-1 (#107) boot wiring: the era-correct witness-set resolution every
// cross-log verify path consumes, replacing the static per-log
// Dependencies.WitnessSets map (era-blind AND rotation-blind — verified
// proofs resolved against one frozen roster forever).
//
// The trust inputs are exactly the inputs the static map had — the config
// rosters — but their role DEMOTES from "the witness set, forever" to
// "the chain ROOT" (each log's year-1 genesis seed, the one legal role a
// config roster has): resolution replays genesis → the journaled verified-
// rotation chain (libs/witnessrotation, VerifyRotation re-run every step)
// and anchors eras by which chain set's K-of-N actually cosigned the head.
// A malformed roster — empty genesis, alias collision, key that does not
// derive, K out of bounds, a cosign scheme the policy refuses — FAILS BOOT
// in the builders below (condition #1's boot half: with an in-memory
// journal the era-0 set IS the config-derived root by construction, so the
// roster cross-check is the constructors' own validation, fatal at startup).
package main

import (
	"fmt"
	"log/slog"

	"github.com/baseproof/baseproof/crypto/cosign"

	"github.com/baseproof/tooling/libs/crosslog"
	"github.com/baseproof/tooling/libs/witnessrotation"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/verification/eras"
)

// buildEraResolution constructs the shared rotation journal + the era
// resolver over EVERY configured trust root:
//
//   - HOME-network logs: cfg.Witness.Sets rosters under the bootstrap-derived
//     NetworkID (what buildWitnessSets always built — now as chain roots);
//   - FOREIGN logs: cfg.GossipIngest.PeerLogs rosters under each peer's
//     pinned NetworkID (the same derivation buildForeignPipeline seeds its
//     live registry from — one recipe, two consumers).
//
// The returned journal is handed to buildGossipIngest so the reconcilers
// write the chains this resolver replays. Ingest disabled ⇒ the journal
// simply never fills: genesis-era resolution still works (every
// never-rotated log), and a post-rotation head fails by NAME instead of
// failing as a bogus quorum mismatch against a stale roster.
func buildEraResolution(
	cfg config.Operational,
	logger *slog.Logger,
) (*eras.Resolver, *witnessrotation.MemoryRotationJournal, error) {
	journal := witnessrotation.NewMemoryRotationJournal()

	var roots []witnessrotation.LogTrustRoot
	var known []string

	// HOME logs — the rosters the static map carried, demoted to roots.
	home, err := buildWitnessSets(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("era resolution: home trust roots: %w", err)
	}
	for logDID, set := range home {
		roots = append(roots, witnessrotation.LogTrustRoot{LogDID: logDID, Genesis: set})
		known = append(known, logDID)
	}

	// FOREIGN logs — one root per PeerLog, under the PEER's pinned NetworkID.
	for i, peerLog := range cfg.GossipIngest.PeerLogs {
		foreignNetworkID, err := cosign.NetworkIDFromWire(peerLog.NetworkID)
		if err != nil {
			return nil, nil, fmt.Errorf("era resolution: peer_logs[%d] NetworkID: %w", i, err)
		}
		spec, err := witnessSpecWithBLS(peerLog.LogDID, peerLog.WitnessDIDs, peerLog.QuorumK, peerLog.WitnessDeclarationsFile, peerLog.AuthorizedBLSWitnessIDs)
		if err != nil {
			return nil, nil, fmt.Errorf("era resolution: peer_logs[%d] witnesses: %w", i, err)
		}
		keysets, err := crosslog.BuildWitnessSetsForPolicy(
			[]crosslog.WitnessSetSpec{spec}, foreignNetworkID, peerLog.AllowedCosignSchemeTags)
		if err != nil {
			return nil, nil, fmt.Errorf("era resolution: peer_logs[%d] keyset: %w", i, err)
		}
		set, ok := keysets[peerLog.LogDID]
		if !ok || set == nil {
			return nil, nil, fmt.Errorf("era resolution: peer_logs[%d] built no keyset for %q", i, peerLog.LogDID)
		}
		roots = append(roots, witnessrotation.LogTrustRoot{LogDID: peerLog.LogDID, Genesis: set})
		known = append(known, peerLog.LogDID)
	}

	if len(roots) == 0 {
		// No trust roots configured at all: a resolver that names every
		// lookup no-such-peer — the same posture as the empty static map,
		// with a better error.
		inner, err := witnessrotation.NewJournalWitnessSetResolver(journal, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("era resolution: %w", err)
		}
		r, err := eras.New(inner, journal, nil, cfg.GossipIngest.EraWarmupGrace, logger)
		if err != nil {
			return nil, nil, err
		}
		return r, journal, nil
	}

	inner, err := witnessrotation.NewJournalWitnessSetResolver(journal, roots)
	if err != nil {
		return nil, nil, fmt.Errorf("era resolution: %w", err)
	}
	resolver, err := eras.New(inner, journal, known, cfg.GossipIngest.EraWarmupGrace, logger)
	if err != nil {
		return nil, nil, err
	}
	return resolver, journal, nil
}
