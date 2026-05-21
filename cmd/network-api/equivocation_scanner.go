/*
FILE PATH: cmd/network-api/equivocation_scanner.go

DESCRIPTION:

	Boot wiring for the proactive equivocation scanner — the JN acting
	as an active auditor rather than a passive receiver. When
	cfg.EquivocationScanner.Enabled is set, buildEquivocationScanner
	assembles:

	  - the scan set + trust root : every log DID JN holds a witness set
	    for (reusing buildWitnessSets / buildTreeHeadClient).
	  - the auditor identity       : a secp256k1 gossip key (PEM) wrapped
	    in a stateful gossipfeed.EventSigner under cfg.GossipDID.
	  - the emit fan-out           : a gossipfeed.Publisher over a
	    gossip.MultiSink of HTTPSinks, one per emit peer (D2: defaults to
	    the GossipIngest peers — gossip topologies are symmetric).

	Returns (nil, nil, nil) when disabled so main() skips the goroutine.
	The Publisher is returned alongside the Scanner so run() can drain
	it on shutdown.

	This file lives in the JN daemon, never the Ledger: the Ledger is a
	dumb sequencer and does not poll peers or evaluate network state.
*/
package main

import (
	"fmt"
	"log/slog"
	"sort"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/equivocation"
	"github.com/clearcompass-ai/judicial-network/gossipfeed"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// buildEquivocationScanner constructs the scanner + its emit publisher
// from operational config. Returns (nil, nil, nil) when disabled. Any
// misconfiguration (missing auditor identity, no ledger endpoint, no
// witness sets, no emit peers) aborts boot rather than failing silently
// in a background goroutine.
func buildEquivocationScanner(
	cfg config.Operational,
	registry *jurisdiction.Registry,
	logger *slog.Logger,
) (*equivocation.Scanner, *gossipfeed.Publisher, error) {
	sc := cfg.EquivocationScanner
	if !sc.Enabled {
		return nil, nil, nil
	}

	// Scan set + trust root: only logs JN holds a witness set for can
	// be verified, so they ARE the scan set.
	witnessSets, err := buildWitnessSets(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("witness sets: %w", err)
	}
	if len(witnessSets) == 0 {
		return nil, nil, fmt.Errorf("equivocation scanner enabled but no witness sets configured (set Witness.Sets)")
	}
	logDIDs := make([]string, 0, len(witnessSets))
	for did := range witnessSets {
		logDIDs = append(logDIDs, did)
	}
	sort.Strings(logDIDs) // deterministic sweep order

	client := buildTreeHeadClient(cfg, registry)
	if client == nil {
		return nil, nil, fmt.Errorf("equivocation scanner requires a ledger endpoint (LedgerEndpoint empty)")
	}

	networkID, err := loadNetworkID(cfg.NetworkBootstrapFile)
	if err != nil {
		return nil, nil, fmt.Errorf("network id: %w", err)
	}

	// Auditor identity (D1): a secp256k1 PEM. The originator DID is a
	// self-certifying did:key derived from the key — never configured,
	// honouring the no-DID-in-Operational invariant.
	key, err := gossipfeed.LoadSigningKeyPEM(sc.SigningKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("gossip signing key: %w", err)
	}
	originator, err := gossipfeed.DIDKeyForSigningKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("derive auditor did: %w", err)
	}
	eventSigner, err := gossipfeed.NewEventSigner(
		cosign.NewECDSAWitnessSigner(key), networkID, originator)
	if err != nil {
		return nil, nil, fmt.Errorf("gossip event signer: %w", err)
	}
	logger.Info("equivocation scanner: auditor identity",
		slog.String("did", originator))

	publisher, err := buildGossipPublisher(cfg, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("gossip publisher: %w", err)
	}

	scanner, err := equivocation.NewScanner(equivocation.ScannerConfig{
		LogDIDs:        logDIDs,
		WitnessSets:    witnessSets,
		Client:         client,
		Emitter:        publisher,
		Signer:         eventSigner.Sign,
		PollInterval:   sc.PollInterval,
		Logger:         logger,
		LedgerEndpoint: cfg.LedgerEndpoint,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("new scanner: %w", err)
	}
	return scanner, publisher, nil
}

// buildGossipPublisher constructs the emit-side publisher fanning out
// to every configured emit peer. D2: EmitPeers overrides; empty reuses
// the symmetric GossipIngest peers.
func buildGossipPublisher(cfg config.Operational, logger *slog.Logger) (*gossipfeed.Publisher, error) {
	baseURLs := cfg.EquivocationScanner.EmitPeers
	if len(baseURLs) == 0 {
		for _, p := range cfg.GossipIngest.Peers {
			if p.BaseURL != "" {
				baseURLs = append(baseURLs, p.BaseURL)
			}
		}
	}
	if len(baseURLs) == 0 {
		return nil, fmt.Errorf("no emit peers (set EquivocationScanner.EmitPeers or GossipIngest.Peers)")
	}

	sinks := make([]gossip.Sink, 0, len(baseURLs))
	for _, u := range baseURLs {
		client, err := gossip.NewClient(u)
		if err != nil {
			return nil, fmt.Errorf("gossip client %q: %w", u, err)
		}
		sink, err := gossip.NewHTTPSink(client)
		if err != nil {
			return nil, fmt.Errorf("gossip sink %q: %w", u, err)
		}
		sinks = append(sinks, sink)
	}
	multi, err := gossip.NewMultiSink(sinks)
	if err != nil {
		return nil, fmt.Errorf("multi sink: %w", err)
	}
	return gossipfeed.NewPublisher(gossipfeed.PublisherConfig{
		Underlying: multi,
		Logger:     logger,
	})
}
