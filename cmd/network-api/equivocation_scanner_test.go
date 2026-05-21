package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

func TestBuildEquivocationScanner_DisabledReturnsNil(t *testing.T) {
	r := jurisdiction.NewRegistry()
	r.Freeze()
	sc, pub, err := buildEquivocationScanner(config.Operational{}, r, slog.Default())
	if err != nil {
		t.Fatalf("disabled scanner should not error: %v", err)
	}
	if sc != nil || pub != nil {
		t.Fatalf("disabled scanner should return (nil, nil), got (%v, %v)", sc, pub)
	}
}

func TestBuildEquivocationScanner_EnabledNoWitnessSets(t *testing.T) {
	r := jurisdiction.NewRegistry()
	r.Freeze()
	cfg := config.Operational{
		EquivocationScanner: config.EquivocationScannerConfig{
			Enabled:        true,
			SigningKeyFile: "/nonexistent.pem",
		},
	}
	_, _, err := buildEquivocationScanner(cfg, r, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "witness sets") {
		t.Fatalf("want a witness-sets error, got %v", err)
	}
}

func TestBuildGossipPublisher_NoPeers(t *testing.T) {
	_, err := buildGossipPublisher(config.Operational{}, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "emit peers") {
		t.Fatalf("want a no-emit-peers error, got %v", err)
	}
}

func TestBuildGossipPublisher_ReusesIngestPeers(t *testing.T) {
	// D2: empty EmitPeers ⇒ fan out to the symmetric GossipIngest peers.
	cfg := config.Operational{
		GossipIngest: config.GossipIngestConfig{
			Peers: []config.GossipPeerConfig{
				{LogDID: "did:web:peer", BaseURL: "https://peer.example"},
			},
		},
	}
	pub, err := buildGossipPublisher(cfg, slog.Default())
	if err != nil {
		t.Fatalf("buildGossipPublisher: %v", err)
	}
	if pub == nil {
		t.Fatalf("publisher must be non-nil")
	}
	_ = pub.Close(context.Background())
}

func TestBuildGossipPublisher_EmitPeersOverride(t *testing.T) {
	cfg := config.Operational{
		EquivocationScanner: config.EquivocationScannerConfig{
			EmitPeers: []string{"https://sentry.example"},
		},
	}
	pub, err := buildGossipPublisher(cfg, slog.Default())
	if err != nil {
		t.Fatalf("buildGossipPublisher: %v", err)
	}
	if pub == nil {
		t.Fatalf("publisher must be non-nil")
	}
	_ = pub.Close(context.Background())
}
