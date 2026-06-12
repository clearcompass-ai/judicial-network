// FILE PATH: e2e/stack/federation_peers.go
//
// FED-1 (#107) federation wiring: render each JN's foreign peer_logs config
// from the SIBLING networks' already-minted bootstraps, so every JN in a
// multi-network run ingests its peers' gossip (rotation findings included)
// and resolves cross-log witness sets ERA-CORRECTLY. Without this the era
// machinery would run dark in the harness — the preset IS its first wired
// consumer.
//
// Trust posture: the seed is the peer's GENESIS roster + pinned NetworkID
// (the chain ROOT, a config roster's one legal role); everything after era 0
// arrives as Tier-2-verified rotation findings over the peer's feed. The
// feed is the peer AUDITOR's plain-http gossip mirror — a peer is only a
// byte source; every pulled event is re-verified.
package stack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// PeerSeed is one foreign log's trust root + feed, in the exact JSON shape
// api/config.PeerLogConfig decodes (the wire contract is the config's).
type PeerSeed struct {
	LogDID                  string   `json:"log_did"`
	NetworkID               string   `json:"network_id"`
	GossipEndpoint          string   `json:"gossip_endpoint"`
	WitnessDIDs             []string `json:"witness_dids"`
	QuorumK                 int      `json:"quorum_k"`
	AllowedCosignSchemeTags []uint8  `json:"allowed_cosign_scheme_tags,omitempty"`
}

// jnPeerConfigFile is the rendered operational-config fragment's filename
// inside the network's fixtures dir (mounted read-only into the JN).
const jnPeerConfigFile = "jn-config.json"

// WriteJNPeerConfig renders the JN operational config carrying gossip_ingest
// peer_logs. The JN binary loads it via --config; env overrides still apply
// on top (env > file > defaults), so the existing jnEnv stays authoritative
// for everything it sets.
func WriteJNPeerConfig(fixturesDir string, peers []PeerSeed) error {
	cfg := map[string]any{
		"gossip_ingest": map[string]any{
			"enabled":   true,
			"peer_logs": peers,
		},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal jn peer config: %w", err)
	}
	return os.WriteFile(filepath.Join(fixturesDir, jnPeerConfigFile), append(data, '\n'), 0o644)
}

// bootstrapSeedFields is the subset of the network bootstrap the peer seed
// needs (strict source: the peer's own minted constitution).
type bootstrapSeedFields struct {
	GenesisWitnessSet      []string `json:"genesis_witness_set"`
	GenesisQuorumK         int      `json:"genesis_quorum_k"`
	GenesisSignaturePolicy struct {
		AllowedCosignSchemeTags []uint8 `json:"allowed_cosign_scheme_tags"`
	} `json:"genesis_signature_policy"`
}

// PeerSeedFor builds the seed describing network `peer` for some OTHER
// network's JN: trust root from peer's minted bootstrap + the peer
// auditor's gossip mirror as the feed.
func PeerSeedFor(peer NetConfig, peerFixturesDir string, networkIDHex string) (PeerSeed, error) {
	raw, err := os.ReadFile(filepath.Join(peerFixturesDir, "network-bootstrap.json"))
	if err != nil {
		return PeerSeed{}, fmt.Errorf("read peer bootstrap: %w", err)
	}
	var b bootstrapSeedFields
	if err := json.Unmarshal(raw, &b); err != nil {
		return PeerSeed{}, fmt.Errorf("parse peer bootstrap: %w", err)
	}
	if len(b.GenesisWitnessSet) == 0 || b.GenesisQuorumK < 1 {
		return PeerSeed{}, fmt.Errorf("peer bootstrap %q carries no witness roster", peer.Spec.Name)
	}
	return PeerSeed{
		LogDID:                  peer.LogDID,
		NetworkID:               networkIDHex,
		GossipEndpoint:          "http://" + peer.Name("auditor-1") + ":8088",
		WitnessDIDs:             b.GenesisWitnessSet,
		QuorumK:                 b.GenesisQuorumK,
		AllowedCosignSchemeTags: b.GenesisSignaturePolicy.AllowedCosignSchemeTags,
	}, nil
}
