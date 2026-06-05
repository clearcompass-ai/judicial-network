// Package networkbundle builds the judicial network's concrete
// protocol.NetworkBundle — the single per-network injection object that drives
// proof GENERATION (the bundle-driven gather) and offline VERIFICATION, without
// the agnostic layer importing any judicial-network code.
//
// This is the FIRST concrete bundle (epic baseproof#5, Wave 4). A second network
// type federates, generates, and verifies by supplying its OWN bundle this same
// way, copying none of this package — that substitutability is the epic's
// acceptance bar.
package networkbundle

import (
	"crypto/sha256"
	"fmt"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/protocol"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// Vocabulary is the per-network generation + federation vocabulary the bundle
// carries BEYOND what the genesis bootstrap pins: the governance/signer schema
// positions a network establishes at mint time (which the gather discovers
// amendments by) and its federation cited member. A genesis-only network leaves
// every field zero.
type Vocabulary struct {
	// GovernanceSchemas maps each governance v2 section name (protocol.
	// GovernanceSectionNames) to its on-log schema position.
	GovernanceSchemas map[string]types.LogPosition
	// SignerRotationSchema is the on-log position of the signer-rotation schema;
	// nil ⇒ no signer-rotation surface.
	SignerRotationSchema *types.LogPosition
	// CitedMemberKey is the SMT key a federation nested proof targets when this
	// network is cited; zero ⇒ not citable.
	CitedMemberKey [32]byte
}

// Build constructs the network's NetworkBundle from its genesis bootstrap, the
// ledger read endpoint, the quorum K, and the per-network Vocabulary. TrustRoot
// and Witnesses are DERIVED from the bootstrap (the same hash-pin the offline
// verifier binds against), so a caller can never desync them from the network's
// identity — only the Vocabulary is operator-supplied.
func Build(doc *network.BootstrapDocument, endpoint string, quorumK int, v Vocabulary) (*protocol.NetworkBundle, error) {
	if doc == nil {
		return nil, fmt.Errorf("networkbundle: nil bootstrap document")
	}
	ids, err := doc.IDs()
	if err != nil {
		return nil, fmt.Errorf("networkbundle: bootstrap IDs: %w", err)
	}
	canonical, err := doc.CanonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("networkbundle: canonical bytes: %w", err)
	}
	keys, err := witness.KeysFromDIDs(doc.GenesisWitnessSet)
	if err != nil {
		return nil, fmt.Errorf("networkbundle: witness keys from genesis DIDs: %w", err)
	}
	set, err := cosign.NewWitnessKeySet(keys, cosign.NetworkID(ids.NetworkID), quorumK, nil)
	if err != nil {
		return nil, fmt.Errorf("networkbundle: witness key set: %w", err)
	}
	b := &protocol.NetworkBundle{
		TrustRoot: protocol.GenesisTrustRoot{
			NetworkID:             cosign.NetworkID(ids.NetworkID),
			GenesisWitnessDIDs:    append([]string(nil), doc.GenesisWitnessSet...),
			QuorumK:               quorumK,
			BootstrapDocumentHash: sha256.Sum256(canonical),
		},
		Witnesses:            set,
		Endpoint:             endpoint,
		GovernanceSchemas:    v.GovernanceSchemas,
		SignerRotationSchema: v.SignerRotationSchema,
		CitedMemberKey:       v.CitedMemberKey,
	}
	if err := b.Validate(); err != nil {
		return nil, fmt.Errorf("networkbundle: %w", err)
	}
	return b, nil
}
