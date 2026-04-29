package consortium

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/identity"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// MappingEscrowManager handles vendor-DID ↔ real-DID mappings
// within a consortium, backed by the SDK's identity.MappingEscrow.
type MappingEscrowManager struct {
	escrow       *identity.MappingEscrow
	contentStore storage.ContentStore
	nodes        []identity.EscrowNode
	threshold    int
}

// MappingEscrowConfig configures the mapping escrow manager.
type MappingEscrowConfig struct {
	ContentStore storage.ContentStore
	Nodes        []identity.EscrowNode // DID + secp256k1 PubKey per escrow node
	Threshold    int                   // M in M-of-N
}

// NewMappingEscrowManager creates a manager for vendor-DID mappings.
func NewMappingEscrowManager(cfg MappingEscrowConfig) (*MappingEscrowManager, error) {
	if cfg.ContentStore == nil {
		return nil, fmt.Errorf("consortium/mapping_escrow: nil content store")
	}
	if cfg.Threshold < 1 {
		return nil, fmt.Errorf("consortium/mapping_escrow: threshold must be >= 1")
	}
	if cfg.Threshold > len(cfg.Nodes) {
		return nil, fmt.Errorf("consortium/mapping_escrow: threshold (%d) > node count (%d)",
			cfg.Threshold, len(cfg.Nodes))
	}

	escrowCfg := identity.DefaultMappingEscrowConfig()
	escrowCfg.ShareThreshold = cfg.Threshold
	escrowCfg.TotalShares = len(cfg.Nodes)
	me := identity.NewMappingEscrow(cfg.ContentStore, escrowCfg)

	return &MappingEscrowManager{
		escrow:       me,
		contentStore: cfg.ContentStore,
		nodes:        cfg.Nodes,
		threshold:    cfg.Threshold,
	}, nil
}

// CreateMapping creates a new identity→credential mapping,
// stores it via the SDK's MappingEscrow, and returns the stored record
// alongside the per-node encrypted shares.
func (m *MappingEscrowManager) CreateMapping(
	identityHash [32]byte,
	credRef identity.CredentialRef,
) (*identity.StoredMapping, []identity.EncryptedShare, error) {
	record := identity.MappingRecord{
		IdentityHash:  identityHash,
		CredentialRef: credRef,
	}

	stored, shares, err := m.escrow.StoreMapping(record, m.nodes)
	if err != nil {
		return nil, nil, fmt.Errorf("consortium/mapping_escrow: store: %w", err)
	}

	return stored, shares, nil
}

// RecoverMapping recovers a real-DID from M-of-N escrow shares.
func (m *MappingEscrowManager) RecoverMapping(
	shares []escrow.Share,
) ([]byte, error) {
	if len(shares) < m.threshold {
		return nil, fmt.Errorf("consortium/mapping_escrow: need %d shares, got %d",
			m.threshold, len(shares))
	}

	secret, err := escrow.ReconstructGF256(shares)
	if err != nil {
		return nil, fmt.Errorf("consortium/mapping_escrow: reconstruct: %w", err)
	}

	return secret, nil
}

// TransferMapping re-creates a mapping for a new set of escrow nodes.
func (m *MappingEscrowManager) TransferMapping(
	identityHash [32]byte,
	credRef identity.CredentialRef,
	newNodes []identity.EscrowNode,
	newThreshold int,
) (*identity.StoredMapping, []identity.EncryptedShare, error) {
	destMgr, err := NewMappingEscrowManager(MappingEscrowConfig{
		ContentStore: m.contentStore,
		Nodes:        newNodes,
		Threshold:    newThreshold,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("consortium/mapping_escrow: transfer init: %w", err)
	}

	return destMgr.CreateMapping(identityHash, credRef)
}
