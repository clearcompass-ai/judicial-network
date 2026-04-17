package consortium

import (
	"crypto/ecdsa"
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
	escrowNodes  []*ecdsa.PublicKey
	threshold    int
}

// MappingEscrowConfig configures the mapping escrow manager.
type MappingEscrowConfig struct {
	ContentStore storage.ContentStore
	EscrowNodes  []*ecdsa.PublicKey // secp256k1 public keys for ECIES
	Threshold    int                // M in M-of-N
}

// NewMappingEscrowManager creates a manager for vendor-DID mappings.
func NewMappingEscrowManager(cfg MappingEscrowConfig) (*MappingEscrowManager, error) {
	if cfg.ContentStore == nil {
		return nil, fmt.Errorf("consortium/mapping_escrow: nil content store")
	}
	if cfg.Threshold < 1 {
		return nil, fmt.Errorf("consortium/mapping_escrow: threshold must be >= 1")
	}
	if cfg.Threshold > len(cfg.EscrowNodes) {
		return nil, fmt.Errorf("consortium/mapping_escrow: threshold (%d) > node count (%d)",
			cfg.Threshold, len(cfg.EscrowNodes))
	}

	me := identity.NewMappingEscrow(cfg.ContentStore, identity.DefaultMappingEscrowConfig())

	return &MappingEscrowManager{
		escrow:       me,
		contentStore: cfg.ContentStore,
		escrowNodes:  cfg.EscrowNodes,
		threshold:    cfg.Threshold,
	}, nil
}

// CreateMapping creates a new identity→credential mapping,
// stores it via the SDK's MappingEscrow, and returns the stored record.
func (m *MappingEscrowManager) CreateMapping(
	identityHash [32]byte,
	credRef identity.CredentialRef,
) (*identity.StoredMapping, error) {
	record := identity.MappingRecord{
		IdentityHash:  identityHash,
		CredentialRef: credRef,
	}

	stored, err := m.escrow.StoreMapping(record)
	if err != nil {
		return nil, fmt.Errorf("consortium/mapping_escrow: store: %w", err)
	}

	return stored, nil
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
	newNodes []*ecdsa.PublicKey,
	newThreshold int,
) (*identity.StoredMapping, error) {
	destMgr, err := NewMappingEscrowManager(MappingEscrowConfig{
		ContentStore: m.contentStore,
		EscrowNodes:  newNodes,
		Threshold:    newThreshold,
	})
	if err != nil {
		return nil, fmt.Errorf("consortium/mapping_escrow: transfer init: %w", err)
	}

	return destMgr.CreateMapping(identityHash, credRef)
}
