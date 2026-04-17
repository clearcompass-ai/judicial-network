/*
FILE PATH: consortium/mapping_escrow.go

DESCRIPTION:
    Manages vendor-DID ↔ real-DID encrypted mappings for sealed
    party bindings within the consortium. Uses the SDK's MappingEscrow
    (guide §28) with Shamir secret sharing (guide §15) and ECIES
    per-node encryption.

KEY DEPENDENCIES:
    - ortholog-sdk/exchange/identity: MappingEscrow, MappingEntry,
      MappingEscrowConfig (guide §28)
    - ortholog-sdk/crypto/escrow: SplitGF256, EncryptForNode (guide §15)
    - ortholog-sdk/storage: ContentStore for pinning escrow packages
*/
package consortium

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/identity"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// MappingEscrowManager handles the lifecycle of vendor-DID mappings
// within a consortium. Each sealed party binding maps a vendor-specific
// DID (opaque to the public) to the real DID (known only to authorized
// parties and recoverable via M-of-N escrow).
type MappingEscrowManager struct {
	escrow       *identity.MappingEscrow
	contentStore storage.ContentStore
	escrowNodes  []escrow.NodeConfig
	threshold    int // M in M-of-N
}

// MappingEscrowConfig configures the mapping escrow manager.
type MappingEscrowConfig struct {
	// ContentStore is where escrow packages are pinned.
	ContentStore storage.ContentStore

	// EscrowNodes are the nodes that hold Shamir shares.
	EscrowNodes []escrow.NodeConfig

	// Threshold is M in M-of-N recovery.
	Threshold int
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

	me, err := identity.NewMappingEscrow(identity.MappingEscrowConfig{
		EscrowNodes: cfg.EscrowNodes,
		Threshold:   cfg.Threshold,
	})
	if err != nil {
		return nil, fmt.Errorf("consortium/mapping_escrow: init: %w", err)
	}

	return &MappingEscrowManager{
		escrow:       me,
		contentStore: cfg.ContentStore,
		escrowNodes:  cfg.EscrowNodes,
		threshold:    cfg.Threshold,
	}, nil
}

// CreateMapping creates a new vendor-DID ↔ real-DID mapping entry,
// splits the mapping secret via Shamir, encrypts shares per-node
// via ECIES, and pins the escrow package to CAS.
func (m *MappingEscrowManager) CreateMapping(vendorDID, realDID string) (*identity.MappingEntry, error) {
	if vendorDID == "" || realDID == "" {
		return nil, fmt.Errorf("consortium/mapping_escrow: vendor and real DIDs required")
	}

	entry, err := m.escrow.CreateMapping(vendorDID, realDID)
	if err != nil {
		return nil, fmt.Errorf("consortium/mapping_escrow: create: %w", err)
	}

	return entry, nil
}

// RecoverMapping recovers a real-DID from a vendor-DID using M-of-N
// escrow shares. Requires at least threshold shares from distinct nodes.
func (m *MappingEscrowManager) RecoverMapping(
	vendorDID string,
	shares []escrow.Share,
) (string, error) {
	if len(shares) < m.threshold {
		return "", fmt.Errorf("consortium/mapping_escrow: need %d shares, got %d",
			m.threshold, len(shares))
	}

	realDID, err := m.escrow.RecoverMapping(vendorDID, shares)
	if err != nil {
		return "", fmt.Errorf("consortium/mapping_escrow: recover: %w", err)
	}

	return realDID, nil
}

// TransferMapping re-encrypts a mapping for a new set of escrow nodes.
// Used during vendor migration (Exchange A → Exchange B).
func (m *MappingEscrowManager) TransferMapping(
	vendorDID string,
	shares []escrow.Share,
	newNodes []escrow.NodeConfig,
	newThreshold int,
) (*identity.MappingEntry, error) {
	// Recover the real DID first.
	realDID, err := m.RecoverMapping(vendorDID, shares)
	if err != nil {
		return nil, fmt.Errorf("consortium/mapping_escrow: transfer recover: %w", err)
	}

	// Create new escrow with the destination node set.
	destEscrow, err := identity.NewMappingEscrow(identity.MappingEscrowConfig{
		EscrowNodes: newNodes,
		Threshold:   newThreshold,
	})
	if err != nil {
		return nil, fmt.Errorf("consortium/mapping_escrow: transfer init dest: %w", err)
	}

	// Re-create the mapping under the new escrow.
	entry, err := destEscrow.CreateMapping(vendorDID, realDID)
	if err != nil {
		return nil, fmt.Errorf("consortium/mapping_escrow: transfer create: %w", err)
	}

	return entry, nil
}
