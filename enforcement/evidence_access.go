/*
FILE PATH: enforcement/evidence_access.go
DESCRIPTION: Sealed evidence access enforcement. Bridge between judicial

	enforcement logic and SDK artifact access.

KEY ARCHITECTURAL DECISIONS:
  - Reads disclosure orders from authority chain to assemble recipient list.
  - Passes to GrantArtifactAccess sealed mode.
  - Uses did_keys.ResolveEncryptionKey for recipient key resolution.
  - Wraps retrieve.go with enforcement-layer policy.

OVERVIEW: GrantEvidenceAccess → sealed-mode artifact grant with enforcement checks.
KEY DEPENDENCIES: ortholog-sdk/lifecycle, cases/artifact
*/
package enforcement

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	sdkartifact "github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/cases/artifact"
)

type EvidenceAccessConfig struct {
	ArtifactCID     storage.CID
	ContentDigest   storage.CID
	FilingEntryPos  types.LogPosition
	CaseRootPos     types.LogPosition
	ScopePos        types.LogPosition
	RequesterPubKey []byte
	RequesterDID    string
	GranterDID      string
	SchemaRef       types.LogPosition
	OwnerMasterKey  []byte
	PkDel           []byte
	Capsule         *sdkartifact.Capsule
}

// GrantEvidenceAccess wraps artifact.RetrieveArtifact with enforcement-layer
// policy for sealed evidence. Resolves recipient encryption key via
// did_keys.ResolveEncryptionKey and delegates to the SDK's sealed-mode grant.
func GrantEvidenceAccess(
	cfg EvidenceAccessConfig,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore artifact.DelegationKeyStore,
	retrievalProvider storage.RetrievalProvider,
	extractor schema.SchemaParameterExtractor,
	leafReader smt.LeafReader,
	fetcher builder.EntryFetcher,
	resolver did.DIDResolver,
) (*lifecycle.GrantArtifactAccessResult, error) {
	if cfg.RequesterDID == "" {
		return nil, fmt.Errorf("enforcement/evidence_access: empty requester DID")
	}

	// Resolve requester's encryption key via did_keys (keyAgreement purpose).
	requesterPubKey := cfg.RequesterPubKey
	if len(requesterPubKey) == 0 && resolver != nil {
		pk, err := artifact.ResolveEncryptionKey(cfg.RequesterDID, resolver)
		if err != nil {
			return nil, fmt.Errorf("enforcement/evidence_access: resolve requester key: %w", err)
		}
		requesterPubKey = pk
	}

	return artifact.RetrieveArtifact(
		artifact.RetrievalRequest{
			ArtifactCID:     cfg.ArtifactCID,
			ContentDigest:   cfg.ContentDigest,
			FilingEntryPos:  cfg.FilingEntryPos,
			CaseRootPos:     cfg.CaseRootPos,
			ScopePos:        cfg.ScopePos,
			RequesterPubKey: requesterPubKey,
			RequesterDID:    cfg.RequesterDID,
			GranterDID:      cfg.GranterDID,
			SchemaRef:       cfg.SchemaRef,
			OwnerMasterKey:  cfg.OwnerMasterKey,
			PkDel:           cfg.PkDel,
			Capsule:         cfg.Capsule,
		},
		keyStore, delKeyStore, retrievalProvider, extractor,
		leafReader, fetcher, resolver,
	)
}
