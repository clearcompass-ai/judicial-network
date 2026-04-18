/*
FILE PATH: parties/binding_sealed.go
DESCRIPTION: Sealed party bindings for juvenile/family cases. PRE-encrypts
    the real-identity-to-vendor-DID mapping so only authorized officers
    can resolve real identity.
KEY ARCHITECTURAL DECISIONS:
    - Calls artifact.PublishArtifact (PRE path) to encrypt the identity mapping.
    - Vendor DID on the log, real DID only in PRE-encrypted artifact.
    - Only scope authority officers can decrypt via GrantArtifactAccess sealed mode.
    - Uses DelegationKeyStore for PRE wrapped keys.
OVERVIEW: CreateSealedBinding → PRE-encrypted mapping + root entity.
KEY DEPENDENCIES: ortholog-sdk/builder, cases/artifact
*/
package parties

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/cases/artifact"
)

// SealedBindingConfig configures a sealed party binding.
type SealedBindingConfig struct {
	Destination string // DID of target exchange. Required.
	SignerDID   string // Authorized court officer DID
	VendorDID   string // Opaque vendor-specific DID (from privacy.go)
	RealDID     string // Real party DID (will be encrypted)
	CaseRef     string
	CaseDID     string
	CaseSeq     uint64
	Role        string
	OwnerDID    string // Owner of the PRE encryption (scope authority)
	SchemaRef   types.LogPosition
	EventTime   int64
}

// SealedBindingResult holds the binding entry and published encrypted mapping.
type SealedBindingResult struct {
	Entry           *envelope.Entry
	EncryptedMapping *artifact.PublishedArtifact
}

// CreateSealedBinding creates a sealed party binding with PRE-encrypted
// identity mapping. The real DID is encrypted; only the vendor DID appears
// on the log. Authorized officers decrypt via GrantArtifactAccess sealed mode.
func CreateSealedBinding(
	cfg SealedBindingConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore artifact.DelegationKeyStore,
	extractor schema.SchemaParameterExtractor,
	fetcher builder.EntryFetcher,
	resolver did.DIDResolver,
) (*SealedBindingResult, error) {
	if cfg.SignerDID == "" || cfg.VendorDID == "" || cfg.RealDID == "" {
		return nil, fmt.Errorf("parties/binding_sealed: signer, vendor, and real DIDs required")
	}

	// Encrypt the real-DID-to-vendor-DID mapping as a PRE artifact.
	mappingPlaintext, _ := json.Marshal(map[string]interface{}{
		"vendor_did": cfg.VendorDID,
		"real_did":   cfg.RealDID,
		"case_ref":   cfg.CaseRef,
		"role":       cfg.Role,
	})

	published, err := artifact.PublishArtifact(
		artifact.PublishConfig{
			Plaintext: mappingPlaintext,
			SchemaRef: cfg.SchemaRef,
			OwnerDID:  cfg.OwnerDID,
		},
		contentStore, keyStore, delKeyStore, extractor, fetcher, resolver,
	)
	if err != nil {
		return nil, fmt.Errorf("parties/binding_sealed: publish mapping: %w", err)
	}

	// Build binding entry with vendor DID (real DID never on log).
	payload, _ := json.Marshal(map[string]interface{}{
		"vendor_did":            cfg.VendorDID,
		"case_ref":              cfg.CaseRef,
		"case_did":              cfg.CaseDID,
		"case_seq":              cfg.CaseSeq,
		"role":                  cfg.Role,
		"status":                "active",
		"encrypted_mapping_cid": published.ArtifactCID.String(),
		"capsule":               published.Capsule,
		"pk_del":                published.PkDel,
		"artifact_encryption":   published.Scheme,
	})

	var schemaRefPtr *types.LogPosition
	if !cfg.SchemaRef.IsNull() {
		schemaRefPtr = &cfg.SchemaRef
	}

	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: cfg.Destination,
		SignerDID: cfg.SignerDID,
		Payload:   payload,
		SchemaRef: schemaRefPtr,
		EventTime: cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("parties/binding_sealed: build root entity: %w", err)
	}

	return &SealedBindingResult{
		Entry:            entry,
		EncryptedMapping: published,
	}, nil
}
