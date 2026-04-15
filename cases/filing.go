/*
FILE PATH:
    cases/filing.go

DESCRIPTION:
    Handles subsequent filings on an existing case. A filing is a Path B
    entry appended to the case root entity. May include an artifact that is
    encrypted via the artifact sub-package.

KEY ARCHITECTURAL DECISIONS:
    - Two key stores passed through: keyStore (AES-GCM) and delKeyStore (PRE).
      Filing.go does not use either directly — they flow to artifact.PublishArtifact.
    - builder.BuildPathBEntry as package-level function. PathBParams.Payload field.
    - Domain Payload carries pk_del for PRE evidence artifacts.

OVERVIEW:
    (1) If plaintext: call artifact.PublishArtifact (both stores passed through).
    (2) Assemble Domain Payload with artifact + disclosure + pk_del fields.
    (3) Build entry via builder.BuildPathBEntry.
    (4) Return unsigned entry.

KEY DEPENDENCIES:
    - ortholog-sdk/builder: BuildPathBEntry, PathBParams, EntryFetcher
    - ortholog-sdk/core/envelope: Entry type
    - judicial-network/cases/artifact: PublishArtifact, DelegationKeyStore
*/
package cases

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

// -------------------------------------------------------------------------------------------------
// 1) Types
// -------------------------------------------------------------------------------------------------

// FilingConfig configures a filing operation.
type FilingConfig struct {
	SignerDID          string
	CaseRootPos        types.LogPosition
	SchemaRef          types.LogPosition
	DelegationPointers []types.LogPosition
	EventTime          int64
	DocumentType       string
	DocumentTitle      string
	Plaintext          []byte
	OwnerDID           string
	DisclosureScope    string
	InitialRecipients  []string
	ExtraPayload       map[string]interface{}
}

// FilingResult holds the outcome of a filing operation.
type FilingResult struct {
	Entry     *envelope.Entry
	Published *artifact.PublishedArtifact
}

// -------------------------------------------------------------------------------------------------
// 2) File
// -------------------------------------------------------------------------------------------------

// File creates a filing entry on an existing case.
// keyStore: AES-GCM keys. delKeyStore: PRE delegation keys. Both passed to PublishArtifact.
func File(
	cfg FilingConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore artifact.DelegationKeyStore,
	extractor schema.SchemaParameterExtractor,
	fetcher builder.EntryFetcher,
	resolver did.DIDResolver,
) (*FilingResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("cases/filing: empty signer DID")
	}
	if cfg.CaseRootPos.IsNull() {
		return nil, fmt.Errorf("cases/filing: null case root position")
	}
	if len(cfg.DelegationPointers) == 0 {
		return nil, fmt.Errorf("cases/filing: empty delegation pointers (Path B requires delegation chain)")
	}

	result := &FilingResult{}

	// (1) Encrypt and store artifact if plaintext provided.
	if len(cfg.Plaintext) > 0 {
		ownerDID := cfg.OwnerDID
		if ownerDID == "" {
			ownerDID = cfg.SignerDID
		}

		published, err := artifact.PublishArtifact(
			artifact.PublishConfig{
				Plaintext:         cfg.Plaintext,
				SchemaRef:         cfg.SchemaRef,
				OwnerDID:          ownerDID,
				Metadata:          map[string]string{"document_type": cfg.DocumentType},
				DisclosureScope:   cfg.DisclosureScope,
				InitialRecipients: cfg.InitialRecipients,
			},
			contentStore,
			keyStore,
			delKeyStore,
			extractor,
			fetcher,
			resolver,
		)
		if err != nil {
			return nil, fmt.Errorf("cases/filing: publish artifact: %w", err)
		}
		result.Published = published
	}

	// (2) Assemble Domain Payload.
	payload := assembleFilingPayload(cfg, result.Published)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("cases/filing: marshal payload: %w", err)
	}

	// (3) Build entry.
	var schemaRefPtr *types.LogPosition
	if !cfg.SchemaRef.IsNull() {
		schemaRefPtr = &cfg.SchemaRef
	}

	entry, err := builder.BuildPathBEntry(builder.PathBParams{
		SignerDID:          cfg.SignerDID,
		TargetRoot:         cfg.CaseRootPos,
		DelegationPointers: cfg.DelegationPointers,
		Payload:            payloadBytes,
		SchemaRef:          schemaRefPtr,
		EventTime:          cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("cases/filing: build entry: %w", err)
	}

	result.Entry = entry
	return result, nil
}

// -------------------------------------------------------------------------------------------------
// 3) Domain Payload assembly
// -------------------------------------------------------------------------------------------------

func assembleFilingPayload(
	cfg FilingConfig,
	published *artifact.PublishedArtifact,
) map[string]interface{} {
	payload := make(map[string]interface{})

	payload["document_type"] = cfg.DocumentType
	payload["document_title"] = cfg.DocumentTitle
	payload["filed_by"] = cfg.SignerDID

	for k, v := range cfg.ExtraPayload {
		payload[k] = v
	}

	if published != nil {
		payload["artifact_cid"] = published.ArtifactCID.String()
		payload["content_digest"] = published.ContentDigest.String()
		payload["artifact_encryption"] = published.Scheme

		if published.Capsule != "" {
			payload["capsule"] = published.Capsule
		}
		if published.PkDel != "" {
			payload["pk_del"] = published.PkDel
		}
		if published.DisclosureScope != "" {
			payload["disclosure_scope"] = published.DisclosureScope
		}
		if len(published.InitialRecipients) > 0 {
			payload["authorized_recipients"] = published.InitialRecipients
		}
	}

	return payload
}
