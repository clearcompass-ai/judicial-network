/*
FILE PATH:
    cases/filing.go

DESCRIPTION:
    Handles subsequent filings on an existing case. A filing is a Path B
    entry (delegated authority) appended to the case root entity. The filing
    may include an artifact that is encrypted via the artifact sub-package
    and referenced by CID in the Domain Payload.

KEY ARCHITECTURAL DECISIONS:
    - No local interface redefinitions. Uses builder.EntryFetcher directly
      from the SDK (import path: builder/, NOT core/builder/).
    - Uses builder.BuildPathBEntry as a package-level function.
    - PathBParams.Payload (not DomainPayload) — matches SDK field name exactly.
    - DelegationPointers required for Path B.
    - Domain Payload carries pk_del for PRE evidence artifacts. retrieve.go
      reads pk_del to pass as OwnerPubKey to GrantArtifactAccess.

OVERVIEW:
    (1) If plaintext provided: call artifact.PublishArtifact to encrypt + push.
    (2) Assemble Domain Payload with artifact fields + disclosure fields + pk_del.
    (3) Build the entry via builder.BuildPathBEntry (delegated filing).
    (4) Return the unsigned entry for the caller to sign and submit.

KEY DEPENDENCIES:
    - ortholog-sdk/builder: BuildPathBEntry, PathBParams, EntryFetcher
    - ortholog-sdk/core/envelope: Entry type
    - judicial-network/cases/artifact: PublishArtifact for document encryption
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

// File creates a filing entry on an existing case, optionally encrypting
// and storing an artifact.
func File(
	cfg FilingConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
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

	// (3) Build the entry via SDK builder.BuildPathBEntry.
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

		// pk_del: per-artifact delegation public key for PRE evidence.
		// retrieve.go reads this field and passes it as OwnerPubKey
		// to GrantArtifactAccess. This is NOT pk_owner.
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
