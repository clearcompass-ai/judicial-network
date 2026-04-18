/*
FILE PATH: cases/filing.go
DESCRIPTION: Handles subsequent filings on an existing case. Supports BOTH
    Path A (same-signer amendments) and Path B (delegated filings).
KEY ARCHITECTURAL DECISIONS:
    - Path A: BuildAmendment when SignerDID matches case root entity signer
      and no DelegationPointers are provided. Attorney files motion then exhibit.
    - Path B: BuildPathBEntry when DelegationPointers are provided. Delegated
      filings from attorneys with delegation chains.
    - Both paths use same artifact.PublishArtifact pipeline.
    - Decision between A/B: if DelegationPointers empty → Path A, else Path B.
OVERVIEW: File → artifact encryption + Path A or Path B entry.
KEY DEPENDENCIES: ortholog-sdk/builder, cases/artifact
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

type FilingConfig struct {
	Destination string // DID of target exchange. Required.
	SignerDID          string
	CaseRootPos        types.LogPosition
	SchemaRef          types.LogPosition
	DelegationPointers []types.LogPosition // Empty → Path A; populated → Path B
	EventTime          int64
	DocumentType       string
	DocumentTitle      string
	Plaintext          []byte
	OwnerDID           string
	DisclosureScope    string
	InitialRecipients  []string
	ExtraPayload       map[string]interface{}
}

type FilingResult struct {
	Entry     *envelope.Entry
	Published *artifact.PublishedArtifact
	Path      string // "A" or "B"
}

// File creates a filing entry on an existing case.
// Path A when no DelegationPointers (same-signer amendment).
// Path B when DelegationPointers provided (delegated filing).
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

	result := &FilingResult{}

	// Encrypt and store artifact if plaintext provided.
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
			contentStore, keyStore, delKeyStore, extractor, fetcher, resolver,
		)
		if err != nil {
			return nil, fmt.Errorf("cases/filing: publish artifact: %w", err)
		}
		result.Published = published
	}

	// Assemble Domain Payload.
	payload := assembleFilingPayload(cfg, result.Published)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("cases/filing: marshal payload: %w", err)
	}

	var schemaRefPtr *types.LogPosition
	if !cfg.SchemaRef.IsNull() {
		schemaRefPtr = &cfg.SchemaRef
	}

	// Decision: Path A (no delegation pointers) or Path B (delegation pointers).
	if len(cfg.DelegationPointers) == 0 {
		// Path A: same-signer amendment. Signer must match case root entity signer.
		entry, bErr := builder.BuildAmendment(builder.AmendmentParams{
			Destination: cfg.Destination,
			SignerDID:  cfg.SignerDID,
			TargetRoot: cfg.CaseRootPos,
			Payload:    payloadBytes,
			SchemaRef:  schemaRefPtr,
			EventTime:  cfg.EventTime,
		})
		if bErr != nil {
			return nil, fmt.Errorf("cases/filing: build Path A amendment: %w", bErr)
		}
		result.Entry = entry
		result.Path = "A"
	} else {
		// Path B: delegated filing via delegation chain.
		entry, bErr := builder.BuildPathBEntry(builder.PathBParams{
			Destination: cfg.Destination,
			SignerDID:          cfg.SignerDID,
			TargetRoot:         cfg.CaseRootPos,
			DelegationPointers: cfg.DelegationPointers,
			Payload:            payloadBytes,
			SchemaRef:          schemaRefPtr,
			EventTime:          cfg.EventTime,
		})
		if bErr != nil {
			return nil, fmt.Errorf("cases/filing: build Path B entry: %w", bErr)
		}
		result.Entry = entry
		result.Path = "B"
	}

	return result, nil
}

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
