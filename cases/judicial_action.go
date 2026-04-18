/*
FILE PATH: cases/judicial_action.go
DESCRIPTION: Judge signs via Path B delegation chain. SDK AssemblePathB resolves
    the chain from judge back to court root. Builds Path B entry for orders.
KEY ARCHITECTURAL DECISIONS:
    - AssemblePathB validates and orders delegation pointers.
    - BuildPathBEntry creates the delegated entry.
    - Artifact encryption via same PublishArtifact pipeline as filing.go.
OVERVIEW: RecordJudicialAction → Path B entry for judge-signed orders.
KEY DEPENDENCIES: ortholog-sdk/builder, cases/artifact
*/
package cases

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/cases/artifact"
)

// JudicialActionConfig configures a judge-signed action.
type JudicialActionConfig struct {
	Destination string // DID of target exchange. Required.
	JudgeDID           string
	CaseRootPos        types.LogPosition
	ActionType         string // "ruling", "order", "sentence", "disposition"
	Description        string
	SchemaRef          types.LogPosition
	CandidatePositions []types.LogPosition // Delegation positions judge knows about
	Plaintext          []byte              // Optional document
	DisclosureScope    string
	InitialRecipients  []string
	ExtraPayload       map[string]interface{}
	EventTime          int64
}

// JudicialActionResult holds the action entry and optional published artifact.
type JudicialActionResult struct {
	Entry     *envelope.Entry
	Published *artifact.PublishedArtifact
}

// RecordJudicialAction assembles the delegation chain and creates a
// Path B entry for a judge-signed action on a case.
func RecordJudicialAction(
	cfg JudicialActionConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore artifact.DelegationKeyStore,
	extractor schema.SchemaParameterExtractor,
	fetcher builder.EntryFetcher,
	leafReader smt.LeafReader,
	resolver did.DIDResolver,
) (*JudicialActionResult, error) {
	if cfg.JudgeDID == "" {
		return nil, fmt.Errorf("cases/judicial_action: empty judge DID")
	}
	if cfg.CaseRootPos.IsNull() {
		return nil, fmt.Errorf("cases/judicial_action: null case root position")
	}

	// Assemble delegation chain.
	assembly, err := builder.AssemblePathB(builder.AssemblePathBParams{
		DelegateDID:        cfg.JudgeDID,
		TargetRoot:         cfg.CaseRootPos,
		LeafReader:         leafReader,
		Fetcher:            fetcher,
		CandidatePositions: cfg.CandidatePositions,
	})
	if err != nil {
		return nil, fmt.Errorf("cases/judicial_action: assemble path B: %w", err)
	}

	result := &JudicialActionResult{}

	// Publish artifact if plaintext provided.
	if len(cfg.Plaintext) > 0 {
		published, pubErr := artifact.PublishArtifact(
			artifact.PublishConfig{
				Plaintext:         cfg.Plaintext,
				SchemaRef:         cfg.SchemaRef,
				OwnerDID:          cfg.JudgeDID,
				DisclosureScope:   cfg.DisclosureScope,
				InitialRecipients: cfg.InitialRecipients,
			},
			contentStore, keyStore, delKeyStore, extractor, fetcher, resolver,
		)
		if pubErr != nil {
			return nil, fmt.Errorf("cases/judicial_action: publish artifact: %w", pubErr)
		}
		result.Published = published
	}

	// Assemble Domain Payload.
	payload := map[string]interface{}{
		"action_type": cfg.ActionType,
		"description": cfg.Description,
		"signed_by":   cfg.JudgeDID,
	}
	for k, v := range cfg.ExtraPayload {
		payload[k] = v
	}
	if result.Published != nil {
		payload["artifact_cid"] = result.Published.ArtifactCID.String()
		payload["content_digest"] = result.Published.ContentDigest.String()
		payload["artifact_encryption"] = result.Published.Scheme
		if result.Published.Capsule != "" {
			payload["capsule"] = result.Published.Capsule
		}
		if result.Published.PkDel != "" {
			payload["pk_del"] = result.Published.PkDel
		}
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("cases/judicial_action: marshal payload: %w", err)
	}

	var schemaRefPtr *types.LogPosition
	if !cfg.SchemaRef.IsNull() {
		schemaRefPtr = &cfg.SchemaRef
	}

	entry, err := builder.BuildPathBEntry(builder.PathBParams{
		Destination: cfg.Destination,
		SignerDID:          cfg.JudgeDID,
		TargetRoot:         cfg.CaseRootPos,
		DelegationPointers: assembly.DelegationPointers,
		Payload:            payloadBytes,
		SchemaRef:          schemaRefPtr,
		EventTime:          cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("cases/judicial_action: build entry: %w", err)
	}

	result.Entry = entry
	return result, nil
}
