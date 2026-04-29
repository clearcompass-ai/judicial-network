/*
FILE PATH: appeals/decision.go
DESCRIPTION: Appellate decision entry via Path B delegation chain.
KEY ARCHITECTURAL DECISIONS:
    - AssemblePathB resolves appellate judge's delegation chain.
    - BuildPathBEntry for the decision entry.
    - Attaches opinion document via PublishArtifact.
    - Uses existing case schema (no dedicated appellate schema).
    - Outcome field determines downstream effect (mandate.go).
OVERVIEW: RecordDecision → Path B entry with opinion artifact.
KEY DEPENDENCIES: ortholog-sdk/builder, cases/artifact
*/
package appeals

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

type DecisionConfig struct {
	Destination string // DID of target exchange. Required.
	JudgeDID           string
	AppealCaseRootPos  types.LogPosition
	CandidatePositions []types.LogPosition
	Outcome            string // "affirm", "reverse", "remand", "dismiss"
	OpinionPlaintext   []byte
	SchemaRef          types.LogPosition
	RemandInstructions string
	EventTime          int64
}

type DecisionResult struct {
	DecisionEntry *envelope.Entry
	OpinionArtifact *artifact.PublishedArtifact
}

func RecordDecision(
	cfg DecisionConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore artifact.DelegationKeyStore,
	extractor schema.SchemaParameterExtractor,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
	resolver did.DIDResolver,
) (*DecisionResult, error) {
	if cfg.JudgeDID == "" {
		return nil, fmt.Errorf("appeals/decision: empty judge DID")
	}

	// Assemble delegation chain.
	assembly, err := builder.AssemblePathB(builder.AssemblePathBParams{
		DelegateDID:        cfg.JudgeDID,
		TargetRoot:         cfg.AppealCaseRootPos,
		LeafReader:         leafReader,
		Fetcher:            fetcher,
		CandidatePositions: cfg.CandidatePositions,
	})
	if err != nil {
		return nil, fmt.Errorf("appeals/decision: assemble path B: %w", err)
	}

	result := &DecisionResult{}

	// Publish opinion document.
	if len(cfg.OpinionPlaintext) > 0 {
		published, pubErr := artifact.PublishArtifact(
			artifact.PublishConfig{
				Plaintext: cfg.OpinionPlaintext,
				SchemaRef: cfg.SchemaRef,
				OwnerDID:  cfg.JudgeDID,
				Metadata:  map[string]string{"document_type": "appellate_opinion"},
			},
			contentStore, keyStore, delKeyStore, extractor, fetcher, resolver,
		)
		if pubErr != nil {
			return nil, fmt.Errorf("appeals/decision: publish opinion: %w", pubErr)
		}
		result.OpinionArtifact = published
	}

	payload := map[string]interface{}{
		"action_type": "appellate_decision",
		"outcome":     cfg.Outcome,
		"signed_by":   cfg.JudgeDID,
	}
	if cfg.RemandInstructions != "" {
		payload["remand_instructions"] = cfg.RemandInstructions
	}
	if result.OpinionArtifact != nil {
		payload["opinion_cid"] = result.OpinionArtifact.ArtifactCID.String()
	}
	payloadBytes, _ := json.Marshal(payload)

	var schemaRefPtr *types.LogPosition
	if !cfg.SchemaRef.IsNull() {
		schemaRefPtr = &cfg.SchemaRef
	}

	entry, err := builder.BuildPathBEntry(builder.PathBParams{
		Destination: cfg.Destination,
		SignerDID:          cfg.JudgeDID,
		TargetRoot:         cfg.AppealCaseRootPos,
		DelegationPointers: assembly.DelegationPointers,
		Payload:            payloadBytes,
		SchemaRef:          schemaRefPtr,
		EventTime:          cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("appeals/decision: build entry: %w", err)
	}
	result.DecisionEntry = entry
	return result, nil
}
