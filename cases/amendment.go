/*
FILE PATH: cases/amendment.go
DESCRIPTION: Case status changes and reassignment via SDK BuildAmendment (Path A).
KEY ARCHITECTURAL DECISIONS:
    - BuildAmendment: same signer as root entity advances OriginTip.
    - Status transitions: active→closed, active→sealed.
    - artifact_cid updates after re-encryption.
OVERVIEW: AmendCase → Path A amendment entry for status changes.
KEY DEPENDENCIES: ortholog-sdk/builder
*/
package cases

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// AmendmentConfig configures a case amendment.
type AmendmentConfig struct {
	SignerDID        string            // Must be same signer as case root entity
	CaseRootPos      types.LogPosition
	AmendmentType    string // "status_change", "reassignment", "artifact_update"
	NewStatus        string // "closed", "sealed", "reopened" (for status_change)
	NewArtifactCID   string // Updated CID after re-encryption (for artifact_update)
	SchemaRef        *types.LogPosition
	EvidencePointers []types.LogPosition
	ExtraPayload     map[string]interface{}
	EventTime        int64
}

// AmendCase creates a Path A amendment entry for a case status change,
// reassignment, or artifact CID update.
func AmendCase(cfg AmendmentConfig) (*envelope.Entry, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("cases/amendment: empty signer DID")
	}
	if cfg.CaseRootPos.IsNull() {
		return nil, fmt.Errorf("cases/amendment: null case root position")
	}

	payload := map[string]interface{}{
		"amendment_type": cfg.AmendmentType,
	}
	if cfg.NewStatus != "" {
		payload["new_status"] = cfg.NewStatus
	}
	if cfg.NewArtifactCID != "" {
		payload["new_artifact_cid"] = cfg.NewArtifactCID
	}
	for k, v := range cfg.ExtraPayload {
		payload[k] = v
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("cases/amendment: marshal payload: %w", err)
	}

	return builder.BuildAmendment(builder.AmendmentParams{
		SignerDID:        cfg.SignerDID,
		TargetRoot:       cfg.CaseRootPos,
		Payload:          payloadBytes,
		SchemaRef:        cfg.SchemaRef,
		EvidencePointers: cfg.EvidencePointers,
		EventTime:        cfg.EventTime,
	})
}
