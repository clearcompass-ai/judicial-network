/*
FILE PATH: enforcement/unsealing.go
DESCRIPTION: Path C unsealing order with cosignature requirement.
KEY ARCHITECTURAL DECISIONS:
    - Requires cosignature from another judge (threshold=1 per sealing schema).
    - Uses lifecycle.BuildApprovalCosignature for the cosignature entry.
    - Same activation pattern: conditions → contest check → activate.
OVERVIEW: UnsealCase → enforcement entry. RequestUnsealCosignature → cosig.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/lifecycle, ortholog-sdk/verifier
*/
package enforcement

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

type UnsealingConfig struct {
	JudgeDID       string
	CaseRootPos    types.LogPosition
	ScopePos       types.LogPosition
	PriorAuthority *types.LogPosition
	SchemaRef      *types.LogPosition
	Reason         string
	EventTime      int64
}

// UnsealCase publishes an unsealing enforcement entry (Path C).
// Unsealing requires cosignature_threshold=1 per tn-sealing-order-v1.
// The cosignature must be collected via RequestUnsealCosignature before
// the unsealing activation entry can be published.
func UnsealCase(cfg UnsealingConfig) (*SealingResult, error) {
	if cfg.JudgeDID == "" {
		return nil, fmt.Errorf("enforcement/unsealing: empty judge DID")
	}
	if cfg.CaseRootPos.IsNull() || cfg.ScopePos.IsNull() {
		return nil, fmt.Errorf("enforcement/unsealing: null position")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"order_type": "unseal",
		"reason":     cfg.Reason,
	})

	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		SignerDID:      cfg.JudgeDID,
		TargetRoot:     cfg.CaseRootPos,
		ScopePointer:   cfg.ScopePos,
		PriorAuthority: cfg.PriorAuthority,
		Payload:        payload,
		SchemaRef:      cfg.SchemaRef,
		EventTime:      cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("enforcement/unsealing: build enforcement: %w", err)
	}

	return &SealingResult{EnforcementEntry: entry}, nil
}

// RequestUnsealCosignature creates a cosignature entry from a second judge
// approving the unsealing order. Required because cosignature_threshold=1.
func RequestUnsealCosignature(
	cosignerDID string,
	unsealingEntryPos types.LogPosition,
	eventTime int64,
) (*envelope.Entry, error) {
	return lifecycle.BuildApprovalCosignature(cosignerDID, unsealingEntryPos, eventTime)
}
