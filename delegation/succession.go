/*
FILE PATH: delegation/succession.go
DESCRIPTION: Judicial rotation via SDK BuildSuccession. Judge retires → new
    judge inherits delegation chain. Old judge signing authority terminates.
KEY ARCHITECTURAL DECISIONS:
    - BuildSuccession is Path A (same signer advances OriginTip).
    - NewSignerDID carried in Domain Payload (SDK does not interpret it).
    - Old delegation becomes non-live (OriginTip != position).
    - New delegation must be created separately via DelegateJudge.
OVERVIEW: RotateJudge → succession entry + new delegation entry.
KEY DEPENDENCIES: ortholog-sdk/builder
*/
package delegation

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// SuccessionConfig configures a judicial rotation.
type SuccessionConfig struct {
	Destination string // DID of target exchange. Required.
	CurrentJudgeDID   string            // Outgoing judge (signer of succession)
	NewJudgeDID       string            // Incoming judge
	DelegationRootPos types.LogPosition // Position of the delegation entry being succeeded
	Division          string
	Reason            string            // "retirement", "reassignment", "recusal"
	SchemaRef         *types.LogPosition
	EventTime         int64
}

// SuccessionResult holds the succession entry.
type SuccessionResult struct {
	SuccessionEntry *envelope.Entry
}

// RotateJudge creates a succession entry for judicial rotation.
// The current judge signs; OriginTip advances, breaking the old
// delegation's liveness. A separate DelegateJudge call creates the
// new delegation for the incoming judge.
func RotateJudge(cfg SuccessionConfig) (*SuccessionResult, error) {
	if cfg.CurrentJudgeDID == "" || cfg.NewJudgeDID == "" {
		return nil, fmt.Errorf("delegation/succession: both judge DIDs required")
	}
	if cfg.DelegationRootPos.IsNull() {
		return nil, fmt.Errorf("delegation/succession: delegation root position required")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"succession_type": "judicial_rotation",
		"new_judge_did":   cfg.NewJudgeDID,
		"division":        cfg.Division,
		"reason":          cfg.Reason,
	})

	entry, err := builder.BuildSuccession(builder.SuccessionParams{
		Destination: cfg.Destination,
		SignerDID:    cfg.CurrentJudgeDID,
		TargetRoot:   cfg.DelegationRootPos,
		NewSignerDID: cfg.NewJudgeDID,
		Payload:      payload,
		SchemaRef:    cfg.SchemaRef,
		EventTime:    cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("delegation/succession: build: %w", err)
	}

	return &SuccessionResult{SuccessionEntry: entry}, nil
}
