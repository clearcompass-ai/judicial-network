/*
FILE PATH: operations/events.go
DESCRIPTION: Flexible operational events via BuildCommentary. Handles
    scheduling, closures, notices, duty assignments, and any future event
    type without hardcoded structures.
KEY ARCHITECTURAL DECISIONS:
    - Single generic PublishEvent wrapping BuildCommentary.
    - Refs []LogPosition for zero-to-many references (zero for court closures,
      one for single-case hearings, many for consolidated proceedings).
    - EventType is a free-form string — no enum. CMS bridges and court ops
      set the type. The SDK never reads it (commentary, zero SMT impact).
    - Caller decides which log to submit to (officers log for court-wide,
      cases log for case-specific). This function builds the entry;
      submission is the caller's responsibility.
    - No schema. Commentary entries don't need one.
OVERVIEW:
    PublishEvent → *envelope.Entry (commentary) with typed payload.
    Covers: scheduling, closure, hours_change, notice, duty, conference,
    continuance, and anything else a CMS or court ops module invents.
KEY DEPENDENCIES: ortholog-sdk/builder (BuildCommentary only)
*/
package operations

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// EventConfig configures an operational event.
// All fields except SignerDID and EventType are optional.
type EventConfig struct {
	SignerDID string
	EventType string // "scheduling", "closure", "notice", "duty", "conference", etc.
	EventTime int64

	// Refs are zero-to-many log positions this event relates to.
	// Empty for court-wide events (closures, hours changes).
	// One entry for single-case events (hearing for docket 24-CR-1234).
	// Multiple for consolidated events (joint hearing across 3 cases).
	Refs []types.LogPosition

	// Payload is the event-specific data. Free-form.
	// CMS bridges and court ops modules populate this.
	// Convention examples:
	//   scheduling: {"hearing_type":"motion","scheduled_date":"2026-05-01","courtroom":"4A"}
	//   closure:    {"reason":"weather","effective_date":"2026-04-20","end_date":"2026-04-21"}
	//   notice:     {"notice_type":"procedure_change","audience":"all_divisions","text":"..."}
	//   duty:       {"officer_did":"did:web:...","duty_type":"on_call","period":"2026-W17"}
	Payload map[string]interface{}
}

// EventResult holds the commentary entry.
type EventResult struct {
	Entry     *envelope.Entry
	EventType string
	RefCount  int
}

// PublishEvent builds a commentary entry for any operational event.
// The caller submits to the appropriate log (officers or cases).
func PublishEvent(cfg EventConfig) (*EventResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("operations/events: empty signer DID")
	}
	if cfg.EventType == "" {
		return nil, fmt.Errorf("operations/events: empty event type")
	}

	// Build payload: event_type + refs + caller's payload.
	fullPayload := make(map[string]interface{})
	fullPayload["event_type"] = cfg.EventType

	if len(cfg.Refs) > 0 {
		refs := make([]string, len(cfg.Refs))
		for i, ref := range cfg.Refs {
			refs[i] = ref.String()
		}
		fullPayload["refs"] = refs
	}

	for k, v := range cfg.Payload {
		fullPayload[k] = v
	}

	payloadBytes, err := json.Marshal(fullPayload)
	if err != nil {
		return nil, fmt.Errorf("operations/events: marshal: %w", err)
	}

	entry, err := builder.BuildCommentary(builder.CommentaryParams{
		SignerDID: cfg.SignerDID,
		Payload:   payloadBytes,
		EventTime: cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("operations/events: build commentary: %w", err)
	}

	return &EventResult{
		Entry:     entry,
		EventType: cfg.EventType,
		RefCount:  len(cfg.Refs),
	}, nil
}
