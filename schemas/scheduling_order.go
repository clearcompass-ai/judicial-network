/*
FILE PATH:

	schemas/scheduling_order.go

DESCRIPTION:

	judicial-scheduling-order-v1 — the order a trial judge issues at
	the initial case-management conference (and amends along the way)
	to set the case calendar: trial date, discovery deadline, motion
	cut-off, pretrial conference. Every case has at least one;
	complex cases have several.

REAL-WORLD USE CASES

	A. Initial case-management conference (the standard path).
	   At the first case-management conference, the judge sets:
	     - Trial date (typically 12-24 months out for civil; 60-180
	       days for criminal)
	     - Discovery close (typically 90-120 days before trial)
	     - Motion cut-off (typically 60-90 days before trial)
	     - Pretrial conference (typically 30 days before trial)
	   The clerk reduces it to writing; the judge signs.

	B. Amended scheduling order (continuance granted).
	   Counsel moves for continuance (motion_continuance), judge
	   grants it via an interlocutory_order, then issues an AMENDED
	   scheduling_order resetting the cascade. The amended order
	   references the original via SupersededBy on the original.

	C. Specialty-court schedules.
	   Drug court / mental health court / veterans court dockets
	   often have non-trial milestones (treatment review hearings,
	   graduation hearings). The Milestones array captures these
	   without forcing every deployment to extend the schema.

SCHEMA SHAPE

	The payload carries the case-root reference + the milestone set.
	Milestones are kept generic ([]Milestone with Name + DueAt)
	rather than hard-coding "trial_date" / "discovery_close" so a
	specialty docket (drug court) can declare its own milestone set
	without a schema bump.

	Standard milestone names (recommended, not enforced):
	  - "trial_date"
	  - "discovery_close"
	  - "motion_cutoff"
	  - "pretrial_conference"
	  - "status_conference"

	Reserved (the schema does NOT enforce; deployments choose):
	  - "treatment_review_hearing" (specialty courts)
	  - "graduation_hearing" (drug court)
	  - "compliance_conference" (probation)

KEY ARCHITECTURAL DECISIONS

  - Generic schema. URI is "judicial-scheduling-order-v1", not "tn-..."
    so federal, GA, or any other consuming network re-uses it
    verbatim. Test fixtures live in this file's _test.go;
    deployment-specific milestones are operator-supplied.

  - CaseRootPos pinned. The order is bound to one case root
    LogPosition; cross-case scheduling orders are NOT supported
    (they would defeat the prerequisite walker's case-root anchor).

  - Milestones immutable post-issuance; amendments use a NEW
    scheduling_order entry referencing the prior via PriorOrderPos.
    No in-place mutation.

  - AmendmentReason free-form. Captures the human-readable "why"
    (e.g., "counsel illness," "newly disclosed witnesses"). Read by
    the case-management dashboard; not parsed by the verifier.

KEY DEPENDENCIES
  - schemas/registry.go: SchemaRegistration type, ErrDeserialize sentinel
  - baseproof/types: LogPosition
*/
package schemas

import (
	"encoding/json"
	"time"

	"github.com/baseproof/baseproof/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Identifier
// -------------------------------------------------------------------------------------------------

// SchemaSchedulingOrderV1 is the canonical schema URI. Generic
// (not "tn-" prefixed) so federal, GA, and other consuming
// networks register it verbatim.
const SchemaSchedulingOrderV1 = "judicial-scheduling-order-v1"

// -------------------------------------------------------------------------------------------------
// 2) Payload
// -------------------------------------------------------------------------------------------------

// SchedulingOrderMilestone is one scheduled item in the case
// calendar (a trial date, a discovery deadline, etc.). Name is
// operator-chosen (recommended set in the file docstring); DueAt
// is the scheduled occurrence in UTC.
type SchedulingOrderMilestone struct {
	// Name is the deployment-chosen milestone identifier
	// (snake_case recommended; e.g., "trial_date",
	// "discovery_close", "motion_cutoff",
	// "treatment_review_hearing").
	Name string `json:"name"`

	// DueAt is the scheduled occurrence (UTC). Past dates are
	// permitted (they describe the historical calendar at
	// amendment time).
	DueAt time.Time `json:"due_at"`

	// Notes is a free-form annotation (e.g., "by stipulation,"
	// "judge's calendar," "conflict resolution"). Not parsed by
	// the verifier; surfaced by the case-management dashboard.
	Notes string `json:"notes,omitempty"`
}

// SchedulingOrderPayload is the Domain Payload for entries
// governed by judicial-scheduling-order-v1.
type SchedulingOrderPayload struct {
	// ── SDK well-known fields ─────────────────────────────────────
	ActivationDelay int64  `json:"activation_delay,omitempty"`
	MigrationPolicy string `json:"migration_policy,omitempty"`

	// ── Order metadata ────────────────────────────────────────────

	// CaseRootPos is the case this order schedules. Required.
	CaseRootPos types.LogPosition `json:"case_root_pos"`

	// Milestones is the scheduled calendar items. Required;
	// MUST be non-empty (an order with no milestones is
	// meaningless).
	Milestones []SchedulingOrderMilestone `json:"milestones"`

	// IssuedAt is the wall-clock time the order was issued
	// (UTC). Required; admission-time sanity check (not in
	// the future, not before the case_initiation date).
	IssuedAt time.Time `json:"issued_at"`

	// IssuingJudgeDID is the Adjudicator's DID. Required;
	// surfaces in the order's recipient set + the case-
	// management dashboard. The cosignature_mix policy
	// independently enforces RequiredSignerRoles=[judge];
	// this field is the human-readable record.
	IssuingJudgeDID string `json:"issuing_judge_did"`

	// PriorOrderPos points at the scheduling_order this one
	// supersedes (the amendment chain). Zero LogPosition for
	// the initial order. Walked by case-management tooling so
	// the live calendar is always the latest order's
	// Milestones.
	PriorOrderPos types.LogPosition `json:"prior_order_pos,omitempty"`

	// AmendmentReason is the human-readable "why" for an
	// amended order (e.g., "counsel illness", "newly
	// disclosed witness"). Empty for the initial order.
	AmendmentReason string `json:"amendment_reason,omitempty"`
}

// -------------------------------------------------------------------------------------------------
// 3) Default params
// -------------------------------------------------------------------------------------------------

// DefaultSchedulingOrderParams returns the canonical schema
// parameters bound to a scheduling order. Used at
// schema-genesis publication.
func DefaultSchedulingOrderParams() []byte {
	params := map[string]interface{}{
		"identifier_scope": "real_did",
		"migration_policy": "amendment",
	}
	b, _ := json.Marshal(params)
	return b
}

// -------------------------------------------------------------------------------------------------
// 4) Serialization
// -------------------------------------------------------------------------------------------------

func SerializeSchedulingOrderPayload(p *SchedulingOrderPayload) ([]byte, error) {
	return json.Marshal(p)
}

func DeserializeSchedulingOrderPayload(data []byte) (*SchedulingOrderPayload, error) {
	var p SchedulingOrderPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, ErrDeserialize
	}
	return &p, nil
}

// -------------------------------------------------------------------------------------------------
// 5) Registration
// -------------------------------------------------------------------------------------------------

func schedulingOrderRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaSchedulingOrderV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*SchedulingOrderPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeSchedulingOrderPayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return DeserializeSchedulingOrderPayload(data)
		},
		DefaultParams:   DefaultSchedulingOrderParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
