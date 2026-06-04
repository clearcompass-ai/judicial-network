/*
FILE PATH:

	schemas/interlocutory_order.go

DESCRIPTION:

	judicial-interlocutory-order-v1 — the order a judge issues to
	rule on a motion mid-case. Interlocutory = not final; the case
	continues. Every motion eventually gets one of these (granted,
	denied, or granted-in-part). High-volume daily event in any
	trial court.

REAL-WORLD USE CASES

	A. Motion to compel discovery (granted).
	   Plaintiff moves to compel defendant to produce 30,000
	   bates-stamped documents. Defendant opposes. Judge holds a
	   hearing, then issues an interlocutory_order GRANTING the
	   motion and ordering production within 21 days. The order
	   carries MotionRefPos pointing at the motion_compel_discovery
	   entry; the prereq walker (deployments/tn/trial/prerequisites.
	   go) refuses to admit this order without that motion already
	   on the case root.

	B. Motion in limine (denied in part).
	   Defense moves to exclude three categories of evidence.
	   Judge admits two, excludes the third. The Disposition is
	   "granted_in_part_denied_in_part"; the OrderText narrates
	   which categories and why. The original motion stays
	   referenced; the order is its dispositive resolution.

	C. Motion to dismiss for failure to state a claim (granted).
	   Civil defendant moves to dismiss under TRCP 12.02(6); judge
	   grants WITH PREJUDICE. This interlocutory_order has
	   IsDispositive=true (it disposes of the motion AND the case);
	   the case-management tooling promotes the case to dismissed.
	   The downstream final_judgment entry uses this order's
	   position as its anchor.

SCHEMA SHAPE

	MotionRefPos is the hard binding: every interlocutory_order
	MUST reference a prior motion entry. The prereq policy enforces
	this with a "motion_*" RequiredAncestor pattern in
	deployments/tn/trial/prerequisites.go.

	Disposition is a closed set ({granted, denied,
	granted_in_part_denied_in_part, denied_without_prejudice,
	taken_under_advisement}) — exhaustive in dictionary §6.

	OrderText is free-form judicial reasoning. NOT parsed by the
	verifier; surfaced by the case-management dashboard + the
	transcript-publication pipeline.

KEY ARCHITECTURAL DECISIONS

  - Generic schema. URI is "judicial-interlocutory-order-v1".

  - MotionRefPos required, not optional. A judge cannot issue an
    interlocutory_order without an underlying motion (sua sponte
    rulings are issued as a different event class — typically
    competency_evaluation_order, scheduling_order, or a sua-sponte
    dismissal). The prereq walker enforces this hard binding.

  - IsDispositive flag. Some interlocutory orders dispose of the
    motion AND the case (granted motion to dismiss; granted
    summary judgment). The flag tells case-management tooling
    that a final_judgment entry should follow.

  - Closed-set Disposition. Free-form Disposition would defeat
    appellate-review filtering ("show me every denied motion to
    compel in the last quarter") — case-management dashboards
    routinely query by disposition.

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

// SchemaInterlocutoryOrderV1 is the canonical schema URI.
const SchemaInterlocutoryOrderV1 = "judicial-interlocutory-order-v1"

// Disposition values — the closed set per dictionary §6.
const (
	DispositionGranted                   = "granted"
	DispositionDenied                    = "denied"
	DispositionGrantedInPartDeniedInPart = "granted_in_part_denied_in_part"
	DispositionDeniedWithoutPrejudice    = "denied_without_prejudice"
	DispositionTakenUnderAdvisement      = "taken_under_advisement"
)

// -------------------------------------------------------------------------------------------------
// 2) Payload
// -------------------------------------------------------------------------------------------------

// InterlocutoryOrderPayload is the Domain Payload for entries
// governed by judicial-interlocutory-order-v1.
type InterlocutoryOrderPayload struct {
	// ── SDK well-known fields ─────────────────────────────────────
	ActivationDelay int64  `json:"activation_delay,omitempty"`
	MigrationPolicy string `json:"migration_policy,omitempty"`

	// ── Order metadata ────────────────────────────────────────────

	// CaseRootPos is the case this order rules within. Required.
	CaseRootPos types.LogPosition `json:"case_root_pos"`

	// MotionRefPos is the motion this order disposes of.
	// REQUIRED — the prereq walker rejects an interlocutory_order
	// whose case root has no prior motion_* event on the chain.
	MotionRefPos types.LogPosition `json:"motion_ref_pos"`

	// Disposition is the closed-set outcome. Required; admission-
	// time validator rejects any value outside the constants
	// declared above.
	Disposition string `json:"disposition"`

	// OrderText is the judge's reasoning. Free-form; NOT parsed
	// by the verifier; surfaced by the case-management dashboard
	// and the transcript-publication pipeline.
	OrderText string `json:"order_text,omitempty"`

	// IssuedAt is the wall-clock time the order was issued
	// (UTC). Required.
	IssuedAt time.Time `json:"issued_at"`

	// IssuingJudgeDID is the Adjudicator's DID. Required.
	IssuingJudgeDID string `json:"issuing_judge_did"`

	// IsDispositive flags an order that resolves not just the
	// motion but the case (granted MTD with prejudice; granted
	// summary judgment). Case-management tooling reads this to
	// drive the downstream final_judgment workflow. Optional;
	// defaults false.
	IsDispositive bool `json:"is_dispositive,omitempty"`
}

// -------------------------------------------------------------------------------------------------
// 3) Default params
// -------------------------------------------------------------------------------------------------

func DefaultInterlocutoryOrderParams() []byte {
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

func SerializeInterlocutoryOrderPayload(p *InterlocutoryOrderPayload) ([]byte, error) {
	return json.Marshal(p)
}

func DeserializeInterlocutoryOrderPayload(data []byte) (*InterlocutoryOrderPayload, error) {
	var p InterlocutoryOrderPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, ErrDeserialize
	}
	return &p, nil
}

// -------------------------------------------------------------------------------------------------
// 5) Registration
// -------------------------------------------------------------------------------------------------

func interlocutoryOrderRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaInterlocutoryOrderV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*InterlocutoryOrderPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeInterlocutoryOrderPayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return DeserializeInterlocutoryOrderPayload(data)
		},
		DefaultParams:   DefaultInterlocutoryOrderParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
