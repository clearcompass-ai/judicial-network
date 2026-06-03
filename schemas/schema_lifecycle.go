/*
FILE PATH:

	schemas/schema_lifecycle.go

DESCRIPTION:

	judicial-schema-lifecycle-v1 — governance events that publish,
	adopt, amend, and deprecate schemas on the log. Foundational for
	rule-of-law evolution: every case for the next 15 years anchors
	against the schemas in effect at issue time, so these events are
	how the courts evolve without breaking historical bundles.

	One schema URI serves all four event_types:
	  schema_publication, schema_adoption, schema_amendment,
	  schema_deprecation.
	The Action discriminator distinguishes them, and the prerequisite
	walker enforces the right cross-event chain (adoption / amendment /
	deprecation all require a prior publication of the target).

REAL-WORLD USE CASES

	A. TN Supreme Court publishes the "mental health court docket"
	   schema. After enacting Tenn. Code Ann. § 16-22 (2024) creating
	   specialty mental health courts, the Supreme Court Clerk
	   publishes judicial-mental-health-court-docket-v1 on the state
	   log. Action=ActionPublication, PublicFields names the
	   per-case fields, PrivateFields names the protected-health-
	   information fields the schema seals at issuance.

	B. Davidson County opts in to the mental health docket. After
	   review, Davidson's chief judge issues a schema_adoption entry
	   on the Davidson log referencing the SC publication's
	   LogPosition. Action=ActionAdoption, AdoptingExchangeDID is
	   Davidson's exchange DID, PredecessorPos points at the SC
	   publication.

	C. Bail reform amendment. After the 2027 bail-reform act raises
	   bond limits, the SC publishes a schema_amendment to
	   judicial-criminal-case-v1 (succession version
	   judicial-criminal-case-v2). Action=ActionAmendment,
	   AmendmentDescription captures the substantive change,
	   PredecessorPos points at the v1 publication. Cases opened
	   under v1 continue to verify under v1 schema parameters; new
	   cases under v2 use the amended ones.

	D. Paper-form deprecation. After the digital-only transition
	   completes, the SC issues a schema_deprecation for
	   judicial-paper-form-v1. Action=ActionDeprecation,
	   DeprecationEffective is the cutover date, GracePeriodSeconds
	   tells the admission gate when to start rejecting new entries
	   under that schema (existing entries remain valid; the gate
	   honors the activation_delay just like every other
	   schema-parameter-driven enforcement).

SCHEMA SHAPE

	Action discriminator (closed set):
	  - publication: SchemaID + PublicFields + PrivateFields required;
	    PredecessorPos optional (chained publications).
	  - adoption:    SchemaID + PredecessorPos required;
	                 AdoptingExchangeDID required.
	  - amendment:   SchemaID + PredecessorPos + AmendmentDescription
	                 required.
	  - deprecation: SchemaID + DeprecationEffective + GracePeriodSeconds
	                 required.

	The schema is generic-portable (judicial-* prefix) so federal,
	state, and county networks all use the same governance vocabulary.

KEY ARCHITECTURAL DECISIONS

  - Single schema for four events. The four §15 events share the
    same governance shape; one payload struct + an Action
    discriminator is more maintainable than four parallel files.
    Cosignature + prerequisite policies are still per-event (the
    governance requirements differ across publication / adoption /
    amendment / deprecation).

  - Network-level, not case-level. These events do NOT carry a
    CaseRootPos — they govern the LOG, not a case. The
    prerequisite walker enforces log-level ancestry: an adoption
    requires a publication somewhere on the log, not on a
    case-root subtree.

  - PredecessorPos points at the prior schema_publication entry,
    not at a SchemaID literal. This anchors the prerequisite
    walker to a CRYPTOGRAPHIC reference (the publication's
    LogPosition is part of the log's Merkle history) rather than
    a string match. A network that forks can resolve which
    publication a given adoption referenced even when SchemaID
    string identifiers happen to collide.

  - Public / Private field declarations are FROZEN at publication.
    The privacy classification of a field cannot change via an
    amendment — that would invalidate the privacy guarantees of
    every entry that issued under the original. An amendment
    that needs to change privacy classification publishes a NEW
    schema (a v2) rather than amending in place.

KEY DEPENDENCIES
  - schemas/registry.go: SchemaRegistration, ErrDeserialize
  - baseproof/types: LogPosition
*/
package schemas

import (
	"encoding/json"
	"time"

	"github.com/baseproof/baseproof/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Identifier + action constants
// -------------------------------------------------------------------------------------------------

// SchemaSchemaLifecycleV1 is the canonical schema URI.
const SchemaSchemaLifecycleV1 = "judicial-schema-lifecycle-v1"

// Action discriminator — the closed set per dictionary §15.
const (
	ActionPublication = "publication"
	ActionAdoption    = "adoption"
	ActionAmendment   = "amendment"
	ActionDeprecation = "deprecation"
)

// -------------------------------------------------------------------------------------------------
// 2) Payload
// -------------------------------------------------------------------------------------------------

// SchemaLifecyclePayload is the Domain Payload for all four
// §15 events. The Action discriminator selects which subset of
// fields is meaningful; the verifier (and downstream tooling)
// reads Action first.
type SchemaLifecyclePayload struct {
	// ── SDK well-known fields ─────────────────────────────────────
	ActivationDelay int64  `json:"activation_delay,omitempty"`
	MigrationPolicy string `json:"migration_policy,omitempty"`

	// ── Discriminator ─────────────────────────────────────────────

	// Action selects the lifecycle event kind. Required;
	// closed-set (publication / adoption / amendment /
	// deprecation).
	Action string `json:"action"`

	// ── Target ────────────────────────────────────────────────────

	// SchemaID is the URI of the schema being acted on. Required
	// for every Action.
	SchemaID string `json:"schema_id"`

	// SchemaVersion is the version of the schema being acted on.
	// Convention: monotonic integer (1, 2, 3...). Required for
	// publication + amendment; ignored for adoption + deprecation
	// (those reference the publication via PredecessorPos).
	SchemaVersion uint32 `json:"schema_version,omitempty"`

	// PredecessorPos points at the prior schema_publication entry
	// this lifecycle event references. REQUIRED for adoption /
	// amendment / deprecation. OPTIONAL for publication (set when
	// publishing a versioned successor; zero for an origin
	// publication).
	PredecessorPos types.LogPosition `json:"predecessor_pos,omitempty"`

	// ── Publication-specific ──────────────────────────────────────

	// PublicFields names the schema's publicly-readable fields
	// (entry.DomainPayload field names that any verifier can
	// extract). Required for publication; empty for other Actions.
	PublicFields []string `json:"public_fields,omitempty"`

	// PrivateFields names the schema's sealed fields (encrypted
	// at issuance under the JN's disclosure-order infrastructure).
	// Required for publication; empty for other Actions.
	PrivateFields []string `json:"private_fields,omitempty"`

	// ── Adoption-specific ─────────────────────────────────────────

	// AdoptingExchangeDID is the DID of the exchange (court) that
	// is formally adopting the published schema. Required for
	// adoption; empty for other Actions.
	AdoptingExchangeDID string `json:"adopting_exchange_did,omitempty"`

	// ── Amendment-specific ────────────────────────────────────────

	// AmendmentDescription is the human-readable substantive
	// change the amendment makes (e.g., "Section 4 bond-limit
	// table raised per 2027 bail reform act, Tenn. Pub. Acts ch.
	// 156"). Required for amendment; empty for other Actions.
	AmendmentDescription string `json:"amendment_description,omitempty"`

	// ── Deprecation-specific ──────────────────────────────────────

	// DeprecationEffective is the cutover wall-clock time after
	// which the admission gate begins rejecting NEW entries against
	// the deprecated schema. Existing entries remain valid forever
	// (immutability invariant). Required for deprecation.
	DeprecationEffective time.Time `json:"deprecation_effective,omitempty"`

	// GracePeriodSeconds extends DeprecationEffective by a soft
	// period during which admission warns but does not reject.
	// Optional; zero = hard cutover at DeprecationEffective. The
	// dictionary's §15 developer flag puts the grace period under
	// network code rather than the schema; this field is the
	// schema's parameter when the network exposes one.
	GracePeriodSeconds int64 `json:"grace_period_seconds,omitempty"`

	// ── Universal metadata ────────────────────────────────────────

	// IssuedAt is the wall-clock time (UTC) the lifecycle event
	// was issued. Required.
	IssuedAt time.Time `json:"issued_at"`

	// IssuingDID is the DID of the principal issuing the
	// lifecycle event (the SC clerk for publications;
	// the adopting court for adoptions; etc.). Required.
	IssuingDID string `json:"issuing_did"`
}

// -------------------------------------------------------------------------------------------------
// 3) Default params
// -------------------------------------------------------------------------------------------------

func DefaultSchemaLifecycleParams() []byte {
	params := map[string]interface{}{
		"identifier_scope": "real_did",
		"migration_policy": "strict",
	}
	b, _ := json.Marshal(params)
	return b
}

// -------------------------------------------------------------------------------------------------
// 4) Serialization
// -------------------------------------------------------------------------------------------------

func SerializeSchemaLifecyclePayload(p *SchemaLifecyclePayload) ([]byte, error) {
	return json.Marshal(p)
}

func DeserializeSchemaLifecyclePayload(data []byte) (*SchemaLifecyclePayload, error) {
	var p SchemaLifecyclePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, ErrDeserialize
	}
	return &p, nil
}

// -------------------------------------------------------------------------------------------------
// 5) Registration
// -------------------------------------------------------------------------------------------------

func schemaLifecycleRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaSchemaLifecycleV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*SchemaLifecyclePayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeSchemaLifecyclePayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return DeserializeSchemaLifecyclePayload(data)
		},
		DefaultParams:   DefaultSchemaLifecycleParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
