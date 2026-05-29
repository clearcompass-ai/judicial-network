/*
FILE PATH:

	schemas/protective_order.go

DESCRIPTION:

	judicial-protective-order-v1 — orders commanding a party to
	stay away from someone (DV protective orders) or forbidding
	destruction of assets (civil restraining orders / TROs).
	High-frequency event in any domestic-violence court; common
	in civil cases on motion-for-TRO.

REAL-WORLD USE CASES

	A. Ex parte domestic-violence protective order.
	   Victim files a sworn affidavit at the morning DV docket.
	   Judge reviews; finds probable cause; issues a 14-day
	   protective_restraining_order ex parte. The respondent
	   has 14 days to seek modification. ProtectedParties names
	   the victim's binding_id; RestrainedParties names the
	   alleged abuser; Restrictions include "no_contact",
	   "stay_away_500ft", "surrender_firearms".

	B. Civil TRO against asset destruction.
	   Plaintiff in a fraud case obtains a TRO against the
	   defendant freezing specific bank accounts and forbidding
	   destruction of documents. Restrictions include
	   "no_destruction_of_assets" and "preserve_documents";
	   FrozenAccounts is the (opaque) list of restricted
	   account references.

	C. Permanent injunction (post-final-judgment).
	   After a civil trial, the court issues a permanent
	   injunction. EffectiveUntil is the zero time (permanent);
	   ConvertedToFinal=true tells case-management tooling this
	   order survives final_judgment.

SCHEMA SHAPE

	The payload distinguishes the TWO populations of party that a
	protective order affects: ProtectedParties (whose interests are
	being protected) and RestrainedParties (who must comply with
	the restrictions). Both are binding_id values from prior
	party_binding entries — never raw DIDs (Goal 7: no cross-
	network replay; binding_ids are network-scoped).

	Restrictions is an open-ended []string. Standard values are
	recommended in dictionary §6 but the schema does not enforce
	a closed set because new statutory authority routinely adds
	new restriction types (e.g., post-2025 cyber-stalking
	statutes added "no_electronic_contact").

	EffectiveUntil is the order's expiration. Zero = permanent
	(injunction).

KEY ARCHITECTURAL DECISIONS

  - Generic schema. URI is "judicial-protective-order-v1".

  - Binding-id references, not raw DIDs. ProtectedParties +
    RestrainedParties hold binding_id values bound to the case
    root, so a federal restraining order does NOT identify the
    same human as a TN restraining order even if both refer to
    the same legal-name individual (Goal 7).

  - Open-ended Restrictions slice. The judge's order text is
    authoritative; Restrictions is the machine-actionable
    summary the case-management tooling uses to surface "active
    restraints against party X." Free-form values supported
    because statutory authority evolves faster than schema
    versions.

  - SourceAuthority pins the statutory citation (e.g., "TCA
    36-3-605" for TN DV; "TRCP 65.03" for civil TROs). The
    case-management dashboard filters by source authority for
    administrative reporting.

KEY DEPENDENCIES
  - schemas/registry.go: SchemaRegistration type, ErrDeserialize sentinel
  - attesta/types: LogPosition
*/
package schemas

import (
	"encoding/json"
	"time"

	"github.com/clearcompass-ai/attesta/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Identifier
// -------------------------------------------------------------------------------------------------

// SchemaProtectiveOrderV1 is the canonical schema URI.
const SchemaProtectiveOrderV1 = "judicial-protective-order-v1"

// -------------------------------------------------------------------------------------------------
// 2) Payload
// -------------------------------------------------------------------------------------------------

// ProtectiveOrderPayload is the Domain Payload for entries
// governed by judicial-protective-order-v1.
type ProtectiveOrderPayload struct {
	// ── SDK well-known fields ─────────────────────────────────────
	ActivationDelay int64  `json:"activation_delay,omitempty"`
	MigrationPolicy string `json:"migration_policy,omitempty"`

	// ── Order metadata ────────────────────────────────────────────

	// CaseRootPos is the case this order is issued within.
	// Required.
	CaseRootPos types.LogPosition `json:"case_root_pos"`

	// ProtectedParties names the binding_id values of parties
	// whose interests are being protected (victims of DV;
	// plaintiffs in TRO cases). At least one required.
	ProtectedParties []string `json:"protected_parties"`

	// RestrainedParties names the binding_id values of parties
	// subject to the restrictions (alleged abusers; defendants
	// against whom a TRO is sought). At least one required.
	RestrainedParties []string `json:"restrained_parties"`

	// Restrictions is the machine-actionable summary of the
	// order's commands. Open-ended set. Recommended values:
	//
	//   "no_contact"
	//   "no_electronic_contact"
	//   "stay_away_500ft"
	//   "stay_away_1000ft"
	//   "surrender_firearms"
	//   "no_destruction_of_assets"
	//   "preserve_documents"
	//   "no_disposition_of_property"
	//   "no_third_party_communication"
	//
	// At least one required.
	Restrictions []string `json:"restrictions"`

	// SourceAuthority is the statutory citation that authorizes
	// the order (e.g., "TCA 36-3-605" for a TN DV protective
	// order; "TRCP 65.03" for a civil TRO; "18 USC 922(g)(8)"
	// for federal firearms-prohibition orders). Free-form
	// string; surfaced by reporting tooling. Required for
	// admission-time auditability.
	SourceAuthority string `json:"source_authority"`

	// IssuedAt is the wall-clock time the order was issued
	// (UTC). Required.
	IssuedAt time.Time `json:"issued_at"`

	// EffectiveUntil is the order's expiration (UTC). Zero =
	// permanent injunction. Ex parte DV orders typically
	// 14-21 days; civil TROs typically 14 days; preliminary
	// injunctions until further order.
	EffectiveUntil time.Time `json:"effective_until,omitempty"`

	// IssuingJudgeDID is the Adjudicator's DID. Required.
	IssuingJudgeDID string `json:"issuing_judge_did"`

	// IsExParte flags an order issued without notice to the
	// restrained party. Triggers expedited-review tooling on
	// the case-management dashboard.
	IsExParte bool `json:"is_ex_parte,omitempty"`
}

// -------------------------------------------------------------------------------------------------
// 3) Default params
// -------------------------------------------------------------------------------------------------

func DefaultProtectiveOrderParams() []byte {
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

func SerializeProtectiveOrderPayload(p *ProtectiveOrderPayload) ([]byte, error) {
	return json.Marshal(p)
}

func DeserializeProtectiveOrderPayload(data []byte) (*ProtectiveOrderPayload, error) {
	var p ProtectiveOrderPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, ErrDeserialize
	}
	return &p, nil
}

// -------------------------------------------------------------------------------------------------
// 5) Registration
// -------------------------------------------------------------------------------------------------

func protectiveOrderRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaProtectiveOrderV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*ProtectiveOrderPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeProtectiveOrderPayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return DeserializeProtectiveOrderPayload(data)
		},
		DefaultParams:   DefaultProtectiveOrderParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
