/*
FILE PATH:

	schemas/warrant.go

DESCRIPTION:

	judicial-warrant-v1 — judicial authorizations for arrest,
	search, or court appearance (bench warrants for failure to
	appear). Combined issuance + return record so the executed
	warrant's chain of custody lives in one place.

REAL-WORLD USE CASES

	A. Arrest warrant on a felony complaint.
	   DA presents a sworn complaint affidavit; judge finds
	   probable cause; signs an ArrestWarrant. ProbableCauseRef
	   points at the underlying motion / complaint entry. The
	   warrant is delivered to the sheriff. Three days later
	   the sheriff arrests the defendant and returns the warrant
	   noting execution: the SAME warrant entry's Return field
	   is populated via an amended entry (PriorWarrantPos
	   references the original).

	B. Search warrant for digital evidence.
	   Detective applies for a search warrant for a suspect's
	   phone and cloud accounts. Affidavit + judge's probable-
	   cause finding produce a SearchWarrant. TargetSpecifications
	   names the locations to be searched (with the level of
	   specificity required for Fourth Amendment compliance).
	   Return entry notes what was seized (or that nothing was
	   found within the warrant's authorized scope).

	C. Bench warrant for failure to appear.
	   Defendant misses a scheduled court date; judge issues a
	   bench warrant via this schema with WarrantType="bench".
	   No probable-cause affidavit (the failure to appear is
	   the cause); the warrant directs any peace officer to
	   bring the defendant before the court. Returned when the
	   defendant is brought in.

SCHEMA SHAPE

	WarrantType is a closed set ({arrest, search, bench, capias,
	material_witness}) — exhaustive in dictionary §6.

	Issuance + Return are nested structs. Issuance is required at
	the time of admission (the warrant must be issued before it
	can be returned). Return is OPTIONAL on the initial entry; an
	amended warrant entry (with PriorWarrantPos pointing at the
	original) populates Return when the warrant is executed.

	TargetSpecifications is open-ended []string — Fourth Amendment
	particularity is a judicial-review question, not a schema-
	enforcement question. The schema captures what the judge
	authorized; the constitutional sufficiency of that scope is
	the judge's responsibility.

	ProbableCauseRef points at the affidavit/motion entry that
	supports the warrant. Required for arrest + search warrants
	(constitutional requirement); optional for bench warrants
	(the failure-to-appear IS the cause).

KEY ARCHITECTURAL DECISIONS

  - Generic schema. URI is "judicial-warrant-v1".

  - Single schema for issuance + return. A returned warrant is
    an AMENDED entry with PriorWarrantPos + Return populated.
    Walking the warrant chain yields both the issuance and the
    execution record without two distinct schemas.

  - WarrantType closed set. Restrictive on purpose — every
    warrant type has its own constitutional / statutory
    requirements (arrest needs probable cause; search needs
    particularity; bench is administrative). A new statutory
    warrant type (e.g., "civil_arrest" in some jurisdictions)
    is a schema-bump, not a hidden enum extension.

  - TargetBinding for arrest warrants (a person's binding_id);
    TargetSpecifications for search warrants (locations,
    devices). Two distinct fields because the constitutional
    review is different (probable cause for the PERSON vs
    particularity of the PLACE).

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

// SchemaWarrantV1 is the canonical schema URI.
const SchemaWarrantV1 = "judicial-warrant-v1"

// Warrant-type values — closed set per dictionary §6.
const (
	WarrantTypeArrest          = "arrest"
	WarrantTypeSearch          = "search"
	WarrantTypeBench           = "bench"
	WarrantTypeCapias          = "capias"
	WarrantTypeMaterialWitness = "material_witness"
)

// -------------------------------------------------------------------------------------------------
// 2) Sub-payload types
// -------------------------------------------------------------------------------------------------

// WarrantIssuance captures the issuance-time facts. Required on
// every warrant entry.
type WarrantIssuance struct {
	// IssuedAt is the wall-clock time of issuance (UTC). Required.
	IssuedAt time.Time `json:"issued_at"`

	// IssuingJudgeDID is the Adjudicator's DID. Required.
	IssuingJudgeDID string `json:"issuing_judge_did"`

	// ExpiresAt is the warrant's expiration (UTC). Zero = no
	// expiration (some arrest warrants are indefinite; bench
	// warrants typically have no expiration). Search warrants
	// typically expire 10 days from issuance per TRCrP 41 /
	// FRCrP 41 — operators set this per their jurisdiction.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// WarrantReturn captures the execution record. Optional on the
// initial entry; populated on an amended entry (PriorWarrantPos
// pointing at the original) when the warrant is executed or
// returned unexecuted.
type WarrantReturn struct {
	// ReturnedAt is the wall-clock time of return (UTC). Required
	// when this struct is present.
	ReturnedAt time.Time `json:"returned_at"`

	// ExecutingOfficerDID identifies the law-enforcement officer
	// who executed (or attempted to execute) the warrant. Required
	// when this struct is present.
	ExecutingOfficerDID string `json:"executing_officer_did"`

	// Executed is true if the warrant achieved its purpose (arrest
	// made; search conducted; defendant brought before the court).
	// False indicates an unsuccessful return (subject not found;
	// premises vacated; etc.) — still a valid return that closes
	// the warrant's active state.
	Executed bool `json:"executed"`

	// Notes captures the officer's narrative ("subject arrested
	// without incident at 1234 Main St"; "premises vacated;
	// nothing seized"). Free-form; surfaced by the chain-of-
	// custody dashboard.
	Notes string `json:"notes,omitempty"`
}

// -------------------------------------------------------------------------------------------------
// 3) Payload
// -------------------------------------------------------------------------------------------------

// WarrantPayload is the Domain Payload for entries governed by
// judicial-warrant-v1.
type WarrantPayload struct {
	// ── SDK well-known fields ─────────────────────────────────────
	ActivationDelay int64  `json:"activation_delay,omitempty"`
	MigrationPolicy string `json:"migration_policy,omitempty"`

	// ── Warrant metadata ──────────────────────────────────────────

	// CaseRootPos is the case this warrant is issued within.
	// Required (warrants without a case anchor would defeat
	// the prereq walker's case-root model).
	CaseRootPos types.LogPosition `json:"case_root_pos"`

	// WarrantType is the closed-set warrant kind. Required;
	// admission-time validator rejects any value outside the
	// constants declared above.
	WarrantType string `json:"warrant_type"`

	// TargetBinding identifies the person the warrant authorizes
	// action against (binding_id from a prior party_binding
	// entry). Required for arrest, bench, capias, and material-
	// witness warrants. Empty for search warrants — those use
	// TargetSpecifications instead.
	TargetBinding string `json:"target_binding,omitempty"`

	// TargetSpecifications names the places/things to be searched
	// or seized (for search warrants) with sufficient particularity
	// to satisfy the Fourth Amendment / TN Art. I § 7. Required
	// for search warrants; ignored for other warrant types.
	TargetSpecifications []string `json:"target_specifications,omitempty"`

	// ProbableCauseRef points at the affidavit / motion / complaint
	// entry that supports this warrant. Required for arrest +
	// search + material-witness warrants; optional for bench +
	// capias (the failure-to-appear or contempt finding IS the
	// cause).
	ProbableCauseRef types.LogPosition `json:"probable_cause_ref,omitempty"`

	// SourceAuthority is the statutory citation (e.g., "TCA 40-6-205"
	// for TN arrest warrants, "FRCrP 41" for federal search
	// warrants). Required for admission-time auditability.
	SourceAuthority string `json:"source_authority"`

	// Issuance is the warrant's issuance record. Required.
	Issuance WarrantIssuance `json:"issuance"`

	// Return is the warrant's execution record. Optional on the
	// initial entry; populated on an amended entry that
	// supersedes the original via PriorWarrantPos.
	Return *WarrantReturn `json:"return,omitempty"`

	// PriorWarrantPos chains an amended return entry back to the
	// original issuance entry. Zero LogPosition for the initial
	// issuance.
	PriorWarrantPos types.LogPosition `json:"prior_warrant_pos,omitempty"`
}

// -------------------------------------------------------------------------------------------------
// 4) Default params
// -------------------------------------------------------------------------------------------------

func DefaultWarrantParams() []byte {
	params := map[string]interface{}{
		"identifier_scope": "real_did",
		"migration_policy": "amendment",
	}
	b, _ := json.Marshal(params)
	return b
}

// -------------------------------------------------------------------------------------------------
// 5) Serialization
// -------------------------------------------------------------------------------------------------

func SerializeWarrantPayload(p *WarrantPayload) ([]byte, error) {
	return json.Marshal(p)
}

func DeserializeWarrantPayload(data []byte) (*WarrantPayload, error) {
	var p WarrantPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, ErrDeserialize
	}
	return &p, nil
}

// -------------------------------------------------------------------------------------------------
// 6) Registration
// -------------------------------------------------------------------------------------------------

func warrantRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaWarrantV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*WarrantPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeWarrantPayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return DeserializeWarrantPayload(data)
		},
		DefaultParams:   DefaultWarrantParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
