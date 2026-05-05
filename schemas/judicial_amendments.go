/*
FILE PATH: schemas/judicial_amendments.go

DESCRIPTION:

	Amendments to judicial-delegation-v1 entries: revocations
	(Path A, same_signer) and successions (institutional Authority_Set
	transitions). Split out of judicial_delegation.go so that file
	can stay focused on the canonical delegation payload.

OVERVIEW:

	JudicialRevocationPayload — early-termination amendment.
	JudicialSuccessionPayload — top-of-chain succession (CJ death,
	    resignation, removal). Inheritance modes: full | narrowed |
	    clean_slate.

KEY DEPENDENCIES:
  - schemas/judicial_delegation.go (LogPositionRef, schema URI consts)
*/
package schemas

import (
	"fmt"
	"time"
)

// JudicialRevocationPayload is the Domain Payload of a revocation
// amendment. Path A (same_signer): only the granter who issued the
// original delegation can revoke it. Reasons are domain-defined.
type JudicialRevocationPayload struct {
	SchemaID         string         `json:"schema_id"`
	TargetDelegation LogPositionRef `json:"target_delegation"`
	Reason           string         `json:"reason"` // "expired" | "officer_transfer"
	// | "performance" | "conflict"
	// | "death_in_office" | other
	RevokedAt string `json:"revoked_at"`
}

// JudicialSuccessionPayload is the Domain Payload of a succession
// entry. Used when a top-of-chain signer (typically chief justice)
// dies/resigns/is removed and the institutional DID's Authority_Set
// must redirect downstream authority to a successor.
//
// The succession entry is signed by the institutional DID with
// Authority_Set cosignatures (per the institution's
// cosignature_threshold, typically 2-of-3). Origin_Tip of the target
// delegation advances to this succession entry. The SDK's
// verifier.EvaluateOrigin returns OriginSucceeded; the
// AuthorityResolver follows the SuccessorDID transparently.
type JudicialSuccessionPayload struct {
	SchemaID         string         `json:"schema_id"`
	TargetDelegation LogPositionRef `json:"target_delegation"`
	SuccessorDID     string         `json:"successor_did"` // new did:key
	Reason           string         `json:"reason"`        // "death_in_office" |
	// "resignation" |
	// "removal"
	Inheritance string `json:"inheritance"` // "full" | "narrowed" |
	// "clean_slate"
	NarrowedScope []string `json:"narrowed_scope,omitempty"` // when
	// Inheritance="narrowed"
	EffectiveAt        string   `json:"effective_at"`
	AuthoritySetCosigs []string `json:"authority_set_cosigs,omitempty"`
}

// SuccessionInheritance enumerates the closed-set inheritance modes.
const (
	InheritanceFull       = "full"
	InheritanceNarrowed   = "narrowed"
	InheritanceCleanSlate = "clean_slate"
)

// Validate runs structural validation on a JudicialRevocationPayload.
func (p *JudicialRevocationPayload) Validate() error {
	if p.SchemaID != SchemaJudicialRevocationV1 {
		return fmt.Errorf("schemas/judicial_delegation: revocation schema_id mismatch: got %q want %q",
			p.SchemaID, SchemaJudicialRevocationV1)
	}
	if p.TargetDelegation.LogDID == "" {
		return fmt.Errorf("schemas/judicial_delegation: revocation target_delegation.log_did required")
	}
	if p.Reason == "" {
		return fmt.Errorf("schemas/judicial_delegation: revocation reason required")
	}
	if p.RevokedAt == "" {
		return fmt.Errorf("schemas/judicial_delegation: revocation revoked_at required")
	}
	if _, err := time.Parse(time.RFC3339Nano, p.RevokedAt); err != nil {
		return fmt.Errorf("schemas/judicial_delegation: malformed revoked_at: %w", err)
	}
	return nil
}

// Validate runs structural validation on a JudicialSuccessionPayload.
func (p *JudicialSuccessionPayload) Validate() error {
	if p.SchemaID != SchemaJudicialSuccessionV1 {
		return fmt.Errorf("schemas/judicial_delegation: succession schema_id mismatch: got %q want %q",
			p.SchemaID, SchemaJudicialSuccessionV1)
	}
	if p.TargetDelegation.LogDID == "" {
		return fmt.Errorf("schemas/judicial_delegation: succession target_delegation.log_did required")
	}
	if p.SuccessorDID == "" {
		return fmt.Errorf("schemas/judicial_delegation: successor_did required")
	}
	if p.Reason == "" {
		return fmt.Errorf("schemas/judicial_delegation: succession reason required")
	}
	switch p.Inheritance {
	case InheritanceFull, InheritanceNarrowed, InheritanceCleanSlate:
	default:
		return fmt.Errorf("schemas/judicial_delegation: succession inheritance must be one of {full, narrowed, clean_slate}, got %q", p.Inheritance)
	}
	if p.Inheritance == InheritanceNarrowed && len(p.NarrowedScope) == 0 {
		return fmt.Errorf("schemas/judicial_delegation: narrowed inheritance requires non-empty narrowed_scope")
	}
	if p.EffectiveAt == "" {
		return fmt.Errorf("schemas/judicial_delegation: effective_at required")
	}
	if _, err := time.Parse(time.RFC3339Nano, p.EffectiveAt); err != nil {
		return fmt.Errorf("schemas/judicial_delegation: malformed effective_at: %w", err)
	}
	return nil
}
