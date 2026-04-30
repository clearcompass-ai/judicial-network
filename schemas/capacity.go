/*
FILE PATH: schemas/capacity.go

DESCRIPTION:
    FiledByCapacity — the on-log credentials claim that an
    ActorFiler embeds in their entry's payload. Per the v1.4 Event
    Dictionary's Tier 2 cosignature requirement (Flag #1), every
    entry submitted by a filer (Prosecutor, Defense Counsel, Civil
    Attorney, Fiduciary, Guardian ad litem) must carry both:

      - a `filed_by_capacity` block in the payload that declares
        the filer's role and credentials (BPR number, jurisdiction,
        firm); and
      - a cosignature from the DID stated in `filed_by_capacity.did`
        (the filer's attestation that they really filed it).

    The Phase 3D verifier walks payload+signatures+policy+catalog
    to enforce the bind. NO off-log registry of attorneys is
    consulted — the on-log claim IS the truth, the cosignature IS
    the attestation.

OVERVIEW:
    FilerRole               — closed-set Tier 2 role enum (5 values).
    FiledByCapacity         — the payload-embedded claim struct.
    Validate                — structural sanity (rejects ActorSigner
                              / ActorParty / unknown roles).
    ExtractFiledByCapacity  — parses payload bytes; returns
                              (nil, false, nil) when absent.

KEY DEPENDENCIES:
    - schemas/actor.go (Actor enum; capacity.Actor must be ActorFiler).
*/
package schemas

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// FilerRole enumerates the closed-set Tier 2 (ActorFiler) roles per
// the v1.4 Event Dictionary, Part 1. Stable identifiers; never
// renumber. The Phase 3C cosignature-mix policy keys on these.
type FilerRole string

const (
	// FilerRoleProsecutor — District Attorney, prosecutor.
	FilerRoleProsecutor FilerRole = "prosecutor"

	// FilerRoleDefenseCounsel — criminal defense or civil defense
	// attorney.
	FilerRoleDefenseCounsel FilerRole = "defense_counsel"

	// FilerRoleCivilAttorney — civil attorney representing a
	// plaintiff or other civil party.
	FilerRoleCivilAttorney FilerRole = "civil_attorney"

	// FilerRoleFiduciary — court-appointed Executor, Conservator,
	// or Guardian managing assets / well-being of another person
	// or estate.
	FilerRoleFiduciary FilerRole = "fiduciary"

	// FilerRoleGuardianAdLitem — independent attorney appointed by
	// an Adjudicator to represent a vulnerable subject (minor,
	// incapacitated adult).
	FilerRoleGuardianAdLitem FilerRole = "guardian_ad_litem"
)

// IsValid reports whether r is a defined filer role.
func (r FilerRole) IsValid() bool {
	switch r {
	case FilerRoleProsecutor, FilerRoleDefenseCounsel,
		FilerRoleCivilAttorney, FilerRoleFiduciary,
		FilerRoleGuardianAdLitem:
		return true
	default:
		return false
	}
}

// FiledByCapacity is the payload-embedded credentials claim. The
// JSON shape is the on-log truth — every field tag is part of the
// public contract. The aggregator (Phase 3E) reads this verbatim
// into Postgres; verifiers parse it for the cosignature check.
type FiledByCapacity struct {
	// Actor classifies the filer. Must equal ActorFiler (=2);
	// Validate rejects ActorSigner and ActorParty.
	Actor Actor `json:"actor"`

	// Role names the specific Tier 2 role per FilerRole. Required.
	Role FilerRole `json:"role"`

	// DID is the filer's signing DID (typically a Privy embedded
	// wallet's did:key). Required, must appear in the entry's
	// Signatures — the Phase 3D verifier enforces this binding.
	DID string `json:"did"`

	// Credentials is the role's free-form credential map. Required
	// keys depend on the role and on the policy module's
	// per-event RequiredCredentials list. Conventional keys:
	//   - bpr_number, jurisdiction, firm   (attorney roles)
	//   - letters_of_administration_ref    (fiduciary)
	//   - appointment_order_ref            (guardian_ad_litem)
	Credentials map[string]string `json:"credentials,omitempty"`

	// SwornAt is when the filer attested the claim. Required;
	// RFC-3339Nano UTC. Stored on-log so audit trails capture the
	// declaration time; not used by the verifier for staleness
	// gating (the cosignature itself is the attestation).
	SwornAt string `json:"sworn_at"`
}

// ─── Sentinel errors ────────────────────────────────────────────────

var (
	// ErrCapacityInvalid wraps any structural validation failure.
	ErrCapacityInvalid = errors.New("schemas/capacity: invalid filed_by_capacity")

	// ErrCapacityWrongActor fires when capacity.Actor != ActorFiler.
	ErrCapacityWrongActor = errors.New("schemas/capacity: actor must be ActorFiler (2)")

	// ErrCapacityUnknownRole fires when capacity.Role is not in
	// the FilerRole closed set.
	ErrCapacityUnknownRole = errors.New("schemas/capacity: role not in {prosecutor, defense_counsel, civil_attorney, fiduciary, guardian_ad_litem}")
)

// Validate runs structural sanity. Returns nil iff:
//   - Actor == ActorFiler
//   - Role.IsValid()
//   - DID != ""
//   - SwornAt parses as RFC-3339Nano
func (c *FiledByCapacity) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: nil capacity", ErrCapacityInvalid)
	}
	if c.Actor != ActorFiler {
		return fmt.Errorf("%w: got actor=%s (%d)",
			ErrCapacityWrongActor, c.Actor.String(), int(c.Actor))
	}
	if !c.Role.IsValid() {
		return fmt.Errorf("%w: got role=%q", ErrCapacityUnknownRole, string(c.Role))
	}
	if c.DID == "" {
		return fmt.Errorf("%w: did required", ErrCapacityInvalid)
	}
	if c.SwornAt == "" {
		return fmt.Errorf("%w: sworn_at required", ErrCapacityInvalid)
	}
	if _, err := time.Parse(time.RFC3339Nano, c.SwornAt); err != nil {
		return fmt.Errorf("%w: malformed sworn_at: %v", ErrCapacityInvalid, err)
	}
	return nil
}

// HasCredential reports whether c.Credentials contains key with a
// non-empty value. Convenience for the policy verifier.
func (c *FiledByCapacity) HasCredential(key string) bool {
	if c == nil || c.Credentials == nil {
		return false
	}
	v, ok := c.Credentials[key]
	return ok && v != ""
}

// ─── Extract ────────────────────────────────────────────────────────

// ExtractFiledByCapacity parses the `filed_by_capacity` block out
// of a domain payload. Three return shapes:
//
//   nil, false, nil  — payload is empty / not JSON / has no
//                      filed_by_capacity key. NOT all entries are
//                      filings; this is the common case.
//   *cap, true, nil  — payload had a parseable filed_by_capacity
//                      block. Validate is NOT called here; the
//                      verifier runs that.
//   nil, false, err  — payload had a `filed_by_capacity` key but
//                      the block could not be parsed.
func ExtractFiledByCapacity(payload []byte) (*FiledByCapacity, bool, error) {
	if len(payload) == 0 {
		return nil, false, nil
	}
	var probe struct {
		FBC json.RawMessage `json:"filed_by_capacity"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		// Payload not JSON-shaped — no capacity block possible.
		return nil, false, nil
	}
	if len(probe.FBC) == 0 {
		return nil, false, nil
	}
	var c FiledByCapacity
	if err := json.Unmarshal(probe.FBC, &c); err != nil {
		return nil, false, fmt.Errorf("%w: parse filed_by_capacity: %v",
			ErrCapacityInvalid, err)
	}
	return &c, true, nil
}

// MarshalFiledByCapacity validates and returns canonical JSON. Used
// by writers (delegation/cosigned.go) to build payloads with a
// well-formed capacity block.
func MarshalFiledByCapacity(c *FiledByCapacity) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}
