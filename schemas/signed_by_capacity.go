/*
FILE PATH: schemas/signed_by_capacity.go

DESCRIPTION:

	SignedByCapacity — the on-log self-description of a Signer
	cosigner. Parallel to FiledByCapacity; the payload symmetry
	that v1.6 guarantees.

	For every cosigning Signer (Adjudicator, Clerk, Court Reporter)
	other than the primary signer at Signatures[0], the writer
	embeds an entry in the payload's `signed_by_capacities` array
	declaring:

	  - did            — the cosigner's DID (matches a Signatures
	                     entry)
	  - role           — catalog role (chief_justice, judge,
	                     court_clerk, court_staff, court_reporter,
	                     deputy_judge)
	  - exchange       — the institutional DID identifying which
	                     exchange this Signer belongs to
	  - delegation_ref — the LogPositionRef where this Signer's
	                     most-recent delegation entry lives. The
	                     verifier walks the chain via
	                     AuthorityResolver to confirm role +
	                     exchange match the claim.

	Self-describing entries: the verifier needs no off-log
	registry. ChainRoleResolver (.signed-by, this commit)
	reads signed_by_capacities, optionally walks each
	delegation_ref via AuthorityResolver, and returns the verified
	role+exchange tuple.

OVERVIEW:

	SignedByCapacity         — typed entry.
	Validate                 — structural sanity.
	ExtractSignedByCapacities — parses payload bytes into a slice.
	Per-DID lookup helper.

KEY DEPENDENCIES:
  - schemas/judicial_delegation.go (LogPositionRef).
*/
package schemas

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SignedByCapacity is the on-log per-cosigner declaration the
// verifier reads to map cosigner DIDs → roles + exchanges.
type SignedByCapacity struct {
	// DID is the cosigner's DID. MUST match one of the entry's
	// Signatures[i].SignerDID values; the verifier rejects
	// otherwise (anti-impersonation, mirror of FiledByCapacity).
	DID string `json:"did"`

	// Role is the Signer's catalog role at signing time. Must be
	// a valid role per the deployment's RoleCatalog. The
	// AuthorityResolver chain walk (when enabled) confirms.
	Role string `json:"role"`

	// Exchange is the institutional DID of the exchange this
	// Signer belongs to. The cosignature mix's IntraExchangeOnly
	// gate checks against this value.
	Exchange string `json:"exchange"`

	// DelegationRef is the log position of the cosigner's most-
	// recent delegation entry. AuthorityResolver walks the chain
	// from here back to the institutional grant. Optional in
	// the trust-mode resolver; required by the verifying-mode
	// resolver (.preqs).
	DelegationRef *LogPositionRef `json:"delegation_ref,omitempty"`
}

// ─── Sentinel errors ────────────────────────────────────────────────

var (
	ErrSignedByCapacityInvalid = errors.New("schemas/signed_by_capacity: invalid")
)

// Validate runs structural sanity. Returns nil iff DID, Role, and
// Exchange are all non-empty. DelegationRef is optional at this
// layer; the verifier decides whether to require chain validation.
func (c *SignedByCapacity) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: nil capacity", ErrSignedByCapacityInvalid)
	}
	if c.DID == "" {
		return fmt.Errorf("%w: did required", ErrSignedByCapacityInvalid)
	}
	if c.Role == "" {
		return fmt.Errorf("%w: role required", ErrSignedByCapacityInvalid)
	}
	if c.Exchange == "" {
		return fmt.Errorf("%w: exchange required", ErrSignedByCapacityInvalid)
	}
	return nil
}

// ─── Extraction helpers ─────────────────────────────────────────────

// ExtractSignedByCapacities parses the `signed_by_capacities`
// array out of a domain payload. Three return shapes:
//
//	nil, false, nil — payload has no signed_by_capacities key
//	                  (the common case; many entries are not
//	                  filer events and do not need the
//	                  symmetric block).
//	slice, true, nil — at least one entry parsed.
//	nil, false, err  — the array was present but malformed.
//
// Validate is NOT called here; the verifier runs it per-entry so
// it can surface per-cosigner failures.
func ExtractSignedByCapacities(payload []byte) ([]SignedByCapacity, bool, error) {
	if len(payload) == 0 {
		return nil, false, nil
	}
	var probe struct {
		SBC json.RawMessage `json:"signed_by_capacities"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return nil, false, nil
	}
	if len(probe.SBC) == 0 {
		return nil, false, nil
	}
	var caps []SignedByCapacity
	if err := json.Unmarshal(probe.SBC, &caps); err != nil {
		return nil, false, fmt.Errorf("%w: parse signed_by_capacities: %v",
			ErrSignedByCapacityInvalid, err)
	}
	return caps, true, nil
}

// FindByDID returns the first SignedByCapacity in caps whose DID
// equals did. Convenience for the verifier's per-cosigner walk.
// Returns nil when not found.
func FindSignedByCapacity(caps []SignedByCapacity, did string) *SignedByCapacity {
	for i := range caps {
		if caps[i].DID == did {
			return &caps[i]
		}
	}
	return nil
}

// ─── Marshal helper ─────────────────────────────────────────────────

// MarshalSignedByCapacities validates each entry and returns
// canonical JSON. Used by writers that build payloads with the
// symmetric capacity block.
func MarshalSignedByCapacities(caps []SignedByCapacity) ([]byte, error) {
	for i := range caps {
		if err := caps[i].Validate(); err != nil {
			return nil, fmt.Errorf("signed_by_capacities[%d]: %w", i, err)
		}
	}
	return json.Marshal(caps)
}
