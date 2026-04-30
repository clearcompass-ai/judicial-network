/*
FILE PATH: directory/attorney_registry.go

DESCRIPTION:
    AttorneyRegistry — the (filed_by → display alias) lookup for
    Tier 2 actors per the v1.3 Event Dictionary.

    Why a separate registry: Tier 2 actors (Prosecutors, Defense
    Counsel, Civil Attorneys, Fiduciaries, Guardians ad litem) DO
    NOT hold network keys, so they are not in OfficerRegistry.
    They appear in payloads as `filed_by` strings; this directory
    maps each `filed_by` to a readable record (alias, attorney
    type, bar number, status).

    The Phase 3D resolver consults this registry when an entry's
    `filed_by` field is set: the entry must additionally carry a
    cosignature whose tier matches the configured mix
    (Phase 3C policy module).

    Status transitions:
      active   → suspended → active (suspension lifted)
      active   → retired (terminal)
      active   → revoked (terminal — disbarred or removed)

    Identifier model: an attorney's protocol identifier is opaque
    to the registry — it could be a did:web (firm-issued), a
    did:key (if the bar association ever issues one), or a
    `bar:TN:12345` reference. Whatever string the writer puts in
    `filed_by` is what the registry keys on. Bar number is a
    SECONDARY index for cross-reference.

OVERVIEW:
    AttorneyType   — closed-set role enum.
    AttorneyStatus — closed-set status enum.
    Attorney       — record shape.
    AttorneyRegistry — interface.
    InMemoryAttorneys — RWMutex-protected map implementation
                        (methods in attorney_registry_inmemory.go).

KEY DEPENDENCIES:
    - schemas (Tier; Phase 3D resolver consults this).
*/
package directory

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// AttorneyType enumerates the closed-set Tier 2 roles per the
// v1.3 Event Dictionary, Part 1. Stable identifiers; never renumber.
type AttorneyType string

const (
	// AttorneyTypeProsecutor — District Attorney, prosecutor.
	// Submits charging instruments to the Clerk.
	AttorneyTypeProsecutor AttorneyType = "prosecutor"

	// AttorneyTypeDefenseCounsel — criminal defense or civil
	// defense attorney. Submits motions, briefs, pleadings.
	AttorneyTypeDefenseCounsel AttorneyType = "defense_counsel"

	// AttorneyTypeCivilAttorney — civil attorney representing a
	// plaintiff or other party.
	AttorneyTypeCivilAttorney AttorneyType = "civil_attorney"

	// AttorneyTypeFiduciary — court-appointed Executor,
	// Conservator, or Guardian managing assets / well-being of
	// another person or estate.
	AttorneyTypeFiduciary AttorneyType = "fiduciary"

	// AttorneyTypeGuardianAdLitem — independent attorney
	// appointed by an Adjudicator to represent a vulnerable
	// subject (minor, incapacitated adult).
	AttorneyTypeGuardianAdLitem AttorneyType = "guardian_ad_litem"
)

// IsValid reports whether t is a defined attorney type.
func (t AttorneyType) IsValid() bool {
	switch t {
	case AttorneyTypeProsecutor, AttorneyTypeDefenseCounsel,
		AttorneyTypeCivilAttorney, AttorneyTypeFiduciary,
		AttorneyTypeGuardianAdLitem:
		return true
	default:
		return false
	}
}

// AttorneyStatus enumerates the closed-set lifecycle states.
type AttorneyStatus string

const (
	AttorneyActive    AttorneyStatus = "active"
	AttorneySuspended AttorneyStatus = "suspended"
	AttorneyRetired   AttorneyStatus = "retired"
	AttorneyRevoked   AttorneyStatus = "revoked"
)

// IsValid reports whether s is a defined status.
func (s AttorneyStatus) IsValid() bool {
	switch s {
	case AttorneyActive, AttorneySuspended, AttorneyRetired, AttorneyRevoked:
		return true
	default:
		return false
	}
}

// IsTerminal reports whether s is a terminal state (retired or
// revoked). Terminal records can never transition back to active;
// re-issuance requires a new record.
func (s AttorneyStatus) IsTerminal() bool {
	return s == AttorneyRetired || s == AttorneyRevoked
}

// Attorney is the registered metadata for a single Tier 2 actor.
type Attorney struct {
	// ID is the protocol-side identifier the writer puts in
	// `filed_by`. Required, unique per registry instance. Opaque
	// string — the registry does not parse it. Examples:
	//   - "bar:TN:12345"
	//   - "did:web:da:da-office#12345"
	//   - "att:smith-jones-llp:eve.smith"
	ID string

	// Alias is the human-readable display name. Required, unique
	// per registry instance.
	Alias string

	// Type classifies the Tier 2 role. Required.
	Type AttorneyType

	// BarNumber is the state bar admission number; optional. When
	// non-empty, must be unique per registry instance (we index
	// on it for inverse lookup).
	BarNumber string

	// Status is the current lifecycle state. Defaults to
	// AttorneyActive at Register.
	Status AttorneyStatus

	// SuspensionReason is set when Status == AttorneySuspended.
	// Cleared when status returns to AttorneyActive.
	SuspensionReason string

	// Email is the verified email associated with bar admission.
	// Optional; Phase 3D may compare against the cosigner's email
	// claim for additional gating.
	Email string

	// CreatedAt is when the attorney was first registered.
	CreatedAt time.Time

	// UpdatedAt is the most recent mutation time.
	UpdatedAt time.Time
}

// Tier always returns Tier2Advocate for an Attorney. Convenience
// accessor used by the Phase 3D cosignature-mix evaluator.
//
// The implementation imports schemas only at the call boundary to
// avoid pulling the whole schemas package into directory's exposed
// types — callers that don't need the tier never pay the import.
func (a *Attorney) IsTier2() bool {
	return a != nil && a.Type.IsValid()
}

// ─── Registry interface ─────────────────────────────────────────────

// AttorneyRegistry is the seam between callers and the storage
// backend. Implementations: InMemoryAttorneys (this file's package);
// PostgresAttorneys (future, mirrors the OfficerRegistry pattern).
type AttorneyRegistry interface {
	// Lookup returns the attorney record by ID, or
	// ErrAttorneyNotFound when unknown.
	Lookup(id string) (*Attorney, error)

	// LookupByAlias returns the attorney record by alias, or
	// ErrAttorneyNotFound when unknown.
	LookupByAlias(alias string) (*Attorney, error)

	// LookupByBarNumber returns the attorney record by bar number,
	// or ErrAttorneyNotFound when unknown. Returns immediately if
	// barNumber is empty (no record can match an empty bar number).
	LookupByBarNumber(barNumber string) (*Attorney, error)

	// Register inserts a new record. Returns ErrAttorneyExists on
	// duplicate ID, ErrAliasTaken on duplicate alias,
	// ErrBarNumberTaken on duplicate bar number.
	Register(a Attorney) error

	// Update replaces a record by ID. Status is preserved unless
	// the caller sets it explicitly. Refuses to rewind a terminal
	// status (retired/revoked → active).
	Update(a Attorney) error

	// Suspend transitions the record to AttorneySuspended with
	// reason recorded.
	Suspend(id string, reason string) error

	// Restore transitions a suspended record back to AttorneyActive
	// and clears the suspension reason. Returns
	// ErrIllegalAttorneyTransition if the record is not currently
	// suspended.
	Restore(id string) error

	// Retire transitions the record to AttorneyRetired (terminal).
	Retire(id string) error

	// Revoke transitions the record to AttorneyRevoked (terminal —
	// disbarment or removal for cause).
	Revoke(id string) error

	// List returns all records in deterministic order (alpha by ID).
	List() []*Attorney

	// ListByType returns all records whose Type equals t.
	ListByType(t AttorneyType) []*Attorney
}

// ─── Sentinel errors ────────────────────────────────────────────────

var (
	// ErrAttorneyNotFound is returned by Lookup* when the queried
	// key is unknown.
	ErrAttorneyNotFound = errors.New("directory/attorney_registry: attorney not found")

	// ErrAttorneyExists is returned by Register when a record with
	// the same ID already exists.
	ErrAttorneyExists = errors.New("directory/attorney_registry: attorney already exists")

	// ErrBarNumberTaken is returned when the proposed bar number is
	// already used by a different attorney.
	ErrBarNumberTaken = errors.New("directory/attorney_registry: bar number already taken")

	// ErrInvalidAttorney is returned for missing required fields or
	// out-of-set type/status values.
	ErrInvalidAttorney = errors.New("directory/attorney_registry: invalid attorney record")

	// ErrIllegalAttorneyTransition is returned when an Update or
	// transition call would cross a forbidden status boundary.
	ErrIllegalAttorneyTransition = errors.New("directory/attorney_registry: illegal attorney status transition")
)

// validateAttorney runs structural sanity on an Attorney record.
// Used by Register and Update before any state mutation.
func validateAttorney(a Attorney) error {
	if a.ID == "" {
		return fmt.Errorf("%w: id required", ErrInvalidAttorney)
	}
	if a.Alias == "" {
		return fmt.Errorf("%w: alias required", ErrInvalidAttorney)
	}
	if !a.Type.IsValid() {
		return fmt.Errorf("%w: type %q not in {prosecutor, defense_counsel, civil_attorney, fiduciary, guardian_ad_litem}",
			ErrInvalidAttorney, string(a.Type))
	}
	if a.Status != "" && !a.Status.IsValid() {
		return fmt.Errorf("%w: status %q not in {active, suspended, retired, revoked}",
			ErrInvalidAttorney, string(a.Status))
	}
	return nil
}

// ─── InMemoryAttorneys ──────────────────────────────────────────────

// InMemoryAttorneys is the default AttorneyRegistry implementation.
// Safe for concurrent use. Methods live in
// attorney_registry_inmemory.go.
type InMemoryAttorneys struct {
	mu          sync.RWMutex
	byID        map[string]*Attorney
	byAlias     map[string]string // alias → ID
	byBarNumber map[string]string // barNumber → ID (only for non-empty)
	nowFn       func() time.Time
}

// NewInMemoryAttorneys constructs an empty registry.
func NewInMemoryAttorneys() *InMemoryAttorneys {
	return &InMemoryAttorneys{
		byID:        make(map[string]*Attorney),
		byAlias:     make(map[string]string),
		byBarNumber: make(map[string]string),
		nowFn:       func() time.Time { return time.Now().UTC() },
	}
}

// SetNowFn replaces the clock — useful for deterministic tests.
func (r *InMemoryAttorneys) SetNowFn(fn func() time.Time) {
	r.mu.Lock()
	r.nowFn = fn
	r.mu.Unlock()
}

// Static check that InMemoryAttorneys satisfies AttorneyRegistry.
// Method bodies are in attorney_registry_inmemory.go.
var _ AttorneyRegistry = (*InMemoryAttorneys)(nil)
