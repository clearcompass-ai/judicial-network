/*
FILE PATH: directory/officer_registry.go

DESCRIPTION:
    OfficerRegistry — the (did:key → display alias) lookup table.

    Why a separate registry: the on-log truth carries did:key
    identifiers (`did:key:zQ3sh…`) — opaque to humans. Audit
    trails, dashboards, and CMS UIs need readable names ("Hon.
    Patricia Williams") and the role context ("Chief Justice,
    Davidson Circuit"). The registry is the single mapping
    consulted by every renderer.

    Inverse lookups (alias → did:key) are also supported: case
    management systems often have a name and need to drive a
    delegation issuance via the protocol DID.

    The registry stores per-officer state:
      - did:key (protocol identity)
      - alias (human-readable display name)
      - role (catalog name; e.g. "chief_justice")
      - delegation_ref (LogPosition of the entry that authorized
        the officer; AuthorityResolver consumes this)
      - status (active | revoked | succeeded)
      - successor_did (set when status==succeeded)
      - email (optional; only stored when EmailVerified at the IdP)

    Storage backends:
      - InMemoryRegistry — production-suitable for single-replica
        deployments, mandatory for tests.
      - PostgresOfficerRegistry — see officer_registry_postgres.go;
        same interface, durable storage. Tests do not require a
        live database — the in-memory impl is the contract.

    The registry is NOT the source of truth. The on-log
    delegation entries are. Registry entries can drift if the
    operator advances Origin_Tip (revocation/succession) without
    a corresponding registry update. Production reconcilers
    (monitoring/officer_reconciler.go, future phase) close that
    gap by walking the on-log truth and updating the registry.

KEY ARCHITECTURAL DECISIONS:
    - Aliases are unique per registry instance. Two officers with
      the same alias are an error at Add time. This protects
      audit-trail readers from ambiguity.
    - The registry does NOT verify on-log positions exist; the
      caller (delegation/issue.go) is responsible for adding
      records only after a successful Issue.
    - Status transitions are explicit (MarkRevoked,
      MarkSucceeded). The registry refuses transitions backwards
      (revoked → active) — you start fresh by removing and re-Adding.

OVERVIEW:
    Officer        — record shape.
    OfficerStatus  — closed-set status enum.
    Registry       — interface.
    InMemoryRegistry — RWMutex-protected map implementation.

KEY DEPENDENCIES:
    - schemas (LogPositionRef).
*/
package directory

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// OfficerStatus enumerates the closed-set status values an Officer
// record may hold.
type OfficerStatus string

const (
	StatusActive    OfficerStatus = "active"
	StatusRevoked   OfficerStatus = "revoked"
	StatusSucceeded OfficerStatus = "succeeded"
)

// Officer is the registered metadata for a single did:key. The
// canonical fields (DID, Alias, Role, DelegationRef) are required.
// Status defaults to StatusActive at Add.
type Officer struct {
	// DID is the protocol identifier (did:key:zQ3sh…). Required.
	DID string

	// Alias is the human-readable display name. Required, unique
	// per registry instance.
	Alias string

	// Role is the catalog role name. Required; the caller is
	// expected to confirm against schemas.RoleCatalog before Add.
	Role string

	// DelegationRef is the LogPositionRef of the on-log entry that
	// authorized this officer. AuthorityResolver consumes this as
	// the chain tip for Resolve. Required.
	DelegationRef schemas.LogPositionRef

	// Status is the current state. Defaults to StatusActive.
	Status OfficerStatus

	// SuccessorDID is set when Status == StatusSucceeded. Empty
	// otherwise.
	SuccessorDID string

	// Email is the verified email address linked to the wallet
	// (Privy IdP). Stored only when the IdP attested email is
	// verified. Optional.
	Email string

	// CreatedAt is when the record was first added to the registry.
	// AddedAt is preserved across Update.
	CreatedAt time.Time

	// UpdatedAt is the most-recent mutation time.
	UpdatedAt time.Time
}

// Registry is the seam between callers and the storage backend.
// Implementations: InMemoryRegistry, PostgresOfficerRegistry.
type Registry interface {
	// Lookup returns the Officer record for did, or
	// ErrOfficerNotFound when unknown.
	Lookup(did string) (*Officer, error)

	// LookupByAlias returns the Officer record by alias, or
	// ErrOfficerNotFound when unknown.
	LookupByAlias(alias string) (*Officer, error)

	// Add inserts a new record. Returns ErrOfficerExists on
	// duplicate DID, ErrAliasTaken on duplicate alias.
	Add(o Officer) error

	// Update replaces a record by DID. Status field is preserved
	// across Update unless the caller sets it explicitly. The
	// registry refuses to use Update to rewind a terminal status
	// (revoked/succeeded → active).
	Update(o Officer) error

	// MarkRevoked transitions the record's status to StatusRevoked.
	// The on-log revocation entry is the source of truth — this
	// updates the registry only.
	MarkRevoked(did string) error

	// MarkSucceeded transitions the record's status to
	// StatusSucceeded with the given successor DID. Reflects an
	// on-log judicial-succession-v1 entry.
	MarkSucceeded(did string, successorDID string) error

	// List returns all records in deterministic order (alpha by DID).
	List() []*Officer

	// ListByRole returns all records whose Role equals role.
	ListByRole(role string) []*Officer
}

// ─── Sentinel errors ────────────────────────────────────────────────

var (
	// ErrOfficerNotFound is returned by Lookup / LookupByAlias when
	// the queried key is unknown.
	ErrOfficerNotFound = errors.New("directory/officer_registry: officer not found")

	// ErrOfficerExists is returned by Add when a record with the
	// same DID already exists.
	ErrOfficerExists = errors.New("directory/officer_registry: officer already exists")

	// ErrAliasTaken is returned by Add / Update when the proposed
	// alias is already used by a different DID.
	ErrAliasTaken = errors.New("directory/officer_registry: alias already taken")

	// ErrInvalidOfficer is returned for missing required fields.
	ErrInvalidOfficer = errors.New("directory/officer_registry: invalid officer record")

	// ErrIllegalTransition is returned when an Update or Mark*
	// call would rewind a terminal status.
	ErrIllegalTransition = errors.New("directory/officer_registry: illegal status transition")
)

// validateOfficer runs structural sanity on an Officer record.
// Used by Add and Update before any state mutation.
func validateOfficer(o Officer) error {
	if o.DID == "" {
		return fmt.Errorf("%w: did required", ErrInvalidOfficer)
	}
	if o.Alias == "" {
		return fmt.Errorf("%w: alias required", ErrInvalidOfficer)
	}
	if o.Role == "" {
		return fmt.Errorf("%w: role required", ErrInvalidOfficer)
	}
	if o.DelegationRef.LogDID == "" {
		return fmt.Errorf("%w: delegation_ref.log_did required", ErrInvalidOfficer)
	}
	if o.Status != "" && o.Status != StatusActive &&
		o.Status != StatusRevoked && o.Status != StatusSucceeded {
		return fmt.Errorf("%w: status %q not in {active, revoked, succeeded}",
			ErrInvalidOfficer, o.Status)
	}
	return nil
}

// isTerminal reports whether s is a terminal status (revoked /
// succeeded). Used to gate illegal-transition checks.
func isTerminal(s OfficerStatus) bool {
	return s == StatusRevoked || s == StatusSucceeded
}

// ─── InMemoryRegistry ───────────────────────────────────────────────

// InMemoryRegistry is the default Registry implementation. Safe for
// concurrent use. Production single-replica deployments may use it;
// multi-replica deployments should use PostgresOfficerRegistry.
type InMemoryRegistry struct {
	mu       sync.RWMutex
	byDID    map[string]*Officer
	byAlias  map[string]string // alias → did
	nowFn    func() time.Time
}

// NewInMemoryRegistry constructs an empty registry.
func NewInMemoryRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{
		byDID:   make(map[string]*Officer),
		byAlias: make(map[string]string),
		nowFn:   func() time.Time { return time.Now().UTC() },
	}
}

// SetNowFn replaces the clock — useful for deterministic tests.
func (r *InMemoryRegistry) SetNowFn(fn func() time.Time) {
	r.mu.Lock()
	r.nowFn = fn
	r.mu.Unlock()
}

// Method implementations live in officer_registry_inmemory.go.
