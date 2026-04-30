/*
FILE PATH: directory/officer_registry_postgres.go

DESCRIPTION:
    PostgresOfficerRegistry — the production storage backend.
    Currently a deliberate stub: the type satisfies the Registry
    interface but every method returns ErrNotImplemented. Wiring
    this to a real *sql.DB is a one-file change in a future phase
    once the deployment's database schema lands.

    Why ship the stub now: the production binary needs to compile
    against a stable Registry seam. Leaving the stub here lets
    `go build ./...` succeed for the production deployment image
    while the in-memory backend serves single-replica tests and
    development.

KEY ARCHITECTURAL DECISIONS:
    - Same Registry interface as InMemoryRegistry. No method
      signatures may diverge — the seam is the contract.
    - The stub returns ErrNotImplemented for every method. A
      production deployment that accidentally constructs a
      PostgresOfficerRegistry without DSN configured will fail
      every call, surfacing the misconfiguration loudly rather
      than silently dropping records.
    - When the real implementation lands, schema:

        officers (
          did            TEXT PRIMARY KEY,
          alias          TEXT NOT NULL UNIQUE,
          role           TEXT NOT NULL,
          delegation_log_did   TEXT NOT NULL,
          delegation_sequence  BIGINT NOT NULL,
          status         TEXT NOT NULL CHECK (
                            status IN ('active','revoked','succeeded')),
          successor_did  TEXT,
          email          TEXT,
          created_at     TIMESTAMPTZ NOT NULL,
          updated_at     TIMESTAMPTZ NOT NULL
        );
        CREATE INDEX officers_role_idx ON officers (role);

      Method shapes already match this layout — Add → INSERT,
      Update → UPDATE WHERE did=$1, MarkRevoked / MarkSucceeded →
      UPDATE status=… WHERE did=$1.

OVERVIEW:
    PostgresOfficerRegistry — type + constructor + method stubs.

KEY DEPENDENCIES:
    - directory/officer_registry.go (Registry interface, errors).
*/
package directory

import "errors"

// ErrNotImplemented is returned by every PostgresOfficerRegistry
// method. Distinct sentinel so callers can errors.Is and either
// degrade or fail loudly.
var ErrNotImplemented = errors.New("directory/officer_registry: postgres backend not implemented (use InMemoryRegistry)")

// PostgresOfficerRegistry is the production-storage Registry seam.
// At present every method returns ErrNotImplemented; the wiring
// lands in a future phase once the deployment's database schema
// is in place.
type PostgresOfficerRegistry struct {
	// dsn is the database connection string. Stored for the
	// future implementation; unused by the stub.
	dsn string
}

// NewPostgresOfficerRegistry constructs a stub registry. Returns
// the value even though every method is unimplemented — the
// production binary builds and starts; calls fail loudly at use
// time.
func NewPostgresOfficerRegistry(dsn string) *PostgresOfficerRegistry {
	return &PostgresOfficerRegistry{dsn: dsn}
}

// DSN exposes the configured connection string for diagnostics.
// The stub does not validate it.
func (p *PostgresOfficerRegistry) DSN() string {
	return p.dsn
}

// Lookup is unimplemented.
func (p *PostgresOfficerRegistry) Lookup(did string) (*Officer, error) {
	return nil, ErrNotImplemented
}

// LookupByAlias is unimplemented.
func (p *PostgresOfficerRegistry) LookupByAlias(alias string) (*Officer, error) {
	return nil, ErrNotImplemented
}

// Add is unimplemented.
func (p *PostgresOfficerRegistry) Add(o Officer) error {
	return ErrNotImplemented
}

// Update is unimplemented.
func (p *PostgresOfficerRegistry) Update(o Officer) error {
	return ErrNotImplemented
}

// MarkRevoked is unimplemented.
func (p *PostgresOfficerRegistry) MarkRevoked(did string) error {
	return ErrNotImplemented
}

// MarkSucceeded is unimplemented.
func (p *PostgresOfficerRegistry) MarkSucceeded(did string, successorDID string) error {
	return ErrNotImplemented
}

// List returns the empty slice (the stub holds no records).
func (p *PostgresOfficerRegistry) List() []*Officer {
	return nil
}

// ListByRole returns the empty slice.
func (p *PostgresOfficerRegistry) ListByRole(role string) []*Officer {
	return nil
}

// Static check that PostgresOfficerRegistry satisfies Registry.
var _ Registry = (*PostgresOfficerRegistry)(nil)
