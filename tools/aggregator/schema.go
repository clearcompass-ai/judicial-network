package aggregator

import (
	_ "embed"

	common "github.com/baseproof/tooling/libs/clitools"
)

// embeddedSchema is the projection schema, embedded so the aggregator binary is
// self-migrating: it needs no sidecar to provision tables, and a rebuild
// (truncate + restart) re-applies it. Every statement is idempotent
// (CREATE TABLE/INDEX IF NOT EXISTS), so applying it at every boot is safe.
//
//go:embed schema.sql
var embeddedSchema string

// Migrate applies the embedded projection schema to db. Idempotent: safe to
// call on every boot. The projection is a rebuildable cache (Ledger Principle
// 12) — the tables here are derived from the log scan, never a source of truth.
func Migrate(db *common.DB) error {
	return RunMigrations(db, embeddedSchema)
}
