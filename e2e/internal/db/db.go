// Package db is the integration tier's Postgres assertion seam. It queries a
// network's PG by `docker exec {container} psql` — zero new Go dependencies
// (mirrors the proven scale-suite pg_query), and no exposed-Postgres host port
// (the deployment doesn't publish PG, so neither do the tests). The container
// name comes from the run config (internal/env.Config.PGContainer — the one
// shared Postgres per run, derived from the runstore manifest).
package db

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Exec runs one SQL statement in database `db` on the named PG container and
// returns trimmed stdout. Uses psql -tAc (tuples-only, unaligned, single
// command) so the output is the bare value(s).
func Exec(container, db, sql string) (string, error) {
	if container == "" {
		return "", fmt.Errorf("db: empty PG container name")
	}
	out, err := exec.Command("docker", "exec", container,
		"psql", "-U", "baseproof", "-d", db, "-tAc", sql).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("db: psql %s/%s failed: %w: %s", container, db, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// Count returns SELECT count(*) FROM table.
func Count(container, db, table string) (int, error) {
	s, err := Exec(container, db, "SELECT count(*) FROM "+table)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("db: count(%s) returned non-numeric %q: %w", table, s, err)
	}
	return n, nil
}

// Reachable reports whether the PG container answers a trivial query — the
// integration gate (skip when no stack/DB is up).
func Reachable(container, db string) bool {
	_, err := Exec(container, db, "SELECT 1")
	return err == nil
}
