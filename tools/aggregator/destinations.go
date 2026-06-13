/*
tools/aggregator/destinations.go — the rc10 destinations directory: a
REBUILDABLE PROJECTION of the on-log platform kinds, with W2's authority
re-judging at replay.

# THE W2 CONTRACT, IMPLEMENTED

Under open admission a well-formed entry that never passed its policy gate
can sequence. Rebuild-determinism alone is NOT authority: this projector
re-judges EVERY destination entry's embedded cosignature mix — by running
THE SAME GATE the submit door runs (handlers.SubmitGater over the
jurisdiction Bundle policies) — before any directory mutation. A
mix-violating record increments a NAMED refusal counter and the directory
does not move. Both the live scan and a drop-and-rebuild replay the same
judge, so they are wrong or right TOGETHER, never apart.

# LIFECYCLE = THE SDK WALK, APPLIED INCREMENTALLY

ApplyProvision/ApplyAmend/ApplyRetire mirror the SDK's never-folded
refusal taxonomy (exchange.ResolveDestinationAt): duplicate-provision,
amend/retire-without-provision, amend-after-retire, foreign-exchange —
each a distinct refusal code, counted, never applied. A refused record is
log pollution wearing valid syntax; the projection records that it saw it
and stays unmoved.

# INERT-BY-ABSENCE (delegation/credential kinds)

DELEGATION-GRANT and CREDENTIAL-ATTESTATION entries project NOTHING here:
their consumers are the PRE-13b/13e waves, and a kind with no consumer
cannot fire (the wave doctrine — inert-by-absence is safe; wired-but-
dormant is not). The rogue-grant lock test pins exactly this: a grant
mutates no view.
*/
package aggregator

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/baseproof/baseproof/exchange"
	"github.com/baseproof/baseproof/kinds"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// Refusal codes — the named counter dimensions. Closed set; tests pin them.
const (
	RefusalGateRejected           = "destination_gate_rejected" // W2: mix re-judging failed
	RefusalGateUnwired            = "destination_gate_unwired"  // fail-closed: no judge, no mutation
	RefusalMalformed              = "destination_malformed"
	RefusalDuplicateProvision     = "destination_duplicate_provision"
	RefusalAmendWithoutProvision  = "destination_amend_without_provision"
	RefusalRetireWithoutProvision = "destination_retire_without_provision"
	RefusalAmendAfterRetire       = "destination_amend_after_retire"
	RefusalForeignExchange        = "destination_foreign_exchange"
)

// RefusalCounter is the in-memory named-refusal surface (exported via the
// aggregator's metrics endpoint; asserted directly by the lock tests).
// Concurrency-safe.
type RefusalCounter struct {
	mu sync.Mutex
	m  map[string]int
}

func NewRefusalCounter() *RefusalCounter { return &RefusalCounter{m: map[string]int{}} }

func (c *RefusalCounter) Inc(code string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[code]++
}

// Count returns the current count for a refusal code.
func (c *RefusalCounter) Count(code string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[code]
}

// Snapshot returns a copy of all counters (metrics rendering).
func (c *RefusalCounter) Snapshot() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int, len(c.m))
	for k, v := range c.m {
		out[k] = v
	}
	return out
}

// DestinationStore is the directory mutation seam — *Indexer implements it
// against Postgres; lock tests use a recording fake. Each Apply returns a
// refusal code ("" = applied) so the projector owns the counting and the
// store owns the state machine.
type DestinationStore interface {
	ApplyProvision(ctx context.Context, p exchange.DestinationProvision, logDID string, seq uint64) (refusal string, err error)
	ApplyAmend(ctx context.Context, a exchange.DestinationAmend, logDID string, seq uint64) (refusal string, err error)
	ApplyRetire(ctx context.Context, r exchange.DestinationRetire, logDID string, seq uint64) (refusal string, err error)
}

// ─── the SQL store (on *Indexer; same DB as every other projection) ────

func endpointsToText(eps map[string]string) string {
	// Deterministic k=v;k=v rendering (sorted) — rebuilds must be
	// byte-identical.
	keys := make([]string, 0, len(eps))
	for k := range eps {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(';')
		}
		fmt.Fprintf(&b, "%s=%s", k, eps[k])
	}
	return b.String()
}

func (idx *Indexer) ApplyProvision(ctx context.Context, p exchange.DestinationProvision, logDID string, seq uint64) (string, error) {
	var status string
	err := idx.db.QueryRowContext(ctx,
		`SELECT status FROM destinations WHERE destination_ref = $1`, p.DestinationRef).Scan(&status)
	switch {
	case err == nil:
		return RefusalDuplicateProvision, nil // active OR retired: a second provision is refused
	case !errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("destinations lookup: %w", err)
	}
	_, err = idx.db.ExecContext(ctx,
		`INSERT INTO destinations (destination_ref, exchange_did, endpoints, status, log_did, provisioned_at, updated_at)
		 VALUES ($1, $2, $3, 'active', $4, $5, $5)`,
		p.DestinationRef, p.ExchangeDID, endpointsToText(p.Endpoints), logDID, int64(seq))
	if err != nil {
		return "", fmt.Errorf("destinations insert: %w", err)
	}
	return "", nil
}

func (idx *Indexer) ApplyAmend(ctx context.Context, a exchange.DestinationAmend, logDID string, seq uint64) (string, error) {
	var status, exchangeDID string
	err := idx.db.QueryRowContext(ctx,
		`SELECT status, exchange_did FROM destinations WHERE destination_ref = $1`, a.DestinationRef).Scan(&status, &exchangeDID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return RefusalAmendWithoutProvision, nil
	case err != nil:
		return "", fmt.Errorf("destinations lookup: %w", err)
	case exchangeDID != a.ExchangeDID:
		return RefusalForeignExchange, nil
	case status == "retired":
		return RefusalAmendAfterRetire, nil
	}
	_, err = idx.db.ExecContext(ctx,
		`UPDATE destinations SET endpoints = $2, updated_at = $3 WHERE destination_ref = $1`,
		a.DestinationRef, endpointsToText(a.Endpoints), int64(seq))
	if err != nil {
		return "", fmt.Errorf("destinations amend: %w", err)
	}
	return "", nil
}

func (idx *Indexer) ApplyRetire(ctx context.Context, r exchange.DestinationRetire, logDID string, seq uint64) (string, error) {
	var status, exchangeDID string
	err := idx.db.QueryRowContext(ctx,
		`SELECT status, exchange_did FROM destinations WHERE destination_ref = $1`, r.DestinationRef).Scan(&status, &exchangeDID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return RefusalRetireWithoutProvision, nil
	case err != nil:
		return "", fmt.Errorf("destinations lookup: %w", err)
	case exchangeDID != r.ExchangeDID:
		return RefusalForeignExchange, nil
	case status == "retired":
		return RefusalAmendAfterRetire, nil // idempotent-retire is still pollution: count it
	}
	_, err = idx.db.ExecContext(ctx,
		`UPDATE destinations SET status = 'retired', updated_at = $2 WHERE destination_ref = $1`,
		r.DestinationRef, int64(seq))
	if err != nil {
		return "", fmt.Errorf("destinations retire: %w", err)
	}
	return "", nil
}

// ─── the read side (GET /v1/judicial/destinations) ─────────────────────

// DestinationRow is one directory entry as served.
type DestinationRow struct {
	DestinationRef string `json:"destination_ref"`
	ExchangeDID    string `json:"exchange_did"`
	Endpoints      string `json:"endpoints"`
	Status         string `json:"status"`
	UpdatedAt      int64  `json:"updated_at"` // log sequence of last mutation
}

// QueryDestinations serves the directory with state/county/type filters
// (the destination_ref convention "state/county/type-N"), keyset
// pagination by destination_ref, and the max log position for ETag use.
func QueryDestinations(ctx context.Context, db *common.DB, state, county, typ, afterRef string, limit int) ([]DestinationRow, int64, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	prefix := ""
	if state != "" {
		prefix = state + "/"
		if county != "" {
			prefix += county + "/"
			if typ != "" {
				prefix += typ
			}
		}
	}
	rows, err := db.QueryContext(ctx,
		`SELECT destination_ref, exchange_did, endpoints, status, updated_at
		   FROM destinations
		  WHERE destination_ref LIKE $1 || '%' AND destination_ref > $2
		  ORDER BY destination_ref LIMIT $3`,
		prefix, afterRef, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []DestinationRow
	for rows.Next() {
		var r DestinationRow
		if err := rows.Scan(&r.DestinationRef, &r.ExchangeDID, &r.Endpoints, &r.Status, &r.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var maxPos sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(updated_at) FROM destinations`).Scan(&maxPos); err != nil {
		return nil, 0, err
	}
	return out, maxPos.Int64, nil
}

// ─── kind probing ───────────────────────────────────────────────────────

// platformKind extracts the rc10 kind discriminator from a classified
// entry's payload ("" when absent or not a string).
func platformKind(c *ClassifiedEntry) string {
	k, _ := c.Payload["kind"].(string)
	return k
}

// isPlatformRegistryKind reports whether k is one of the rc10 registry
// kinds this aggregator recognizes (destination lifecycle + the
// deliberately-inert delegation/credential/burn/genesis kinds).
func isPlatformRegistryKind(k string) bool {
	switch k {
	case kinds.EntryExchangeGenesisV1,
		kinds.EntryDestinationProvisionV1,
		kinds.EntryDestinationAmendV1,
		kinds.EntryDestinationRetireV1,
		kinds.EntryDelegationGrantV1,
		kinds.EntryCredentialAttestationV1,
		kinds.EntryNetworkBurnV1:
		return true
	}
	return false
}
