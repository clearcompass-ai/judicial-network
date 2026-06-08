package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "federation.shadow", Tags: []string{"federation", "shadow", "verify"}, Run: federationShadow})
}

// federation.shadow (Gate 3 — PG-optional + multi-network safe): on each network,
// prove the SAME committed entry against BOTH the PG-backed writer AND the
// object-store-backed PG-OFF reader — both must verify fully offline, so the
// object store is a faithful SHADOW of Postgres (PG-optional). Then assert every
// network serves a DISTINCT smt_root — no two logs collide on a shared
// object-store namespace (the multi-network-safe invariant, extending
// federation.diag's runtime clobber detection).
//
// Requires the read front (E2E_READER=1 at `up`). Cross-net distinctness is only
// meaningful on a multi-network preset (federation/mega); on `single` it is
// trivially satisfied.
func federationShadow(s *Session) error {
	ctx := context.Background()
	n := intEnv("E2E_SHADOW_ENTRIES", 8)
	byRoot := map[string][]string{} // smt_root → networks serving it (collision ⇒ clobber)

	if err := forEachNetwork(s, func(name string, t stack.Target) error {
		if t.ReaderPort == 0 {
			return fmt.Errorf("%s: no read front — bring the stack up with E2E_READER=1", name)
		}

		// Workload → committed + shipped to the object store.
		before, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
		st, err := stack.Backfill(t, s.Images.Ledger, n, intEnv("E2E_BACKFILL_WORKERS", 8), 0.0, intEnv("E2E_BACKFILL_BATCH", 1))
		if err != nil {
			return fmt.Errorf("%s: backfill: %w", name, err)
		}
		if !stack.WaitDrained(t.CertsDir, t.LedgerPort, before+st.Roots,
			time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 15))*time.Minute) {
			return fmt.Errorf("%s: backfill did not drain", name)
		}
		if len(st.Leaves) == 0 {
			return fmt.Errorf("%s: backfill produced no leaves", name)
		}
		key := st.Leaves[0].Key

		// PG-optional: the SAME entry proves against the PG-backed writer AND the
		// PG-off, object-store-backed reader — both verify offline ⇒ the object
		// store faithfully shadows the Postgres projection.
		if err := proveEntry(ctx, name+"/writer(pg)", t, key); err != nil {
			return fmt.Errorf("%s: writer (PG) proof: %w", name, err)
		}
		reader := t
		reader.LedgerPort = t.ReaderPort
		if err := proveEntry(ctx, name+"/reader(pg-off)", reader, key); err != nil {
			return fmt.Errorf("%s: reader (object-store, PG-off) proof: %w", name, err)
		}

		// Record the served smt_root for the cross-net distinctness check.
		hz, err := stack.FetchHorizon(t.CertsDir, t.LedgerPort)
		if err != nil {
			return fmt.Errorf("%s: fetch horizon: %w", name, err)
		}
		if hz.SMTRoot == "" {
			return fmt.Errorf("%s: cosigned horizon has no smt_root", name)
		}
		byRoot[hz.SMTRoot] = append(byRoot[hz.SMTRoot], name)
		fmt.Printf("  [PASS] %-8s shadow: entry proves identically PG-backed (writer) and PG-off (reader); smt_root %s…\n",
			name, hz.SMTRoot[:16])
		return nil
	}); err != nil {
		return err
	}

	// Multi-network safe: no two networks may serve the SAME smt_root — that would
	// mean their logs share an object-store namespace (the clobber class).
	for root, nets := range byRoot {
		if len(nets) > 1 {
			return fmt.Errorf("multi-network UNSAFE: networks %v serve the SAME smt_root %s — shared-namespace clobber", nets, root)
		}
	}
	fmt.Printf("  [PASS] multi-network safe: %d network(s) each serve a DISTINCT smt_root (no cross-net clobber)\n", len(byRoot))
	return nil
}
