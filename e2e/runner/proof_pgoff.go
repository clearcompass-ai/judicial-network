package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "federation.proof.pgoff", Tags: []string{"proof", "pgoff", "verify"}, Run: federationProofPgOff})
}

// federation.proof.pgoff: prove a committed entry against the PG-OFF read front — the
// ledger-reader (Phase 1, 1.3) booted with Postgres unreachable, serving horizon /
// inclusion / SMT / entry / receipt proofs reconstructed from the OBJECT-STORE
// archives (1.1a checkpoint, 1.2a receipt, 1.2b rotation) alone. The proof must
// verify FULLY OFFLINE, identical to the PG-backed path — the cold-read contract:
// the read front needs no database.
//
// The PG-off reader is brought up by the stack (same image's /ledger-reader
// entrypoint, same object store, PG pointed at a dead host) and its port exported as
// E2E_READER_PORT. Until that reader-launch lands this arm SKIPS (no-op, not a
// failure) so it can be merged ahead of the stack wiring.
func federationProofPgOff(s *Session) error {
	t, ok := s.Target("")
	if !ok {
		return fmt.Errorf("no network in the persisted manifest")
	}
	// The stack launches the read front when brought up with E2E_READER=1 — its
	// host port lands in the persisted manifest (t.ReaderPort). E2E_READER_PORT
	// remains a manual override for a reader started out-of-band.
	readerPort := t.ReaderPort
	if override := intEnv("E2E_READER_PORT", 0); override != 0 {
		readerPort = override
	}
	if readerPort == 0 {
		fmt.Println("== federation.proof.pgoff SKIPPED: bring the stack up with E2E_READER=1 (or set E2E_READER_PORT) to launch the PG-off read front ==")
		return nil
	}
	ctx := context.Background()

	// 1. A workload on the WRITER ledger so the archives exist in the shared object
	//    store the reader serves from.
	n := intEnv("E2E_PROOF_ENTRIES", 16)
	st, err := stack.Backfill(t, s.Images.Ledger, n, 8, 0.0, 1)
	if err != nil {
		return fmt.Errorf("backfill: %w", err)
	}
	if len(st.Leaves) == 0 {
		return fmt.Errorf("backfill produced no leaves")
	}
	if !stack.WaitDrained(t.CertsDir, t.LedgerPort, st.Roots+1, // +1 genesis seed
		time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 15))*time.Minute) {
		return fmt.Errorf("writer did not drain the backfill (raise E2E_DRAIN_TIMEOUT_MIN)")
	}

	// 2. Prove a committed entry against the PG-OFF READER (not the writer): the
	//    reader resolves the horizon + builds inclusion / SMT / receipt proofs from
	//    the object store with no Postgres. Same offline verify + tamper matrix.
	reader := t
	reader.LedgerPort = readerPort
	if err := proveEntry(ctx, t.Network+"/pgoff", reader, st.Leaves[0].Key); err != nil {
		return fmt.Errorf("PG-off proof: %w", err)
	}
	fmt.Printf("  [PASS] entry proven + verified OFFLINE against the PG-OFF read front (:%d)\n", readerPort)
	return nil
}
