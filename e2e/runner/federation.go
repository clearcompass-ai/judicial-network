package runner

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "federation.load", Tags: []string{"federation", "load"}, Run: federationLoad})
	Register(Recipe{Name: "federation.crosslog", Tags: []string{"federation", "crosslog"}, Run: federationCrossLog})
}

// federation.load — submit a CLIENT workload to EACH network's OWN endpoint and
// confirm every network advances and stays witness-cosigned. The multi-network
// analog of audit.tiles: each network's own ledger admits its own entries via its
// own admission path (credits/PoW); we never write to a foreign network. Raise
// E2E_FED_ENTRIES (e.g. 300000) for the soak.
func federationLoad(s *Session) error {
	nets := s.Manifest.Networks
	if len(nets) == 0 {
		return fmt.Errorf("no networks in the persisted manifest")
	}
	n := intEnv("E2E_FED_ENTRIES", 64)
	workers := intEnv("E2E_FED_WORKERS", 8)
	batch := intEnv("E2E_FED_BATCH_SIZE", 1)
	drain := time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 30)) * time.Minute

	for _, nm := range nets {
		t, ok := s.Target(nm.Name)
		if !ok {
			return fmt.Errorf("no target for network %q", nm.Name)
		}
		before, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
		st, err := stack.Backfill(t, s.Images.Ledger, n, workers, 0.5, batch)
		if err != nil {
			return fmt.Errorf("network %s backfill: %w", nm.Name, err)
		}
		if !stack.WaitDrained(t.CertsDir, t.LedgerPort, before+n, drain) {
			sz, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
			return fmt.Errorf("network %s: builder did not drain to >=%d in %s (stuck at %d) — raise E2E_DRAIN_TIMEOUT_MIN",
				nm.Name, before+n, drain, sz)
		}
		sz, sigs := stack.HeadStatus(t.CertsDir, t.LedgerPort)
		if sigs < t.QuorumK {
			return fmt.Errorf("network %s head below quorum after load (sigs=%d, K=%d)", nm.Name, sigs, t.QuorumK)
		}
		fmt.Printf("  [PASS] %-8s submitted %d as client (roots=%d amends=%d) → size=%d sigs=%d (K=%d)\n",
			nm.Name, n, st.Roots, st.Amendments, sz, sigs, t.QuorumK)
	}
	return nil
}

// federation.crosslog — create cross-network ANCHOR references the ONLY valid
// way: each network's OWN client submits, to its OWN endpoint, a log entry that
// REFERENCES another network's current witness-cosigned head. You never write to a
// foreign network; the cross-network relationship lives entirely as a reference
// inside an own-log entry. We then confirm the reference committed on the
// destination's own log AND that the source head it names is independently
// K-of-N cosigned (so the reference points at a real, quorum-finalized head).
func federationCrossLog(s *Session) error {
	nets := s.Manifest.Networks
	if len(nets) < 2 {
		return fmt.Errorf("cross-log requires >= 2 networks (one network = one log), have %d", len(nets))
	}

	// Resolve each network's target + its live, quorum-cosigned head.
	targets := make([]stack.Target, len(nets))
	heads := make([]stack.Checkpoint, len(nets))
	names := make([]string, len(nets))
	for i, nm := range nets {
		t, ok := s.Target(nm.Name)
		if !ok {
			return fmt.Errorf("no target for network %q", nm.Name)
		}
		h, err := stack.FetchHead(t.CertsDir, t.LedgerPort)
		if err != nil {
			return fmt.Errorf("network %s head: %w", nm.Name, err)
		}
		if len(h.Signatures) < t.QuorumK {
			return fmt.Errorf("network %s head below quorum (sigs=%d, K=%d) — cannot anchor an unfinalized head",
				nm.Name, len(h.Signatures), t.QuorumK)
		}
		targets[i], heads[i], names[i] = t, h, nm.Name
	}

	// Each adjacent pair (i ← i+1, wrapping): the DESTINATION network's own client
	// anchors a reference to the SOURCE network's head into its OWN log.
	for i := range nets {
		dst := targets[i]
		srcIdx := (i + 1) % len(nets)
		src, srcHead, srcName := targets[srcIdx], heads[srcIdx], names[srcIdx]

		before, _ := stack.HeadStatus(dst.CertsDir, dst.LedgerPort)
		// The reference: a cross-log pointer to the source network's head, carried
		// in a commentary entry on the DESTINATION's own log.
		payload := fmt.Sprintf("xlog-ref:src=%s,size=%d,root=%s", src.LogDID, srcHead.TreeSize, srcHead.RootHash)
		if err := stack.SubmitStamp(dst, s.Images.Ledger, payload); err != nil {
			return fmt.Errorf("network %s anchoring ref to %s: %w", names[i], srcName, err)
		}
		if !stack.WaitDrained(dst.CertsDir, dst.LedgerPort, before+1, 60*time.Second) {
			sz, _ := stack.HeadStatus(dst.CertsDir, dst.LedgerPort)
			return fmt.Errorf("network %s did not commit the cross-ref to %s (size stuck at %d, want >=%d)",
				names[i], srcName, sz, before+1)
		}
		fmt.Printf("  [PASS] %-8s anchored a ref to %-8s head (size=%d, K-cosigned) in its OWN log\n",
			names[i], srcName, srcHead.TreeSize)
	}
	return nil
}
