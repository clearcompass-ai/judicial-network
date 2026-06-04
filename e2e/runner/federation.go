package runner

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/baseproof/baseproof/anchor"
	sdkcosign "github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/witness"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/bootstrap"
	"github.com/clearcompass-ai/judicial-network/e2e/internal/clients"
	e2ecosign "github.com/clearcompass-ai/judicial-network/e2e/internal/cosign"
	"github.com/clearcompass-ai/judicial-network/e2e/internal/httpx"
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

// federation.crosslog — create cross-network ANCHORS the ONLY valid way: each
// network's OWN client publishes, to its OWN log, a REAL CosignedAnchorV1 that
// commits another network's witness-cosigned head. You never write to a foreign
// network; the cross-network relationship lives entirely as a structured,
// cryptographically-verifiable anchor inside an own-log entry.
//
// For each ordered pair (destination ← source): fetch the SOURCE network's live
// head, build the CosignedAnchorV1 of it, VERIFY it offline against the source's
// own witness set (anchor.VerifyCosignedAnchor — the head recomputes a valid
// K-of-N quorum), then publish that verified anchor into the DESTINATION's own
// log and confirm it committed. The published payload is the structured anchor
// any verifier can re-check end-to-end — not an opaque reference string.
func federationCrossLog(s *Session) error {
	nets := s.Manifest.Networks
	if len(nets) < 2 {
		return fmt.Errorf("cross-log requires >= 2 networks (one network = one log), have %d", len(nets))
	}
	targets := make([]stack.Target, len(nets))
	for i, nm := range nets {
		t, ok := s.Target(nm.Name)
		if !ok {
			return fmt.Errorf("no target for network %q", nm.Name)
		}
		targets[i] = t
	}

	for i, nm := range nets {
		dst := targets[i]
		srcIdx := (i + 1) % len(nets)
		src, srcName := targets[srcIdx], nets[srcIdx].Name

		// Build + verify the SOURCE network's CosignedAnchorV1 (its live head,
		// proven K-of-N under its own witness set).
		payload, srcSize, err := buildVerifiedAnchor(src, dst.LogDID)
		if err != nil {
			return fmt.Errorf("network %s building verified anchor of %s: %w", nm.Name, srcName, err)
		}

		// Publish the structured anchor into the DESTINATION's OWN log.
		before, _ := stack.HeadStatus(dst.CertsDir, dst.LedgerPort)
		if err := stack.SubmitStamp(dst, s.Images.Ledger, payload); err != nil {
			return fmt.Errorf("network %s publishing CosignedAnchorV1 of %s: %w", nm.Name, srcName, err)
		}
		if !stack.WaitDrained(dst.CertsDir, dst.LedgerPort, before+1, 60*time.Second) {
			sz, _ := stack.HeadStatus(dst.CertsDir, dst.LedgerPort)
			return fmt.Errorf("network %s did not commit the anchor of %s (size stuck at %d, want >=%d)",
				nm.Name, srcName, sz, before+1)
		}
		fmt.Printf("  [PASS] %-8s published a VERIFIED CosignedAnchorV1 of %-8s head (size=%d) into its OWN log\n",
			nm.Name, srcName, srcSize)
	}
	return nil
}

// buildVerifiedAnchor fetches src's live cosigned head, builds the CosignedAnchorV1
// of it (to be published on dstLogDID's own log), verifies it offline against src's
// own witness set, and returns the structured anchor payload + the source tree size.
func buildVerifiedAnchor(src stack.Target, dstLogDID string) (string, uint64, error) {
	ledger, err := caLedger(src)
	if err != nil {
		return "", 0, fmt.Errorf("source ledger client: %w", err)
	}
	head, code, err := ledger.TreeHead()
	if err != nil || code != 200 {
		return "", 0, fmt.Errorf("source /v1/tree/head: code=%d err=%v", code, err)
	}
	sdkHead, err := e2ecosign.ToSDKHead(head)
	if err != nil {
		return "", 0, fmt.Errorf("map source head to SDK head: %w", err)
	}
	set, nid, err := witnessSet(src)
	if err != nil {
		return "", 0, fmt.Errorf("source witness set: %w", err)
	}
	entry, err := anchor.BuildCosignedAnchorEntry(anchor.CosignedAnchorParams{
		SignerDID:    dstLogDID,
		Destination:  dstLogDID,
		SourceLogDID: src.LogDID,
		Head:         sdkHead,
		NetworkID:    nid,
		EventTime:    time.Now().Unix(),
	})
	if err != nil {
		return "", 0, fmt.Errorf("build anchor entry: %w", err)
	}
	// Offline cryptographic verification before publishing: the embedded head
	// recomputes a valid K-of-N quorum against the source's own witness set.
	if _, err := anchor.VerifyCosignedAnchor(entry.DomainPayload, set); err != nil {
		return "", 0, fmt.Errorf("anchor of source head fails verification (not K-of-N): %w", err)
	}
	return string(entry.DomainPayload), head.TreeSize, nil
}

// caLedger builds a CA-pinned (open-HTTPS, server-verify) ledger client for a
// network's host port — the recipe-side analog of the harness ledger client.
func caLedger(t stack.Target) (*clients.Ledger, error) {
	base := fmt.Sprintf("https://localhost:%d", t.LedgerPort)
	c, err := httpx.NewServerTrust(base, filepath.Join(t.CertsDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	return &clients.Ledger{Client: c}, nil
}

// witnessSet builds a network's K-of-N witness key set from its genesis bootstrap
// (the same construction the cosign verifier uses), returning the set + NetworkID.
func witnessSet(t stack.Target) (*sdkcosign.WitnessKeySet, sdkcosign.NetworkID, error) {
	boot, err := bootstrap.Load(filepath.Join(t.FixturesDir, "network-bootstrap.json"))
	if err != nil {
		return nil, sdkcosign.NetworkID{}, fmt.Errorf("load bootstrap: %w", err)
	}
	keys, err := witness.KeysFromDIDs(boot.GenesisWitnessSet)
	if err != nil {
		return nil, sdkcosign.NetworkID{}, fmt.Errorf("witness keys from genesis DIDs: %w", err)
	}
	nid := sdkcosign.NetworkID(boot.NetworkID)
	set, err := sdkcosign.NewWitnessKeySet(keys, nid, t.QuorumK, nil)
	if err != nil {
		return nil, sdkcosign.NetworkID{}, fmt.Errorf("build witness key set: %w", err)
	}
	return set, nid, nil
}
