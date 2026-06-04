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
	Register(Recipe{Name: "federation.soak", Tags: []string{"federation", "soak"}, Run: federationSoak})
}

// federation.soak — the FULL federated-network validation in one ordered run.
// Every touchpoint is re-derived from first principles (the publisher's claimed
// values are never trusted), producing indisputable evidence:
//
//	1/4  load N entries as a CLIENT to EACH network's OWN endpoint, drain, then
//	     re-verify the head's K-of-N MULTI-WITNESS quorum cryptographically from
//	     the genesis set, and run a light-client SMT audit + dump the evidence
//	     bundle (witnessed checkpoint + manifest + audit + full log) under the run;
//	2/4  cross-network anchoring — build a REAL CosignedAnchorV1 of each network's
//	     loaded head, verify it offline, and publish it into another network's log;
//	3/4  full INDEPENDENT re-verification of every network (checkpoint, head↔horizon,
//	     witness K-of-N vs genesis, SMT proofs, oracle, logs, auditor, aggregator);
//	4/4  post-anchor multi-witness re-verification — the anchors disturbed nothing.
//
// Scale knobs (defaults are a quick soak): E2E_FED_ENTRIES (e.g. 300000),
// E2E_FED_WORKERS, E2E_FED_BATCH_SIZE (>1 needs credits admission),
// E2E_DRAIN_TIMEOUT_MIN (raise for 300K), E2E_AUDIT_FULL=1 (audit every key),
// E2E_AUDIT_SAMPLES, E2E_AUDIT_RANDOM.
func federationSoak(s *Session) error {
	nets := s.Manifest.Networks
	if len(nets) < 2 {
		return fmt.Errorf("federation.soak requires >= 2 networks (one network = one log), have %d", len(nets))
	}
	n := intEnv("E2E_FED_ENTRIES", 2000)
	workers := intEnv("E2E_FED_WORKERS", 16)
	batch := intEnv("E2E_FED_BATCH_SIZE", 1)
	drain := time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 60)) * time.Minute
	samples := intEnv("E2E_AUDIT_SAMPLES", 64)
	random := intEnv("E2E_AUDIT_RANDOM", 16)
	auditFull := intEnv("E2E_AUDIT_FULL", 0) == 1

	fmt.Printf("== federation.soak 1/4: load %d entries/network + multi-witness verify + SMT audit ==\n", n)
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
		// Wait for the ledger to PUBLISH the cosigned HORIZON (the async second
		// write — the tile-durable, witness-cosigned checkpoint that verification
		// anchors on) at the post-load size. The head advances first and carries no
		// quorum guarantee; the horizon is the durable trust anchor.
		if !waitHorizon(t, uint64(before+n), 5*time.Minute) {
			c, _ := stack.FetchHorizon(t.CertsDir, t.LedgerPort)
			return fmt.Errorf("network %s horizon not finalized after load (got size=%d sigs=%d, want size>=%d sigs>=K=%d) — raise the wait or check witness liveness",
				nm.Name, c.TreeSize, len(c.Signatures), before+n, t.QuorumK)
		}
		// MULTI-WITNESS validation: recompute the K-of-N quorum from the genesis
		// witness set — the publisher's claimed signature count is NOT trusted.
		valid, err := validateQuorum(t)
		if err != nil {
			return fmt.Errorf("network %s quorum verify: %w", nm.Name, err)
		}
		// Light-client SMT audit of committed keys against the cosigned root + evidence.
		smp := samples
		if auditFull && len(st.Leaves) > smp {
			smp = len(st.Leaves)
		}
		out, err := stack.RunAudit(t, s.Images.Ledger, smp, random, true)
		if err != nil {
			return fmt.Errorf("network %s SMT audit: %w", nm.Name, err)
		}
		if err := stack.CaptureEvidence(s.Layout, t, out); err != nil {
			return fmt.Errorf("network %s evidence capture: %w", nm.Name, err)
		}
		sz, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
		fmt.Printf("  [PASS] %-8s load=%d (roots=%d amends=%d) size=%d | %d/%d witnesses re-verified | %d SMT proofs audited\n",
			nm.Name, n, st.Roots, st.Amendments, sz, valid, t.QuorumK, smp)
	}

	fmt.Println("== federation.soak 2/4: cross-network anchoring (real CosignedAnchorV1) ==")
	if err := federationCrossLog(s); err != nil {
		return fmt.Errorf("cross-network anchoring: %w", err)
	}

	fmt.Println("== federation.soak 3/4: full independent re-verification (all networks) ==")
	if err := verifyAll(s); err != nil {
		return fmt.Errorf("re-verification: %w", err)
	}

	fmt.Println("== federation.soak 4/4: post-anchor multi-witness re-verification ==")
	for _, nm := range nets {
		t, ok := s.Target(nm.Name)
		if !ok {
			return fmt.Errorf("no target for network %q", nm.Name)
		}
		valid, err := validateQuorum(t)
		if err != nil {
			return fmt.Errorf("network %s post-anchor quorum: %w", nm.Name, err)
		}
		fmt.Printf("  [PASS] %-8s post-anchor: %d/%d witnesses re-verified (anchors disturbed nothing)\n",
			nm.Name, valid, t.QuorumK)
	}

	fmt.Println("== federation.soak COMPLETE — every touchpoint re-derived; evidence captured under the run dir ==")
	return nil
}

// validateQuorum re-verifies a network's current head's K-of-N witness quorum
// against the genesis witness set (recomputing each cosignature — the publisher's
// claimed count is not trusted), returning the number of cryptographically-valid
// cosignatures. Fail-closed below quorum.
func validateQuorum(t stack.Target) (int, error) {
	ledger, err := caLedger(t)
	if err != nil {
		return 0, err
	}
	head, code, err := ledger.TreeHead()
	if err != nil || code != 200 {
		return 0, fmt.Errorf("head: code=%d err=%v", code, err)
	}
	boot, err := bootstrap.Load(filepath.Join(t.FixturesDir, "network-bootstrap.json"))
	if err != nil {
		return 0, fmt.Errorf("bootstrap: %w", err)
	}
	res, err := e2ecosign.Verify(boot, t.QuorumK, head)
	if err != nil {
		return 0, fmt.Errorf("cosign verify: %w", err)
	}
	if res.ValidCount < t.QuorumK {
		return res.ValidCount, fmt.Errorf("head carries %d/%d VALID witness cosignatures — below quorum", res.ValidCount, t.QuorumK)
	}
	return res.ValidCount, nil
}

// waitHorizon polls the PUBLISHED cosigned horizon (GET /v1/tree/horizon) until it
// reaches minSize with a full K-of-N DISTINCT-witness quorum, or times out.
//
// This is the system's two-step / async "second write": an entry is first
// SEQUENCED — /v1/tree/head advances (step 1) but "carries no guarantee its
// cosignatures form a quorum yet" — and only AFTER the root's SMT tiles are durable
// AND K-of-N witnesses have cosigned it does the builder REPUBLISH the head as the
// durable cosigned horizon (step 2, tessera.PublishCosignedCheckpoint). The horizon
// "advances ONLY once" finalized, so it lags the head by design. ALL verification
// (vCheckpoint, SMT proofs) anchors on the horizon — so the soak must wait for the
// HORIZON, not the head.
func waitHorizon(t stack.Target, minSize uint64, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		c, err := stack.FetchHorizon(t.CertsDir, t.LedgerPort)
		if err == nil && uint64(c.TreeSize) >= minSize &&
			len(c.Signatures) >= t.QuorumK && c.DistinctSigners() >= t.QuorumK {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Second)
	}
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
		// Drain = SEQUENCED, not finalized. Wait for the cosigned HORIZON (the async
		// second write) to republish the post-anchor head at K-of-N before declaring
		// the anchor committed — verification anchors on the horizon, not the head.
		if !waitHorizon(dst, uint64(before+1), 5*time.Minute) {
			c, _ := stack.FetchHorizon(dst.CertsDir, dst.LedgerPort)
			return fmt.Errorf("network %s horizon not finalized after anchoring %s (got size=%d sigs=%d, want size>=%d sigs>=K=%d)",
				nm.Name, srcName, c.TreeSize, len(c.Signatures), before+1, dst.QuorumK)
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
	// Build + offline-verify in ONE agnostic SDK call: the embedded head must
	// recompute a valid K-of-N quorum against the source's own witness set before
	// the anchor is publishable (fail-closed otherwise).
	entry, err := anchor.BuildVerifiedAnchorEntry(anchor.CosignedAnchorParams{
		SignerDID:    dstLogDID,
		Destination:  dstLogDID,
		SourceLogDID: src.LogDID,
		Head:         sdkHead,
		NetworkID:    nid,
		EventTime:    time.Now().Unix(),
	}, set)
	if err != nil {
		return "", 0, fmt.Errorf("build+verify anchor of source head: %w", err)
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
