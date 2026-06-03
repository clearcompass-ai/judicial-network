//go:build e2e

// Phase 6 — Cross-component flows (T1–T9), SCENARIOS.md.
package jn

import (
	"errors"
	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/cosign"
	"github.com/clearcompass-ai/judicial-network/e2e/internal/httpx"
)

// S6.1 — T1 witness→ledger: the cosigned head verifies under the real genesis
// witness keys (consumer-side crypto, not trusting the JSON). Needs H5.
func TestS6_1_CosignedHeadVerifies(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	s.RequireBootstrap(t)
	head, code, err := s.Ledger.TreeHead()
	if code == 404 {
		t.Skip("no cosigned head yet (empty log)")
	}
	harness.Truthy(t, err == nil, "tree head error: "+harness.ErrStr(err))
	res, verr := cosign.Verify(s.Boot, s.QuorumK(), head)
	if errors.Is(verr, cosign.ErrNotWired) {
		s.Pending(t, "H5: %v", verr)
		return
	}
	harness.Truthy(t, verr == nil, "cosign verify error: "+harness.ErrStr(verr))
	harness.Truthy(t, res.ValidCount >= s.QuorumK(), "valid cosignatures below quorum K")
}

// S6.2 — T5 JN→ledger: build→sign→submit through the enforcer, then assert the
// entry is sequenced + cosigned. Needs H1 (distinct logs + delegated signer).
func TestS6_2_JNSubmitSequenced(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	_ = s.JN(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S6.2: JN build→sign→submit then assert sequenced + cosigned (needs H1)")
}

// S6.3 — T2 ledger→auditor: the auditor pulls + re-verifies + serves the
// ledger's heads; its feed comes to reference the ledger's DID.
func TestS6_3_LedgerToAuditor(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	s.RequireAuditor(t)
	s.RequireBootstrap(t)
	did := s.Boot.ExchangeDID
	ok := httpx.Poll(30*time.Second, 2*time.Second, func() (bool, error) {
		code, body, err := s.Auditor.GossipSince("0", 100)
		if err != nil || code != 200 {
			return false, err
		}
		return harness.Contains(body, did), nil
	})
	s.Gate(t, ok, "auditor /v1/gossip/since never reflected ledger DID %s within timeout (T2 propagation)", did)
}

// S6.4 — T3 auditor→JN: the JN's verify-only trusted head advances and
// references the ledger DID (the JN re-verified a CosignedTreeHead pulled from
// the auditor). Needs the peer-consistency endpoint (H3).
func TestS6_4_AuditorToJN(t *testing.T) {
	s := harness.NewStack(t)
	jn := s.JN(t)
	s.RequireBootstrap(t)
	// 404 ⇒ the deployed JN image predates the H3 endpoint; gate.
	if code, _, err := jn.PeerConsistency(); err == nil && code == 404 {
		s.Pending(t, "H3: JN peer-consistency endpoint not present (404) — rebuild the JN image from the H3 branch")
		return
	}
	did := s.Boot.ExchangeDID
	ok := httpx.Poll(30*time.Second, 2*time.Second, func() (bool, error) {
		code, body, err := jn.PeerConsistency()
		if err != nil || code != 200 {
			return false, err
		}
		return harness.Contains(body, did), nil
	})
	s.Gate(t, ok, "JN peer-consistency never reflected ledger DID %s within timeout (T3: auditor→JN trusted-head advance)", did)
}

// S6.5 — T4 ledger→aggregator: a submitted case is projected and a rebuild
// reproduces it. Needs H1 + aggregator DB access (see S4.5).
func TestS6_5_LedgerToAggregator(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireAggregator(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S6.5: case projected + rebuild reproduces (see S4.5; needs H1 + aggregator DB access)")
}

// S6.6 — T6 cross-log/federation: court A anchors court B; the anchor
// quorum-verifies under B's witness set + inclusion holds. Needs H2 + H5.
func TestS6_6_CrossLogAnchor(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireSecondCourt(t)
	if !cosign.Wired() {
		s.Pending(t, "H5: cross-log anchor verification needs the SDK cosign verifier")
		return
	}
	s.Pending(t, "S6.6: produce an anchor of court B on court A, then anchor.Verify(setB)+VerifyInclusion (needs H2 + H5)")
}

// S6.7 — T7 equivocation, DEPLOYED chain: inject a fork into a RUNNING auditor →
// auditor scanner emits an Equivocation finding → slasher re-verifies → JN fails
// closed. The SDK-tier chain (detect → finding → position-aware → burn-gate) is
// already CAPTURED, infra-free, in S6.16–S6.18 + S5.17 via the H4 fork fixture
// (../equivocation); this scenario is only the live-injection piece, gated on
// E2E_FORK_ENABLE + an auditor ingest path.
func TestS6_7_Equivocation(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireForkFixture(t)
	s.Pending(t, "S6.7 (deployed): inject the H4 fork into the running auditor; assert it emits Equivocation + slasher re-verifies (no false slash) + JN fails closed. SDK chain captured in S6.16–S6.18/S5.17.")
}

// S6.8 — T8 shared trust root: identical to S0.2.
func TestS6_8_SharedTrustRoot(t *testing.T) {
	t.Skip("same assertion as S0.2 (TestS0_2_SharedTrustRoot)")
}

// S6.9 — T9 rotation: a witness-set rotation propagates ledger→auditor→JN,
// verify-before-swap, quorum inherited. Needs H2 + H3.
func TestS6_9_WitnessRotation(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireSecondCourt(t)
	s.Pending(t, "S6.9: rotate a witness set; assert verify-before-swap + quorum inheritance across ledger→auditor→JN (needs H2 + H3)")
}
