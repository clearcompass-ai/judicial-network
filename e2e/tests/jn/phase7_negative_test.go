//go:build e2e

// Phase 7 — Negative / fail-closed matrix (security), SCENARIOS.md.
package jn

import (
	"errors"
	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/cosign"
	"github.com/clearcompass-ai/judicial-network/e2e/internal/types"
)

// S7.1 — Tampered head signature: a flipped sig byte must drop below quorum.
// Needs the consumer-side verifier (H5).
func TestS7_1_TamperedSigRejected(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	s.RequireBootstrap(t)
	head, code, _ := s.Ledger.TreeHead()
	if code == 404 || len(head.Signatures) == 0 {
		t.Skip("no cosigned head with signatures yet")
	}
	tampered := head
	tampered.Signatures = append([]types.WitnessSignature(nil), head.Signatures...)
	tampered.Signatures[0].SigBytes = flipHex(head.Signatures[0].SigBytes)
	res, verr := cosign.Verify(s.Boot, s.QuorumK(), tampered)
	if errors.Is(verr, cosign.ErrNotWired) {
		s.Pending(t, "H5: %v", verr)
		return
	}
	harness.Truthy(t, verr != nil || res.ValidCount < s.QuorumK(), "tampered signature still reached quorum")
}

// S7.2 — Sub-quorum head: K−1 signatures must not verify to quorum. Needs H5.
func TestS7_2_SubQuorumRejected(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	s.RequireBootstrap(t)
	head, code, _ := s.Ledger.TreeHead()
	if code == 404 || len(head.Signatures) == 0 {
		t.Skip("no cosigned head with signatures yet")
	}
	k := s.QuorumK()
	if len(head.Signatures) < k {
		t.Skip("fewer than K signatures present; cannot meaningfully drop below K")
	}
	sub := head
	sub.Signatures = head.Signatures[:k-1]
	res, verr := cosign.Verify(s.Boot, k, sub)
	if errors.Is(verr, cosign.ErrNotWired) {
		s.Pending(t, "H5: %v", verr)
		return
	}
	harness.Truthy(t, verr != nil || res.ValidCount < k, "sub-quorum head accepted")
}

// S7.3 — Unknown finding kind: the ledger gossip ingest must reject an
// unregistered kind (fail-closed), not accept it.
func TestS7_3_UnknownFindingKind(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	code, _, err := s.Ledger.PostRaw("/v1/gossip", "application/json", []byte(`{"kind":"totally-unknown-kind"}`))
	harness.Truthy(t, err == nil, "POST /v1/gossip error: "+harness.ErrStr(err))
	harness.Truthy(t, code >= 400 && code < 500, "ledger accepted an unknown-kind gossip event (status "+harness.Itoa(code)+")")
}

// S7.4 — Cross-exchange replay: a valid entry resubmitted to a different
// destination exchange must be rejected. Needs H1 (a real entry + 2nd exchange).
func TestS7_4_CrossExchangeReplay(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S7.4: resubmit a valid entry to another destination; assert rejection (needs H1)")
}

// S7.5 — Bad authority path: a submit from an undelegated caller must 403 with
// a closed-set code. Needs H1.
func TestS7_5_BadAuthorityPath(t *testing.T) {
	s := harness.NewStack(t)
	_ = s.JN(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S7.5: submit from an undelegated DID; assert 403 closed-set rejection (needs H1)")
}

// S7.6 — Witness rollback → 409: needs a valid cosign then a smaller-size
// re-cosign (SDK WireRequest builder, H5).
func TestS7_6_WitnessRollback(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireWitnesses(t)
	s.Pending(t, "S7.6 needs a valid cosign then a smaller-size re-cosign (SDK WireRequest builder, H5)")
}

// S7.7 — Auditor non-allowlisted peer → no ingest: needs a reconfigured peer.
func TestS7_7_AuditorPeerNotAllowlisted(t *testing.T) {
	s := harness.NewStack(t)
	s.Pending(t, "S7.7 needs the auditor pointed at a non-allowlisted peer (deployment variant)")
}

// S7.8 — JN request without a client cert is rejected at TLS.
func TestS7_8_JNNoClientCert(t *testing.T) {
	s := harness.NewStack(t)
	nc := s.JNNoCert(t)
	code, _, err := nc.GetRaw("/readyz")
	ok := err != nil || (code >= 400 && code < 500)
	harness.Truthy(t, ok, "JN served /readyz without a client cert (code="+harness.Itoa(code)+" err="+harness.ErrStr(err)+")")
}

// S7.9 — Sealed-artifact access without a grant is denied. Needs the JN
// artifact grant flow (H1).
func TestS7_9_SealedArtifactNoGrant(t *testing.T) {
	s := harness.NewStack(t)
	_ = s.JN(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S7.9: retrieve a sealed artifact without a grant; assert denied (needs H1 + artifact flow)")
}

// S7.10 — Escrow override unauthorized → rejected.
func TestS7_10_EscrowOverrideUnauthorized(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	code, _, err := s.Ledger.EscrowOverride([]byte("{}"))
	harness.Truthy(t, err == nil, "escrow-override error: "+harness.ErrStr(err))
	harness.Truthy(t, code >= 400 && code < 500, "ledger accepted an unauthorized escrow override (status "+harness.Itoa(code)+")")
}

// S7.11 — Rejection→HTTP-status matrix: a malformed entry deserialize-fails to
// a 4xx (not a 5xx, not accepted).
func TestS7_11_RejectionStatusMatrix(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	_, code, err := s.Ledger.SubmitEntry([]byte("not-a-canonical-entry"))
	harness.Truthy(t, err == nil, "submit error: "+harness.ErrStr(err))
	harness.StatusIn(t, code, "malformed submit (deserialize_failed → 4xx)", 400, 422)
}

// flipHex flips the first hex character so the signature no longer verifies.
func flipHex(s string) string {
	if s == "" {
		return "0"
	}
	b := []byte(s)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}
