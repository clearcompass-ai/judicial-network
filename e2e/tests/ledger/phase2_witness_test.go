//go:build e2e

// Phase 2 — Witness wire contract (L8), SCENARIOS.md.
package ledger

import (
	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/bootstrap"
)

// S2.1 — Cosign purpose allowlist + network binding: a malformed cosign
// request is rejected (4xx). The positive path (valid purpose/network) is
// covered cryptographically by S6.1; a valid WireRequest needs the SDK builder
// (H5).
func TestS2_1_CosignRejectsMalformed(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireWitnesses(t)
	code, _, err := s.Witnesses[0].Cosign([]byte(`{"not":"a-cosign-request"}`))
	harness.Truthy(t, err == nil, "cosign POST error: "+harness.ErrStr(err))
	harness.Truthy(t, code >= 400 && code < 500, "witness accepted a malformed cosign request (status "+harness.Itoa(code)+")")
}

// S2.2 — Monotonicity guard (409 on tree_size rollback): needs a valid cosign
// followed by a smaller-size re-cosign — both require the SDK WireRequest
// builder (H5).
func TestS2_2_MonotonicityGuard(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireWitnesses(t)
	s.Pending(t, "S2.2 needs a valid cosign then a smaller-size re-cosign (SDK WireRequest builder, H5) to trip the 409 guard")
}

// S2.3 — secp256k1 did:key identity: every genesis witness DID is secp256k1
// and the fleet is live (a witness exposes no pubkey endpoint to cross-check).
func TestS2_3_Secp256k1Identity(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireWitnesses(t)
	s.RequireBootstrap(t)
	for _, did := range s.Boot.GenesisWitnessSet {
		harness.Truthy(t, bootstrap.IsSecp256k1(did), "non-secp256k1 genesis DID: "+did)
	}
	for i, w := range s.Witnesses {
		code, _, _ := w.Health()
		harness.Eq(t, code, 200, "witness["+harness.Itoa(i)+"] /healthz status")
	}
}

// S2.4 — Rate-limit + body cap: an oversized cosign body is rejected.
func TestS2_4_BodyCap(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireWitnesses(t)
	big := make([]byte, 4<<20) // 4 MiB
	for i := range big {
		big[i] = 'A'
	}
	code, _, err := s.Witnesses[0].Cosign(big)
	harness.Truthy(t, err == nil, "cosign POST error: "+harness.ErrStr(err))
	harness.Truthy(t, code >= 400 && code < 500, "witness accepted an oversized body (status "+harness.Itoa(code)+")")
}

// S2.5 — Health / metrics.
func TestS2_5_HealthMetrics(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireWitnesses(t)
	w := s.Witnesses[0]
	code, body, _ := w.Health()
	harness.Eq(t, code, 200, "witness /healthz status")
	harness.Eq(t, body, "ok", "witness /healthz body")
	mc, _ := w.Metrics()
	harness.StatusIn(t, mc, "witness /metrics status", 200)
}

// S2.6 — Live BLS-witness cosignature on the head. Every cosignature the ledger
// serves on /v1/tree/head must carry a scheme_tag the SDK verify-dispatch
// handles: ECDSA=1 or BLS=2; an unknown tag is a real wire-contract break. When
// a BLS (2) cosignature is present, the live BLS path is end-to-end exercised:
// the witness BLS-signed (gen-fixtures --scheme=bls + witness -cosign-scheme=bls)
// AND the ledger quorum verified it (NewProductionBLSVerifier, PoP-checked) and
// served it on a cosigned head. The JN-cross-log-verifies-this-head leg rides
// S5.16 (/v1/verify/authority pins + verifies the latest head against the
// witness set, BLS verifier included). On the ECDSA-only baseline this pends
// until a BLS witness is provisioned.
func TestS2_6_BLSWitnessCosignScheme(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)

	head, code, err := s.Ledger.TreeHead()
	harness.Truthy(t, err == nil, "/v1/tree/head error: "+harness.ErrStr(err))
	if code == 404 {
		t.Skip("/v1/tree/head 404 — no cosigned head yet (empty log)")
	}
	harness.Eq(t, code, 200, "/v1/tree/head status")
	harness.Truthy(t, len(head.Signatures) > 0, "cosigned head carries no cosignatures")

	blsCount := 0
	for i, sig := range head.Signatures {
		harness.Truthy(t, sig.SchemeTag == 1 || sig.SchemeTag == 2,
			"signatures["+harness.Itoa(i)+"].scheme_tag is neither ECDSA(1) nor BLS(2): "+harness.Itoa(int(sig.SchemeTag)))
		if sig.SchemeTag == 2 {
			blsCount++
		}
	}
	if blsCount == 0 {
		s.Pending(t, "S2.6: head carries only ECDSA(1) cosignatures — the stack provisioned ECDSA witnesses; bring up a BLS witness (gen-fixtures --scheme=bls + witness -cosign-scheme=bls, with the genesis policy admitting cosign 0x02) to exercise the live BLS quorum path")
		return
	}
	t.Logf("S2.6: %d BLS (scheme_tag=2) cosignature(s) on the head — live BLS witness→ledger-quorum path verified", blsCount)
}
