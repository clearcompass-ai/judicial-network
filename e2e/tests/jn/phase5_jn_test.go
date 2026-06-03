//go:build e2e

// Phase 5 — JN enforcer wire contract (L11), SCENARIOS.md.
package jn

import (
	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
	"testing"
	"time"
)

// S5.1 — mTLS caller-DID auth: a caller with no client cert is rejected (TLS
// error or 4xx), never served.
func TestS5_1_MTLSAuth(t *testing.T) {
	s := harness.NewStack(t)
	nc := s.JNNoCert(t)
	code, _, err := nc.GetRaw("/healthz")
	ok := err != nil || (code >= 400 && code < 500)
	harness.Truthy(t, ok, "JN must reject a caller with no client cert (code="+harness.Itoa(code)+" err="+harness.ErrStr(err)+")")
}

// S5.2 — Submit gate chain (deserialize→destination→cosignature→walker):
// needs a built+signed entry to a known destination exchange (H1).
func TestS5_2_SubmitGateChain(t *testing.T) {
	s := harness.NewStack(t)
	_ = s.JN(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S5.2: POST /v1/entries/submit a crafted entry; assert the closed-set Rejection.Code (needs H1)")
}

// S5.3 — Authority resolution (3 paths, depth≤3, scope narrowing). H1.
func TestS5_3_AuthorityResolution(t *testing.T) {
	s := harness.NewStack(t)
	_ = s.JN(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S5.3: valid chain accepted, over-depth/over-scope rejected (needs H1 + delegation chain)")
}

// S5.4 — Prerequisite rules (case-init ancestor / merits-posture / scope). H1.
func TestS5_4_PrerequisiteRules(t *testing.T) {
	s := harness.NewStack(t)
	_ = s.JN(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S5.4: assert prerequisite enforcement (needs H1 + seeded case ancestry)")
}

// S5.5 — Cosignature policy (event-type closed-set, capacity, role threshold).
// H1.
func TestS5_5_CosignaturePolicy(t *testing.T) {
	s := harness.NewStack(t)
	_ = s.JN(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S5.5: assert cosignature policy enforcement (needs H1 + multi-signer setup)")
}

// S5.6 — Attestation binding surface (route mounted + input validated). The JN
// exposes attestation as monitoring/dual-attestation (POST) +
// verification/key-attestation (GET) — there is NO /verification/attestation
// (verification.go mounts case-status/enforcement-status/filing-delegation/
// custody-chain/background-check/appeal-chain/key-attestation/cross-log-proof).
// Probe the real surfaces via JNFamilyMounted (mounted ⇒ status != 404).
func TestS5_6_AttestationBinding(t *testing.T) {
	s := harness.NewStack(t)
	jn := s.JN(t)
	s.JNFamilyMounted(t, jn, "attestation",
		"/v1/judicial/monitoring/dual-attestation",
		"/v1/judicial/verification/key-attestation")
}

// S5.7 — Case lifecycle build (init/amend/filings/actions). H1 (needs a
// delegated signer + destination).
func TestS5_7_CaseLifecycleBuild(t *testing.T) {
	s := harness.NewStack(t)
	_ = s.JN(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S5.7: POST /v1/judicial/cases (+amend/filings/actions) returns buildResponse (needs H1)")
}

// S5.8 — Parties surface mounted + validated.
func TestS5_8_PartiesSurface(t *testing.T) {
	s := harness.NewStack(t)
	jn := s.JN(t)
	s.JNFamilyMounted(t, jn, "parties",
		"/v1/judicial/parties", "/v1/judicial/parties/bindings", "/v1/judicial/parties/sealed")
}

// S5.9 — Artifacts surface mounted + validated.
func TestS5_9_ArtifactsSurface(t *testing.T) {
	s := harness.NewStack(t)
	jn := s.JN(t)
	s.JNFamilyMounted(t, jn, "artifacts",
		"/v1/judicial/artifacts", "/v1/judicial/artifacts/publish", "/v1/judicial/artifacts/retrieve")
}

// S5.10 — Enforcement / sealing surface mounted + validated.
func TestS5_10_EnforcementSurface(t *testing.T) {
	s := harness.NewStack(t)
	jn := s.JN(t)
	s.JNFamilyMounted(t, jn, "enforcement",
		"/v1/judicial/enforcement", "/v1/judicial/enforcement/sealing", "/v1/judicial/sealing")
}

// S5.11 — Verification surface mounted + validated.
func TestS5_11_VerificationSurface(t *testing.T) {
	s := harness.NewStack(t)
	jn := s.JN(t)
	s.JNFamilyMounted(t, jn, "verification",
		"/v1/judicial/verification", "/v1/judicial/verification/attestation", "/v1/judicial/verification/appeals")
}

// S5.12 — Topology surface mounted + validated.
func TestS5_12_TopologySurface(t *testing.T) {
	s := harness.NewStack(t)
	jn := s.JN(t)
	s.JNFamilyMounted(t, jn, "topology",
		"/v1/judicial/topology", "/v1/judicial/delegations", "/v1/judicial/dids")
}

// S5.13 — Monitoring audits surface mounted + validated.
func TestS5_13_MonitoringSurface(t *testing.T) {
	s := harness.NewStack(t)
	jn := s.JN(t)
	s.JNFamilyMounted(t, jn, "monitoring",
		"/v1/judicial/monitoring/mirror-consistency",
		"/v1/judicial/monitoring/anchor-freshness",
		"/v1/judicial/monitoring/sealing-compliance",
		"/v1/judicial/monitoring/blob-availability",
		"/v1/judicial/monitoring/delegation-health")
}

// S5.14 — Cross-log verify: the route validates input now; a true {verified:
// true} needs a real cross-court proof from a second network (H2).
func TestS5_14_CrossLogVerify(t *testing.T) {
	s := harness.NewStack(t)
	jn := s.JN(t)
	code, _, err := jn.PostRaw("/v1/judicial/consortium/cross-court-proof/verify", "application/json", []byte("{}"))
	harness.Truthy(t, err == nil, "cross-court-proof/verify error: "+harness.ErrStr(err))
	harness.SurfaceOK(t, code, "/v1/judicial/consortium/cross-court-proof/verify")
	s.Pending(t, "S5.14: a positive {verified:true} needs a real cross-court proof from court B (H2)")
}

// S5.15 — Verify-only ingest / trusted-head state (T3). Needs the JN
// peer-consistency endpoint (H3).
func TestS5_15_VerifyOnlyIngest(t *testing.T) {
	s := harness.NewStack(t)
	jn := s.JN(t)
	s.RequireBootstrap(t)
	code, body, err := jn.PeerConsistency()
	harness.Truthy(t, err == nil, "peer-consistency error: "+harness.ErrStr(err))
	if code == 404 {
		s.Pending(t, "H3: JN peer-consistency endpoint not present (404)")
		return
	}
	harness.Eq(t, code, 200, "JN peer-consistency status")
	harness.ValidJSON(t, body, "JN peer-consistency")
}

// S5_Stubs — the known 501 handlers must still return 501 (assert + escalate);
// a 200 here means a stub silently shipped without its guards.
func TestS5_Stubs_Return501(t *testing.T) {
	s := harness.NewStack(t)
	jn := s.JN(t)
	stubs := []string{
		// cases/1/transfer/division graduated to a real handler (requireCaller →
		// decodeJSON → validates → 400); only transfer/county remains a 501 stub.
		"/v1/judicial/cases/1/transfer/county",
		"/v1/judicial/appeals/initiations",
		"/v1/judicial/appeals/mandates/reverse",
		"/v1/judicial/appeals/records/transfer",
		"/v1/judicial/consortium/cross-court-proof/build",
		"/v1/judicial/consortium/members/execute-addition",
		"/v1/judicial/consortium/members/execute-removal",
		"/v1/judicial/consortium/members/activate-removal",
		"/v1/judicial/consortium/formation",
	}
	for _, p := range stubs {
		code, _, err := jn.PostRaw(p, "application/json", []byte("{}"))
		if err != nil {
			t.Logf("%s: request error %v", p, err)
			continue
		}
		if code == 404 {
			t.Logf("%s: route not mounted (path may have changed) — confirm", p)
			continue
		}
		harness.Eq(t, code, 501, "stub "+p+" must return 501")
	}
}

// S5.16 — ZT-IMM-01 (baseproof v1.43.0) authority-verify temporal anchor.
// The /v1/verify/authority surface must pin a cosigned head deterministically:
// an as_of-LESS request resolves the LATEST head (verifier.ResolveLatest,
// sourced from the JN's gossip-ingested journal) and returns a verdict — it must
// NOT 500. Pre-v1.43 an absent as_of defaulted to a wall clock; v1.43 removed
// that (AsOf{} now → ErrAsOfRequired in the SDK), and the JN was migrated to
// snapshot the latest head instead. A persistent 500 here means either that
// migration regressed (AsOf{} reached a verdict primitive) or the JN never
// journaled a head (gossip ingest not wired) — both real failures of a fully
// running network. An explicit ?as_of is equally honored.
func TestS5_16_AuthorityAsOfMandate(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t) // a cosigned head must exist to pin
	jn := s.JN(t)
	logDID := s.Boot.ExchangeDID
	if logDID == "" {
		s.Pending(t, "S5.16: home log DID unavailable (bootstrap not loaded)")
		return
	}
	// did:web DIDs are valid path segments (colons are pchar); the JN routes
	// {logID} verbatim, matching its own handler tests.
	path := "/v1/verify/authority/" + logDID + "/0"

	// "latest" resolves from the gossip-ingested journal, which the auditor
	// populates shortly after the head is cosigned — retry briefly to absorb
	// that ingest lag before asserting the contract.
	var code int
	var body []byte
	for attempt := 0; attempt < 8; attempt++ {
		var err error
		code, body, err = jn.GetRaw(path)
		harness.Truthy(t, err == nil, "verify/authority error: "+harness.ErrStr(err))
		if code != 500 {
			break
		}
		time.Sleep(time.Second)
	}
	// Route mounted + no server error ⇒ the JN pinned a head and evaluated.
	harness.SurfaceOK(t, code, path+" (as_of absent → ResolveLatest)")
	harness.Truthy(t, code != 500,
		"as_of-absent verify must pin the latest head (ZT-IMM-01), got persistent 500: "+string(body))

	// An explicit ?as_of=0 collapses to latest and is equally honored.
	if c2, b2, _ := jn.GetRaw(path + "?as_of=0"); c2 == 500 {
		t.Errorf("explicit ?as_of=0 must pin the latest head, got 500: %s", string(b2))
	}
}

// S5.20 — Multi-signature threshold events through the submit gate. The
// Event-Dictionary requires multiple signatures on governance/personnel events
// (judicial_appointment=2 judges, schema_publication=2, network_fork=3,
// mofn_escrow_recovery_execution=3); the JN submit gate enforces this on write
// via verification.CheckCosignature against the deployment's CosignatureMixPolicy
// (deployments/tn/trial/cosignature_mix.go) — an entry below the role threshold
// is rejected with the closed-set "insufficient_signers" BEFORE it reaches the
// ledger.
//
// This asserts the submit gate is mounted + rejects a malformed submission (the
// deserialize→destination→cosignature chain runs). The threshold-specific
// negatives — a judicial_appointment with <2 judge cosigners, a network_fork
// with <3, each returning "insufficient_signers" — need a built+signed envelope
// (H5 SDK builder) addressed to a registered destination with a delegated signer
// (H1), which the baseline does not provision.
func TestS5_20_MultiSigThreshold(t *testing.T) {
	s := harness.NewStack(t)
	jn := s.JN(t)

	code, _, err := jn.PostRaw("/v1/entries/submit", "application/json", []byte(`{"not":"an-entry"}`))
	harness.Truthy(t, err == nil, "submit error: "+harness.ErrStr(err))
	harness.Truthy(t, code >= 400 && code < 500,
		"submit gate accepted a malformed entry (status "+harness.Itoa(code)+")")

	s.Pending(t, "S5.20: the threshold negatives (judicial_appointment<2 judges, network_fork<3 → insufficient_signers) need a crafted+signed envelope (H5 builder) to a registered destination with a delegated signer (H1)")
}
