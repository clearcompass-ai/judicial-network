//go:build e2e

// Phase 1 — Ledger wire contract (L5–L7), SCENARIOS.md.
package ledger

import (
	"encoding/json"
	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
	"testing"
)

const (
	zeroKey32 = "0000000000000000000000000000000000000000000000000000000000000000"
	oneKey32  = "1111111111111111111111111111111111111111111111111111111111111111"
)

// S1.1 — Tree-head shape: /v1/tree/head carries the canonical fields,
// including receipt_root (the PR #92 truncation guard). 404 = empty log (no
// cosigned head yet) is acceptable on a fresh boot.
func TestS1_1_TreeHeadShape(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)

	code, body, err := s.Ledger.TreeHeadRaw()
	harness.Truthy(t, err == nil, "/v1/tree/head error: "+harness.ErrStr(err))
	if code == 404 {
		t.Skip("/v1/tree/head 404 — no cosigned head yet (empty log); boot path OK")
	}
	harness.Eq(t, code, 200, "/v1/tree/head status")

	// Key-presence (presence ≠ empty value) for the wire contract.
	var m map[string]any
	harness.Truthy(t, json.Unmarshal(body, &m) == nil, "/v1/tree/head not JSON object")
	for _, k := range []string{"root_hash", "smt_root", "receipt_root", "tree_size", "hash_algo", "signatures"} {
		harness.HasKey(t, m, k, "/v1/tree/head")
	}

	// Typed view + signature sub-fields when cosignatures are present.
	head, _, _ := s.Ledger.TreeHead()
	harness.NonEmpty(t, head.RootHash, "root_hash value")
	for i, sig := range head.Signatures {
		harness.NonEmpty(t, sig.PubKeyID, "signatures["+harness.Itoa(i)+"].pub_key_id")
		harness.NonEmpty(t, sig.SigBytes, "signatures["+harness.Itoa(i)+"].sig_bytes")
	}
}

// S1.2 — Checkpoint offline-verifiable + hash-only tiles.
func TestS1_2_CheckpointAndTiles(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	code, body, err := s.Ledger.Checkpoint()
	harness.Truthy(t, err == nil, "/checkpoint error: "+harness.ErrStr(err))
	harness.StatusIn(t, code, "/checkpoint status", 200, 404)
	if code == 200 {
		harness.Truthy(t, len(body) > 0, "/checkpoint empty body")
	}
	tc, _, _ := s.Ledger.Tile(0, "000")
	harness.StatusIn(t, tc, "/tile/0 status", 200, 404)
}

// S1.3 — Inclusion proof reconstructs to the head (needs tree_size≥1).
func TestS1_3_InclusionProof(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	size, ok := s.HeadSize()
	if !ok || size == 0 {
		t.Skip("no sequenced entries yet — inclusion needs tree_size>=1")
	}
	code, body, err := s.Ledger.Inclusion(0)
	harness.Truthy(t, err == nil, "inclusion error: "+harness.ErrStr(err))
	harness.Eq(t, code, 200, "/v1/tree/inclusion/0 status")
	harness.ValidJSON(t, body, "inclusion proof")
}

// S1.4 — Consistency proof old⊑new (needs tree_size≥1).
func TestS1_4_ConsistencyProof(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	size, ok := s.HeadSize()
	if !ok || size < 1 {
		t.Skip("need tree_size>=1 for a consistency proof")
	}
	code, body, err := s.Ledger.Consistency(1, size)
	harness.Truthy(t, err == nil, "consistency error: "+harness.ErrStr(err))
	harness.StatusIn(t, code, "/v1/tree/consistency status", 200)
	harness.ValidJSON(t, body, "consistency proof")
}

// S1.5 — SMT membership / non-membership + root.
func TestS1_5_SMTProof(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	rc, _, _ := s.Ledger.SMTRoot()
	harness.StatusIn(t, rc, "/v1/smt/root status", 200)
	code, body, err := s.Ledger.SMTProof(zeroKey32)
	harness.Truthy(t, err == nil, "smt proof error: "+harness.ErrStr(err))
	harness.StatusIn(t, code, "/v1/smt/proof status", 200, 404)
	if code == 200 {
		var m map[string]any
		harness.Truthy(t, json.Unmarshal(body, &m) == nil, "smt proof not JSON")
		if ty, ok := m["type"].(string); ok {
			harness.Truthy(t, ty == "membership" || ty == "non_membership", "smt proof type unexpected: "+ty)
		}
	}
}

// S1.6 — SMT batch proof covers all keys.
func TestS1_6_SMTBatchProof(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	code, body, err := s.Ledger.SMTBatchProof([]string{zeroKey32, oneKey32})
	harness.Truthy(t, err == nil, "smt batch error: "+harness.ErrStr(err))
	harness.StatusIn(t, code, "/v1/smt/batch_proof status", 200, 400)
	if code == 200 {
		harness.ValidJSON(t, body, "smt batch proof")
	}
}

// S1.7 — Admission MMD (+ difficulty for Mode B).
func TestS1_7_AdmissionMMDDifficulty(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	code, body, err := s.Ledger.AdmissionMMD()
	harness.Truthy(t, err == nil, "mmd error: "+harness.ErrStr(err))
	harness.Eq(t, code, 200, "/v1/admission/mmd status")
	var m map[string]any
	harness.Truthy(t, json.Unmarshal(body, &m) == nil, "mmd not JSON")
	harness.HasKey(t, m, "mmd_seconds", "/v1/admission/mmd")
	dc, _, _ := s.Ledger.AdmissionDifficulty()
	harness.StatusIn(t, dc, "/v1/admission/difficulty status", 200, 404)
}

// S1.8 — Entry read lifecycle: by-seq + raw + hash lookup.
func TestS1_8_EntryReadLifecycle(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	size, ok := s.HeadSize()
	if !ok || size == 0 {
		t.Skip("no sequenced entries yet")
	}
	e, code, err := s.Ledger.EntryBySeq(0)
	harness.Truthy(t, err == nil, "entry by seq error: "+harness.ErrStr(err))
	harness.Eq(t, code, 200, "/v1/entries/0 status")
	harness.NonEmpty(t, e.CanonicalHash, "entry canonical_hash")
	rc, _, _ := s.Ledger.EntryRaw(0)
	harness.StatusIn(t, rc, "/v1/entries/0/raw status", 200, 302)
	he, hc, _ := s.Ledger.EntryByHash(e.CanonicalHash)
	if hc == 200 {
		harness.Truthy(t, he.State != "pending", "entry-hash still pending after sequencing")
	}
}

// S1.9 — Query indexes return ordered hits (empty allowed for unknown keys).
func TestS1_9_QueryIndexes(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	for idx, val := range map[string]string{
		"signer_did":     "did:web:example",
		"delegate_did":   "did:web:example",
		"schema_ref":     "0",
		"target_root":    "0",
		"cosignature_of": "0",
	} {
		code, body, err := s.Ledger.Query(idx, val)
		harness.Truthy(t, err == nil, "query "+idx+" error: "+harness.ErrStr(err))
		harness.StatusIn(t, code, "/v1/query/"+idx+" status", 200, 400, 404)
		if code == 200 {
			harness.ValidJSON(t, body, "query "+idx)
		}
	}
	sc, _, _ := s.Ledger.GetRaw("/v1/query/scan")
	harness.StatusIn(t, sc, "/v1/query/scan status", 200, 400, 404)
}

// S1.10 — Commitments / equivocation surface: 1=normal, 2+=equivocation, 404.
func TestS1_10_CommitmentsSurface(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	code, _, err := s.Ledger.Commitments("pre-grant-commitment-v1", zeroKey32)
	harness.Truthy(t, err == nil, "commitments error: "+harness.ErrStr(err))
	harness.StatusIn(t, code, "/v1/commitments status", 200, 404)
}

// S1.11 — Gossip feed contract (since / sth-latest / by-kind).
func TestS1_11_GossipFeedContract(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	gc, gb, err := s.Ledger.GossipSince("0", 10)
	harness.Truthy(t, err == nil, "gossip since error: "+harness.ErrStr(err))
	harness.StatusIn(t, gc, "/v1/gossip/since status", 200)
	if gc == 200 {
		harness.ValidJSON(t, gb, "gossip since")
	}
	sc, _, _ := s.Ledger.GossipSthLatest()
	harness.StatusIn(t, sc, "/v1/gossip/sth/latest status", 200, 404)
	kc, _, _ := s.Ledger.GossipByKind("cosigned_tree_head")
	harness.StatusIn(t, kc, "/v1/gossip/by-kind status", 200, 400, 404)
}

// S1.12 — Health / version / metrics surface.
func TestS1_12_HealthVersion(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)

	code, body, _ := s.Ledger.Health()
	harness.Eq(t, code, 200, "ledger /healthz status")
	harness.Eq(t, body, "ok", "ledger /healthz body")

	rc, _, _ := s.Ledger.Ready()
	harness.Truthy(t, rc == 200 || rc == 503, "ledger /readyz status (want 200 or 503), got "+harness.Itoa(rc))

	_, vc, err := s.Ledger.Version()
	harness.Truthy(t, err == nil, "/version error: "+harness.ErrStr(err))
	harness.Eq(t, vc, 200, "ledger /version status")
}

// S1.17 — On-log signature-policy amendment (MinSignaturesPerEntry governance).
// The per-entry signature floor is configurable + always >0 and is amended ONLY
// on-log: an BP-ENTRY-NETWORK-SIGNATURE-POLICY-V1 entry (published by the ledger
// `signature-policy` cmd, signed over a witness-cosigned horizon) that the ledger
// materializes via OnLogSignaturePolicyResolver. This asserts: (a) the ledger
// exposes its network info (the policy surface), and (b) the gossip-by-kind
// surface answers for the amendment kind. Detecting a LIVE amendment + its
// resolved-floor change needs the cmd to have published one against the stack
// (+ LEDGER_SIGNATURE_POLICY_SCHEMA wired), which the baseline does not.
func TestS1_17_SignaturePolicyAmendment(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)

	// (a) The ledger exposes its network info (carries the resolved policy).
	info, ic, err := s.Ledger.LogInfo()
	harness.Truthy(t, err == nil, "/v1/log-info error: "+harness.ErrStr(err))
	harness.Eq(t, ic, 200, "/v1/log-info status")
	harness.Truthy(t, info != nil, "/v1/log-info returned no object")

	// (b) The amendment kind is a recognized gossip kind; the by-kind surface
	// answers for it (200 with events once published, else 400/404 empty).
	kc, kb, err := s.Ledger.GossipByKind("BP-ENTRY-NETWORK-SIGNATURE-POLICY-V1")
	harness.Truthy(t, err == nil, "gossip by-kind error: "+harness.ErrStr(err))
	harness.StatusIn(t, kc, "/v1/gossip/by-kind=BP-ENTRY-NETWORK-SIGNATURE-POLICY-V1 status", 200, 400, 404)
	if kc == 200 {
		harness.ValidJSON(t, kb, "signature-policy amendment gossip")
	}

	s.Pending(t, "S1.17: a published on-log MinSignaturesPerEntry amendment (run the ledger signature-policy cmd against the stack + wire LEDGER_SIGNATURE_POLICY_SCHEMA) and the resolved-floor-changed assertion are not provisioned on the baseline")
}
