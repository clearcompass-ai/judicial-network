package verification

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/attesta/anchor"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
)

// ── fixtures (replicated from attesta/anchor's package-private test helpers,
//    using only public SDK APIs) ─────────────────────────────────────────────

func wsWitnessSet(t *testing.T, n, k int) ([]cosign.WitnessSigner, *cosign.WitnessKeySet, cosign.NetworkID) {
	t.Helper()
	var nid cosign.NetworkID
	for i := 0; i < 32; i++ {
		nid[i] = byte(i + 7)
	}
	keys := make([]types.WitnessPublicKey, n)
	signers := make([]cosign.WitnessSigner, n)
	for i := 0; i < n; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		signers[i] = cosign.NewECDSAWitnessSigner(priv)
		pub := signatures.PubKeyBytes(&priv.PublicKey)
		keys[i] = types.WitnessPublicKey{ID: sha256.Sum256(pub), PublicKey: pub, SchemeTag: signatures.SchemeECDSA}
	}
	set, err := cosign.NewWitnessKeySet(keys, nid, k, nil)
	if err != nil {
		t.Fatal(err)
	}
	return signers, set, nid
}

func wsCosignHead(t *testing.T, head types.TreeHead, signers []cosign.WitnessSigner, nid cosign.NetworkID) types.CosignedTreeHead {
	t.Helper()
	cth := types.CosignedTreeHead{TreeHead: head}
	for _, s := range signers {
		sig, err := s.Sign(context.Background(), cosign.NewTreeHeadPayload(head), nid, cosign.HashAlgoSHA256)
		if err != nil {
			t.Fatal(err)
		}
		cth.Signatures = append(cth.Signatures, sig)
	}
	return cth
}

func wsCanonicalAnchorBytes(t *testing.T, e *envelope.Entry) []byte {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signatures.SignEntry(sha256.Sum256(envelope.SigningPayload(e)), priv)
	if err != nil {
		t.Fatal(err)
	}
	e.Signatures = []envelope.Signature{{SignerDID: e.Header.SignerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	raw, err := envelope.Serialize(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// court bundles a source log (one cited case) + its witness set.
type court struct {
	logDID   string
	tree     *smt.StubMerkleTree
	citedPos uint64
	citedHex []byte
	signers  []cosign.WitnessSigner
	set      *cosign.WitnessKeySet
	nid      cosign.NetworkID
}

func newCourt(t *testing.T, logDID string, caseBytes []byte) court {
	t.Helper()
	tree := smt.NewStubMerkleTree()
	pos, err := tree.AppendLeaf(caseBytes)
	if err != nil {
		t.Fatal(err)
	}
	signers, set, nid := wsWitnessSet(t, 5, 5)
	return court{logDID: logDID, tree: tree, citedPos: pos, citedHex: caseBytes, signers: signers, set: set, nid: nid}
}

// appealProofFromSource builds the cross-log proof that the HIGHER court
// (anchorSignerDID) records to reference the LOWER court `src`. Per
// BuildCrossLogProof semantics the SOURCE side is the referenced (lower) court,
// so the head is cosigned by the LOWER court's witnesses (src.signers).
func appealProofFromSource(t *testing.T, src court, anchorSignerDID string) types.CrossLogProof {
	t.Helper()
	head, err := src.tree.Head()
	if err != nil {
		t.Fatal(err)
	}
	head.SMTRoot = [32]byte{0xBB}
	head.ReceiptRoot = [32]byte{0xCC}
	cth := wsCosignHead(t, head, src.signers, src.nid)
	entry, err := anchor.BuildCosignedAnchorEntry(anchor.CosignedAnchorParams{
		SignerDID:    anchorSignerDID,
		Destination:  anchorSignerDID,
		SourceLogDID: src.logDID,
		Head:         cth,
		NetworkID:    src.nid,
		EventTime:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	incl, err := src.tree.InclusionProof(context.Background(), src.citedPos, head.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	return types.CrossLogProof{
		AnchorEntryCanonical: wsCanonicalAnchorBytes(t, entry),
		SourceInclusion:      *incl,
		SourceEntryHash:      envelope.EntryLeafHashBytes(src.citedHex),
		SourceEntry:          types.LogPosition{LogDID: src.logDID, Sequence: src.citedPos},
	}
}

// TestVerifyAppealChain_MultiHop_DistinctWitnessSets is the authoritative pin:
// a real 3-hop chain trial → COA → SupCt, each court with its OWN witness set.
// Each hop's proof references the court BELOW it, so its source head is cosigned
// by the LOWER court's witnesses. A correct verifier must therefore check each
// proof against the SOURCE (lower) court's witness set.
func TestVerifyAppealChain_MultiHop_DistinctWitnessSets(t *testing.T) {
	trial := newCourt(t, "did:web:courts.tn.gov:davidson", []byte("davidson: 2027-CR-001 judgment"))
	coa := newCourt(t, "did:web:courts.tn.gov:coa", []byte("coa: affirmed"))
	supct := newCourt(t, "did:web:courts.tn.gov:supct", []byte("supct: cert denied"))

	steps := []AppealStep{
		{Step: 1, LogDID: trial.logDID, CasePos: types.LogPosition{LogDID: trial.logDID, Sequence: trial.citedPos}},
		{Step: 2, LogDID: coa.logDID, CasePos: types.LogPosition{LogDID: coa.logDID, Sequence: coa.citedPos},
			Proof: ptr(appealProofFromSource(t, trial, coa.logDID))},
		{Step: 3, LogDID: supct.logDID, CasePos: types.LogPosition{LogDID: supct.logDID, Sequence: supct.citedPos},
			Proof: ptr(appealProofFromSource(t, coa, supct.logDID))},
	}

	witnessSetByLog := map[string]*cosign.WitnessKeySet{
		trial.logDID: trial.set,
		coa.logDID:   coa.set,
		supct.logDID: supct.set,
	}

	out, err := VerifyAppealChain(steps, witnessSetByLog)
	if err != nil {
		t.Fatalf("VALID 3-hop chain rejected: %v\n"+
			"  → each hop's proof source is the LOWER court; verifying it against the\n"+
			"    CURRENT step's witness set (witnessSetByLog[steps[i].LogDID]) uses the\n"+
			"    WRONG keys. The verifier must resolve the SOURCE court's witness set.", err)
	}
	for i := 1; i < len(out); i++ {
		if !out[i].ProofVerified {
			t.Errorf("hop %d not verified on a valid chain", i)
		}
	}
}

// TestVerifyAppealChain_ZeroTrust_Negatives proves the chain is treated as
// untrusted input: each tampering fails closed.
func TestVerifyAppealChain_ZeroTrust_Negatives(t *testing.T) {
	trial := newCourt(t, "did:web:courts.tn.gov:davidson", []byte("davidson: judgment"))
	coa := newCourt(t, "did:web:courts.tn.gov:coa", []byte("coa: affirmed"))
	mkSteps := func() []AppealStep {
		return []AppealStep{
			{Step: 1, LogDID: trial.logDID, CasePos: types.LogPosition{LogDID: trial.logDID, Sequence: trial.citedPos}},
			{Step: 2, LogDID: coa.logDID, CasePos: types.LogPosition{LogDID: coa.logDID, Sequence: coa.citedPos},
				Proof: ptr(appealProofFromSource(t, trial, coa.logDID))},
		}
	}

	t.Run("substituted witness set fails quorum", func(t *testing.T) {
		_, wrongSet, _ := wsWitnessSet(t, 5, 5) // not trial's keys
		_, err := VerifyAppealChain(mkSteps(), map[string]*cosign.WitnessKeySet{
			trial.logDID: wrongSet, coa.logDID: coa.set,
		})
		if err == nil {
			t.Fatal("a head presented under trial's DID but verified against a different set must fail")
		}
	})

	t.Run("missing source witness set fails closed", func(t *testing.T) {
		_, err := VerifyAppealChain(mkSteps(), map[string]*cosign.WitnessKeySet{
			coa.logDID: coa.set, // trial's set absent
		})
		if err == nil {
			t.Fatal("absent source witness set must fail closed")
		}
	})

	t.Run("unlinked hop (proof source != prior case) fails", func(t *testing.T) {
		steps := mkSteps()
		steps[0].CasePos = types.LogPosition{LogDID: trial.logDID, Sequence: trial.citedPos + 99} // wrong case
		_, err := VerifyAppealChain(steps, map[string]*cosign.WitnessKeySet{
			trial.logDID: trial.set, coa.logDID: coa.set,
		})
		if err == nil {
			t.Fatal("a proof not bound to the previous step's case must fail (no unrelated-proof chains)")
		}
	})
}

func ptr(p types.CrossLogProof) *types.CrossLogProof { return &p }
