package crosslog

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

// crossLogWitnesses builds n ECDSA witness signers and a K-of-N keyset bound
// to the shared test NetworkID. It exposes the signers so the caller can
// cosign a head whose RootHash is the genuine Merkle root of a real source
// tree — required for the inclusion step to actually verify.
func crossLogWitnesses(t *testing.T, n, k int) ([]cosign.WitnessSigner, *cosign.WitnessKeySet, cosign.NetworkID) {
	t.Helper()
	nid := testNetworkID()
	keys := make([]types.WitnessPublicKey, n)
	signers := make([]cosign.WitnessSigner, n)
	for i := 0; i < n; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		signers[i] = cosign.NewECDSAWitnessSigner(priv)
		pub := signatures.PubKeyBytes(&priv.PublicKey)
		keys[i] = types.WitnessPublicKey{ID: sha256.Sum256(pub), PublicKey: pub, SchemeTag: signatures.SchemeECDSA}
	}
	set, err := cosign.NewECDSAWitnessKeySet(keys, nid, k)
	if err != nil {
		t.Fatalf("NewECDSAWitnessKeySet: %v", err)
	}
	return signers, set, nid
}

// cosignReal cosigns a real TreeHead with every signer, producing the
// CosignedTreeHead a ledger would embed in a cosigned_tree_head_v1 anchor.
func cosignReal(t *testing.T, head types.TreeHead, signers []cosign.WitnessSigner, nid cosign.NetworkID) types.CosignedTreeHead {
	t.Helper()
	cth := types.CosignedTreeHead{TreeHead: head}
	for _, s := range signers {
		sig, err := s.Sign(context.Background(), cosign.NewTreeHeadPayload(head), nid, cosign.HashAlgoSHA256)
		if err != nil {
			t.Fatalf("witness Sign: %v", err)
		}
		cth.Signatures = append(cth.Signatures, sig)
	}
	return cth
}

// canonicalAnchor signs the (unsigned) anchor entry produced by the SDK
// builder and serializes it to the canonical bytes the local log would
// store — the AnchorEntryCanonical a CrossLogProof carries. VerifyCrossLog
// only deserializes these bytes and reads DomainPayload; the entry's own
// signature is never crypto-verified here, so a single structurally-valid
// ECDSA signature is sufficient to satisfy envelope.Serialize.
func canonicalAnchor(t *testing.T, e *envelope.Entry) []byte {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256(envelope.SigningPayload(e))
	sig, err := signatures.SignEntry(digest, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	e.Signatures = []envelope.Signature{{
		SignerDID: e.Header.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	raw, err := envelope.Serialize(e)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return raw
}

// TestVerifyCrossLog_EndToEnd is the JN consumer mirror of the SDK's
// anchor cross-log test: a foreign (source-log) entry's REAL RFC-6962
// inclusion is proven against a self-contained cosigned anchor whose
// K-of-N quorum is recomputed OFFLINE — no callback to the source log.
// This is the exact path the JN appeal flow relies on.
func TestVerifyCrossLog_EndToEnd(t *testing.T) {
	ctx := context.Background()

	// 1. A real source (Davidson) log with several sequenced entries.
	src := smt.NewStubMerkleTree()
	entries := [][]byte{
		[]byte("acme-v-beta: civil filing"),
		[]byte("acme-v-beta: party binding"),
		[]byte("acme-v-beta: judgment for ACME"), // the entry the appeal cites
		[]byte("acme-v-beta: counsel appearance"),
	}
	var citedPos uint64
	for i, e := range entries {
		pos, err := src.AppendLeaf(e)
		if err != nil {
			t.Fatalf("AppendLeaf: %v", err)
		}
		if i == 2 {
			citedPos = pos
		}
	}
	head, err := src.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	// The stub is RFC-6962-only; a real producer pairs the chronological
	// root with its SMT state + receipt root before signing.
	head.SMTRoot = [32]byte{0xBB}
	head.ReceiptRoot = [32]byte{0xCC}

	// 2. The 5-witness fleet cosigns that head (K=5).
	signers, set, nid := crossLogWitnesses(t, 5, 5)
	cth := cosignReal(t, head, signers, nid)

	// 3. The destination (COA) log publishes a self-contained cosigned
	//    anchor; we serialize it to canonical bytes as the local log would.
	anchorEntry, err := anchor.BuildCosignedAnchorEntry(anchor.CosignedAnchorParams{
		SignerDID:    "did:web:state:tn:coa",
		Destination:  "did:web:state:tn:coa",
		SourceLogDID: "did:web:state:tn:davidson",
		Head:         cth,
		NetworkID:    nid,
		EventTime:    1,
	})
	if err != nil {
		t.Fatalf("BuildCosignedAnchorEntry: %v", err)
	}
	canonical := canonicalAnchor(t, anchorEntry)

	// 4. Prove the cited entry's inclusion against the head's root.
	proof, err := src.InclusionProof(ctx, citedPos, head.TreeSize)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	entryHash := envelope.EntryLeafHashBytes(entries[2])
	if entryHash != proof.LeafHash {
		t.Fatalf("entry hash %x != proof leaf %x", entryHash[:8], proof.LeafHash[:8])
	}

	good := types.CrossLogProof{
		AnchorEntryCanonical: canonical,
		SourceInclusion:      *proof,
		SourceEntryHash:      entryHash,
	}
	if err := VerifyCrossLog(good, set); err != nil {
		t.Fatalf("VerifyCrossLog (happy path): %v", err)
	}

	// ── negatives (fail-closed) ──

	// Claiming a different entry's hash for this proof → binding fails.
	bad := good
	bad.SourceEntryHash = envelope.EntryLeafHashBytes(entries[0])
	if err := VerifyCrossLog(bad, set); err == nil {
		t.Error("mismatched entry hash must fail")
	}

	// A genuine proof from an UNRELATED tree → Merkle fails against the head.
	other := smt.NewStubMerkleTree()
	if _, err := other.AppendLeaf([]byte("unrelated")); err != nil {
		t.Fatalf("AppendLeaf(other): %v", err)
	}
	op, err := other.InclusionProof(ctx, 0, 1)
	if err != nil {
		t.Fatalf("InclusionProof(other): %v", err)
	}
	foreign := good
	foreign.SourceInclusion = *op
	foreign.SourceEntryHash = op.LeafHash
	if err := VerifyCrossLog(foreign, set); err == nil {
		t.Error("foreign-tree proof must fail against the verified head")
	}

	// The wrong witness set (disjoint keys, same NetworkID) → quorum fails
	// BEFORE any inclusion check (you never trust an unverified head).
	_, wrongSet, _ := crossLogWitnesses(t, 5, 5)
	if err := VerifyCrossLog(good, wrongSet); err == nil {
		t.Error("wrong witness set must fail quorum")
	}

	// An anchor whose head only carries 2-of-5 cosignatures → quorum fails.
	weak := cosignReal(t, head, signers[:2], nid)
	weakEntry, err := anchor.BuildCosignedAnchorEntry(anchor.CosignedAnchorParams{
		SignerDID: "did:a", Destination: "did:b", SourceLogDID: "did:src", Head: weak, NetworkID: nid, EventTime: 1,
	})
	if err != nil {
		t.Fatalf("BuildCosignedAnchorEntry(weak): %v", err)
	}
	weakProof := good
	weakProof.AnchorEntryCanonical = canonicalAnchor(t, weakEntry)
	if err := VerifyCrossLog(weakProof, set); err == nil {
		t.Error("below-quorum anchor must fail verification")
	}

	// Malformed anchor bytes → deserialize fails.
	mangled := good
	mangled.AnchorEntryCanonical = []byte("not a serialized entry")
	if err := VerifyCrossLog(mangled, set); err == nil {
		t.Error("malformed anchor bytes must fail deserialize")
	}

	// Nil witness set → fail-closed.
	if err := VerifyCrossLog(good, nil); err == nil {
		t.Error("nil witness set must fail")
	}
}
