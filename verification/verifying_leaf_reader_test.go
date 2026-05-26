package verification

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/types"
)

// ─────────────────────────────────────────────────────────────────────
// Fixtures (mirror the SDK log package's own horizon test fixtures)
// ─────────────────────────────────────────────────────────────────────

type testWitness struct {
	priv *ecdsa.PrivateKey
	key  types.WitnessPublicKey
}

// mintWitnesses creates n ECDSA witnesses + a *cosign.WitnessKeySet at the
// given quorum, bound to a fixed non-zero NetworkID (the cosign canonical
// message rejects the zero NetworkID).
func mintWitnesses(t *testing.T, n, quorum int) ([]testWitness, *cosign.WitnessKeySet, cosign.NetworkID) {
	t.Helper()
	var nid cosign.NetworkID
	nid[0] = 0x11
	wits := make([]testWitness, n)
	keys := make([]types.WitnessPublicKey, n)
	for i := 0; i < n; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		pub := signatures.PubKeyBytes(&priv.PublicKey)
		k := types.WitnessPublicKey{ID: sha256.Sum256(pub), PublicKey: pub, SchemeTag: signatures.SchemeECDSA}
		wits[i] = testWitness{priv: priv, key: k}
		keys[i] = k
	}
	set, err := cosign.NewECDSAWitnessKeySet(keys, nid, quorum)
	if err != nil {
		t.Fatalf("NewECDSAWitnessKeySet: %v", err)
	}
	return wits, set, nid
}

// signHead has the first `signers` witnesses cosign head.
func signHead(t *testing.T, head types.TreeHead, wits []testWitness, signers int, nid cosign.NetworkID) types.CosignedTreeHead {
	t.Helper()
	out := types.CosignedTreeHead{TreeHead: head}
	payload := cosign.NewTreeHeadPayload(head)
	for i := 0; i < signers; i++ {
		sig, err := cosign.SignECDSA(payload, nid, cosign.HashAlgoSHA256, wits[i].priv)
		if err != nil {
			t.Fatalf("SignECDSA[%d]: %v", i, err)
		}
		out.Signatures = append(out.Signatures, types.WitnessSignature{
			PubKeyID:  wits[i].key.ID,
			SchemeTag: signatures.SchemeECDSA,
			SigBytes:  sig,
		})
	}
	return out
}

// treeFixture builds a one-leaf SMT, returning its root, the member key +
// leaf, and the node store proofs are generated from.
func treeFixture(t *testing.T) (root, memberKey [32]byte, member types.SMTLeaf, nodes smt.NodeStore) {
	t.Helper()
	ctx := context.Background()
	tr := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	memberKey = [32]byte{0x0A, 0x0B, 0x0C}
	member = types.SMTLeaf{
		Key:          memberKey,
		OriginTip:    types.LogPosition{LogDID: "did:test:origin", Sequence: 7},
		AuthorityTip: types.LogPosition{LogDID: "did:test:authority", Sequence: 9},
	}
	if err := tr.SetLeaf(ctx, memberKey, member); err != nil {
		t.Fatalf("SetLeaf: %v", err)
	}
	var err error
	if root, err = tr.Root(ctx); err != nil {
		t.Fatalf("Root: %v", err)
	}
	return root, memberKey, member, tr.Nodes()
}

// lightClientServer serves the cosigned head (wire shape) at /v1/tree/horizon
// and a real proof (against proofRoot) at /v1/smt/proof/{key}, mirroring the
// ledger. The returned counter tracks horizon hits (for the cache assertion).
func lightClientServer(t *testing.T, cosigned types.CosignedTreeHead, proofRoot [32]byte, nodes smt.NodeStore) (*httptest.Server, *int64) {
	t.Helper()
	headJSON, err := json.Marshal(types.FromCosignedTreeHead(cosigned))
	if err != nil {
		t.Fatalf("marshal head: %v", err)
	}
	var horizonHits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/tree/horizon":
			atomic.AddInt64(&horizonHits, 1)
			_, _ = w.Write(headJSON)
		case strings.HasPrefix(r.URL.Path, "/v1/smt/proof/"):
			kb, err := hex.DecodeString(strings.TrimPrefix(r.URL.Path, "/v1/smt/proof/"))
			if err != nil || len(kb) != 32 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var k [32]byte
			copy(k[:], kb)
			proof, err := smt.GenerateProofAt(nodes, proofRoot, k)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			typ := "non_membership"
			if proof.TerminalKind == types.SMTTerminalLeaf && proof.TerminalLeaf != nil && proof.TerminalLeaf.Key == k {
				typ = "membership"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"type": typ, "proof": proof})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv, &horizonHits
}

func newReader(t *testing.T, url string, set *cosign.WitnessKeySet) *VerifyingLeafReader {
	t.Helper()
	hc := &http.Client{Timeout: 5 * time.Second}
	cp, err := sdklog.NewHTTPCheckpointClient(sdklog.HTTPCheckpointClientConfig{BaseURL: url, Client: hc})
	if err != nil {
		t.Fatalf("NewHTTPCheckpointClient: %v", err)
	}
	pr, err := smt.NewHTTPProofReader(smt.HTTPProofReaderConfig{BaseURL: url, Client: hc})
	if err != nil {
		t.Fatalf("NewHTTPProofReader: %v", err)
	}
	r, err := NewVerifyingLeafReader(VerifyingLeafReaderConfig{
		Checkpoint: cp,
		Proofs:     pr,
		WitnessSet: set,
	})
	if err != nil {
		t.Fatalf("NewVerifyingLeafReader: %v", err)
	}
	return r
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

// Gold path: a member key returns its leaf, verified against the witnessed root.
func TestVerifyingLeafReader_Membership(t *testing.T) {
	root, memberKey, member, nodes := treeFixture(t)
	wits, set, nid := mintWitnesses(t, 3, 2)
	cosigned := signHead(t, types.TreeHead{RootHash: [32]byte{0x01}, SMTRoot: root, TreeSize: 1}, wits, 2, nid)
	srv, _ := lightClientServer(t, cosigned, root, nodes)
	defer srv.Close()

	leaf, err := newReader(t, srv.URL, set).Get(context.Background(), memberKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if leaf == nil {
		t.Fatal("Get returned nil leaf for a member key")
	}
	if leaf.Key != memberKey {
		t.Errorf("leaf.Key = %x, want %x", leaf.Key, memberKey)
	}
	if leaf.OriginTip != member.OriginTip || leaf.AuthorityTip != member.AuthorityTip {
		t.Errorf("leaf tips = %+v/%+v, want %+v/%+v",
			leaf.OriginTip, leaf.AuthorityTip, member.OriginTip, member.AuthorityTip)
	}
}

// A verified non-membership proof is the LeafReader "not found" contract:
// (nil, nil) — but proven against the witnessed root, not asserted.
func TestVerifyingLeafReader_VerifiedAbsence(t *testing.T) {
	root, _, _, nodes := treeFixture(t)
	wits, set, nid := mintWitnesses(t, 3, 2)
	cosigned := signHead(t, types.TreeHead{RootHash: [32]byte{0x01}, SMTRoot: root, TreeSize: 1}, wits, 2, nid)
	srv, _ := lightClientServer(t, cosigned, root, nodes)
	defer srv.Close()

	absent := [32]byte{0x99, 0x88, 0x77}
	leaf, err := newReader(t, srv.URL, set).Get(context.Background(), absent)
	if err != nil {
		t.Fatalf("Get(absent): %v", err)
	}
	if leaf != nil {
		t.Fatalf("Get(absent) = %+v, want nil (verified absence)", leaf)
	}
}

// A horizon below quorum is rejected at the trust step → the read fails closed.
func TestVerifyingLeafReader_SubQuorum(t *testing.T) {
	root, memberKey, _, nodes := treeFixture(t)
	wits, set, nid := mintWitnesses(t, 3, 3) // need all 3
	cosigned := signHead(t, types.TreeHead{RootHash: [32]byte{0x01}, SMTRoot: root, TreeSize: 1}, wits, 1, nid)
	srv, _ := lightClientServer(t, cosigned, root, nodes)
	defer srv.Close()

	if _, err := newReader(t, srv.URL, set).Get(context.Background(), memberKey); err == nil {
		t.Fatal("Get accepted a sub-quorum horizon")
	}
}

// The proof is bound to the WITNESSED root: a validly-cosigned head over a
// different SMTRoot than the proof resolves to must be rejected (not absence).
func TestVerifyingLeafReader_ProofBoundToWitnessedRoot(t *testing.T) {
	root, memberKey, _, nodes := treeFixture(t)
	wrong := root
	wrong[0] ^= 0xFF
	wits, set, nid := mintWitnesses(t, 3, 2)
	cosigned := signHead(t, types.TreeHead{RootHash: [32]byte{0x01}, SMTRoot: wrong, TreeSize: 1}, wits, 2, nid)
	srv, _ := lightClientServer(t, cosigned, root, nodes) // proof against REAL root
	defer srv.Close()

	leaf, err := newReader(t, srv.URL, set).Get(context.Background(), memberKey)
	if err == nil {
		t.Fatalf("Get accepted a proof that does not resolve to the witnessed smt_root (leaf=%+v)", leaf)
	}
}

// The verified horizon is cached: N reads do ONE horizon fetch (one trust
// step, many proofs).
func TestVerifyingLeafReader_HorizonCached(t *testing.T) {
	root, memberKey, _, nodes := treeFixture(t)
	wits, set, nid := mintWitnesses(t, 3, 2)
	cosigned := signHead(t, types.TreeHead{RootHash: [32]byte{0x01}, SMTRoot: root, TreeSize: 1}, wits, 2, nid)
	srv, hits := lightClientServer(t, cosigned, root, nodes)
	defer srv.Close()

	r := newReader(t, srv.URL, set)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := r.Get(ctx, memberKey); err != nil {
			t.Fatalf("Get #%d: %v", i, err)
		}
	}
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Fatalf("horizon fetched %d times across 5 reads, want 1 (cache)", got)
	}
}

func TestNewVerifyingLeafReader_NilDeps(t *testing.T) {
	_, set, _ := mintWitnesses(t, 1, 1)
	hc := &http.Client{Timeout: 5 * time.Second}
	cp, err := sdklog.NewHTTPCheckpointClient(sdklog.HTTPCheckpointClientConfig{BaseURL: "http://x", Client: hc})
	if err != nil {
		t.Fatalf("NewHTTPCheckpointClient: %v", err)
	}
	pr, err := smt.NewHTTPProofReader(smt.HTTPProofReaderConfig{BaseURL: "http://x", Client: hc})
	if err != nil {
		t.Fatalf("NewHTTPProofReader: %v", err)
	}
	cases := []VerifyingLeafReaderConfig{
		{Checkpoint: nil, Proofs: pr, WitnessSet: set},
		{Checkpoint: cp, Proofs: nil, WitnessSet: set},
		{Checkpoint: cp, Proofs: pr, WitnessSet: nil},
	}
	for i, c := range cases {
		if _, err := NewVerifyingLeafReader(c); err == nil {
			t.Errorf("case %d: nil dep accepted", i)
		}
	}
}
