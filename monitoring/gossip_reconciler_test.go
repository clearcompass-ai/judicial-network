package monitoring

import (
	"context"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
)

// stubVerifier returns a fixed (event, err), simulating the two-tier verifier.
type stubVerifier struct {
	ev  gossip.Event
	err error
}

func (s stubVerifier) Verify(_ context.Context, _ gossip.SignedEvent) (gossip.Event, error) {
	return s.ev, s.err
}

func cthFinding(t *testing.T, size uint64, root byte) *findings.CosignedTreeHeadFinding {
	t.Helper()
	head := types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: size, RootHash: [32]byte{root}, SMTRoot: [32]byte{0xBB}, ReceiptRoot: [32]byte{0xCC}},
		Signatures: []types.WitnessSignature{{PubKeyID: [32]byte{0x01}, SchemeTag: 1, SigBytes: []byte{0xAA}}},
	}
	f, err := findings.NewCosignedTreeHeadFinding(head, "ep")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// A verification failure must error and reach no enforcer.
func TestReconciler_VerifyFails_NoAct(t *testing.T) {
	heads := NewTrustedHeadStore(nil)
	r, _ := NewReconciler(ReconcilerConfig{Verifier: stubVerifier{err: errors.New("forged")}, Heads: heads})
	if err := r.HandleSignedEvent(context.Background(), gossip.SignedEvent{Kind: gossip.KindCosignedTreeHead, Originator: "did:peer"}); err == nil {
		t.Fatal("verification failure must surface as an error")
	}
	if _, ok := heads.TrustedHead("did:peer"); ok {
		t.Fatal("no head may be recorded when verification fails")
	}
}

func TestReconciler_CosignedTreeHead_RecordsHead(t *testing.T) {
	heads := NewTrustedHeadStore(nil)
	r, _ := NewReconciler(ReconcilerConfig{Verifier: stubVerifier{ev: cthFinding(t, 100, 0xAA)}, Heads: heads})
	ev := gossip.SignedEvent{Kind: gossip.KindCosignedTreeHead, Originator: "did:peer"}
	if err := r.HandleSignedEvent(context.Background(), ev); err != nil {
		t.Fatalf("handle: %v", err)
	}
	h, ok := heads.TrustedHead("did:peer")
	if !ok || h.TreeSize != 100 {
		t.Fatalf("head not recorded: %+v ok=%v", h, ok)
	}
}

func TestReconciler_Equivocation_DrivesResponder(t *testing.T) {
	ap := &stubApplier{}
	resp, _ := NewEquivocationResponder(ap, nil)
	r, _ := NewReconciler(ReconcilerConfig{
		Verifier:     stubVerifier{ev: &findings.EquivocationFinding{LedgerEndpoint: "https://led"}},
		Heads:        NewTrustedHeadStore(nil),
		Equivocation: resp,
	})
	if err := r.HandleSignedEvent(context.Background(), gossip.SignedEvent{Kind: gossip.KindEquivocationFinding}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if !ap.called {
		t.Fatal("equivocation responder/slasher not driven")
	}
}

// A verified Kind with no enforcer wired is logged, not errored.
func TestReconciler_NoEnforcer_NoError(t *testing.T) {
	f, err := findings.NewGhostLeafFinding(7, 3, [32]byte{0xAB}, "did:log", 1_700_000_000_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := NewReconciler(ReconcilerConfig{Verifier: stubVerifier{ev: f}, Heads: NewTrustedHeadStore(nil)})
	if err := r.HandleSignedEvent(context.Background(), gossip.SignedEvent{Kind: gossip.KindGhostLeaf}); err != nil {
		t.Fatalf("ghost leaf (no enforcer) should not error: %v", err)
	}
}

func TestNewReconciler_Validation(t *testing.T) {
	if _, err := NewReconciler(ReconcilerConfig{Heads: NewTrustedHeadStore(nil)}); err == nil {
		t.Fatal("nil Verifier must error")
	}
	if _, err := NewReconciler(ReconcilerConfig{Verifier: stubVerifier{}}); err == nil {
		t.Fatal("nil Heads must error")
	}
}
