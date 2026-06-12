// FILE PATH: verification/eras/eras_test.go
//
// One rejection test per class (never folded), the warmth state machine,
// and the era-flip through the REAL stack (memory journal → libs resolver →
// this wrapper) — the JN-altitude twin of the libs transitional-head
// boundary test, proving the exact wiring the verify path runs.
package eras

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness/witnesstest"

	"github.com/baseproof/tooling/libs/witnessrotation"
)

const peerDID = "did:web:peer.eras.test"

type fakeInner struct {
	set *cosign.WitnessKeySet
	err error
}

func (f fakeInner) SetForHead(context.Context, string, types.CosignedTreeHead) (*cosign.WitnessKeySet, error) {
	return f.set, f.err
}
func (f fakeInner) CurrentSet(context.Context, string) (*cosign.WitnessKeySet, error) {
	return f.set, f.err
}

type fakeChains struct{ n int }

func (f fakeChains) RecordsFor(context.Context, string) ([]types.WitnessRotationRecord, error) {
	return make([]types.WitnessRotationRecord, f.n), nil
}

func newTestResolver(t *testing.T, inner fakeInner, chainLen int, graceElapsed bool) *Resolver {
	t.Helper()
	r, err := New(inner, fakeChains{n: chainLen}, []string{peerDID}, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	if graceElapsed {
		r.nowFunc = func() time.Time { return r.bootAt.Add(2 * time.Minute) }
	} else {
		r.nowFunc = func() time.Time { return r.bootAt }
	}
	return r
}

func TestClasses_OneRejectionPerClass(t *testing.T) {
	ctx := context.Background()
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 9}}
	resolveErr := fmt.Errorf("no journaled chain set cosigns the head")

	t.Run("no-such-peer is decided locally, before the resolver", func(t *testing.T) {
		r := newTestResolver(t, fakeInner{err: resolveErr}, 0, false)
		_, err := r.SetForHead(ctx, "did:web:stranger", head)
		if !errors.Is(err, ErrNoSuchPeer) {
			t.Fatalf("want ErrNoSuchPeer, got %v", err)
		}
		if r.C.NoSuchPeer.Load() != 1 || r.C.Warming.Load() != 0 || r.C.CannotResolveEra.Load() != 0 {
			t.Fatal("classes must never fold into each other (counters)")
		}
	})

	t.Run("warming: cold journal inside the grace window", func(t *testing.T) {
		r := newTestResolver(t, fakeInner{err: resolveErr}, 0, false)
		_, err := r.SetForHead(ctx, peerDID, head)
		if !errors.Is(err, ErrWarming) {
			t.Fatalf("want ErrWarming, got %v", err)
		}
		if r.C.Warming.Load() != 1 || r.C.CannotResolveEra.Load() != 0 {
			t.Fatal("warming must not count as staleness")
		}
	})

	t.Run("cannot-resolve-era: grace elapsed makes the failure genuine", func(t *testing.T) {
		r := newTestResolver(t, fakeInner{err: resolveErr}, 0, true)
		_, err := r.SetForHead(ctx, peerDID, head)
		if !errors.Is(err, ErrCannotResolveEra) {
			t.Fatalf("want ErrCannotResolveEra, got %v", err)
		}
	})

	t.Run("cannot-resolve-era: a non-empty journal is warm immediately", func(t *testing.T) {
		r := newTestResolver(t, fakeInner{err: resolveErr}, 1, false)
		_, err := r.SetForHead(ctx, peerDID, head)
		if !errors.Is(err, ErrCannotResolveEra) {
			t.Fatalf("a delivered chain ends warming: want ErrCannotResolveEra, got %v", err)
		}
	})

	t.Run("a success marks the peer warm for every later verdict", func(t *testing.T) {
		ok := newTestResolver(t, fakeInner{set: &cosign.WitnessKeySet{}}, 0, false)
		if _, err := ok.SetForHead(ctx, peerDID, head); err != nil {
			t.Fatal(err)
		}
		ok.inner = fakeInner{err: resolveErr} // the next head is unexplainable
		_, err := ok.SetForHead(ctx, peerDID, head)
		if !errors.Is(err, ErrCannotResolveEra) {
			t.Fatalf("post-success failures are genuine: want ErrCannotResolveEra, got %v", err)
		}
	})

	t.Run("CurrentSet: unknown log and broken chain only", func(t *testing.T) {
		r := newTestResolver(t, fakeInner{err: resolveErr}, 0, false)
		if _, err := r.CurrentSet(ctx, "did:web:stranger"); !errors.Is(err, ErrNoSuchPeer) {
			t.Fatalf("want ErrNoSuchPeer, got %v", err)
		}
		if _, err := r.CurrentSet(ctx, peerDID); !errors.Is(err, ErrCannotResolveEra) {
			t.Fatalf("want ErrCannotResolveEra (no warming class on current-set reads), got %v", err)
		}
	})
}

// TestEraFlip_ThroughTheRealStack drives the EXACT production wiring: a
// foreign rotation journaled into the shared MemoryRotationJournal (as the
// reconciler does), the libs journal-first resolver over the config-root
// genesis, this wrapper on top — and a transitional head cosigned by the
// OUTGOING set resolves to ITS era while a rogue head fails by name.
func TestEraFlip_ThroughTheRealStack(t *testing.T) {
	ctx := context.Background()
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 7)
	}
	s0 := witnesstest.NewSet(t, nid, 3, 2)
	s1 := witnesstest.NewSet(t, nid, 3, 2)

	journal := witnessrotation.NewMemoryRotationJournal()
	if err := journal.RecordRotation(ctx, types.WitnessRotationRecord{
		Rotation:     witnesstest.MintRotation(t, nid, s0, s1, 2),
		EffectivePos: types.LogPosition{LogDID: peerDID, Sequence: 100},
	}); err != nil {
		t.Fatal(err)
	}
	inner, err := witnessrotation.NewJournalWitnessSetResolver(journal, []witnessrotation.LogTrustRoot{{
		LogDID: peerDID, Genesis: s0.KeySet,
	}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(inner, journal, []string{peerDID}, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}

	// A post-rotation head still cosigned by the OUTGOING set (the
	// operationally-fuzzy adoption window) resolves to ITS era.
	head := types.TreeHead{RootHash: [32]byte{1}, SMTRoot: [32]byte{2}, ReceiptRoot: [32]byte{3}, TreeSize: 150}
	payload := cosign.NewTreeHeadPayload(head)
	sigs := make([]types.WitnessSignature, 2)
	for i := 0; i < 2; i++ {
		sb, serr := cosign.SignECDSA(payload, nid, cosign.HashAlgoSHA256, s0.Privs[i])
		if serr != nil {
			t.Fatal(serr)
		}
		sigs[i] = types.WitnessSignature{PubKeyID: s0.Keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb}
	}
	transitional := types.CosignedTreeHead{TreeHead: head, Signatures: sigs}

	got, err := r.SetForHead(ctx, peerDID, transitional)
	if err != nil {
		t.Fatalf("transitional head must resolve era-correctly: %v", err)
	}
	if got.SetHash() != s0.KeySet.SetHash() {
		t.Fatal("transitional head must resolve to the OUTGOING era set")
	}

	// A head cosigned by keys on NO chain: named refusal (peer is warm —
	// the journal holds the chain — so this is cannot-resolve-era).
	rogue := witnesstest.NewSet(t, nid, 3, 2)
	rsigs := make([]types.WitnessSignature, 2)
	for i := 0; i < 2; i++ {
		sb, serr := cosign.SignECDSA(payload, nid, cosign.HashAlgoSHA256, rogue.Privs[i])
		if serr != nil {
			t.Fatal(serr)
		}
		rsigs[i] = types.WitnessSignature{PubKeyID: rogue.Keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb}
	}
	_, err = r.SetForHead(ctx, peerDID, types.CosignedTreeHead{TreeHead: head, Signatures: rsigs})
	if !errors.Is(err, ErrCannotResolveEra) {
		t.Fatalf("rogue head: want ErrCannotResolveEra, got %v", err)
	}
}
