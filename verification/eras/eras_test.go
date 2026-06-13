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

// TestEraFlip_SuccessorEraResolvesToNewSet completes #107's era-N+1 verdict
// matrix IN PROCESS (memory journal → real resolver; no PG, no Docker): the
// SAME stack that resolves an era-N head to set(N) must resolve an era-N+1
// head (cosigned by the SUCCESSOR set after a rotation) to set(N+1) — and a
// head cosigned by a CROSS-ERA mix (one key from each set) satisfies neither
// era's quorum and is refused by name. This is the "rotate, then era-N
// verifies under set(N) and era-N+1 under set(N+1), wrong refused" leg —
// proven without the federation fleet; the live tri-network run is then
// belt-and-suspenders, not the invariant's only home.
func TestEraFlip_SuccessorEraResolvesToNewSet(t *testing.T) {
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

	// helper: a head at TreeSize cosigned by the first two members of `set`.
	headCosignedBy := func(set *witnesstest.Set) types.CosignedTreeHead {
		h := types.TreeHead{RootHash: [32]byte{9}, SMTRoot: [32]byte{8}, ReceiptRoot: [32]byte{7}, TreeSize: 200}
		p := cosign.NewTreeHeadPayload(h)
		ss := make([]types.WitnessSignature, 2)
		for i := 0; i < 2; i++ {
			sb, serr := cosign.SignECDSA(p, nid, cosign.HashAlgoSHA256, set.Privs[i])
			if serr != nil {
				t.Fatal(serr)
			}
			ss[i] = types.WitnessSignature{PubKeyID: set.Keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb}
		}
		return types.CosignedTreeHead{TreeHead: h, Signatures: ss}
	}

	// era N+1: a head cosigned by the SUCCESSOR set resolves to set(N+1).
	got, err := r.SetForHead(ctx, peerDID, headCosignedBy(s1))
	if err != nil {
		t.Fatalf("successor-era head must resolve era-correctly: %v", err)
	}
	if got.SetHash() != s1.KeySet.SetHash() {
		t.Fatal("a head cosigned by the NEW set must resolve to set(N+1), not set(N)")
	}

	// era N: the same stack still resolves an outgoing-set head to set(N).
	gotN, err := r.SetForHead(ctx, peerDID, headCosignedBy(s0))
	if err != nil || gotN.SetHash() != s0.KeySet.SetHash() {
		t.Fatalf("outgoing-set head must still resolve to set(N): set=%v err=%v", gotN != nil, err)
	}

	// cross-era mix: one key from each set — neither era's quorum is met;
	// refused by name (the "wrong era is refused" half).
	h := types.TreeHead{RootHash: [32]byte{9}, SMTRoot: [32]byte{8}, ReceiptRoot: [32]byte{7}, TreeSize: 200}
	p := cosign.NewTreeHeadPayload(h)
	mix := make([]types.WitnessSignature, 2)
	for i, src := range []*witnesstest.Set{s0, s1} {
		sb, serr := cosign.SignECDSA(p, nid, cosign.HashAlgoSHA256, src.Privs[i])
		if serr != nil {
			t.Fatal(serr)
		}
		mix[i] = types.WitnessSignature{PubKeyID: src.Keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb}
	}
	if _, err := r.SetForHead(ctx, peerDID, types.CosignedTreeHead{TreeHead: h, Signatures: mix}); !errors.Is(err, ErrCannotResolveEra) {
		t.Fatalf("a cross-era cosignature mix must refuse by name: %v", err)
	}
}

// TestRebuildByReIngest_ByteIdenticalEraResolution is #173's invariant proven
// IN PROCESS (memory journal → real resolver; no PG, no Docker): a JN's
// per-peer rotation chain is an enforcer's CACHE — destroy it and rebuild
// from the peers' feeds (here: re-record the SAME rotation sequence a cold
// puller would re-ingest) and era resolution is BYTE-IDENTICAL. "Discard the
// journal object and build a fresh one" IS process-death for an in-memory
// cache; the dockerx container-restart leg is then environmental
// confirmation, not the invariant's only home.
func TestRebuildByReIngest_ByteIdenticalEraResolution(t *testing.T) {
	ctx := context.Background()
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 11)
	}
	s0 := witnesstest.NewSet(t, nid, 3, 2)
	s1 := witnesstest.NewSet(t, nid, 3, 2)
	s2 := witnesstest.NewSet(t, nid, 3, 2)

	// The peer's rotation feed, in delivery order: s0→s1 @100, s1→s2 @200.
	feed := []types.WitnessRotationRecord{
		{Rotation: witnesstest.MintRotation(t, nid, s0, s1, 2), EffectivePos: types.LogPosition{LogDID: peerDID, Sequence: 100}},
		{Rotation: witnesstest.MintRotation(t, nid, s1, s2, 2), EffectivePos: types.LogPosition{LogDID: peerDID, Sequence: 200}},
	}
	// headBy: a head at TreeSize cosigned by the first two members of `set`.
	headBy := func(set *witnesstest.Set, treeSize uint64) types.CosignedTreeHead {
		h := types.TreeHead{RootHash: [32]byte{1}, SMTRoot: [32]byte{2}, ReceiptRoot: [32]byte{3}, TreeSize: treeSize}
		p := cosign.NewTreeHeadPayload(h)
		ss := make([]types.WitnessSignature, 2)
		for i := 0; i < 2; i++ {
			sb, serr := cosign.SignECDSA(p, nid, cosign.HashAlgoSHA256, set.Privs[i])
			if serr != nil {
				t.Fatal(serr)
			}
			ss[i] = types.WitnessSignature{PubKeyID: set.Keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb}
		}
		return types.CosignedTreeHead{TreeHead: h, Signatures: ss}
	}

	// build constructs a fresh journal+resolver and re-ingests the feed —
	// exactly what a cold-booted puller does (in-memory cursors restart).
	build := func() *Resolver {
		j := witnessrotation.NewMemoryRotationJournal()
		for _, rec := range feed {
			if err := j.RecordRotation(ctx, rec); err != nil {
				t.Fatal(err)
			}
		}
		inner, err := witnessrotation.NewJournalWitnessSetResolver(j, []witnessrotation.LogTrustRoot{{LogDID: peerDID, Genesis: s0.KeySet}})
		if err != nil {
			t.Fatal(err)
		}
		r, err := New(inner, j, []string{peerDID}, time.Minute, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// Resolve a head from EACH era against the original and the rebuilt
	// resolver; every verdict must be byte-identical.
	heads := []struct {
		name string
		head types.CosignedTreeHead
		want [32]byte
	}{
		{"era-0 (genesis s0)", headBy(s0, 50), s0.KeySet.SetHash()},
		{"era-1 (s1)", headBy(s1, 150), s1.KeySet.SetHash()},
		{"era-2 (s2)", headBy(s2, 250), s2.KeySet.SetHash()},
	}
	orig := build()
	rebuilt := build() // the "restart": a fresh process re-ingesting the same feed
	for _, hc := range heads {
		o, oerr := orig.SetForHead(ctx, peerDID, hc.head)
		rb, rerr := rebuilt.SetForHead(ctx, peerDID, hc.head)
		if oerr != nil || rerr != nil {
			t.Fatalf("%s: resolution errored (orig=%v rebuilt=%v)", hc.name, oerr, rerr)
		}
		if o.SetHash() != hc.want || rb.SetHash() != hc.want {
			t.Fatalf("%s: era-correctness broke (orig=%x rebuilt=%x want=%x)", hc.name, o.SetHash(), rb.SetHash(), hc.want)
		}
		if o.SetHash() != rb.SetHash() {
			t.Fatalf("%s: REBUILD LAW BROKEN — rebuilt resolution differs from original", hc.name)
		}
	}
}
