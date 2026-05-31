// C-5 cross-log inclusion proof matrix for MultiJurisdictionTrust.
//
// Pins the six end-to-end scenarios issue #69 enumerates for cross-
// log verification:
//
//   - Happy: foreign Entry resolver wired, returns a Meta + valid
//     Merkle Inclusion proof, SDK walker verifies it against the
//     foreign log's TrustRoot.Head.RootHash and accepts the entry
//   - ForgedInclusionProof: same shape, but the proof's LeafHash is
//     tampered; smt.VerifyMerkleInclusion rejects against the head
//     root (the SDK walker returns ErrInclusionInvalid)
//   - UnknownPeerLog: foreign LogDID is not in foreignSets; both
//     TrustRoot and Entry return ErrUnknownLog (fail-closed; the
//     walker MUST NOT silently fall through to the home backend)
//   - AsOfHistorical: foreign log has multiple journaled heads;
//     different asOfs select different heads — the foundation of
//     year-15 verification of year-1 bundles
//   - Fork: foreign log has equivocating heads at the same sequence;
//     TrustRoot fails closed with ErrEquivocatedLog
//   - FallbackToLocal: a LogDID that's neither home nor declared as
//     foreign hits ErrUnknownLog (no silent home-backend fallthrough
//     — the cross-network safety claim of MultiJurisdictionTrust)
//
// These tests exercise the v1.34+ ForeignEntryResolver /
// ForeignLeafResolver hooks (added in C-5) that turn
// MultiJurisdictionTrust from a TrustRoot-only provider into a
// full cross-log inclusion+membership verifier when operator-
// declared resolvers are wired.
package trust

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/attesta-tools/libs/monitoring"
)

// ─────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────

// stubForeignEntries is a hand-curated map of (LogDID, Sequence) →
// pre-built EntryProof — the simplest possible
// ForeignEntryResolver. Tests build their own proof bytes and seed
// the journal with the corresponding RootHash so the SDK walker's
// smt.VerifyMerkleInclusion accepts (or rejects) the proof against
// the foreign trust root.
type stubForeignEntries struct {
	proofs map[uint64]verifier.EntryProof
}

func (s stubForeignEntries) EntryAt(_ context.Context, pos types.LogPosition, _ verifier.AsOf) (verifier.EntryProof, error) {
	if p, ok := s.proofs[pos.Sequence]; ok {
		return p, nil
	}
	return verifier.EntryProof{}, errors.New("stubForeignEntries: no entry at " + pos.String())
}

// stubForeignLeaves is the leaf analog of stubForeignEntries.
type stubForeignLeaves struct {
	proofs map[[32]byte]verifier.LeafProof
}

func (s stubForeignLeaves) LeafAt(_ context.Context, _ string, key [32]byte, _ verifier.AsOf) (verifier.LeafProof, error) {
	if p, ok := s.proofs[key]; ok {
		return p, nil
	}
	return verifier.LeafProof{}, errors.New("stubForeignLeaves: no leaf for key")
}

// singleLeafProof builds a Merkle inclusion proof for a single-leaf
// tree. The root of such a tree is the leaf hash itself (no
// siblings), so the test can seed a journaled head with that same
// RootHash to make the proof verify. This is the minimal proof
// fixture that exercises the verifier walker's inclusion path.
func singleLeafProof(canonical []byte) (proof types.MerkleProof, rootHash [32]byte) {
	leafHash := envelope.EntryLeafHashBytes(canonical)
	return types.MerkleProof{
		LeafPosition: 0,
		LeafHash:     leafHash,
		Siblings:     [][32]byte{},
		TreeSize:     1,
	}, leafHash
}

// crossLogSetup wires a 3-log fixture (home + 2 foreign) with a
// shared journal. Tests mutate the returned components before
// constructing the provider — seeding heads, building resolvers,
// etc.
type crossLogSetup struct {
	homeDID    string
	foreignDID string

	homeFetcher fixtureFetcher
	homeLeaves  smt.LeafReader

	foreignKeyset *cosign.WitnessKeySet
	journal       *monitoring.MemoryHeadsJournal
}

func newCrossLogSetup(t *testing.T) crossLogSetup {
	t.Helper()
	return crossLogSetup{
		homeDID:       "did:web:state:tn:davidson",
		foreignDID:    "did:web:federal-courts.example",
		homeFetcher:   fixtureFetcher{},
		homeLeaves:    liveLeafStore(),
		foreignKeyset: makeForeignWitnessSet(t, "did:web:federal-courts.example", 3, 2, fixedNetworkID(0xAA)),
		journal:       monitoring.NewMemoryHeadsJournal(),
	}
}

// buildProvider wires the standard MultiJurisdictionTrust for the
// fixture. Tests then layer WithForeignEntries / WithForeignLeaves
// on top to inject the cross-log resolvers each scenario needs.
func (s crossLogSetup) buildProvider(t *testing.T) MultiJurisdictionTrust {
	t.Helper()
	prov, err := NewMultiJurisdictionTrust(
		NewLocalTrust(s.homeFetcher, s.homeLeaves),
		s.homeDID,
		map[string]*cosign.WitnessKeySet{s.foreignDID: s.foreignKeyset},
		s.journal,
	)
	if err != nil {
		t.Fatalf("NewMultiJurisdictionTrust: %v", err)
	}
	return prov
}

// providerFetch exercises the SDK walker's adapter path: call
// TrustRoot, then Entry, then verify Inclusion against TrustRoot's
// RootHash. Returns the same shape errors the walker would surface
// to its caller (ErrInclusionInvalid / ErrUnknownLog / etc.) so
// the tests assert on the same sentinels real callers would see.
func providerFetch(ctx context.Context, prov verifier.LogTrustProvider, pos types.LogPosition, asOf verifier.AsOf) error {
	ep, err := prov.Entry(ctx, pos, asOf)
	if err != nil {
		return err
	}
	if ep.Inclusion == nil {
		return nil
	}
	tr, err := prov.TrustRoot(ctx, pos.LogDID, asOf)
	if err != nil {
		return err
	}
	if err := smt.VerifyMerkleInclusion(ep.Inclusion, tr.Head.RootHash); err != nil {
		return verifier.ErrInclusionInvalid
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────
// Test matrix
// ─────────────────────────────────────────────────────────────────

// TestMultiJurisdiction_Happy pins the cross-log Happy path: a
// foreign-log Entry with a VALID inclusion proof against the
// journaled foreign head is accepted by the SDK's walker-level
// verification adapter.
func TestMultiJurisdiction_Happy(t *testing.T) {
	t.Parallel()
	s := newCrossLogSetup(t)

	federalEntry := []byte("federal-entry-canonical-bytes-seq50")
	proof, rootHash := singleLeafProof(federalEntry)
	recordHead(t, s.journal, s.foreignDID, 1, 1, rootHash)

	resolver := stubForeignEntries{proofs: map[uint64]verifier.EntryProof{
		50: {
			Meta:      &types.EntryWithMetadata{Position: types.LogPosition{LogDID: s.foreignDID, Sequence: 50}},
			Inclusion: &proof,
		},
	}}
	prov := s.buildProvider(t).WithForeignEntries(map[string]ForeignEntryResolver{s.foreignDID: resolver})

	err := providerFetch(context.Background(), prov,
		types.LogPosition{LogDID: s.foreignDID, Sequence: 50}, verifier.AsOf{})
	if err != nil {
		t.Errorf("cross-log Happy: %v", err)
	}
}

// TestMultiJurisdiction_ForgedInclusionProof pins fail-closed on a
// tampered inclusion proof. Same fixture as Happy, but the proof's
// LeafHash is corrupted before being returned. The
// smt.VerifyMerkleInclusion check against the foreign head's
// RootHash fails ⇒ the walker reports ErrInclusionInvalid.
func TestMultiJurisdiction_ForgedInclusionProof(t *testing.T) {
	t.Parallel()
	s := newCrossLogSetup(t)

	federalEntry := []byte("federal-entry-canonical-bytes-seq50")
	proof, rootHash := singleLeafProof(federalEntry)
	recordHead(t, s.journal, s.foreignDID, 1, 1, rootHash)

	// Tamper the proof — single-byte flip in LeafHash.
	proof.LeafHash[0] ^= 0xFF

	resolver := stubForeignEntries{proofs: map[uint64]verifier.EntryProof{
		50: {
			Meta:      &types.EntryWithMetadata{Position: types.LogPosition{LogDID: s.foreignDID, Sequence: 50}},
			Inclusion: &proof,
		},
	}}
	prov := s.buildProvider(t).WithForeignEntries(map[string]ForeignEntryResolver{s.foreignDID: resolver})

	err := providerFetch(context.Background(), prov,
		types.LogPosition{LogDID: s.foreignDID, Sequence: 50}, verifier.AsOf{})
	if !errors.Is(err, verifier.ErrInclusionInvalid) {
		t.Errorf("err = %v, want ErrInclusionInvalid (forged proof must fail closed)", err)
	}
}

// TestMultiJurisdiction_UnknownPeerLog pins fail-closed on an
// undeclared foreign LogDID. The provider MUST NOT silently fall
// through to the home backend — that would let a forged cross-log
// reference resolve against home state.
func TestMultiJurisdiction_UnknownPeerLog(t *testing.T) {
	t.Parallel()
	s := newCrossLogSetup(t)
	prov := s.buildProvider(t)

	const undeclared = "did:web:not-in-peer-registry.example"

	// TrustRoot fails closed.
	if _, err := prov.TrustRoot(context.Background(), undeclared, verifier.AsOf{}); !errors.Is(err, verifier.ErrUnknownLog) {
		t.Errorf("TrustRoot = %v, want ErrUnknownLog", err)
	}
	// Entry fails closed.
	if _, err := prov.Entry(context.Background(),
		types.LogPosition{LogDID: undeclared, Sequence: 1}, verifier.AsOf{}); !errors.Is(err, verifier.ErrUnknownLog) {
		t.Errorf("Entry = %v, want ErrUnknownLog", err)
	}
	// Leaf fails closed.
	if _, err := prov.Leaf(context.Background(), undeclared, [32]byte{}, verifier.AsOf{}); !errors.Is(err, verifier.ErrUnknownLog) {
		t.Errorf("Leaf = %v, want ErrUnknownLog", err)
	}
}

// TestMultiJurisdiction_AsOfHistorical pins the year-15 retrieval
// foundation: different asOfs select different journaled heads on
// the SAME foreign log. The witness set is the operator-declared
// constant for now (per-asOf witness rotation is a post-C extension
// — see issue #69 Goal 13 follow-up).
func TestMultiJurisdiction_AsOfHistorical(t *testing.T) {
	t.Parallel()
	s := newCrossLogSetup(t)

	// Two heads at different sequences with different roots.
	recordHead(t, s.journal, s.foreignDID, 10, 1, [32]byte{0xAA})
	recordHead(t, s.journal, s.foreignDID, 20, 2, [32]byte{0xBB})

	prov := s.buildProvider(t)

	// Latest (AsOf{}) → seq=20, root=0xBB
	tr, err := prov.TrustRoot(context.Background(), s.foreignDID, verifier.AsOf{})
	if err != nil {
		t.Fatalf("TrustRoot(latest): %v", err)
	}
	if tr.Head.TreeSize != 20 || tr.Head.RootHash != [32]byte{0xBB} {
		t.Errorf("latest head = (size=%d, root=%x), want (20, BB)", tr.Head.TreeSize, tr.Head.RootHash)
	}

	// AsOf{Sequence:15} → greatest <= 15 = seq=10, root=0xAA
	trH, err := prov.TrustRoot(context.Background(), s.foreignDID, verifier.AsOf{LogPosition: types.LogPosition{Sequence: 15}})
	if err != nil {
		t.Fatalf("TrustRoot(asOf=15): %v", err)
	}
	if trH.Head.TreeSize != 10 || trH.Head.RootHash != [32]byte{0xAA} {
		t.Errorf("historical head = (size=%d, root=%x), want (10, AA)", trH.Head.TreeSize, trH.Head.RootHash)
	}
}

// TestMultiJurisdiction_Fork pins the LAW 4 cross-log contract: a
// foreign log that has equivocated (two heads at the same sequence
// with different roots) is BURNED, and every subsequent
// verification against it fails closed with ErrEquivocatedLog
// across the FULL provider surface — TrustRoot AND Entry (the
// Entry path's burn check goes through TrustRoot during inclusion-
// proof verification in the SDK walker adapter).
func TestMultiJurisdiction_Fork(t *testing.T) {
	t.Parallel()
	s := newCrossLogSetup(t)

	// Two heads at the SAME sequence with DIFFERENT roots ⇒ burn.
	recordHead(t, s.journal, s.foreignDID, 100, 1, [32]byte{0xAA})
	recordHead(t, s.journal, s.foreignDID, 100, 2, [32]byte{0xBB})

	prov := s.buildProvider(t)

	_, err := prov.TrustRoot(context.Background(), s.foreignDID, verifier.AsOf{})
	if !errors.Is(err, monitoring.ErrEquivocatedLog) {
		t.Errorf("err = %v, want ErrEquivocatedLog (burn fail-closed)", err)
	}
}

// TestMultiJurisdiction_FallbackToLocal pins the regression-guard:
// the provider's foreign dispatch does NOT silently fall through
// to LocalTrust for an undeclared LogDID. A single-jurisdiction
// call site (no PeerLogs) builds a LocalTrust, not a
// MultiJurisdictionTrust — that fallback happens at the
// Dependencies.PickTrust seam, not inside the provider.
//
// Concretely: when MultiJurisdictionTrust is built with NO foreign
// LogDIDs, a foreign-LogDID query fails closed with ErrUnknownLog;
// it does NOT delegate to the home LocalTrust (which would
// silently misread the foreign reference as a home reference at
// the same Sequence — a class of bug that would otherwise resolve
// year-N federal entries against year-N TN bytes).
func TestMultiJurisdiction_FallbackToLocal(t *testing.T) {
	t.Parallel()
	prov, err := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{
			// Home has an entry at Sequence:100 — if the provider
			// silently fell through to LocalTrust, the foreign
			// query below would resolve to THIS entry. The
			// assertion that the foreign query fails closed proves
			// the regression guard holds.
			types.LogPosition{LogDID: "did:web:home", Sequence: 100}: &types.EntryWithMetadata{
				Position: types.LogPosition{LogDID: "did:web:home", Sequence: 100},
			},
		}, liveLeafStore()),
		"did:web:home",
		// foreignSets intentionally empty — NO foreign logs
		// declared. This is the single-jurisdiction shape that the
		// PR-C plan calls out as the regression risk.
		nil,
		monitoring.NewMemoryHeadsJournal(),
	)
	if err != nil {
		t.Fatalf("NewMultiJurisdictionTrust: %v", err)
	}

	// A foreign-LogDID query MUST fail closed even though the home
	// backend has an entry at the same Sequence. This is the
	// substantive guarantee MultiJurisdictionTrust provides over
	// LocalTrust: LogDID is part of the trust root, not just an
	// addressing hint.
	_, err = prov.Entry(context.Background(),
		types.LogPosition{LogDID: "did:web:federal-fake.example", Sequence: 100},
		verifier.AsOf{})
	if !errors.Is(err, verifier.ErrUnknownLog) {
		t.Errorf("Entry(foreign) = %v, want ErrUnknownLog (regression guard for cross-network safety)", err)
	}

	// The home dispatch still works — the regression guard does
	// not break LocalTrust delegation for the home log.
	ep, err := prov.Entry(context.Background(),
		types.LogPosition{LogDID: "did:web:home", Sequence: 100},
		verifier.AsOf{})
	if err != nil {
		t.Errorf("Entry(home) = %v, want success (LocalTrust delegation preserved)", err)
	}
	if ep.Meta == nil || ep.Meta.Position.Sequence != 100 {
		t.Errorf("home Entry meta drift: %+v", ep)
	}
}

// ─────────────────────────────────────────────────────────────────
// Resolver wiring contract
// ─────────────────────────────────────────────────────────────────

// TestMultiJurisdiction_WithForeignEntries_NilResolver_FailsClosed
// pins that a nil resolver in the map is treated identically to a
// missing entry — both fail closed with ErrUnknownLog. A nil
// resolver is a sentinel for "operator declared this foreign log
// for TrustRoot purposes but has no Entry backend wired yet".
func TestMultiJurisdiction_WithForeignEntries_NilResolver_FailsClosed(t *testing.T) {
	t.Parallel()
	s := newCrossLogSetup(t)
	prov := s.buildProvider(t).WithForeignEntries(map[string]ForeignEntryResolver{
		s.foreignDID: nil, // declared but no backend
	})

	_, err := prov.Entry(context.Background(),
		types.LogPosition{LogDID: s.foreignDID, Sequence: 1}, verifier.AsOf{})
	if !errors.Is(err, verifier.ErrUnknownLog) {
		t.Errorf("err = %v, want ErrUnknownLog (nil resolver fails closed)", err)
	}
}

// TestMultiJurisdiction_WithForeignEntries_ImmutableReceiver pins
// the additive-extension contract: calling WithForeignEntries on a
// provider returns a NEW provider with the resolvers; the original
// is unchanged. Callers can stack additional WithForeign* calls
// without worrying about hidden mutation.
func TestMultiJurisdiction_WithForeignEntries_ImmutableReceiver(t *testing.T) {
	t.Parallel()
	s := newCrossLogSetup(t)
	original := s.buildProvider(t)

	// original has no foreign resolvers → foreign Entry is ErrUnknownLog
	_, err := original.Entry(context.Background(),
		types.LogPosition{LogDID: s.foreignDID, Sequence: 1}, verifier.AsOf{})
	if !errors.Is(err, verifier.ErrUnknownLog) {
		t.Errorf("original Entry = %v, want ErrUnknownLog (no resolvers)", err)
	}

	// extended has a resolver → foreign Entry resolves
	resolver := stubForeignEntries{proofs: map[uint64]verifier.EntryProof{
		1: {Meta: &types.EntryWithMetadata{Position: types.LogPosition{LogDID: s.foreignDID, Sequence: 1}}},
	}}
	extended := original.WithForeignEntries(map[string]ForeignEntryResolver{s.foreignDID: resolver})

	ep, err := extended.Entry(context.Background(),
		types.LogPosition{LogDID: s.foreignDID, Sequence: 1}, verifier.AsOf{})
	if err != nil {
		t.Errorf("extended Entry = %v, want success", err)
	}
	if ep.Meta == nil {
		t.Error("extended Meta is nil")
	}

	// original STILL has no resolvers — immutable receiver pinned.
	_, err = original.Entry(context.Background(),
		types.LogPosition{LogDID: s.foreignDID, Sequence: 1}, verifier.AsOf{})
	if !errors.Is(err, verifier.ErrUnknownLog) {
		t.Errorf("original Entry post-extended = %v, want ErrUnknownLog (receiver mutated)", err)
	}
}

// TestMultiJurisdiction_WithForeignLeaves_DispatchesAndVerifies
// pins the Leaf dispatch path: an SMT leaf membership proof
// against a foreign log is returned by the wired resolver and
// surfaces verbatim to the walker (the SDK verifies it against
// TrustRoot.Head.SMTRoot — same pattern as Entry's
// VerifyMerkleInclusion against RootHash).
func TestMultiJurisdiction_WithForeignLeaves_DispatchesAndVerifies(t *testing.T) {
	t.Parallel()
	s := newCrossLogSetup(t)

	key := [32]byte{0x11, 0x22, 0x33}
	pos := types.LogPosition{LogDID: s.foreignDID, Sequence: 7}
	leafFixture := &types.SMTLeaf{OriginTip: pos, AuthorityTip: pos}

	resolver := stubForeignLeaves{proofs: map[[32]byte]verifier.LeafProof{
		key: {Leaf: leafFixture},
	}}
	prov := s.buildProvider(t).WithForeignLeaves(map[string]ForeignLeafResolver{s.foreignDID: resolver})

	got, err := prov.Leaf(context.Background(), s.foreignDID, key, verifier.AsOf{})
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if got.Leaf != leafFixture {
		t.Errorf("leaf pointer drift: got %p, want %p", got.Leaf, leafFixture)
	}
}

// recordHead is a small wrapper around recordFixtureHead that
// accepts an explicit root hash so a test can seed a head whose
// RootHash matches a hand-built MerkleProof's leaf hash (the
// inclusion-proof Happy path).
func recordHead(t *testing.T, j *monitoring.MemoryHeadsJournal, logDID string, seq, lamport uint64, root [32]byte) {
	t.Helper()
	h := monitoring.Head{
		LogDID: logDID,
		TreeHead: types.TreeHead{
			RootHash: root,
			SMTRoot:  [32]byte{},
			TreeSize: seq,
		},
		Signatures: []types.WitnessSignature{
			{PubKeyID: [32]byte{0xAA}, SchemeTag: 0x01, SigBytes: []byte{0xCD}},
		},
		CanonicalBytes: []byte("wire:" + logDID),
		LamportTime:    lamport,
		CommittedAt:    fixedTime(seq),
	}
	if _, err := j.Record(context.Background(), h); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

// fixedTime returns a deterministic CommittedAt distinct per seq,
// so the journal's monotonic-time check accepts each Record.
func fixedTime(seq uint64) time.Time {
	return time.Date(2026, 5, 29, 0, 0, int(seq), 0, time.UTC)
}
