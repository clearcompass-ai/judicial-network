// MultiJurisdictionTrust tests.
//
// Pins the C-3 contract: a cross-network LogTrustProvider that
// dispatches by LogDID — home → LocalTrust delegation, foreign →
// journal-resolved head + pre-declared WitnessKeySet, unknown →
// ErrUnknownLog (STRICT FAIL-CLOSED).
//
// LAW 4 (burn fail-closed) is pinned by
// TestMultiTrust_TrustRoot_Foreign_Burned_FailsClosed.
package trust

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/attesta-tools/libs/crosslog"
	"github.com/clearcompass-ai/attesta-tools/libs/monitoring"
)

// ─────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────

// makeForeignWitnessSet builds a single-log witness keyset bound to
// the supplied NetworkID. It is the same shape the foreign gossip
// pipeline binds its GossipVerifier to (see cmd/network-api/
// gossip_reconciler.go:buildForeignPipeline).
func makeForeignWitnessSet(t *testing.T, logDID string, n, k int, nid cosign.NetworkID) *cosign.WitnessKeySet {
	t.Helper()
	ws := make([]string, n)
	for i := 0; i < n; i++ {
		kp, err := did.GenerateDIDKeySecp256k1()
		if err != nil {
			t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
		}
		ws[i] = kp.DID
	}
	out, err := crosslog.BuildWitnessSetsECDSAOnly([]crosslog.WitnessSetSpec{
		{LogDID: logDID, WitnessDIDs: ws, QuorumK: k},
	}, nid)
	if err != nil {
		t.Fatalf("BuildWitnessSetsECDSAOnly: %v", err)
	}
	return out[logDID]
}

// fixedNetworkID returns a deterministic NetworkID for tests.
func fixedNetworkID(seed byte) cosign.NetworkID {
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = seed
	}
	return nid
}

// recordFixtureHead writes a verified head into the journal under
// logDID at the given sequence + Lamport time. Used to seed the
// journal for TrustRoot resolution tests.
func recordFixtureHead(t *testing.T, j *monitoring.MemoryHeadsJournal, logDID string, seq, lamport uint64, rootSeed byte) monitoring.Head {
	t.Helper()
	h := monitoring.Head{
		LogDID: logDID,
		TreeHead: types.TreeHead{
			RootHash: [32]byte{rootSeed},
			SMTRoot:  [32]byte{rootSeed ^ 0xFF},
			TreeSize: seq,
		},
		Signatures: []types.WitnessSignature{
			{PubKeyID: [32]byte{0xAA, rootSeed}, SchemeTag: 0x01, SigBytes: []byte{0xCD, rootSeed}},
		},
		CanonicalBytes: []byte("wire:" + logDID),
		LamportTime:    lamport,
		CommittedAt:    time.Date(2026, 5, 29, 0, 0, int(seq), 0, time.UTC),
	}
	if _, err := j.Record(context.Background(), h); err != nil {
		t.Fatalf("Record: %v", err)
	}
	return h
}

// ─────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────

// TestNewMultiJurisdictionTrust_HappyPath pins that a fully-wired
// constructor returns a non-zero provider that satisfies the SDK
// interface.
func TestNewMultiJurisdictionTrust_HappyPath(t *testing.T) {
	t.Parallel()
	const homeDID = "did:web:state:tn:davidson"
	const foreignDID = "did:web:federal-courts.example"

	prov, err := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore()),
		homeDID,
		map[string]*cosign.WitnessKeySet{
			foreignDID: makeForeignWitnessSet(t, foreignDID, 3, 2, fixedNetworkID(0xAA)),
		},
		monitoring.NewMemoryHeadsJournal(),
	)
	if err != nil {
		t.Fatalf("NewMultiJurisdictionTrust: %v", err)
	}
	var _ verifier.LogTrustProvider = prov
}

// TestNewMultiJurisdictionTrust_EmptyHomeDID_Rejected pins the
// fail-fast contract: homeLogDID is the dispatch key, an empty
// value would route every TrustRoot lookup to LocalTrust silently.
func TestNewMultiJurisdictionTrust_EmptyHomeDID_Rejected(t *testing.T) {
	t.Parallel()
	_, err := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore()),
		"", // empty home
		nil,
		monitoring.NewMemoryHeadsJournal(),
	)
	if !errors.Is(err, ErrMultiTrustConfig) {
		t.Errorf("err = %v, want ErrMultiTrustConfig", err)
	}
}

// TestNewMultiJurisdictionTrust_NilForeignKeyset_Rejected pins that
// a declared foreign log without a witness set is a boot-failing
// misconfiguration (it could never be verified against, so deferring
// the failure to TrustRoot would be a silent fail-closed).
func TestNewMultiJurisdictionTrust_NilForeignKeyset_Rejected(t *testing.T) {
	t.Parallel()
	_, err := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore()),
		"did:web:home",
		map[string]*cosign.WitnessKeySet{
			"did:web:foreign": nil, // nil keyset
		},
		monitoring.NewMemoryHeadsJournal(),
	)
	if !errors.Is(err, ErrMultiTrustConfig) {
		t.Errorf("err = %v, want ErrMultiTrustConfig", err)
	}
}

// TestNewMultiJurisdictionTrust_HomeDIDCollision_Rejected pins that
// a foreign-log entry that collides with the home LogDID is a boot-
// failing misconfiguration (the foreign keyset would shadow the
// home LocalTrust resolution).
func TestNewMultiJurisdictionTrust_HomeDIDCollision_Rejected(t *testing.T) {
	t.Parallel()
	const did = "did:web:home"
	_, err := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore()),
		did,
		map[string]*cosign.WitnessKeySet{
			did: makeForeignWitnessSet(t, did, 2, 1, fixedNetworkID(0xAA)),
		},
		monitoring.NewMemoryHeadsJournal(),
	)
	if !errors.Is(err, ErrMultiTrustConfig) {
		t.Errorf("err = %v, want ErrMultiTrustConfig", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// TrustRoot — HOME log
// ─────────────────────────────────────────────────────────────────

// TestMultiTrust_TrustRoot_Home_DelegatesToLocal pins that calls
// for the home LogDID route to LocalTrust verbatim — preserves the
// byte-for-byte parity guarantee the C-1 → C-4 migration depends on.
func TestMultiTrust_TrustRoot_Home_DelegatesToLocal(t *testing.T) {
	t.Parallel()
	const homeDID = "did:web:state:tn:davidson"
	local := NewLocalTrust(fixtureFetcher{}, liveLeafStore())
	prov, err := NewMultiJurisdictionTrust(local, homeDID, nil, monitoring.NewMemoryHeadsJournal())
	if err != nil {
		t.Fatalf("NewMultiJurisdictionTrust: %v", err)
	}
	got, err := prov.TrustRoot(context.Background(), homeDID, verifier.AsOf{})
	if err != nil {
		t.Fatalf("TrustRoot(home): %v", err)
	}
	// LocalTrust returns zero WitnessSet + zero Head — the surface
	// is permissive (SingleLog never errors).
	if got.WitnessSet != nil {
		t.Errorf("home WitnessSet = %v, want nil (LocalTrust pass-through)", got.WitnessSet)
	}
	if got.Head.TreeSize != 0 {
		t.Errorf("home Head.TreeSize = %d, want 0 (LocalTrust pass-through)", got.Head.TreeSize)
	}
}

// ─────────────────────────────────────────────────────────────────
// TrustRoot — FOREIGN log
// ─────────────────────────────────────────────────────────────────

// TestMultiTrust_TrustRoot_Foreign_Latest pins the foreign LATEST
// path: TrustRoot with AsOf{} returns the journal's LatestHead +
// the pre-declared keyset.
func TestMultiTrust_TrustRoot_Foreign_Latest(t *testing.T) {
	t.Parallel()
	const homeDID = "did:web:state:tn:davidson"
	const foreignDID = "did:web:federal-courts.example"

	journal := monitoring.NewMemoryHeadsJournal()
	// Seed two heads at sequences 10 and 20 — latest is 20.
	_ = recordFixtureHead(t, journal, foreignDID, 10, 1, 0xAA)
	want := recordFixtureHead(t, journal, foreignDID, 20, 2, 0xBB)

	foreignKS := makeForeignWitnessSet(t, foreignDID, 3, 2, fixedNetworkID(0xAA))
	prov, _ := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore()),
		homeDID,
		map[string]*cosign.WitnessKeySet{foreignDID: foreignKS},
		journal,
	)
	got, err := prov.TrustRoot(context.Background(), foreignDID, verifier.AsOf{})
	if err != nil {
		t.Fatalf("TrustRoot(foreign, latest): %v", err)
	}
	if got.WitnessSet != foreignKS {
		t.Errorf("WitnessSet pointer drift")
	}
	if got.Head.TreeSize != want.TreeSize || got.Head.RootHash != want.RootHash {
		t.Errorf("Head = %+v, want %+v", got.Head, want.TreeHead)
	}
}

// TestMultiTrust_TrustRoot_Foreign_HistoricalAsOf pins the foreign
// AS-OF path: TrustRoot with AsOf.Sequence = 15 returns the head
// whose sequence is the greatest <= 15 (i.e., 10) — the monotonic
// asOf contract every JN call site relies on.
func TestMultiTrust_TrustRoot_Foreign_HistoricalAsOf(t *testing.T) {
	t.Parallel()
	const homeDID = "did:web:state:tn:davidson"
	const foreignDID = "did:web:federal-courts.example"

	journal := monitoring.NewMemoryHeadsJournal()
	want := recordFixtureHead(t, journal, foreignDID, 10, 1, 0xAA)
	_ = recordFixtureHead(t, journal, foreignDID, 20, 2, 0xBB)

	foreignKS := makeForeignWitnessSet(t, foreignDID, 3, 2, fixedNetworkID(0xAA))
	prov, _ := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore()),
		homeDID,
		map[string]*cosign.WitnessKeySet{foreignDID: foreignKS},
		journal,
	)
	got, err := prov.TrustRoot(context.Background(), foreignDID, verifier.AsOf{Sequence: 15})
	if err != nil {
		t.Fatalf("TrustRoot(foreign, asOf=15): %v", err)
	}
	if got.Head.TreeSize != want.TreeSize {
		t.Errorf("Head.TreeSize = %d, want %d (greatest <= asOf 15)", got.Head.TreeSize, want.TreeSize)
	}
}

// TestMultiTrust_TrustRoot_Foreign_NoHead_FailsClosed pins the
// no-head fail-closed path: a foreign log that's declared but has
// no journaled head returns the journal's ErrNoHead — the walker
// MUST NOT default to the home log.
func TestMultiTrust_TrustRoot_Foreign_NoHead_FailsClosed(t *testing.T) {
	t.Parallel()
	const homeDID = "did:web:state:tn:davidson"
	const foreignDID = "did:web:federal-courts.example"

	foreignKS := makeForeignWitnessSet(t, foreignDID, 3, 2, fixedNetworkID(0xAA))
	prov, _ := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore()),
		homeDID,
		map[string]*cosign.WitnessKeySet{foreignDID: foreignKS},
		monitoring.NewMemoryHeadsJournal(), // empty journal
	)
	_, err := prov.TrustRoot(context.Background(), foreignDID, verifier.AsOf{})
	if !errors.Is(err, monitoring.ErrNoHead) {
		t.Errorf("err = %v, want ErrNoHead", err)
	}
}

// TestMultiTrust_TrustRoot_Foreign_Burned_FailsClosed pins the LAW
// 4 contract: a burned foreign log (observed equivocation)
// surfaces monitoring.ErrEquivocatedLog from TrustRoot — no asOf
// can resolve a burned log until governance acts (Decision 5:
// STRICT FAIL-CLOSED).
func TestMultiTrust_TrustRoot_Foreign_Burned_FailsClosed(t *testing.T) {
	t.Parallel()
	const homeDID = "did:web:state:tn:davidson"
	const foreignDID = "did:web:federal-courts.example"

	journal := monitoring.NewMemoryHeadsJournal()
	// Two heads at the SAME sequence with DIFFERENT roots ⇒
	// equivocation ⇒ burn.
	_ = recordFixtureHead(t, journal, foreignDID, 100, 1, 0xAA)
	_ = recordFixtureHead(t, journal, foreignDID, 100, 2, 0xBB)

	foreignKS := makeForeignWitnessSet(t, foreignDID, 3, 2, fixedNetworkID(0xAA))
	prov, _ := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore()),
		homeDID,
		map[string]*cosign.WitnessKeySet{foreignDID: foreignKS},
		journal,
	)
	_, err := prov.TrustRoot(context.Background(), foreignDID, verifier.AsOf{})
	if !errors.Is(err, monitoring.ErrEquivocatedLog) {
		t.Errorf("err = %v, want ErrEquivocatedLog (burn fail-closed)", err)
	}
}

// TestMultiTrust_TrustRoot_UnknownLog_FailsClosed pins the unknown-
// log fail-closed: a LogDID that is neither home nor in foreignSets
// returns verifier.ErrUnknownLog (the SDK sentinel).
func TestMultiTrust_TrustRoot_UnknownLog_FailsClosed(t *testing.T) {
	t.Parallel()
	prov, _ := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore()),
		"did:web:home",
		nil,
		monitoring.NewMemoryHeadsJournal(),
	)
	_, err := prov.TrustRoot(context.Background(), "did:web:not-declared", verifier.AsOf{})
	if !errors.Is(err, verifier.ErrUnknownLog) {
		t.Errorf("err = %v, want ErrUnknownLog", err)
	}
}

// TestMultiTrust_TrustRoot_Foreign_NilJournal_FailsClosed pins the
// degenerate path: a foreign log declared, but the JN was booted
// without an ingest journal — must fail closed (no way to resolve
// a head).
func TestMultiTrust_TrustRoot_Foreign_NilJournal_FailsClosed(t *testing.T) {
	t.Parallel()
	const foreignDID = "did:web:federal.example"
	foreignKS := makeForeignWitnessSet(t, foreignDID, 2, 1, fixedNetworkID(0xAA))
	prov, _ := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore()),
		"did:web:home",
		map[string]*cosign.WitnessKeySet{foreignDID: foreignKS},
		nil, // no journal
	)
	_, err := prov.TrustRoot(context.Background(), foreignDID, verifier.AsOf{})
	if !errors.Is(err, verifier.ErrUnknownLog) {
		t.Errorf("err = %v, want ErrUnknownLog (nil journal)", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Entry + Leaf
// ─────────────────────────────────────────────────────────────────

// TestMultiTrust_Entry_Home_Delegates pins that Entry for the home
// LogDID routes to LocalTrust (which fetches from the home backend).
func TestMultiTrust_Entry_Home_Delegates(t *testing.T) {
	t.Parallel()
	const homeDID = "did:web:home"
	pos := types.LogPosition{LogDID: homeDID, Sequence: 42}
	want := &types.EntryWithMetadata{Position: pos}
	prov, _ := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{pos: want}, liveLeafStore()),
		homeDID,
		nil,
		monitoring.NewMemoryHeadsJournal(),
	)
	ep, err := prov.Entry(context.Background(), pos, verifier.AsOf{})
	if err != nil {
		t.Fatalf("Entry(home): %v", err)
	}
	if ep.Meta != want {
		t.Errorf("Meta = %v, want %v", ep.Meta, want)
	}
}

// TestMultiTrust_Entry_Foreign_FailsClosed pins that a foreign log
// returns ErrUnknownLog — call sites pass inclusion proofs in
// their payload; no foreign-log fetcher is wired in C-3.
func TestMultiTrust_Entry_Foreign_FailsClosed(t *testing.T) {
	t.Parallel()
	const foreignDID = "did:web:federal.example"
	prov, _ := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore()),
		"did:web:home",
		map[string]*cosign.WitnessKeySet{
			foreignDID: makeForeignWitnessSet(t, foreignDID, 2, 1, fixedNetworkID(0xAA)),
		},
		monitoring.NewMemoryHeadsJournal(),
	)
	_, err := prov.Entry(context.Background(),
		types.LogPosition{LogDID: foreignDID, Sequence: 1}, verifier.AsOf{})
	if !errors.Is(err, verifier.ErrUnknownLog) {
		t.Errorf("err = %v, want ErrUnknownLog", err)
	}
}

// TestMultiTrust_Leaf_Home_Delegates pins that Leaf for the home
// LogDID routes to LocalTrust.
func TestMultiTrust_Leaf_Home_Delegates(t *testing.T) {
	t.Parallel()
	const homeDID = "did:web:home"
	pos := types.LogPosition{LogDID: homeDID, Sequence: 7}
	prov, _ := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore(pos)),
		homeDID,
		nil,
		monitoring.NewMemoryHeadsJournal(),
	)
	got, err := prov.Leaf(context.Background(), homeDID, smt.DeriveKey(pos), verifier.AsOf{})
	if err != nil {
		t.Fatalf("Leaf(home): %v", err)
	}
	if got.Leaf == nil {
		t.Fatal("home Leaf returned nil")
	}
}

// TestMultiTrust_Leaf_Foreign_FailsClosed pins foreign-log Leaf =
// ErrUnknownLog (same posture as Entry).
func TestMultiTrust_Leaf_Foreign_FailsClosed(t *testing.T) {
	t.Parallel()
	const foreignDID = "did:web:federal.example"
	prov, _ := NewMultiJurisdictionTrust(
		NewLocalTrust(fixtureFetcher{}, liveLeafStore()),
		"did:web:home",
		map[string]*cosign.WitnessKeySet{
			foreignDID: makeForeignWitnessSet(t, foreignDID, 2, 1, fixedNetworkID(0xAA)),
		},
		monitoring.NewMemoryHeadsJournal(),
	)
	_, err := prov.Leaf(context.Background(), foreignDID, [32]byte{}, verifier.AsOf{})
	if !errors.Is(err, verifier.ErrUnknownLog) {
		t.Errorf("err = %v, want ErrUnknownLog", err)
	}
}
