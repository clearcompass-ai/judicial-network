// Package trust tests for LocalTrust.
//
// These tests pin LocalTrust's three LogTrustProvider methods
// (TrustRoot, Entry, Leaf) plus its constructor + interface
// satisfaction. The pre-v1.36 *LegacyParity_* tests have been
// retired (see the "PARITY CONTRACT (historical note)" block at
// the bottom of this file) because the legacy single-reader
// walkers they compared against were deleted from the SDK in
// attesta v1.36.0.
package trust

import (
	"context"
	"testing"

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// ─────────────────────────────────────────────────────────────────────
// Test fixtures — minimal in-memory fetcher + leaf reader. They match
// the SDK's own SingleLog test fixtures so the parity contract is
// exercised against the same shapes the SDK uses internally.
// ─────────────────────────────────────────────────────────────────────

type fixtureFetcher map[types.LogPosition]*types.EntryWithMetadata

func (f fixtureFetcher) Fetch(_ context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	if e, ok := f[pos]; ok {
		return e, nil
	}
	return nil, nil
}

// liveLeafStore returns a LeafReader where every supplied position is
// reported "live" — OriginTip == Position. The SDK's authority walker
// treats anything else as revoked.
func liveLeafStore(positions ...types.LogPosition) smt.LeafReader {
	store := smt.NewInMemoryLeafStore()
	for _, p := range positions {
		key := smt.DeriveKey(p)
		_ = store.Set(context.Background(), key, types.SMTLeaf{
			OriginTip:    p,
			AuthorityTip: p,
		})
	}
	return store
}

// ─────────────────────────────────────────────────────────────────────
// Constructor + interface satisfaction
// ─────────────────────────────────────────────────────────────────────

func TestNewLocalTrust_SatisfiesLogTrustProvider(t *testing.T) {
	// Compile-time check is at trust.go's package var; this is the
	// runtime confirmation that NewLocalTrust returns a value of the
	// expected type with the expected method set.
	t.Helper()
	var prov verifier.LogTrustProvider = NewLocalTrust(fixtureFetcher{}, liveLeafStore())
	if prov == nil {
		t.Fatal("NewLocalTrust returned a nil LogTrustProvider")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Method coverage
// ─────────────────────────────────────────────────────────────────────

func TestLocalTrust_TrustRoot_NeverErrors(t *testing.T) {
	prov := NewLocalTrust(fixtureFetcher{}, liveLeafStore())
	// LocalTrust wraps SingleLog which is permissive: TrustRoot
	// never fails. Surfacing that contract in a JN-side test makes
	// the assumption explicit (and audit-traceable) for handlers
	// that fan out to multiple providers in the future.
	root, err := prov.TrustRoot(context.Background(), "did:web:any.example.gov", verifier.AsOf{})
	if err != nil {
		t.Fatalf("TrustRoot: %v", err)
	}
	// LocalTrust does not populate WitnessSet or Head — surfacing
	// either as non-zero would be a future incompatible change a
	// downstream caller could rely on. Pin the zero value.
	if root.WitnessSet != nil {
		t.Errorf("WitnessSet = %v, want nil", root.WitnessSet)
	}
	if root.Head.TreeSize != 0 {
		t.Errorf("Head.TreeSize = %d, want 0", root.Head.TreeSize)
	}
}

func TestLocalTrust_Entry_DelegatesToFetcher(t *testing.T) {
	pos := types.LogPosition{LogDID: "did:web:logs.example.gov", Sequence: 42}
	want := &types.EntryWithMetadata{Position: pos}
	prov := NewLocalTrust(fixtureFetcher{pos: want}, liveLeafStore())

	ep, err := prov.Entry(context.Background(), pos, verifier.AsOf{})
	if err != nil {
		t.Fatalf("Entry: %v", err)
	}
	if ep.Meta != want {
		t.Errorf("Meta = %v, want %v", ep.Meta, want)
	}
	if ep.Inclusion != nil {
		t.Errorf("Inclusion = %v, want nil (SingleLog never returns a proof)", ep.Inclusion)
	}
}

func TestLocalTrust_Entry_UnknownPos_ReturnsNilMeta(t *testing.T) {
	pos := types.LogPosition{LogDID: "did:web:logs.example.gov", Sequence: 99}
	prov := NewLocalTrust(fixtureFetcher{}, liveLeafStore())

	ep, err := prov.Entry(context.Background(), pos, verifier.AsOf{})
	if err != nil {
		t.Fatalf("Entry on unknown pos: %v", err)
	}
	// The SDK's fixture stub returns (nil, nil) on miss; SingleLog
	// passes that through. Anything else would be a SDK contract
	// change worth catching.
	if ep.Meta != nil {
		t.Errorf("Meta = %v, want nil (fetcher miss)", ep.Meta)
	}
}

func TestLocalTrust_Leaf_DelegatesToLeafReader(t *testing.T) {
	pos := types.LogPosition{LogDID: "did:web:logs.example.gov", Sequence: 7}
	prov := NewLocalTrust(fixtureFetcher{}, liveLeafStore(pos))

	lp, err := prov.Leaf(context.Background(),
		pos.LogDID, smt.DeriveKey(pos), verifier.AsOf{})
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if lp.Leaf == nil {
		t.Fatal("Leaf returned nil; expected a live leaf")
	}
	if lp.Leaf.OriginTip != pos {
		t.Errorf("OriginTip = %v, want %v", lp.Leaf.OriginTip, pos)
	}
	if lp.Membership != nil {
		t.Errorf("Membership = %v, want nil (SingleLog never returns a proof)", lp.Membership)
	}
}

// ─────────────────────────────────────────────────────────────────────
// PARITY CONTRACT (historical note)
// ─────────────────────────────────────────────────────────────────────
//
// Three TestLocalTrust_LegacyParity_* tests lived here during the
// v1.34 cutover: TestLocalTrust_LegacyParity_EvaluateAuthority,
// TestLocalTrust_LegacyParity_VerifyDelegationProvenance, and
// TestLocalTrust_LegacyParity_EmptyPointers. They constructed
// identical (fetcher, leafReader) inputs to the legacy single-
// reader walkers (verifier.EvaluateAuthority,
// verifier.VerifyDelegationProvenance) and to their *WithTrust
// counterparts fed by LocalTrust, then asserted reflect.DeepEqual
// on the result.
//
// Those tests are deleted at the v1.36 floor. The legacy entry
// points were removed from the SDK in attesta v1.36.0 (the
// follow-up the PR #66 commit message tracked); only the
// *WithTrust variants survive. The parity contract is fulfilled
// by definition: there is no longer a "legacy" to compare
// against. The 5 LocalTrust unit tests above (constructor,
// interface satisfaction, TrustRoot, Entry, Leaf) continue to pin
// every production-relevant behavior.
//
// The SDK retains its own internal regression tests
// (TestEvalAuthWithTrust_LegacyParity equivalents) that pinned the
// pre-deletion equivalence; the v1.34 → v1.36 transition is locked
// upstream.
