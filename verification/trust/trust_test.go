// Package trust tests for LocalTrust.
//
// The load-bearing assertions in this file are the parity tests
// against the SDK's legacy single-reader walkers:
//
//   TestLocalTrust_LegacyParity_EvaluateAuthority
//   TestLocalTrust_LegacyParity_VerifyDelegationProvenance
//
// They construct identical (fetcher, leafReader) inputs and assert
// that:
//
//   verifier.EvaluateAuthority(ctx, key, leaf, fetcher, ext) ==
//   verifier.EvaluateAuthorityWithTrust(ctx, entity, NewLocalTrust(fetcher, leaf),
//                                       ext, verifier.AsOf{})
//
//   verifier.VerifyDelegationProvenance(ctx, ptrs, fetcher, leaf) ==
//   verifier.VerifyDelegationProvenanceWithTrust(ctx, ptrs, NewLocalTrust(fetcher, leaf),
//                                                verifier.AsOf{})
//
// If the SDK ever changes its SingleLog/WithTrust contract such
// that these stop being equal, the parity test surfaces it before
// any JN handler regressions ship.
package trust

import (
	"context"
	"reflect"
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
// PARITY TESTS — the load-bearing contract
// ─────────────────────────────────────────────────────────────────────

// TestLocalTrust_LegacyParity_EvaluateAuthority pins that
// verifier.EvaluateAuthority(ctx, key, leaf, fetcher, ext) and
// verifier.EvaluateAuthorityWithTrust(ctx, entity, LocalTrust{F,L}, ext, AsOf{})
// return equivalent results. This is the post-migration regression
// guard for compliance.go, sealing_check.go, verify_authority.go,
// verify_batch.go.
//
// Uses the SDK-shipped "base case" of an entity with no active
// constraints — the simplest input that exercises both walkers'
// happy path. A richer fixture (full delegation chain) would not
// add coverage at the parity boundary; the SDK's own
// TestEvalAuthWithTrust_LegacyParity already pins the deep-shape
// equivalence.
//nolint:staticcheck // SA1019 — intentionally exercises the deprecated entry point to lock parity
func TestLocalTrust_LegacyParity_EvaluateAuthority(t *testing.T) {
	entity := types.LogPosition{LogDID: "did:web:logs.example.gov", Sequence: 1}
	leafKey := smt.DeriveKey(entity)
	leaf := liveLeafStore(entity)
	fetcher := fixtureFetcher{}

	legacy, errLegacy := verifier.EvaluateAuthority(
		context.Background(), leafKey, leaf, fetcher, nil)
	withTrust, errWithTrust := verifier.EvaluateAuthorityWithTrust(
		context.Background(), entity,
		NewLocalTrust(fetcher, leaf), nil, verifier.AsOf{})

	if (errLegacy == nil) != (errWithTrust == nil) {
		t.Fatalf("error parity broken: legacy=%v withTrust=%v", errLegacy, errWithTrust)
	}
	if errLegacy != nil {
		// Both errored — that's the parity. Specific message text is
		// the SDK's contract and we deliberately don't pin it here.
		return
	}
	if !reflect.DeepEqual(legacy, withTrust) {
		t.Fatalf("AuthorityEvaluation parity broken\n  legacy:   %+v\n  withTrust: %+v",
			legacy, withTrust)
	}
}

// TestLocalTrust_LegacyParity_VerifyDelegationProvenance is the
// post-migration regression guard for delegation_chain.go.
//
//nolint:staticcheck // SA1019 — intentionally exercises the deprecated entry point to lock parity
func TestLocalTrust_LegacyParity_VerifyDelegationProvenance(t *testing.T) {
	// Two pointers, both reporting live leaves. With no actual entry
	// bodies in the fetcher, the SDK's walker reports each hop as
	// not-live (no entry to inspect), but parity holds — both walkers
	// reach the same not-live verdict via the same code paths.
	ptrs := []types.LogPosition{
		{LogDID: "did:web:logs.example.gov", Sequence: 10},
		{LogDID: "did:web:logs.example.gov", Sequence: 11},
	}
	leaf := liveLeafStore(ptrs...)
	fetcher := fixtureFetcher{}

	legacy, errLegacy := verifier.VerifyDelegationProvenance(
		context.Background(), ptrs, fetcher, leaf)
	withTrust, errWithTrust := verifier.VerifyDelegationProvenanceWithTrust(
		context.Background(), ptrs,
		NewLocalTrust(fetcher, leaf), verifier.AsOf{})

	if (errLegacy == nil) != (errWithTrust == nil) {
		t.Fatalf("error parity broken: legacy=%v withTrust=%v", errLegacy, errWithTrust)
	}
	if errLegacy != nil {
		return
	}
	if !reflect.DeepEqual(legacy, withTrust) {
		t.Fatalf("[]DelegationHop parity broken\n  legacy:    %+v\n  withTrust: %+v",
			legacy, withTrust)
	}
}

// TestLocalTrust_LegacyParity_EmptyPointers — the trivial case the
// SDK explicitly documents (nil, nil for an empty input). Locks it
// across the migration boundary.
//
//nolint:staticcheck // SA1019 — intentionally exercises the deprecated entry point to lock parity
func TestLocalTrust_LegacyParity_EmptyPointers(t *testing.T) {
	leaf := liveLeafStore()
	fetcher := fixtureFetcher{}

	legacy, errLegacy := verifier.VerifyDelegationProvenance(
		context.Background(), nil, fetcher, leaf)
	withTrust, errWithTrust := verifier.VerifyDelegationProvenanceWithTrust(
		context.Background(), nil,
		NewLocalTrust(fetcher, leaf), verifier.AsOf{})

	if errLegacy != nil || errWithTrust != nil {
		t.Fatalf("empty input must not error: legacy=%v withTrust=%v",
			errLegacy, errWithTrust)
	}
	if legacy != nil || withTrust != nil {
		t.Fatalf("empty input must return nil slice: legacy=%v withTrust=%v",
			legacy, withTrust)
	}
}
