// Dependencies.PickTrust coverage.
//
// Pins the C-4 dispatch contract on the judicial side: the same
// helper every JN call site reads to choose between the C-3
// MultiJurisdictionTrust (cross-network) and a freshly-constructed
// LocalTrust (single-network fallback).
package judicial

import (
	"context"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

// stubProvider is a sentinel LogTrustProvider used to assert
// PickTrust returns the wired pointer verbatim (not a rebuilt
// LocalTrust).
type stubProvider struct{}

func (stubProvider) TrustRoot(context.Context, string, verifier.AsOf) (verifier.TrustRoot, error) {
	return verifier.TrustRoot{}, nil
}
func (stubProvider) Entry(context.Context, types.LogPosition, verifier.AsOf) (verifier.EntryProof, error) {
	return verifier.EntryProof{}, nil
}
func (stubProvider) Leaf(context.Context, string, [32]byte, verifier.AsOf) (verifier.LeafProof, error) {
	return verifier.LeafProof{}, nil
}

// stubEntryFetcher is the LocalTrust fallback's input — passed via
// deps.Fetcher to exercise the fallback construction path.
type stubEntryFetcher struct{}

func (stubEntryFetcher) Fetch(context.Context, types.LogPosition) (*types.EntryWithMetadata, error) {
	return nil, nil
}

// TestPickTrust_MultiTrustWired_ReturnsItVerbatim pins the
// cross-network deployment path: when boot built a
// MultiJurisdictionTrust (cfg.GossipIngest.PeerLogs declared), every
// call site sees the SAME provider — one trust topology across the
// 5 sites.
func TestPickTrust_MultiTrustWired_ReturnsItVerbatim(t *testing.T) {
	t.Parallel()
	stub := stubProvider{}
	d := &Dependencies{MultiTrust: stub}
	got := d.PickTrust()
	if got != verifier.LogTrustProvider(stub) {
		t.Errorf("PickTrust = %T, want the wired MultiTrust", got)
	}
}

// TestPickTrust_MultiTrustNil_FallsBackToLocalTrust pins the
// single-network path: nil MultiTrust ⇒ a freshly-constructed
// LocalTrust over deps.Fetcher + deps.LeafReader. Byte-for-byte
// equivalent to the pre-C-4 inline trust.NewLocalTrust(...) shape.
func TestPickTrust_MultiTrustNil_FallsBackToLocalTrust(t *testing.T) {
	t.Parallel()
	d := &Dependencies{
		Fetcher:    stubEntryFetcher{},
		LeafReader: smt.NewInMemoryLeafStore(),
		// MultiTrust intentionally nil.
	}
	got := d.PickTrust()
	if got == nil {
		t.Fatal("PickTrust returned nil; LocalTrust fallback expected")
	}
	if _, ok := got.(stubProvider); ok {
		t.Error("PickTrust returned the stub when MultiTrust was nil — fallback path bypassed")
	}
}
