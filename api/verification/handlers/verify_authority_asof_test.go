// VerifyAuthorityHandler ?as_of= + PickTrust coverage.
//
// Pins the read-side surface under the attesta v1.43.0 Temporal-Anchor
// mandate (ZT-IMM-01):
//  1. asOfRequest classifies ?as_of=<seq> into a (seq, explicit) intent:
//     absent / empty / 0 ⇒ (0, false) "no pin → resolve latest"; >0 ⇒
//     (n, true) historical pin. Malformed ⇒ a 400-shaped error.
//  2. resolveAsOf turns "no explicit pin" into a SNAPSHOTTED current head
//     (a real AsOf with a RootHash) — never the zero AsOf{} the SDK now
//     rejects with ErrAsOfRequired.
//  3. Dependencies.PickTrust returns MultiTrust when wired, else falls
//     back to a freshly-constructed LocalTrust.
package handlers

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// stubLogTrust is a minimal LogTrustProvider used to verify
// PickTrust returns the SAME pointer it was wired with (not a
// rebuilt LocalTrust).
type stubLogTrust struct{}

func (stubLogTrust) TrustRoot(context.Context, string, verifier.AsOf) (verifier.TrustRoot, error) {
	return verifier.TrustRoot{}, nil
}
func (stubLogTrust) Entry(context.Context, types.LogPosition, verifier.AsOf) (verifier.EntryProof, error) {
	return verifier.EntryProof{}, nil
}
func (stubLogTrust) Leaf(context.Context, string, [32]byte, verifier.AsOf) (verifier.LeafProof, error) {
	return verifier.LeafProof{}, nil
}

// stubFetcher is the LocalTrust fallback's input — passed to
// PickTrust to verify the helper does NOT panic when MultiTrust is
// nil.
type stubFetcher struct{}

func (stubFetcher) Fetch(context.Context, types.LogPosition) (*types.EntryWithMetadata, error) {
	return nil, nil
}

// ────────────────────────────────────────────────────────────────
// parseAsOf
// ────────────────────────────────────────────────────────────────

func TestAsOfRequest_Absent_NotExplicit(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42", nil)
	seq, explicit, err := asOfRequest(r)
	if err != nil {
		t.Fatalf("asOfRequest: %v", err)
	}
	if explicit || seq != 0 {
		t.Errorf("absent as_of: got (seq=%d, explicit=%v), want (0, false)", seq, explicit)
	}
}

func TestAsOfRequest_Empty_NotExplicit(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42?as_of=", nil)
	seq, explicit, err := asOfRequest(r)
	if err != nil {
		t.Fatalf("asOfRequest: %v", err)
	}
	if explicit || seq != 0 {
		t.Errorf("empty as_of: got (seq=%d, explicit=%v), want (0, false)", seq, explicit)
	}
}

func TestAsOfRequest_Zero_NotExplicit(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42?as_of=0", nil)
	seq, explicit, err := asOfRequest(r)
	if err != nil {
		t.Fatalf("asOfRequest: %v", err)
	}
	if explicit || seq != 0 {
		t.Errorf("as_of=0: got (seq=%d, explicit=%v), want (0, false) — 0 collapses to latest", seq, explicit)
	}
}

func TestAsOfRequest_Positive_Explicit(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42?as_of=123", nil)
	seq, explicit, err := asOfRequest(r)
	if err != nil {
		t.Fatalf("asOfRequest: %v", err)
	}
	if !explicit || seq != 123 {
		t.Errorf("as_of=123: got (seq=%d, explicit=%v), want (123, true)", seq, explicit)
	}
}

func TestAsOfRequest_NonNumeric_BadAsOf(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42?as_of=notanint", nil)
	if _, _, err := asOfRequest(r); !errors.Is(err, errBadAsOf) {
		t.Errorf("err = %v, want errBadAsOf", err)
	}
}

func TestAsOfRequest_Negative_BadAsOf(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42?as_of=-5", nil)
	if _, _, err := asOfRequest(r); !errors.Is(err, errBadAsOf) {
		t.Errorf("err = %v, want errBadAsOf", err)
	}
}

// headProvider is a LogTrustProvider whose current head ResolveLatest can pin.
// (stubLogTrust above returns an empty head — TreeSize 0 — which ResolveLatest
// correctly rejects, so it cannot exercise the success path.)
type headProvider struct{ head types.CosignedTreeHead }

func (h headProvider) TrustRoot(context.Context, string, verifier.AsOf) (verifier.TrustRoot, error) {
	return verifier.TrustRoot{Head: h.head}, nil
}
func (headProvider) Entry(context.Context, types.LogPosition, verifier.AsOf) (verifier.EntryProof, error) {
	return verifier.EntryProof{}, nil
}
func (headProvider) Leaf(context.Context, string, [32]byte, verifier.AsOf) (verifier.LeafProof, error) {
	return verifier.LeafProof{}, nil
}

// TestResolveAsOf_Absent_PinsLatestHead is the load-bearing ZT-IMM-01 proof and
// the direct correction of what this file used to assert (absent ?as_of= →
// AsOf{} "latest"). Under attesta v1.43.0 a null AsOf is REJECTED by the verdict
// primitives, so resolveAsOf MUST snapshot the current head into a PINNED
// selector — a real (Sequence = TreeSize-1, RootHash), never the zero value.
func TestResolveAsOf_Absent_PinsLatestHead(t *testing.T) {
	t.Parallel()
	prov := headProvider{head: types.CosignedTreeHead{
		TreeHead: types.TreeHead{TreeSize: 20, RootHash: [32]byte{0xAB}},
	}}
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42", nil)

	asOf, err := resolveAsOf(context.Background(), r, "did:web:l", prov, nil)
	if err != nil {
		t.Fatalf("resolveAsOf: %v", err)
	}
	if asOf.IsNull() {
		t.Fatal("absent ?as_of must pin a head, not return the zero AsOf{} (ZT-IMM-01)")
	}
	if asOf.Sequence != 19 || asOf.RootHash != [32]byte{0xAB} {
		t.Errorf("AsOf = (seq=%d, root=%x), want (19, ab) — TreeSize-1 + RootHash", asOf.Sequence, asOf.RootHash)
	}
}

// ────────────────────────────────────────────────────────────────
// Dependencies.PickTrust
// ────────────────────────────────────────────────────────────────

// TestPickTrust_MultiTrustWired_ReturnsIt pins that a deployment
// with cfg.GossipIngest.PeerLogs declared (MultiTrust non-nil)
// gets the cross-network provider for EVERY handler call —
// foreign-log positions resolve correctly.
func TestPickTrust_MultiTrustWired_ReturnsIt(t *testing.T) {
	t.Parallel()
	stub := stubLogTrust{}
	deps := &Dependencies{
		LeafReader: smt.NewInMemoryLeafStore(),
		MultiTrust: stub,
	}
	got := deps.PickTrust(stubFetcher{})
	if got != verifier.LogTrustProvider(stub) {
		t.Errorf("PickTrust = %T, want the wired MultiTrust", got)
	}
}

// TestPickTrust_MultiTrustNil_FallsBackToLocalTrust pins the
// single-network deployment path: nil MultiTrust ⇒ a freshly-
// constructed LocalTrust over the per-request fetcher.
func TestPickTrust_MultiTrustNil_FallsBackToLocalTrust(t *testing.T) {
	t.Parallel()
	deps := &Dependencies{
		LeafReader: smt.NewInMemoryLeafStore(),
		// MultiTrust: nil (default)
	}
	got := deps.PickTrust(stubFetcher{})
	if got == nil {
		t.Fatal("PickTrust returned nil; LocalTrust fallback expected")
	}
	// LocalTrust satisfies the interface but is NOT the stubLogTrust;
	// type check is the cleanest assertion that the fallback fired.
	if _, ok := got.(stubLogTrust); ok {
		t.Error("PickTrust returned the wrong concrete type")
	}
}
