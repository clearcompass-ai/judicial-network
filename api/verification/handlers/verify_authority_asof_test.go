// VerifyAuthorityHandler ?as_of= + PickTrust coverage.
//
// Pins the C-4 read-side surface:
//   1. parseAsOf interprets ?as_of=<seq> per the contract: absent /
//      empty / 0 ⇒ AsOf{} (latest); >0 ⇒ AsOf{LogDID, Sequence:n}.
//   2. Malformed values surface as a 400-shaped error.
//   3. Dependencies.PickTrust returns MultiTrust when wired, else
//      falls back to a freshly-constructed LocalTrust.
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

func TestParseAsOf_Absent_ReturnsLatest(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42", nil)
	asOf, err := parseAsOf(r, "did:web:l")
	if err != nil {
		t.Fatalf("parseAsOf: %v", err)
	}
	if asOf != (verifier.AsOf{}) {
		t.Errorf("AsOf = %+v, want zero (latest)", asOf)
	}
}

func TestParseAsOf_Empty_ReturnsLatest(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42?as_of=", nil)
	asOf, err := parseAsOf(r, "did:web:l")
	if err != nil {
		t.Fatalf("parseAsOf: %v", err)
	}
	if asOf != (verifier.AsOf{}) {
		t.Errorf("AsOf = %+v, want zero (latest)", asOf)
	}
}

func TestParseAsOf_Zero_ReturnsLatest(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42?as_of=0", nil)
	asOf, err := parseAsOf(r, "did:web:l")
	if err != nil {
		t.Fatalf("parseAsOf: %v", err)
	}
	if asOf != (verifier.AsOf{}) {
		t.Errorf("AsOf = %+v, want zero (explicit 0 collapses to latest)", asOf)
	}
}

func TestParseAsOf_Positive_PinsLogIDPlusSequence(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42?as_of=123", nil)
	asOf, err := parseAsOf(r, "did:web:l")
	if err != nil {
		t.Fatalf("parseAsOf: %v", err)
	}
	want := verifier.AsOf{LogDID: "did:web:l", Sequence: 123}
	if asOf != want {
		t.Errorf("AsOf = %+v, want %+v", asOf, want)
	}
}

func TestParseAsOf_NonNumeric_400Error(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42?as_of=notanint", nil)
	_, err := parseAsOf(r, "did:web:l")
	if err == nil {
		t.Fatal("parseAsOf must reject non-numeric as_of")
	}
	if !errors.Is(err, errBadAsOf) {
		t.Errorf("err = %v, want errBadAsOf", err)
	}
}

func TestParseAsOf_Negative_400Error(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/v1/verify/authority/did:web:l/42?as_of=-5", nil)
	_, err := parseAsOf(r, "did:web:l")
	if err == nil {
		t.Fatal("parseAsOf must reject negative as_of")
	}
	if !errors.Is(err, errBadAsOf) {
		t.Errorf("err = %v, want errBadAsOf", err)
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
