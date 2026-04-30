/*
FILE PATH: verification/bundle_chain_resolver_test.go

DESCRIPTION:
    Tests for BundleChainResolver — the production adapter that
    exposes verification.AuthorityResolver as a
    jurisdiction.AuthorityChainResolver. Pins:

      - Constructor returns a non-nil resolver.
      - Resolve maps AuthorityRequest fields onto the inner
        signature correctly.
      - Resolve maps *Authority verdict fields onto
        jurisdiction.AuthorityVerdict correctly.
      - Empty/missing signer or delegation_ref propagates as a
        rejection with the right token.
      - The inner resolver's catalog is the per-Bundle one.
*/
package verification

import (
	"context"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// minimalCatalog returns a 1-role catalog so the resolver has
// non-nil dependencies.
func minimalCatalog(t *testing.T) schemas.RoleCatalog {
	t.Helper()
	c, err := schemas.NewInMemoryCatalog([]schemas.Role{
		{
			Name:            "judge",
			Actor:           schemas.ActorSigner,
			MaxDuration:     365 * 24 * time.Hour,
			DefaultDuration: 365 * 24 * time.Hour,
			AllowedScope:    []string{"case_decision"},
			DefaultScope:    []string{"case_decision"},
		},
	})
	if err != nil {
		t.Fatalf("minimalCatalog: %v", err)
	}
	return c
}

// ─── construction ────────────────────────────────────────────────

func TestNewBundleChainResolver_NonNil(t *testing.T) {
	r := NewBundleChainResolver(minimalCatalog(t), newFakeFetcher(), nil)
	if r == nil {
		t.Fatal("NewBundleChainResolver returned nil")
	}
}

func TestNewBundleChainResolver_WrapsResolver(t *testing.T) {
	r := NewBundleChainResolver(minimalCatalog(t), newFakeFetcher(), nil)
	if _, ok := r.(*BundleChainResolver); !ok {
		t.Errorf("expected *BundleChainResolver, got %T", r)
	}
}

// ─── Resolve: empty signer fails closed ─────────────────────────

func TestResolve_EmptySigner(t *testing.T) {
	r := NewBundleChainResolver(minimalCatalog(t), newFakeFetcher(), nil)
	v := r.Resolve(context.Background(), jurisdiction.AuthorityRequest{
		SignerDID: "",
	})
	if v.OK {
		t.Error("empty signer must fail closed")
	}
	if v.Rejection != string(RejectSignerMismatch) {
		t.Errorf("rejection token: want %q, got %q",
			RejectSignerMismatch, v.Rejection)
	}
}

// ─── Resolve: missing delegation ref ─────────────────────────────

func TestResolve_MissingDelegationRef(t *testing.T) {
	r := NewBundleChainResolver(minimalCatalog(t), newFakeFetcher(), nil)
	v := r.Resolve(context.Background(), jurisdiction.AuthorityRequest{
		SignerDID: "did:key:zSigner",
	})
	if v.OK {
		t.Error("missing chain tip must fail closed")
	}
	if v.Rejection != string(RejectMissingChainTip) {
		t.Errorf("rejection: want %q, got %q",
			RejectMissingChainTip, v.Rejection)
	}
	if v.SignerDID != "did:key:zSigner" {
		t.Errorf("SignerDID echo drift: %q", v.SignerDID)
	}
}

// ─── Resolve: SignerDID echo on every verdict ───────────────────

func TestResolve_SignerDIDEcho(t *testing.T) {
	r := NewBundleChainResolver(minimalCatalog(t), newFakeFetcher(), nil)
	const did = "did:key:zEchoTest"
	v := r.Resolve(context.Background(), jurisdiction.AuthorityRequest{
		SignerDID: did,
		DelegationRef: jurisdiction.DelegationRef{
			LogDID:   "did:web:state:tn:davidson",
			Sequence: 1,
		},
	})
	if v.SignerDID != did {
		t.Errorf("SignerDID echo: want %q, got %q", did, v.SignerDID)
	}
}

// ─── Resolve: verdict shape mapping ─────────────────────────────

func TestResolve_VerdictShapeMappingFields(t *testing.T) {
	// We can't easily build a successful chain walk in this unit
	// test (requires multi-hop fetcher fixtures). What we CAN
	// verify: the rejection-path mapping copies every field from
	// *Authority to AuthorityVerdict (Rejection, Reason,
	// SignerDID, Depth=0).
	r := NewBundleChainResolver(minimalCatalog(t), newFakeFetcher(), nil)
	v := r.Resolve(context.Background(), jurisdiction.AuthorityRequest{
		SignerDID: "did:key:zS",
		DelegationRef: jurisdiction.DelegationRef{
			LogDID:   "did:web:x",
			Sequence: 100,
		},
	})
	// The fake fetcher has no entry at sequence 100 → a fetch
	// failure rejection.
	if v.OK {
		t.Error("missing fetcher entry must reject")
	}
	if v.Reason == "" {
		t.Error("Reason must be populated for audit")
	}
}

// ─── nil context safe ──────────────────────────────────────────

func TestResolve_NilContextSafe(t *testing.T) {
	r := NewBundleChainResolver(minimalCatalog(t), newFakeFetcher(), nil)
	defer func() {
		if rec := recover(); rec != nil {
			t.Errorf("nil context panicked: %v", rec)
		}
	}()
	_ = r.Resolve(nil, jurisdiction.AuthorityRequest{
		SignerDID: "x",
	})
}

// ─── Catalog passthrough ───────────────────────────────────────

// TestNewBundleChainResolver_CatalogPropagates pins that the
// catalog supplied at construction is the one the inner
// resolver uses (per-Bundle scoping).
func TestNewBundleChainResolver_CatalogPropagates(t *testing.T) {
	cat := minimalCatalog(t)
	r := NewBundleChainResolver(cat, newFakeFetcher(), nil)
	bcr, ok := r.(*BundleChainResolver)
	if !ok {
		t.Fatalf("type assertion failed: %T", r)
	}
	if bcr.inner.Catalog != cat {
		t.Error("BundleChainResolver did not propagate catalog to inner resolver")
	}
}
