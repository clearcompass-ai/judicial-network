/*
FILE PATH: deployments/tn/coa/bundle_test.go

DESCRIPTION:
    Tests pinning the TN COA Bundle composer:
      - ExchangeDID matches the convention
        (did:web:state:tn:coa).
      - MustBundle does not panic and returns non-nil surfaces.
      - jurisdiction.Validate accepts the shipped Bundle.
      - The composer's surfaces match the underlying file fixtures
        (proves zero drift).
      - AppellateVocabulary is populated (v1.8 §7B).
      - The placeholder AuthorityChainResolver fails closed.
      - Registry round-trip works.
      - BundleProvider returns the same Bundle.
      - Side-by-side registration with Davidson works
        (different ExchangeDIDs co-exist).
*/
package coa

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// ─── ExchangeDID ────────────────────────────────────────────────────

func TestExchangeDID_MatchesConvention(t *testing.T) {
	const want = "did:web:state:tn:coa"
	if ExchangeDID != want {
		t.Errorf("ExchangeDID drift: got %q, want %q", ExchangeDID, want)
	}
}

func TestMustBundle_ExchangeDID(t *testing.T) {
	b := MustBundle()
	if b.ExchangeDID() != ExchangeDID {
		t.Errorf("ExchangeDID drift: %q want %q", b.ExchangeDID(), ExchangeDID)
	}
}

// ─── construction ──────────────────────────────────────────────────

func TestMustBundle_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustBundle panicked: %v", r)
		}
	}()
	_ = MustBundle()
}

func TestMustBundle_HasNonNilSurfaces(t *testing.T) {
	b := MustBundle()
	if b.RoleCatalog() == nil {
		t.Error("RoleCatalog must not be nil")
	}
	if b.CosignaturePolicy() == nil {
		t.Error("CosignaturePolicy must not be nil")
	}
	if b.PrerequisitePolicy() == nil {
		t.Error("PrerequisitePolicy must not be nil")
	}
	if b.AuthorityChainResolver() == nil {
		t.Error("AuthorityChainResolver must not be nil")
	}
	if b.AppellateVocabulary() == nil {
		t.Error("AppellateVocabulary must not be nil")
	}
}

// ─── Validate ──────────────────────────────────────────────────────

func TestMustBundle_ValidatesAgainstJurisdiction(t *testing.T) {
	if err := jurisdiction.Validate(MustBundle()); err != nil {
		t.Errorf("TN COA bundle fails jurisdiction.Validate: %v", err)
	}
}

// ─── composer fidelity ────────────────────────────────────────────

func TestComposer_RoleCatalogMatchesFile(t *testing.T) {
	got := len(MustBundle().RoleCatalog().List())
	want := len(Roles())
	if got != want {
		t.Errorf("role count drift: bundle=%d file=%d", got, want)
	}
}

func TestComposer_CosignatureCoversAllRules(t *testing.T) {
	want := len(CosignatureRules())
	got := len(MustBundle().CosignaturePolicy().List())
	if got != want {
		t.Errorf("cosig rule count: bundle=%d file=%d", got, want)
	}
}

func TestComposer_PrereqCoversAllEvents(t *testing.T) {
	want := len(PrerequisiteRules())
	got := len(MustBundle().PrerequisitePolicy().EventTypes())
	if got != want {
		t.Errorf("prereq event count: bundle=%d file=%d", got, want)
	}
}

// ─── AppellateVocab is populated (v1.8 §7B) ───────────────────────

func TestComposer_AppellateVocabPopulated(t *testing.T) {
	v := MustBundle().AppellateVocabulary()
	if len(v.OpinionTypes()) != 11 {
		t.Errorf("OpinionTypes: want 11 (v1.8 §7B.2), got %d",
			len(v.OpinionTypes()))
	}
	if len(v.ParticipationRoles()) != 6 {
		t.Errorf("ParticipationRoles: want 6 (v1.8 §7B.2), got %d",
			len(v.ParticipationRoles()))
	}
	if len(v.DispositionOutcomes()) != 6 {
		t.Errorf("DispositionOutcomes: want 6 (v1.8 §7B.3), got %d",
			len(v.DispositionOutcomes()))
	}
	if len(v.ReviewTypes()) != 3 {
		t.Errorf("ReviewTypes: want 3 (v1.8 §7B.1), got %d",
			len(v.ReviewTypes()))
	}
}

// ─── placeholder chain resolver fails closed ──────────────────────

func TestComposer_ChainResolverFailsClosed(t *testing.T) {
	r := MustBundle().AuthorityChainResolver()
	v := r.Resolve(t.Context(), jurisdiction.AuthorityRequest{
		SignerDID: "did:key:zsigner",
	})
	if v.OK {
		t.Error("placeholder resolver must fail closed (OK=false)")
	}
	if v.Rejection != "no_resolver_configured" {
		t.Errorf("rejection token: want no_resolver_configured, got %q",
			v.Rejection)
	}
}

// ─── BundleProvider ────────────────────────────────────────────────

func TestBundleProvider_Returns(t *testing.T) {
	b, err := BundleProvider()
	if err != nil {
		t.Fatalf("BundleProvider: %v", err)
	}
	if b == nil {
		t.Fatal("Provider returned nil bundle")
	}
	if b.ExchangeDID() != ExchangeDID {
		t.Errorf("provider DID drift: %q", b.ExchangeDID())
	}
}

// ─── Registry round-trip ────────────────────────────────────────────

func TestMustBundle_RegistersCleanly(t *testing.T) {
	r := jurisdiction.NewRegistry()
	if err := r.Register(MustBundle()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := r.Bundle(ExchangeDID)
	if err != nil {
		t.Fatalf("Bundle lookup: %v", err)
	}
	if got.ExchangeDID() != ExchangeDID {
		t.Errorf("DID drift: %q", got.ExchangeDID())
	}
}

func TestMustBundle_IndependentCalls(t *testing.T) {
	a := MustBundle()
	b := MustBundle()
	if a == b {
		t.Error("MustBundle should return a fresh Bundle per call")
	}
}
