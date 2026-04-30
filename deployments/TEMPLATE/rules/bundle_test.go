/*
FILE PATH: deployments/TEMPLATE/rules/bundle_test.go

DESCRIPTION:
    Tests pinning the TEMPLATE Bundle composer:
      - the placeholder ExchangeDID is the documented marker so
        no production deployment accidentally inherits it,
      - MustBundle does not panic and returns non-nil surfaces,
      - jurisdiction.Validate accepts the skeleton out-of-the-
        box (so a deployment can copy → run → fill in roles
        without pre-validation breakage),
      - the composer's surfaces match the underlying skeleton
        files,
      - the placeholder AuthorityChainResolver fails closed,
      - registry round-trip works.
*/
package rules

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// ─── ExchangeDID placeholder ───────────────────────────────────────

func TestExchangeDID_IsPlaceholder(t *testing.T) {
	const want = "did:web:TEMPLATE:replace-me"
	if ExchangeDID != want {
		t.Errorf("TEMPLATE ExchangeDID drift: got %q, want %q (placeholder)",
			ExchangeDID, want)
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

func TestMustBundle_ValidatesAgainstJurisdiction(t *testing.T) {
	if err := jurisdiction.Validate(MustBundle()); err != nil {
		t.Errorf("TEMPLATE skeleton fails jurisdiction.Validate: %v", err)
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

// ─── trial-only AppellateVocab ────────────────────────────────────

func TestComposer_AppellateVocabIsEmpty(t *testing.T) {
	v := MustBundle().AppellateVocabulary()
	if len(v.OpinionTypes()) != 0 {
		t.Error("TEMPLATE skeleton AppellateVocab must be empty")
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
