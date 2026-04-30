// FILE PATH: deployments/davidson_county/rules/bundle_test.go
//
// Tests pinning Davidson's jurisdiction.Bundle composition: the
// Bundle exposes the same fixtures that MustRoleCatalog,
// MustCosignaturePolicy, and MustPrerequisitePolicy build, the
// ExchangeDID matches, and jurisdiction.Validate accepts the
// shipped Bundle out-of-the-box.
package rules

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

func TestMustBundle_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustBundle panicked: %v", r)
		}
	}()
	_ = MustBundle()
}

func TestMustBundle_ExchangeDID(t *testing.T) {
	b := MustBundle()
	if b.ExchangeDID() != ExchangeDID {
		t.Errorf("ExchangeDID drift: %q want %q", b.ExchangeDID(), ExchangeDID)
	}
	if ExchangeDID != "did:web:state:tn:davidson" {
		t.Errorf("Davidson ExchangeDID constant changed: %q", ExchangeDID)
	}
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

func TestMustBundle_AppellateVocabIsEmpty(t *testing.T) {
	// Davidson is trial-only; appellate sets MUST be empty.
	v := MustBundle().AppellateVocabulary()
	if len(v.OpinionTypes()) != 0 {
		t.Errorf("trial Bundle: OpinionTypes should be empty, got %v",
			v.OpinionTypes())
	}
	if len(v.ParticipationRoles()) != 0 {
		t.Errorf("trial Bundle: ParticipationRoles should be empty, got %v",
			v.ParticipationRoles())
	}
	if len(v.DispositionOutcomes()) != 0 {
		t.Errorf("trial Bundle: DispositionOutcomes should be empty, got %v",
			v.DispositionOutcomes())
	}
	if len(v.ReviewTypes()) != 0 {
		t.Errorf("trial Bundle: ReviewTypes should be empty, got %v",
			v.ReviewTypes())
	}
}

func TestMustBundle_ChainResolverFailsClosed(t *testing.T) {
	// v0.5.0 placeholder: NoAuthorityChainResolver is wired
	// until the production verifier-backed resolver lands.
	r := MustBundle().AuthorityChainResolver()
	v := r.Resolve(t.Context(), jurisdiction.AuthorityRequest{
		SignerDID: "did:key:zsigner",
	})
	if v.OK {
		t.Error("Davidson placeholder resolver must fail closed (OK=false)")
	}
	if v.Rejection != "no_resolver_configured" {
		t.Errorf("rejection token: want no_resolver_configured, got %q",
			v.Rejection)
	}
}

func TestMustBundle_ValidatesAgainstJurisdiction(t *testing.T) {
	if err := jurisdiction.Validate(MustBundle()); err != nil {
		t.Errorf("Davidson bundle fails jurisdiction.Validate: %v", err)
	}
}

func TestMustBundle_RoleCatalogMatchesMustRoleCatalog(t *testing.T) {
	b := MustBundle()
	cat := b.RoleCatalog()
	other := MustRoleCatalog()
	if len(cat.List()) != len(other.List()) {
		t.Errorf("role count drift: bundle=%d standalone=%d",
			len(cat.List()), len(other.List()))
	}
}

func TestMustBundle_CosignatureCoversAllRules(t *testing.T) {
	want := len(CosignatureRules())
	got := len(MustBundle().CosignaturePolicy().List())
	if got != want {
		t.Errorf("cosig rule count: bundle=%d standalone=%d", got, want)
	}
}

func TestMustBundle_PrereqCoversAllEvents(t *testing.T) {
	want := len(PrerequisiteRules())
	got := len(MustBundle().PrerequisitePolicy().EventTypes())
	if got != want {
		t.Errorf("prereq event count: bundle=%d standalone=%d", got, want)
	}
}

// ─── Provider (v3 plugin path) ──────────────────────────────────────

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
