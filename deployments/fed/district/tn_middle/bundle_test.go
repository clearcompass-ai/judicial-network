// Tests pinning the US District Court (Middle TN) placeholder Bundle.
package tn_middle

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

func TestExchangeDID_MatchesConvention(t *testing.T) {
	const want = "did:web:fed:district:tn_middle"
	if ExchangeDID != want {
		t.Errorf("ExchangeDID drift: got %q, want %q", ExchangeDID, want)
	}
}

func TestMustBundle_NonNilSurfacesAndValid(t *testing.T) {
	b := MustBundle()
	if b.ExchangeDID() != ExchangeDID {
		t.Errorf("ExchangeDID drift: %q want %q", b.ExchangeDID(), ExchangeDID)
	}
	if b.RoleCatalog() == nil ||
		b.CosignaturePolicy() == nil ||
		b.PrerequisitePolicy() == nil ||
		b.AuthorityChainResolver() == nil ||
		b.AppellateVocabulary() == nil {
		t.Fatal("bundle has nil surface(s)")
	}
	if err := jurisdiction.Validate(b); err != nil {
		t.Errorf("jurisdiction.Validate: %v", err)
	}
}

func TestRegistry_RoundTrip(t *testing.T) {
	r := jurisdiction.NewRegistry()
	if err := r.Register(MustBundle()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	b, err := r.Bundle(ExchangeDID)
	if err != nil {
		t.Fatalf("Bundle(%s): %v", ExchangeDID, err)
	}
	if b.ExchangeDID() != ExchangeDID {
		t.Errorf("Bundle(%s).ExchangeDID() = %q", ExchangeDID, b.ExchangeDID())
	}
}

func TestBundleProvider_ReturnsSameBundle(t *testing.T) {
	b, err := BundleProvider()
	if err != nil {
		t.Fatalf("BundleProvider: %v", err)
	}
	if b.ExchangeDID() != ExchangeDID {
		t.Errorf("Provider DID %q want %q", b.ExchangeDID(), ExchangeDID)
	}
}
