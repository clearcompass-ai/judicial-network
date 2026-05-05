/*
FILE PATH: deployments/tn/sup_ct/bundle_test.go

DESCRIPTION:

	Tests pinning the TN Supreme Court Bundle composer:
	  - ExchangeDID matches the convention.
	  - All five surfaces non-nil.
	  - jurisdiction.Validate accepts.
	  - Composer fidelity (file vs bundle counts).
	  - AppellateVocabulary populated.
	  - Cross-exchange revocation rule reachable from the
	    bundle's CosignaturePolicy.
	  - Registry round-trip works.
	  - All three TN exchanges (Davidson, COA, Sup Ct) can
	    register into the same Registry without DID collision.
*/
package sup_ct

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/deployments/tn/coa"
	davidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

func TestExchangeDID_MatchesConvention(t *testing.T) {
	const want = "did:web:state:tn:sc"
	if ExchangeDID != want {
		t.Errorf("ExchangeDID drift: got %q, want %q", ExchangeDID, want)
	}
}

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
		t.Errorf("Sup Ct bundle fails jurisdiction.Validate: %v", err)
	}
}

// ─── composer fidelity ───────────────────────────────────────────

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

// ─── cross-exchange revocation reachable from the bundle ────────

func TestComposer_AuthorityRevocationDisciplinaryReachable(t *testing.T) {
	r, err := MustBundle().CosignaturePolicy().Lookup(
		"authority_revocation_disciplinary")
	if err != nil {
		t.Fatalf("authority_revocation_disciplinary missing: %v", err)
	}
	if r.IntraExchangeOnly {
		t.Error("revocation must be cross-exchange (target on trial county)")
	}
	if r.MinSignerCosigners < 3 {
		t.Errorf("revocation must require ≥3 Justices; got %d",
			r.MinSignerCosigners)
	}
}

// ─── BundleProvider ──────────────────────────────────────────────

func TestBundleProvider_Returns(t *testing.T) {
	b, err := BundleProvider()
	if err != nil {
		t.Fatalf("BundleProvider: %v", err)
	}
	if b == nil || b.ExchangeDID() != ExchangeDID {
		t.Errorf("provider DID drift: %v", b)
	}
}

// ─── Registry: all three TN exchanges co-exist ──────────────────

func TestRegistry_AllThreeTNExchangesCoexist(t *testing.T) {
	r := jurisdiction.NewRegistry()
	if err := r.Register(davidson.MustBundle()); err != nil {
		t.Fatalf("register Davidson: %v", err)
	}
	if err := r.Register(coa.MustBundle()); err != nil {
		t.Fatalf("register COA: %v", err)
	}
	if err := r.Register(MustBundle()); err != nil {
		t.Fatalf("register Sup Ct: %v", err)
	}
	for _, did := range []string{
		davidson.ExchangeDID,
		coa.ExchangeDID,
		ExchangeDID,
	} {
		got, err := r.Bundle(did)
		if err != nil {
			t.Errorf("%s missing: %v", did, err)
		}
		if got.ExchangeDID() != did {
			t.Errorf("DID drift for %q: got %q", did, got.ExchangeDID())
		}
	}
}
