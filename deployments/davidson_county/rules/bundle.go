/*
FILE PATH: deployments/davidson_county/rules/bundle.go

DESCRIPTION:
    Davidson County's jurisdiction.Bundle. Single value plumbed
    through registry.Register so the verifier and aggregator can
    look up Davidson's policies by ExchangeDID.

    Composition: this file owns the Bundle plumbing only — the
    underlying policies live in role_catalog.go,
    cosignature_mix.go, and prerequisites.go and remain accessible
    to operators that want them directly (e.g., schema validation
    tools).

OVERVIEW:
    ExchangeDID    — institutional DID constant.
    MustBundle     — canonical Bundle factory (panics on error).
    BundleProvider — jurisdiction.Provider for v3 plugin loading.
    davidsonBundle — unexported impl of jurisdiction.Bundle.

KEY DEPENDENCIES:
    - jurisdiction.Bundle / jurisdiction.Provider.
    - schemas.RoleCatalog.
    - policy.CosignatureMixPolicy.
    - prerequisites.Policy.
*/
package rules

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ExchangeDID is the institutional DID for the Davidson County
// court system. Used as the registry key and the IntraExchangeOnly
// reference value.
const ExchangeDID = "did:web:da:davidson-tn"

// davidsonBundle implements jurisdiction.Bundle. Constructed once
// at boot; immutable thereafter.
type davidsonBundle struct {
	catalog *schemas.InMemoryCatalog
	cosig   *policy.InMemoryPolicy
	preqs   *prerequisites.InMemoryPolicy
}

func (b *davidsonBundle) ExchangeDID() string                          { return ExchangeDID }
func (b *davidsonBundle) RoleCatalog() schemas.RoleCatalog             { return b.catalog }
func (b *davidsonBundle) CosignaturePolicy() policy.CosignatureMixPolicy { return b.cosig }
func (b *davidsonBundle) PrerequisitePolicy() prerequisites.Policy     { return b.preqs }

// Static check.
var _ jurisdiction.Bundle = (*davidsonBundle)(nil)

// MustBundle returns the canonical Davidson Bundle. Panics if any
// underlying fixture fails to validate (a bug in this package).
func MustBundle() jurisdiction.Bundle {
	b := &davidsonBundle{
		catalog: MustRoleCatalog(),
		cosig:   MustCosignaturePolicy(),
		preqs:   MustPrerequisitePolicy(),
	}
	if err := jurisdiction.Validate(b); err != nil {
		panic(fmt.Sprintf("davidson_county/rules: bundle invalid: %v", err))
	}
	return b
}

// BundleProvider satisfies jurisdiction.Provider so the same
// fixture is loadable via the v3 plugin path:
//
//   p, _ := plugin.Open("davidson.so")
//   sym, _ := p.Lookup("BundleProvider")
//   provider := sym.(jurisdiction.Provider)
//   bundle, err := provider()
//
// The plugin loader signs and seals the .so file; Provider's job
// is only to surface the same Bundle the in-tree path returns.
var BundleProvider jurisdiction.Provider = func() (jurisdiction.Bundle, error) {
	defer func() { _ = recover() }()
	return MustBundle(), nil
}
