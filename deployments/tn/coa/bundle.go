/*
FILE PATH: deployments/tn/coa/bundle.go

DESCRIPTION:
    Tennessee Court of Appeals Bundle — the composer that wires
    the four COA policy files into a single jurisdiction.Bundle:

      RoleCatalog            — coa.MustRoleCatalog()
                               (chief_judge, judge, court_clerk,
                               deputy_clerk)
      CosignaturePolicy      — coa.MustCosignaturePolicy()
                               (10 rules covering v1.8 §7B
                               appellate family + personnel +
                               topology)
      PrerequisitePolicy     — coa.MustPrerequisitePolicy()
                               (vocabulary + per-event prereqs)
      AppellateVocabulary    — coa.AppellateVocabulary()
                               (v1.8 §7B closed-set enums)
      AuthorityChainResolver — jurisdiction.NoAuthorityChainResolver()
                               (closed-by-default placeholder;
                               production resolver lands when
                               the verifier registry refactor
                               wires it through)

    DID convention:
      ExchangeDID = "did:web:state:tn:coa"

OVERVIEW:
    ExchangeDID    — institutional DID constant.
    MustBundle     — canonical Bundle factory (panics on error).
    BundleProvider — jurisdiction.Provider for v3 plugin loading.
    bundle         — unexported impl of jurisdiction.Bundle.

KEY DEPENDENCIES:
    - jurisdiction.Bundle / Provider / NoAuthorityChainResolver.
    - coa.{Roles, CosignatureRules, PrerequisiteRules,
            AppellateVocabulary} (the four siblings in this dir).
*/
package coa

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ExchangeDID is the institutional DID for the Tennessee Court
// of Appeals (a single statewide exchange). Used as the registry
// key and the IntraExchangeOnly reference value.
const ExchangeDID = "did:web:state:tn:coa"

// bundle implements jurisdiction.Bundle for the TN Court of
// Appeals. Constructed once at boot; immutable thereafter.
type bundle struct {
	catalog schemas.RoleCatalog
	cosig   policy.CosignatureMixPolicy
	preqs   prerequisites.Policy
}

func (b *bundle) ExchangeDID() string                            { return ExchangeDID }
func (b *bundle) RoleCatalog() schemas.RoleCatalog               { return b.catalog }
func (b *bundle) CosignaturePolicy() policy.CosignatureMixPolicy { return b.cosig }
func (b *bundle) PrerequisitePolicy() prerequisites.Policy       { return b.preqs }

// AuthorityChainResolver returns the COA's per-jurisdiction
// delegation chain walker. v0.5.0 wires NoAuthorityChainResolver
// as a closed-by-default placeholder; production wiring lands
// when the verifier registry refactor (3E.3) plugs the
// concrete verification.AuthorityResolver through.
func (b *bundle) AuthorityChainResolver() jurisdiction.AuthorityChainResolver {
	return jurisdiction.NoAuthorityChainResolver()
}

// AppellateVocabulary returns the populated v1.8 §7B closed sets
// (opinion types, participation roles, disposition outcomes,
// review types). The verifier consults these when validating
// appellate_* event payload enums.
func (b *bundle) AppellateVocabulary() jurisdiction.AppellateVocab {
	return AppellateVocabulary()
}

// Static check.
var _ jurisdiction.Bundle = (*bundle)(nil)

// MustBundle returns the canonical TN COA Bundle. Panics if any
// underlying fixture fails to validate (a bug in this package).
func MustBundle() jurisdiction.Bundle {
	b := &bundle{
		catalog: MustRoleCatalog(),
		cosig:   MustCosignaturePolicy(),
		preqs:   MustPrerequisitePolicy(),
	}
	if err := jurisdiction.Validate(b); err != nil {
		panic(fmt.Sprintf("tn/coa: bundle invalid: %v", err))
	}
	return b
}

// BundleProvider satisfies jurisdiction.Provider for the v3
// plugin path:
//
//	p, _ := plugin.Open("tn-coa.so")
//	sym, _ := p.Lookup("BundleProvider")
//	provider := sym.(jurisdiction.Provider)
//	bundle, err := provider()
var BundleProvider jurisdiction.Provider = func() (jurisdiction.Bundle, error) {
	defer func() { _ = recover() }()
	return MustBundle(), nil
}
