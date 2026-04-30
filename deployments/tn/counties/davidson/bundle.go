/*
FILE PATH: deployments/tn/counties/davidson/bundle.go

DESCRIPTION:
    Davidson County Bundle — a thin composer over the shared TN
    trial framework (deployments/tn/trial/). Davidson contributes
    ONLY its ExchangeDID; every policy method delegates to the
    framework so all 95 TN counties stay in lockstep on roles,
    cosignature mix, prerequisites, and appellate vocabulary.

    Why a composer pattern: each new TN county becomes a ~30-line
    Bundle (this file shape × 95 counties = 95 small files,
    instead of 95 copies of the policy fixtures).

    DID convention:
        State courts:   did:web:state:tn:<court-id>
        Federal courts: did:web:fed:<level>:<court-id>

OVERVIEW:
    ExchangeDID    — institutional DID constant.
    MustBundle     — canonical Bundle factory (panics on error).
    BundleProvider — jurisdiction.Provider for v3 plugin loading.
    bundle         — unexported impl of jurisdiction.Bundle.

KEY DEPENDENCIES:
    - deployments/tn/trial  (the shared TN trial framework).
    - jurisdiction.Bundle / Provider / NoAuthorityChainResolver.
*/
package davidson

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ExchangeDID is the institutional DID for Davidson County's
// court system. Used as the registry key and the
// IntraExchangeOnly reference value.
const ExchangeDID = "did:web:state:tn:davidson"

// bundle implements jurisdiction.Bundle by delegating every
// policy method to the shared TN trial framework. Constructed
// once at boot; immutable thereafter.
type bundle struct {
	catalog schemas.RoleCatalog
	cosig   policy.CosignatureMixPolicy
	preqs   prerequisites.Policy
}

func (b *bundle) ExchangeDID() string                              { return ExchangeDID }
func (b *bundle) RoleCatalog() schemas.RoleCatalog                 { return b.catalog }
func (b *bundle) CosignaturePolicy() policy.CosignatureMixPolicy   { return b.cosig }
func (b *bundle) PrerequisitePolicy() prerequisites.Policy         { return b.preqs }

// authorityChainResolver is the package-level wiring point for
// the production verifier-backed resolver. Defaults to
// NoAuthorityChainResolver() so tests and the in-tree
// MustBundle() factory work out-of-the-box without a fetcher
// dependency. Production deployments call
// SetAuthorityChainResolver(resolver) at boot — typically with
// a verification.NewBundleChainResolver(catalog, fetcher,
// leafReader) — before registering the Bundle.
var authorityChainResolver jurisdiction.AuthorityChainResolver = jurisdiction.NoAuthorityChainResolver()

// SetAuthorityChainResolver injects a production resolver. Pass
// nil to revert to the closed-by-default placeholder.
// Production callers wire this once at boot, before
// registry.Register(MustBundle()).
func SetAuthorityChainResolver(r jurisdiction.AuthorityChainResolver) {
	if r == nil {
		authorityChainResolver = jurisdiction.NoAuthorityChainResolver()
		return
	}
	authorityChainResolver = r
}

// AuthorityChainResolver returns Davidson's per-jurisdiction
// delegation chain walker. Defaults to closed-by-default; the
// production resolver is wired via SetAuthorityChainResolver.
func (b *bundle) AuthorityChainResolver() jurisdiction.AuthorityChainResolver {
	return authorityChainResolver
}

// AppellateVocabulary returns the empty TN-trial appellate vocab.
// Davidson is a trial-court exchange and never accepts
// appellate_* event payloads. The TN Court of Appeals Bundle
// (deployments/tn/coa/) owns the v1.8 §7B vocabulary.
func (b *bundle) AppellateVocabulary() jurisdiction.AppellateVocab {
	return trial.AppellateVocabulary()
}

// Static check.
var _ jurisdiction.Bundle = (*bundle)(nil)

// MustBundle returns the canonical Davidson Bundle. Panics if
// any underlying TN trial fixture fails to validate (a bug in
// the shared framework).
func MustBundle() jurisdiction.Bundle {
	b := &bundle{
		catalog: trial.MustRoleCatalog(),
		cosig:   trial.MustCosignaturePolicy(),
		preqs:   trial.MustPrerequisitePolicy(),
	}
	if err := jurisdiction.Validate(b); err != nil {
		panic(fmt.Sprintf("tn/counties/davidson: bundle invalid: %v", err))
	}
	return b
}

// BundleProvider satisfies jurisdiction.Provider for the v3
// plugin path:
//
//	p, _ := plugin.Open("davidson.so")
//	sym, _ := p.Lookup("BundleProvider")
//	provider := sym.(jurisdiction.Provider)
//	bundle, err := provider()
//
// The plugin loader signs and seals the .so file; Provider's
// job is only to surface the same Bundle the in-tree path
// returns.
var BundleProvider jurisdiction.Provider = func() (jurisdiction.Bundle, error) {
	defer func() { _ = recover() }()
	return MustBundle(), nil
}
