/*
FILE PATH: deployments/fed/scotus/bundle.go

DESCRIPTION:

	Supreme Court of the United States (SCOTUS) Bundle — federal-tier
	institutional placeholder for the cross-network e2e topology
	(e2e-tests' "Federal Court System" network).

	ExchangeDID = did:web:fed:scotus:us

	The federal hierarchy is its OWN network with its OWN trust
	root, ledger, witness set, and exchange registry — the e2e
	provisioner brings up both the TN network (Davidson + TN COA +
	TN Sup Ct) and the federal network (SCOTUS + 6th Circuit +
	US District Court, Middle District of TN) so cross-network
	scenarios (S6.6 cross-log, S8.2 cross-ledger determinism, S5.14
	appellate jurisdiction transitions) are representable end-to-end.

	# Policy framework — placeholder for e2e

	Production federal policy fixtures (federal-specific role
	catalog, appellate vocabulary, prerequisite vocabulary) are NOT
	in scope for this bundle today — they land when an actual
	federal-court consumer arrives. For e2e provisioning the bundle
	delegates every policy method to deployments/tn/trial, the
	smallest valid policy framework in the tree. This gives the JN
	a registered, queryable destination DID; the e2e wire tests
	(Phase 5 JN handler contracts, Phase 6 cross-component flows)
	exercise the handler surface, not federal-specific policy
	depth. When federal-specific policies arrive, this file becomes
	a 5-minute refactor that swaps the framework import — no shape
	changes — exactly the davidson → trial pattern this file mirrors.

OVERVIEW:

	ExchangeDID    — institutional DID constant.
	MustBundle     — canonical Bundle factory (panics on error).
	BundleProvider — jurisdiction.Provider for v3 plugin loading.
	bundle         — unexported impl of jurisdiction.Bundle.

KEY DEPENDENCIES:
  - deployments/tn/trial  (placeholder policy framework).
  - jurisdiction.Bundle / Provider / NoAuthorityChainResolver.
*/
package scotus

import (
	"fmt"

	prerequisites "github.com/clearcompass-ai/attesta-tools/libs/prereq"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ExchangeDID is the institutional DID for the Supreme Court of
// the United States. Used as the registry key and the
// IntraExchangeOnly reference value.
const ExchangeDID = "did:web:fed:scotus:us"

// bundle implements jurisdiction.Bundle by delegating every policy
// method to the shared TN trial framework — see the package-level
// doc comment for the placeholder-policy rationale.
type bundle struct {
	catalog schemas.RoleCatalog
	cosig   policy.CosignatureMixPolicy
	preqs   prerequisites.Policy
}

func (b *bundle) ExchangeDID() string                            { return ExchangeDID }
func (b *bundle) RoleCatalog() schemas.RoleCatalog               { return b.catalog }
func (b *bundle) CosignaturePolicy() policy.CosignatureMixPolicy { return b.cosig }
func (b *bundle) PrerequisitePolicy() prerequisites.Policy       { return b.preqs }

// authorityChainResolver is the package-level wiring point for the
// production resolver. Defaults to closed-by-default; production
// callers (cmd/network-api) call SetAuthorityChainResolver at boot
// before registry.Register(MustBundle()).
var authorityChainResolver jurisdiction.AuthorityChainResolver = jurisdiction.NoAuthorityChainResolver()

// SetAuthorityChainResolver injects a production resolver. Pass
// nil to revert to the closed-by-default placeholder.
func SetAuthorityChainResolver(r jurisdiction.AuthorityChainResolver) {
	if r == nil {
		authorityChainResolver = jurisdiction.NoAuthorityChainResolver()
		return
	}
	authorityChainResolver = r
}

func (b *bundle) AuthorityChainResolver() jurisdiction.AuthorityChainResolver {
	return authorityChainResolver
}

// AppellateVocabulary returns the empty trial vocab — see the
// package-level doc comment. When federal-specific appellate
// fixtures land, swap this to fed/appellate.AppellateVocabulary().
func (b *bundle) AppellateVocabulary() jurisdiction.AppellateVocab {
	return trial.AppellateVocabulary()
}

var _ jurisdiction.Bundle = (*bundle)(nil)

// MustBundle returns the canonical SCOTUS Bundle. Panics if the
// underlying TN trial fixtures fail to validate (a bug in the
// shared framework).
func MustBundle() jurisdiction.Bundle {
	b := &bundle{
		catalog: trial.MustRoleCatalog(),
		cosig:   trial.MustCosignaturePolicy(),
		preqs:   trial.MustPrerequisitePolicy(),
	}
	if err := jurisdiction.Validate(b); err != nil {
		panic(fmt.Sprintf("fed/scotus: bundle invalid: %v", err))
	}
	return b
}

// BundleProvider satisfies jurisdiction.Provider for the v3 plugin
// path. The plugin loader signs and seals the .so file; Provider's
// job is only to surface the same Bundle the in-tree path returns.
var BundleProvider jurisdiction.Provider = func() (jurisdiction.Bundle, error) {
	defer func() { _ = recover() }()
	return MustBundle(), nil
}
