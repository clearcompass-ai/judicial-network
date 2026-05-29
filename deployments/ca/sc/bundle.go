/*
FILE PATH: deployments/ca/sc/bundle.go

DESCRIPTION:

	Supreme Court of California Bundle — apex of the California court
	hierarchy. Federal-equivalent terminology: "Supreme Court of
	California" (7 justices, statewide). The CA Supreme Court is the
	final state-court arbiter for civil and criminal appeals
	originating in the California Courts of Appeal.

	ExchangeDID = did:web:state:ca:sc

	# California court hierarchy (the e2e topology stack)

	    Supreme Court of California             (apex; this bundle)
	          ↑
	    California Court of Appeal              (6 districts)
	      4th Appellate District (Riverside)
	      6th Appellate District (Santa Clara/San Jose)
	          ↑
	    Superior Court of California            (trial; county-level)
	      County of Riverside
	      County of Santa Clara

	# Policy framework — placeholder for e2e

	See deployments/fed/scotus/bundle.go's package doc for the full
	rationale. This bundle delegates every policy method to
	deployments/tn/trial as a placeholder so the JN has a registered,
	queryable destination DID without standing up a California-
	specific policy framework. When CA-specific fixtures arrive, the
	framework import swaps with no shape changes.

OVERVIEW:

	ExchangeDID    — institutional DID constant.
	MustBundle     — canonical Bundle factory (panics on error).
	BundleProvider — jurisdiction.Provider for v3 plugin loading.
	bundle         — unexported impl of jurisdiction.Bundle.

KEY DEPENDENCIES:
  - deployments/tn/trial  (placeholder policy framework).
  - jurisdiction.Bundle / Provider / NoAuthorityChainResolver.
*/
package sc

import (
	"fmt"

	prerequisites "github.com/clearcompass-ai/attesta-tools/libs/prereq"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ExchangeDID is the institutional DID for the Supreme Court of
// California (the apex of the CA state-court hierarchy).
const ExchangeDID = "did:web:state:ca:sc"

type bundle struct {
	catalog schemas.RoleCatalog
	cosig   policy.CosignatureMixPolicy
	preqs   prerequisites.Policy
}

func (b *bundle) ExchangeDID() string                            { return ExchangeDID }
func (b *bundle) RoleCatalog() schemas.RoleCatalog               { return b.catalog }
func (b *bundle) CosignaturePolicy() policy.CosignatureMixPolicy { return b.cosig }
func (b *bundle) PrerequisitePolicy() prerequisites.Policy       { return b.preqs }

var authorityChainResolver jurisdiction.AuthorityChainResolver = jurisdiction.NoAuthorityChainResolver()

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

func (b *bundle) AppellateVocabulary() jurisdiction.AppellateVocab {
	return trial.AppellateVocabulary()
}

var _ jurisdiction.Bundle = (*bundle)(nil)

// MustBundle returns the canonical Supreme Court of California Bundle.
func MustBundle() jurisdiction.Bundle {
	b := &bundle{
		catalog: trial.MustRoleCatalog(),
		cosig:   trial.MustCosignaturePolicy(),
		preqs:   trial.MustPrerequisitePolicy(),
	}
	if err := jurisdiction.Validate(b); err != nil {
		panic(fmt.Sprintf("ca/sc: bundle invalid: %v", err))
	}
	return b
}

var BundleProvider jurisdiction.Provider = func() (jurisdiction.Bundle, error) {
	defer func() { _ = recover() }()
	return MustBundle(), nil
}
