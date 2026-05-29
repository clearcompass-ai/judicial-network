/*
FILE PATH: deployments/ca/coa/sixth/bundle.go

DESCRIPTION:

	California Court of Appeal, Sixth Appellate District — the
	intermediate appellate court covering Monterey, San Benito,
	Santa Clara, and Santa Cruz counties. The natural appellate
	stop for cases originating in the Superior Court of California,
	County of Santa Clara.

	ExchangeDID = did:web:state:ca:coa:6

	# Policy framework — placeholder for e2e

	See deployments/ca/sc/bundle.go's package doc for the
	California-hierarchy diagram and the placeholder-policy
	rationale.

OVERVIEW:

	ExchangeDID    — institutional DID constant.
	MustBundle     — canonical Bundle factory (panics on error).
	BundleProvider — jurisdiction.Provider for v3 plugin loading.
	bundle         — unexported impl of jurisdiction.Bundle.

KEY DEPENDENCIES:
  - deployments/tn/trial  (placeholder policy framework).
  - jurisdiction.Bundle / Provider / NoAuthorityChainResolver.
*/
package sixth

import (
	"fmt"

	prerequisites "github.com/clearcompass-ai/attesta-tools/libs/prereq"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ExchangeDID is the institutional DID for the California Court
// of Appeal, Sixth Appellate District (Santa Clara-region).
const ExchangeDID = "did:web:state:ca:coa:6"

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

// MustBundle returns the canonical CA Court of Appeal, 6th District Bundle.
func MustBundle() jurisdiction.Bundle {
	b := &bundle{
		catalog: trial.MustRoleCatalog(),
		cosig:   trial.MustCosignaturePolicy(),
		preqs:   trial.MustPrerequisitePolicy(),
	}
	if err := jurisdiction.Validate(b); err != nil {
		panic(fmt.Sprintf("ca/coa/sixth: bundle invalid: %v", err))
	}
	return b
}

var BundleProvider jurisdiction.Provider = func() (jurisdiction.Bundle, error) {
	defer func() { _ = recover() }()
	return MustBundle(), nil
}
