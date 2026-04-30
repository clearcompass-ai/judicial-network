/*
FILE PATH: deployments/tn/sup_ct/bundle.go

DESCRIPTION:
    Tennessee Supreme Court Bundle composer. Wires the four
    Sup Ct policy files into a single jurisdiction.Bundle.

    ExchangeDID = did:web:state:tn:sc

    This is the v0.7.0 cross-exchange production deployment:
    a TN Sup Ct registered alongside TN COA + Davidson trial
    proves the multi-exchange model works end-to-end.
*/
package sup_ct

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ExchangeDID is the institutional DID for the Tennessee
// Supreme Court (a single statewide highest-court exchange).
const ExchangeDID = "did:web:state:tn:sc"

// bundle implements jurisdiction.Bundle for the TN Supreme Court.
type bundle struct {
	catalog schemas.RoleCatalog
	cosig   policy.CosignatureMixPolicy
	preqs   prerequisites.Policy
}

func (b *bundle) ExchangeDID() string                            { return ExchangeDID }
func (b *bundle) RoleCatalog() schemas.RoleCatalog               { return b.catalog }
func (b *bundle) CosignaturePolicy() policy.CosignatureMixPolicy { return b.cosig }
func (b *bundle) PrerequisitePolicy() prerequisites.Policy       { return b.preqs }

// authorityChainResolver is the package-level wiring point for
// the production verifier-backed resolver. Defaults to closed-
// by-default; production calls SetAuthorityChainResolver at boot.
var authorityChainResolver jurisdiction.AuthorityChainResolver = jurisdiction.NoAuthorityChainResolver()

// SetAuthorityChainResolver injects a production resolver.
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
	return AppellateVocabulary()
}

// Static check.
var _ jurisdiction.Bundle = (*bundle)(nil)

// MustBundle returns the canonical TN Sup Ct Bundle.
func MustBundle() jurisdiction.Bundle {
	b := &bundle{
		catalog: MustRoleCatalog(),
		cosig:   MustCosignaturePolicy(),
		preqs:   MustPrerequisitePolicy(),
	}
	if err := jurisdiction.Validate(b); err != nil {
		panic(fmt.Sprintf("tn/sup_ct: bundle invalid: %v", err))
	}
	return b
}

// BundleProvider satisfies jurisdiction.Provider for the v3
// plugin path.
var BundleProvider jurisdiction.Provider = func() (jurisdiction.Bundle, error) {
	defer func() { _ = recover() }()
	return MustBundle(), nil
}
