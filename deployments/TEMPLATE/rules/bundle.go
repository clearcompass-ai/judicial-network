/*
FILE PATH: deployments/TEMPLATE/rules/bundle.go

DESCRIPTION:
    TEMPLATE deployment — Bundle composer. Wires the four
    skeleton policy files (role_catalog, cosignature_mix,
    prerequisites, appellate) into a single jurisdiction.Bundle.

    Copy this entire deployments/TEMPLATE/ tree to a new
    deployments/<framework>/<court>/ tree, then:
      1. Replace ExchangeDID with the deployment's actual DID
         (e.g., did:web:state:tn:shelby for a TN county; or
         did:web:fed:trial:tnm for a federal trial court).
      2. Edit role_catalog.go to add the deployment's Signer
         roles.
      3. Edit cosignature_mix.go to define the cosignature mix.
      4. Edit prerequisites.go to define the event vocabulary
         and per-event prereqs.
      5. (Appellate exchanges only) edit appellate.go to define
         the closed-set payload-enum vocabulary.

    The skeleton compiles, passes jurisdiction.Validate, and
    registers cleanly into a jurisdiction.Registry — but the
    placeholder ExchangeDID makes it unsafe for production until
    the actual DID is wired.

OVERVIEW:
    ExchangeDID    — institutional DID constant (PLACEHOLDER).
    MustBundle     — canonical Bundle factory (panics on error).
    BundleProvider — jurisdiction.Provider for v3 plugin loading.
    bundle         — unexported impl of jurisdiction.Bundle.

KEY DEPENDENCIES:
    - jurisdiction.Bundle / Provider / NoAuthorityChainResolver.
*/
package rules

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ExchangeDID is the TEMPLATE deployment's PLACEHOLDER DID.
// Real deployments replace this with their actual institutional
// DID (e.g., did:web:state:tn:shelby).
const ExchangeDID = "did:web:TEMPLATE:replace-me"

// bundle implements jurisdiction.Bundle for the TEMPLATE
// skeleton. Composes the four sibling policy files.
type bundle struct {
	catalog schemas.RoleCatalog
	cosig   policy.CosignatureMixPolicy
	preqs   prerequisites.Policy
}

func (b *bundle) ExchangeDID() string                            { return ExchangeDID }
func (b *bundle) RoleCatalog() schemas.RoleCatalog               { return b.catalog }
func (b *bundle) CosignaturePolicy() policy.CosignatureMixPolicy { return b.cosig }
func (b *bundle) PrerequisitePolicy() prerequisites.Policy       { return b.preqs }

// authorityChainResolver is the package-level wiring point.
// New deployments copying this TEMPLATE inherit the same
// pattern: default closed; SetAuthorityChainResolver injects
// the production resolver at boot.
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

// MustBundle returns the canonical TEMPLATE Bundle. Panics if
// the underlying skeleton fails to validate (a bug in this
// package).
func MustBundle() jurisdiction.Bundle {
	b := &bundle{
		catalog: MustRoleCatalog(),
		cosig:   MustCosignaturePolicy(),
		preqs:   MustPrerequisitePolicy(),
	}
	if err := jurisdiction.Validate(b); err != nil {
		panic(fmt.Sprintf("TEMPLATE/rules: bundle invalid: %v", err))
	}
	return b
}

// BundleProvider satisfies jurisdiction.Provider for the v3
// plugin path.
var BundleProvider jurisdiction.Provider = func() (jurisdiction.Bundle, error) {
	defer func() { _ = recover() }()
	return MustBundle(), nil
}
