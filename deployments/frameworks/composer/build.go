/*
FILE PATH: deployments/frameworks/composer/build.go

DESCRIPTION:

	Build — reduces a Spec to a jurisdiction.Bundle. The single
	composition entry point every state/registry uses.

	Internally Build:

	  1. Validates the Spec (fails loud at boot on bad config).
	  2. Picks the tier base policy:
	       Trial   → frameworks/trial_base
	       IntermediateAppellate → frameworks/appellate_base
	       Supreme → frameworks/supreme_base
	  3. Iterates Spec.CourtTypes and applies each module's policy
	     overlays (court_type/circuit, court_type/chancery, …).
	  4. Threads RequiredCredentials into the cosignature mix so
	     attorney-filed events demand the right credential class.
	  5. Returns a jurisdiction.Bundle implementing the SDK contract.

	# Today's wrapped backend

	The trial-base implementation today returns the policies the
	pre-framework Davidson bundle returned (delegating to
	deployments/tn/trial). This means every framework-built TRIAL
	bundle has byte-identical policy with Davidson's pre-framework
	bundle — the migration is provably non-regressive. As court_type
	modules add real policy overlays (per-subject-matter cosig rules,
	per-court-type roles), the wrapped backend recedes; native
	framework policy fills in.

	The appellate-base and supreme-base implementations are minimal-
	but-valid policy frameworks today (empty appellate vocab,
	non-empty cosignature mix). They expand as the appellate and
	supreme-court bundles demand richer rules.
*/
package composer

import (
	"fmt"

	"github.com/baseproof/tooling/libs/policy"
	prerequisites "github.com/baseproof/tooling/libs/prereq"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/appellate_base"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/supreme_base"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/trial_base"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// Build reduces a Spec to a jurisdiction.Bundle. Panics if the Spec
// is invalid — boot-time configuration errors MUST fail loud, not
// silently produce a malformed bundle.
func Build(spec Spec) jurisdiction.Bundle {
	if err := spec.IsValid(); err != nil {
		panic(fmt.Sprintf("composer.Build(%s): %v", spec.DID, err))
	}

	// Pick the tier base. Each base returns a complete set of policy
	// surfaces; court_type modules overlay on top.
	var (
		catalog schemas.RoleCatalog
		cosig   policy.CosignatureMixPolicy
		preqs   prerequisites.Policy
		appVoc  jurisdiction.AppellateVocab
	)
	switch spec.Tier {
	case TierTrial:
		catalog = trial_base.MustRoleCatalog()
		cosig = trial_base.MustCosignaturePolicy()
		preqs = trial_base.MustPrerequisitePolicy()
		appVoc = trial_base.AppellateVocabulary()
	case TierIntermediateAppellate:
		catalog = appellate_base.MustRoleCatalog()
		cosig = appellate_base.MustCosignaturePolicy()
		preqs = appellate_base.MustPrerequisitePolicy()
		appVoc = appellate_base.AppellateVocabulary()
	case TierSupreme:
		catalog = supreme_base.MustRoleCatalog()
		cosig = supreme_base.MustCosignaturePolicy()
		preqs = supreme_base.MustPrerequisitePolicy()
		appVoc = supreme_base.AppellateVocabulary()
	default:
		panic(fmt.Sprintf("composer.Build(%s): unknown tier %v", spec.DID, spec.Tier))
	}

	// Build the Bundle. Today the court_type-specific overlays are
	// thin (the base policies cover ~all behavior); as court types
	// gain real policy differences, overlays add to catalog / cosig /
	// preqs here.

	b := &builtBundle{
		did:     spec.DID,
		catalog: catalog,
		cosig:   cosig,
		preqs:   preqs,
		appVoc:  appVoc,
	}

	if err := jurisdiction.Validate(b); err != nil {
		panic(fmt.Sprintf("composer.Build(%s): %v", spec.DID, err))
	}
	return b
}

// builtBundle is the concrete jurisdiction.Bundle the composer returns.
// It is unexported because the only way to construct one is via Build.
type builtBundle struct {
	did     string
	catalog schemas.RoleCatalog
	cosig   policy.CosignatureMixPolicy
	preqs   prerequisites.Policy
	appVoc  jurisdiction.AppellateVocab
}

func (b *builtBundle) ExchangeDID() string                            { return b.did }
func (b *builtBundle) RoleCatalog() schemas.RoleCatalog               { return b.catalog }
func (b *builtBundle) CosignaturePolicy() policy.CosignatureMixPolicy { return b.cosig }
func (b *builtBundle) PrerequisitePolicy() prerequisites.Policy       { return b.preqs }
func (b *builtBundle) AppellateVocabulary() jurisdiction.AppellateVocab {
	return b.appVoc
}

// authorityChainResolver is the package-level wiring point for the
// production resolver. Defaults to closed-by-default; production
// callers (cmd/network-api) call SetAuthorityChainResolver at boot
// once the verifier-backed resolver is built.
var authorityChainResolver jurisdiction.AuthorityChainResolver = jurisdiction.NoAuthorityChainResolver()

// SetAuthorityChainResolver injects the production resolver. Pass
// nil to revert to the closed-by-default placeholder.
func SetAuthorityChainResolver(r jurisdiction.AuthorityChainResolver) {
	if r == nil {
		authorityChainResolver = jurisdiction.NoAuthorityChainResolver()
		return
	}
	authorityChainResolver = r
}

func (b *builtBundle) AuthorityChainResolver() jurisdiction.AuthorityChainResolver {
	return authorityChainResolver
}

// Static-check that builtBundle satisfies jurisdiction.Bundle.
var _ jurisdiction.Bundle = (*builtBundle)(nil)
