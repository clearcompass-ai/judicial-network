/*
FILE PATH: deployments/frameworks/trial_base/trial_base.go

DESCRIPTION:

	trial_base — the shared policy framework EVERY trial court in
	EVERY jurisdiction composes onto. TN Circuit, TN Chancery, CA
	Superior, federal District — all start here, then layer
	court_type modules + jurisdiction credentials on top via the
	composer.

	# Today's backend

	trial_base wraps deployments/tn/trial. That package already
	carries the production-tested role catalog, cosignature mix,
	prerequisite policy, and (empty) appellate vocabulary the legacy
	Davidson bundle used. Wrapping (not duplicating) lets every
	framework-built trial bundle have byte-identical policy with the
	legacy Davidson bundle — the migration is provably non-regressive.

	The single TN-specific leak in the wrapped policy (the hardcoded
	"bpr_number" credential string in tn/trial/cosignature_mix.go) is
	parameterized OUT in the composer step: the wrapped policy returns
	the cosignature rules with the placeholder credential ID, and the
	composer rewrites it to the bundle's RequiredCredentials at Build
	time.

	# Tomorrow's backend

	As court_type modules (circuit, chancery, probate, etc.) gain
	real policy overlays, the wrapped backend recedes — court_type
	rules accumulate on top of trial_base, then native trial_base
	rules replace the wrapped tn/trial calls. The interface this file
	exposes stays stable across that migration.
*/
package trial_base

import (
	"github.com/baseproof/tooling/libs/policy"
	prerequisites "github.com/baseproof/tooling/libs/prereq"
	tntrial "github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// MustRoleCatalog returns the shared trial-court role catalog. Today
// wraps tn/trial; tomorrow becomes native + adds Tier-of-roles.
func MustRoleCatalog() schemas.RoleCatalog {
	return tntrial.MustRoleCatalog()
}

// MustCosignaturePolicy returns the shared trial-court cosignature
// mix. Today wraps tn/trial; the bpr_number placeholder is
// parameterized OUT by the composer at Build time.
func MustCosignaturePolicy() policy.CosignatureMixPolicy {
	return tntrial.MustCosignaturePolicy()
}

// MustPrerequisitePolicy returns the shared trial-court prerequisite
// policy.
func MustPrerequisitePolicy() prerequisites.Policy {
	return tntrial.MustPrerequisitePolicy()
}

// AppellateVocabulary returns the trial-court appellate vocabulary
// (empty by design — trial courts don't emit appellate vocabulary;
// the COA / Supreme bundles do).
func AppellateVocabulary() jurisdiction.AppellateVocab {
	return tntrial.AppellateVocabulary()
}
