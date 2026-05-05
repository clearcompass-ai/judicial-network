/*
FILE PATH: deployments/tn/trial/appellate.go

DESCRIPTION:

	AppellateVocabulary for TN trial-court exchanges. Trial
	courts never accept appellate_* event payloads — those are
	owned by the TN Court of Appeals exchange (deployments/tn/coa/).
	This file returns the closed-empty vocabulary so every TN
	county Bundle can satisfy the Bundle.AppellateVocabulary()
	contract without duplicating boilerplate.

	Why a separate file rather than wiring jurisdiction.
	EmptyAppellateVocab() inline at each county Bundle: when a
	TN exchange ever needs to extend the appellate vocab (e.g.,
	a hypothetical county-level merits-review subset), only this
	one file changes. Composer Bundles stay 30-line shims.

OVERVIEW:

	AppellateVocabulary  — returns jurisdiction.EmptyAppellateVocab().

KEY DEPENDENCIES:
  - jurisdiction.AppellateVocab / EmptyAppellateVocab.
*/
package trial

import "github.com/clearcompass-ai/judicial-network/jurisdiction"

// AppellateVocabulary returns the TN trial-court appellate
// vocabulary — definitionally empty. Every TN county Bundle
// returns this from Bundle.AppellateVocabulary().
//
// The TN Court of Appeals Bundle (deployments/tn/coa/) provides
// the v1.8 §7B values (opinion types, participation roles,
// disposition outcomes, review types) for entries destined to
// the COA exchange.
func AppellateVocabulary() jurisdiction.AppellateVocab {
	return jurisdiction.EmptyAppellateVocab()
}
