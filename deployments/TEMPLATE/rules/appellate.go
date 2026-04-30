/*
FILE PATH: deployments/TEMPLATE/rules/appellate.go

DESCRIPTION:
    TEMPLATE deployment — AppellateVocabulary skeleton. Returns
    the empty vocab for trial-only exchanges. Appellate
    deployments override with their jurisdiction's closed-set
    enums (see deployments/tn/coa/appellate.go for v1.8 §7B
    closed-set values: 11 opinion types, 6 participation roles,
    6 disposition outcomes, 3 review types).

OVERVIEW:
    AppellateVocabulary  — returns jurisdiction.EmptyAppellateVocab().
*/
package rules

import "github.com/clearcompass-ai/judicial-network/jurisdiction"

// AppellateVocabulary returns the TEMPLATE deployment's
// appellate vocab. Trial-only by default; appellate deployments
// replace this with a populated AppellateVocab.
func AppellateVocabulary() jurisdiction.AppellateVocab {
	return jurisdiction.EmptyAppellateVocab()
}
