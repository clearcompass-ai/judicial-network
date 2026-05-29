/*
FILE PATH: deployments/frameworks/supreme_base/supreme_base.go

DESCRIPTION:

	supreme_base — the shared policy framework for apex courts:
	SCOTUS, TN Supreme Court, CA Supreme Court.

	# Today's backend

	Wraps deployments/tn/sup_ct (the TN Supreme Court bundle). The TN
	Sup Ct package carries an apex-shaped role catalog, cosignature
	mix, and appellate vocabulary. CA Supreme Court and SCOTUS compose
	onto the same backend; jurisdiction-specific rules (SCOTUS's
	original jurisdiction grants, CA's automatic-review-of-death-
	penalty cases, …) are deferred until a real workflow demands them.

	# Tomorrow's backend

	Native rules will eventually capture:
	  - Original-jurisdiction event types (SCOTUS interstate disputes)
	  - Discretionary-review policy (certiorari granted / denied)
	  - En-banc-only signing rules
	but again, the four MustXxx + AppellateVocabulary returners on
	this package stay stable.
*/
package supreme_base

import (
	prerequisites "github.com/clearcompass-ai/attesta-tools/libs/prereq"
	tnsupct "github.com/clearcompass-ai/judicial-network/deployments/tn/sup_ct"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

func MustRoleCatalog() schemas.RoleCatalog {
	return tnsupct.MustRoleCatalog()
}

func MustCosignaturePolicy() policy.CosignatureMixPolicy {
	return tnsupct.MustCosignaturePolicy()
}

func MustPrerequisitePolicy() prerequisites.Policy {
	return tnsupct.MustPrerequisitePolicy()
}

func AppellateVocabulary() jurisdiction.AppellateVocab {
	return tnsupct.AppellateVocabulary()
}
