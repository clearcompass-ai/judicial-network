/*
FILE PATH: deployments/frameworks/appellate_base/appellate_base.go

DESCRIPTION:

	appellate_base — the shared policy framework for intermediate
	appellate courts: TN COA + COCA, CA Court of Appeal, federal
	Circuit Courts of Appeals.

	# Today's backend

	Wraps deployments/tn/coa's policy returners. The TN Court of
	Appeals package already carries an appellate-shaped role catalog
	(chief_judge / judge / court_clerk / deputy_clerk), an appellate
	cosignature mix (10 rules covering the v1.8 §7B appellate family),
	and a prerequisite vocabulary. The Bundle wrappers for CA Court
	of Appeal divisions and federal Circuit courts compose onto this
	same backend; jurisdiction differences are jurisdictional, not
	procedural at this abstraction layer.

	# Tomorrow's backend

	Native rules will incorporate:
	  - en-banc cosignature mix (more required signers)
	  - mandate-issuance prerequisites
	  - intermediate-vs-discretionary review policy variants
	but the interface this file exposes (the four MustXxx +
	AppellateVocabulary returners) stays stable.
*/
package appellate_base

import (
	"github.com/baseproof/tooling/libs/auth/policy"
	prerequisites "github.com/baseproof/tooling/libs/prereq"
	tncoa "github.com/clearcompass-ai/judicial-network/deployments/tn/coa"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

func MustRoleCatalog() schemas.RoleCatalog {
	return tncoa.MustRoleCatalog()
}

func MustCosignaturePolicy() policy.CosignatureMixPolicy {
	return tncoa.MustCosignaturePolicy()
}

func MustPrerequisitePolicy() prerequisites.Policy {
	return tncoa.MustPrerequisitePolicy()
}

func AppellateVocabulary() jurisdiction.AppellateVocab {
	return tncoa.AppellateVocabulary()
}
