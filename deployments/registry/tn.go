/*
FILE PATH: deployments/registry/tn.go

DESCRIPTION:

	Tennessee STATE-LEVEL court entries:

	  TN Supreme Court                   (1)
	  TN Court of Appeals                (3 grand divisions)
	  TN Court of Criminal Appeals       (3 grand divisions)

	County-level entries live in tn_counties.go as CountyProfile
	literals; the loader expands them.

	# Why state-level here, county-level there

	State-level courts are unique entities (one TN Supreme Court;
	three fixed grand divisions of the COA/COCA). They're cheap to
	declare directly. County-level courts are MANY (95 counties ×
	multiple court types each), benefit from the CountyProfile
	abstraction, and have shared structural rules best expressed
	declaratively per county.
*/
package registry

import (
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials/attorney"
)

// TennesseeStateLevelSpecs returns the TN Supreme Court + 3 COA grand
// divisions + 3 COCA grand divisions. County-level courts are NOT
// included; the loader appends those via TennesseeCounties().
func TennesseeStateLevelSpecs() []composer.Spec {
	const apex = "did:web:state:tn:sc"
	return []composer.Spec{
		// ─── Supreme Court ─────────────────────────────────────
		{
			DID:        "did:web:state:tn:sc",
			Name:       "Tennessee Supreme Court",
			Tier:       composer.TierSupreme,
			CourtTypes: []composer.CourtType{composer.CourtTypeSupreme},
			Jurisdiction: composer.Jurisdiction{
				State: "TN",
			},
			RequiredCredentials: tnAttorney(),
		},

		// ─── Court of Appeals (3 grand divisions) ──────────────
		tnIntermediateAppellate("did:web:state:tn:coa:east",
			"Tennessee Court of Appeals, Eastern Grand Division (Knoxville)", apex),
		tnIntermediateAppellate("did:web:state:tn:coa:middle",
			"Tennessee Court of Appeals, Middle Grand Division (Nashville)", apex),
		tnIntermediateAppellate("did:web:state:tn:coa:west",
			"Tennessee Court of Appeals, Western Grand Division (Jackson)", apex),

		// ─── Court of Criminal Appeals (3 grand divisions) ─────
		tnIntermediateAppellate("did:web:state:tn:coca:east",
			"Tennessee Court of Criminal Appeals, Eastern Grand Division (Knoxville)", apex),
		tnIntermediateAppellate("did:web:state:tn:coca:middle",
			"Tennessee Court of Criminal Appeals, Middle Grand Division (Nashville)", apex),
		tnIntermediateAppellate("did:web:state:tn:coca:west",
			"Tennessee Court of Criminal Appeals, Western Grand Division (Jackson)", apex),
	}
}

func tnAttorney() []credentials.Credential {
	return []credentials.Credential{attorney.TN_BPR()}
}

// tnIntermediateAppellate is the per-grand-division spec builder.
func tnIntermediateAppellate(did, name, appealTo string) composer.Spec {
	return composer.Spec{
		DID:                 did,
		Name:                name,
		Tier:                composer.TierIntermediateAppellate,
		CourtTypes:          []composer.CourtType{composer.CourtTypeIntermediateAppellate},
		Jurisdiction:        composer.Jurisdiction{State: "TN"},
		RequiredCredentials: tnAttorney(),
		AppellatePath:       appealTo,
	}
}
