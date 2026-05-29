/*
FILE PATH: deployments/registry/ca.go

DESCRIPTION:

	California STATE-LEVEL court entries:

	  California Supreme Court           (1)
	  California Court of Appeal         (4th District + 6th District,
	                                      with divisions where applicable)

	Superior Court entries (one per county) live in ca_counties.go
	as CountyProfile literals. The loader expands them via
	state_profile.CA conventions.
*/
package registry

import (
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials/attorney"
)

// CaliforniaStateLevelSpecs returns CA Supreme + Court of Appeal
// district + division entries.
func CaliforniaStateLevelSpecs() []composer.Spec {
	const apex = "did:web:state:ca:sc"
	return []composer.Spec{
		// ─── California Supreme Court ──────────────────────────
		{
			DID:                 "did:web:state:ca:sc",
			Name:                "Supreme Court of California",
			Tier:                composer.TierSupreme,
			CourtTypes:          []composer.CourtType{composer.CourtTypeSupreme},
			Jurisdiction:        composer.Jurisdiction{State: "CA"},
			RequiredCredentials: caAttorney(),
		},

		// ─── 4th District (3 geographic divisions) ─────────────
		caAppellate("did:web:state:ca:coa:4:1",
			"California Court of Appeal, Fourth Appellate District, Division 1 (San Diego)", apex),
		caAppellate("did:web:state:ca:coa:4:2",
			"California Court of Appeal, Fourth Appellate District, Division 2 (Riverside)", apex),
		caAppellate("did:web:state:ca:coa:4:3",
			"California Court of Appeal, Fourth Appellate District, Division 3 (Santa Ana)", apex),

		// ─── 6th District (single division, San Jose) ──────────
		caAppellate("did:web:state:ca:coa:6",
			"California Court of Appeal, Sixth Appellate District (San Jose)", apex),
	}
}

func caAttorney() []credentials.Credential {
	return []credentials.Credential{attorney.CA_Bar()}
}

func caAppellate(did, name, appealTo string) composer.Spec {
	return composer.Spec{
		DID:                 did,
		Name:                name,
		Tier:                composer.TierIntermediateAppellate,
		CourtTypes:          []composer.CourtType{composer.CourtTypeIntermediateAppellate},
		Jurisdiction:        composer.Jurisdiction{State: "CA"},
		RequiredCredentials: caAttorney(),
		AppellatePath:       appealTo,
	}
}
