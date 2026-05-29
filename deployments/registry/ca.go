/*
FILE PATH: deployments/registry/ca.go

DESCRIPTION:

	California court registry entries — every court in scope:

	  California Supreme Court           (1)
	  California Court of Appeal         (4th District + 6th District,
	                                      with divisions where applicable)
	  Superior Court of California       (Riverside, Santa Clara)

	# CA's trial-court structure (one Superior Court per county)

	California has a UNIFIED trial-court system: ONE Superior Court
	per county, with internal organizational departments (Family,
	Probate, Criminal, Civil, Juvenile) that are NOT separate courts.
	Each Superior Court is one Spec with CourtTypeUnifiedSuperior;
	the composer expands that into the full subject-matter coverage.

	# CA Court of Appeal — the divisional structure

	The Court of Appeal sits in 6 districts. Two have multiple
	divisions (1st Dist has 5, 2nd Dist has 8); the others sit as a
	single division (3rd, 5th, 6th). The 4th District has 3 divisions
	geographically split between San Diego, Riverside, and Santa Ana.

	Cases route appellate-wise:

	  Riverside Superior     → 4th Dist, Division 2 (Riverside)
	  Santa Clara Superior   → 6th Dist (San Jose)
	  Both →                   California Supreme Court

	The 4th District's 3 divisions are modeled as 3 separate specs
	(each with its own DID, its own panel). The 6th District is one.
*/
package registry

import (
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials/attorney"
)

// CaliforniaSpecs returns every CA court entry. Stable order:
// Supreme, Court of Appeal districts (4th then 6th), Superior Courts.
func CaliforniaSpecs() []composer.Spec {
	return []composer.Spec{
		// ─── California Supreme Court ──────────────────────────
		{
			DID:                 "did:web:state:ca:sc",
			Name:                "Supreme Court of California",
			Tier:                composer.TierSupreme,
			CourtTypes:          []composer.CourtType{composer.CourtTypeSupreme},
			Jurisdiction:        composer.Jurisdiction{State: "CA"},
			RequiredCredentials: []credentials.Credential{attorney.CA_Bar()},
		},

		// ─── 4th District Court of Appeal (Division 1: San Diego;
		//     Division 2: Riverside; Division 3: Santa Ana) ──────
		caAppellate("did:web:state:ca:coa:4:1",
			"California Court of Appeal, Fourth Appellate District, Division 1 (San Diego)"),
		caAppellate("did:web:state:ca:coa:4:2",
			"California Court of Appeal, Fourth Appellate District, Division 2 (Riverside)"),
		caAppellate("did:web:state:ca:coa:4:3",
			"California Court of Appeal, Fourth Appellate District, Division 3 (Santa Ana)"),

		// ─── 6th District Court of Appeal (San Jose, single division) ──
		caAppellate("did:web:state:ca:coa:6",
			"California Court of Appeal, Sixth Appellate District (San Jose)"),

		// ─── Superior Courts (unified trial; one per county) ───
		caSuperior("did:web:state:ca:superior:riverside",
			"Superior Court of California, County of Riverside",
			"did:web:state:ca:coa:4:2"),
		caSuperior("did:web:state:ca:superior:santa_clara",
			"Superior Court of California, County of Santa Clara",
			"did:web:state:ca:coa:6"),
	}
}

// caAppellate is the per-CA-CoA-division Spec builder.
func caAppellate(did, name string) composer.Spec {
	return composer.Spec{
		DID:                 did,
		Name:                name,
		Tier:                composer.TierIntermediateAppellate,
		CourtTypes:          []composer.CourtType{composer.CourtTypeIntermediateAppellate},
		Jurisdiction:        composer.Jurisdiction{State: "CA"},
		RequiredCredentials: []credentials.Credential{attorney.CA_Bar()},
		AppellatePath:       "did:web:state:ca:sc",
	}
}

// caSuperior is the per-CA-Superior-Court Spec builder. CA Superior
// Courts are UNIFIED — composer expands CourtTypeUnifiedSuperior into
// the full subject-matter coverage (civil + criminal + family + probate
// + juvenile + small claims).
func caSuperior(did, name, appealTo string) composer.Spec {
	return composer.Spec{
		DID:                 did,
		Name:                name,
		Tier:                composer.TierTrial,
		CourtTypes:          []composer.CourtType{composer.CourtTypeUnifiedSuperior},
		Jurisdiction:        composer.Jurisdiction{State: "CA"},
		RequiredCredentials: []credentials.Credential{attorney.CA_Bar()},
		AppellatePath:       appealTo,
	}
}
