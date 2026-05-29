/*
FILE PATH: deployments/frameworks/state_profile/ca.go

DESCRIPTION:

	California state convention. Mirrors TN's structure where
	mechanisms are equivalent and diverges where CA's institutional
	pattern differs.

	# Critical differences from TN

	  Court structure: CA has a UNIFIED Superior Court per county
	  (all subject matters in one court), where TN has separate
	  Circuit / Chancery / Criminal / etc. CA CountyProfiles list
	  ONE CourtSlot of type UnifiedSuperior.

	  Clerk structure: CA has ONE appointed Court Executive Officer
	  per Superior Court, NOT four parallel elected clerks. The CEO
	  is appointed by the presiding judge of the Superior Court.

	  Appellate routing: CA's 6 Court of Appeal districts cover
	  multiple counties each; 4th District has 3 divisions.

	# Adding CA Superior Court counties

	A new county = literal in registry/ca_counties.go:

	    var orange = CountyProfile{
	        State: "CA", Name: "Orange", Size: SizeLarge,
	        Courthouses: []Courthouse{{ID: "santa_ana", Address: "..."}},
	        Courts: []CourtSlot{
	            {Type: CourtTypeUnifiedSuperior, Count: 1,
	             NameFmt: "Superior Court of California, County of Orange"},
	        },
	    }

	No state-profile changes; the CA convention generates the single
	CEO clerk automatically.
*/
package state_profile

import (
	"strings"

	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/county_profile"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials/attorney"
)

// CA returns the California state convention.
func CA() county_profile.Conventions {
	return &caConventions{}
}

type caConventions struct{}

func (c *caConventions) StatePostalCode() string { return "CA" }

// AttorneyCredentials returns the CA Bar credential for every CA
// court. CA Bar is statewide.
func (c *caConventions) AttorneyCredentials(_ string) []credentials.Credential {
	return []credentials.Credential{attorney.CA_Bar()}
}

// ClerksFor returns CA's clerk roster: a SINGLE Court Executive
// Officer per Superior Court, appointed by the presiding judge.
// Size is ignored — CA's CEO model is the same across all 58
// counties; only branch counts vary.
func (c *caConventions) ClerksFor(profile county_profile.CountyProfile) []county_profile.ClerkSlot {
	return []county_profile.ClerkSlot{
		{
			Type:      county_profile.ClerkTypeCourtExecutiveOfficer,
			Selection: county_profile.SelectionAppointedByPresidingJudge,
			NameFmt:   "Court Executive Officer, Superior Court of California, County of %s",
		},
	}
}

// caCoADistrict maps counties to their Court of Appeal district +
// division. CA CoA has 6 districts; 4th Dist has 3 divisions
// geographically split (Div 1 San Diego, Div 2 Riverside, Div 3
// Santa Ana). Most counties go to a single division.
func caCoADistrict(countyName string) string {
	switch strings.ToLower(countyName) {
	// 4th District, Division 1 (San Diego).
	case "san_diego", "imperial":
		return "4:1"
	// 4th District, Division 2 (Riverside).
	case "riverside", "san_bernardino", "inyo":
		return "4:2"
	// 4th District, Division 3 (Santa Ana).
	case "orange":
		return "4:3"
	// 6th District (San Jose).
	case "santa_clara", "monterey", "san_benito", "santa_cruz":
		return "6"
	// 5th District (Fresno).
	case "fresno", "kings", "kern", "madera", "merced",
		"stanislaus", "tulare", "tuolumne", "mariposa":
		return "5"
	// 3rd District (Sacramento).
	case "sacramento", "el_dorado", "placer", "yolo", "sutter",
		"butte", "amador":
		return "3"
	// 2nd District (Los Angeles) — has 8 divisions; pick a default.
	case "los_angeles", "ventura", "santa_barbara", "san_luis_obispo":
		return "2"
	// 1st District (San Francisco) — has 5 divisions; default.
	case "san_francisco", "alameda", "contra_costa", "marin",
		"san_mateo", "sonoma", "napa", "solano":
		return "1"
	default:
		// Default to 1st District (San Francisco) for unknown counties.
		// Production deployments would override per-county.
		return "1"
	}
}

// CivilAppellateDID returns the CA Court of Appeal district covering
// the given county.
func (c *caConventions) CivilAppellateDID(countyName string) string {
	return "did:web:state:ca:coa:" + caCoADistrict(strings.ReplaceAll(strings.ToLower(countyName), " ", "_"))
}

// CriminalAppellateDID for CA: same Court of Appeal as civil (CA's
// CoA hears both). The criminal/civil split that TN has does NOT
// exist in CA.
func (c *caConventions) CriminalAppellateDID(countyName string) string {
	return c.CivilAppellateDID(countyName)
}
