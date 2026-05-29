/*
FILE PATH: deployments/frameworks/state_profile/tn.go

DESCRIPTION:

	Tennessee state convention. Implements county_profile.Conventions
	for TN-specific facts:

	  - 31 judicial districts; civil appeals route to the COA grand
	    division covering the county's geography (East / Middle /
	    West); criminal appeals route to COCA's equivalent grand
	    division.

	  - Clerk roster depends on county size:
	      Large  → 4 clerks (County / Circuit / Criminal / Clerk
	               and Master)
	      Medium → 3 clerks (County / Circuit consolidating
	               Criminal+GS / Clerk and Master)
	      Small  → 3 clerks (County / Circuit consolidating
	               Criminal+GS+Juvenile / Clerk and Master)

	  - Attorney credential is TN BPR number (Board of Professional
	    Responsibility) across every court tier.

	Adding a new TN county = literal in registry/tn_counties.go;
	this file doesn't change. Adding a new clerk roster pattern
	(e.g. "extra-large" county with separate Juvenile Court Clerk)
	= a new case in the ClerksFor switch.
*/
package state_profile

import (
	"strings"

	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/county_profile"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials/attorney"
)

// TN returns the Tennessee state convention.
func TN() county_profile.Conventions {
	return &tnConventions{}
}

type tnConventions struct{}

func (c *tnConventions) StatePostalCode() string { return "TN" }

// AttorneyCredentials returns the TN BPR credential for every TN
// court. courtDID is unused (TN bar is statewide); kept in the
// signature for the Conventions interface symmetry.
func (c *tnConventions) AttorneyCredentials(_ string) []credentials.Credential {
	return []credentials.Credential{attorney.TN_BPR()}
}

// ClerksFor returns TN's clerk roster for a county of the given size.
//
// Roster facts (TN Code Annotated):
//
//   - Every county elects a County Clerk (civic admin).
//   - Every county has a Circuit Court Clerk (sometimes consolidating
//     other court records).
//   - Large counties elect a separate Criminal Court Clerk; smaller
//     counties fold criminal records under the Circuit Court Clerk.
//   - Every county's Chancery Court has a Clerk and Master appointed
//     by the Chancellors — NEVER consolidated, even in small counties.
func (c *tnConventions) ClerksFor(profile county_profile.CountyProfile) []county_profile.ClerkSlot {
	switch profile.Size {
	case county_profile.SizeLarge:
		// Davidson, Knox, Shelby, Hamilton: four separate offices.
		return []county_profile.ClerkSlot{
			{
				Type:      county_profile.ClerkTypeCounty,
				Selection: county_profile.SelectionElected,
				NameFmt:   "%s County Clerk",
			},
			{
				Type:      county_profile.ClerkTypeCircuitCourt,
				Selection: county_profile.SelectionElected,
				NameFmt:   "%s Circuit Court Clerk",
			},
			{
				Type:      county_profile.ClerkTypeCriminalCourt,
				Selection: county_profile.SelectionElected,
				NameFmt:   "%s Criminal Court Clerk",
			},
			{
				Type:      county_profile.ClerkTypeClerkAndMaster,
				Selection: county_profile.SelectionAppointedByChancellors,
				NameFmt:   "%s Clerk and Master",
			},
		}
	case county_profile.SizeMedium:
		// Circuit Court Clerk consolidates Criminal + GS records.
		return []county_profile.ClerkSlot{
			{
				Type:      county_profile.ClerkTypeCounty,
				Selection: county_profile.SelectionElected,
				NameFmt:   "%s County Clerk",
			},
			{
				Type:      county_profile.ClerkTypeCircuitCourt,
				Selection: county_profile.SelectionElected,
				ServesAlso: []county_profile.ClerkType{
					county_profile.ClerkTypeCriminalCourt,
					county_profile.ClerkTypeGeneralSessions,
				},
				NameFmt: "%s Circuit Court Clerk",
			},
			{
				Type:      county_profile.ClerkTypeClerkAndMaster,
				Selection: county_profile.SelectionAppointedByChancellors,
				NameFmt:   "%s Clerk and Master",
			},
		}
	case county_profile.SizeSmall:
		// Fully consolidated: Circuit Court Clerk also handles
		// Juvenile records.
		return []county_profile.ClerkSlot{
			{
				Type:      county_profile.ClerkTypeCounty,
				Selection: county_profile.SelectionElected,
				NameFmt:   "%s County Clerk",
			},
			{
				Type:      county_profile.ClerkTypeCircuitCourt,
				Selection: county_profile.SelectionElected,
				ServesAlso: []county_profile.ClerkType{
					county_profile.ClerkTypeCriminalCourt,
					county_profile.ClerkTypeGeneralSessions,
					county_profile.ClerkTypeJuvenile,
				},
				NameFmt: "%s Circuit Court Clerk",
			},
			{
				Type:      county_profile.ClerkTypeClerkAndMaster,
				Selection: county_profile.SelectionAppointedByChancellors,
				NameFmt:   "%s Clerk and Master",
			},
		}
	}
	return nil
}

// tnGrandDivision returns "east" / "middle" / "west" for a TN
// county. Stub implementation: known counties hard-mapped; unknown
// counties default to "middle". Replace with a comprehensive map
// when needed.
func tnGrandDivision(countyName string) string {
	switch strings.ToLower(countyName) {
	// Eastern Grand Division anchor counties.
	case "knox", "hamilton", "sullivan", "blount", "jefferson",
		"anderson", "bradley", "polk", "monroe", "loudon":
		return "east"
	// Western Grand Division anchor counties.
	case "shelby", "madison", "fayette", "haywood", "hardeman",
		"hardin", "tipton", "henderson":
		return "west"
	// Middle Grand Division — Davidson + the rest of TN.
	default:
		return "middle"
	}
}

// CivilAppellateDID returns the TN COA grand division DID covering
// the given county.
func (c *tnConventions) CivilAppellateDID(countyName string) string {
	return "did:web:state:tn:coa:" + tnGrandDivision(countyName)
}

// CriminalAppellateDID returns the TN COCA grand division DID
// covering the given county.
func (c *tnConventions) CriminalAppellateDID(countyName string) string {
	return "did:web:state:tn:coca:" + tnGrandDivision(countyName)
}
