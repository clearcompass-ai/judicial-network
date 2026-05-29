/*
FILE PATH: deployments/registry/tn_counties.go

DESCRIPTION:

	Tennessee county DATA. Every county is one CountyProfile literal.
	The framework's county_profile.Expand + state_profile.TN convert
	these into court Specs + ClerkSpecs at boot.

	Adding a new TN county = one literal entry in TennesseeCounties.
	No new functions. No new files in registry/.

	The framework derives:
	  - Court DIDs and names from CourtSlot.NameFmt + Count.
	  - Clerk offices from state_profile.TN's roster for the county's
	    Size (Davidson SizeLarge → 4 clerks; small-county → 3).
	  - Civil + criminal appellate paths from TN's grand-division
	    geography (Davidson → middle; Knox → east).

	Captured structural facts:

	  Davidson Circuit Court Part 7 is the Probate Division.
	    Encoded as Overlays[7] = [CourtTypeProbate] on the Davidson
	    Circuit slot.

	  Davidson Juvenile Court is the Juvenile & Family Court (a
	    correction from the prior model — Davidson combines J&F into
	    one institutional court).
	    Encoded as ExtraTypes: [CourtTypeFamily] on the Davidson
	    Juvenile slot.

	  Davidson Chancery does NOT hear probate — probate is in
	    Circuit Court Part 7. The Chancery slot has no ExtraTypes.

	  Knox Chancery DOES hear probate (no separate Probate Court).
	    Knox Chancery slot has ExtraTypes: [CourtTypeProbate].
*/
package registry

import (
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/county_profile"
)

// TennesseeCounties returns the list of TN county profiles.
func TennesseeCounties() []county_profile.CountyProfile {
	return []county_profile.CountyProfile{
		davidson,
		knox,
		sullivan,
	}
}

// ─── Davidson County (Nashville) ─────────────────────────────────────
// Largest county in TN: 8 Circuit Court Parts, 4 Chancery Parts, 6
// Criminal Court Divisions, multiple General Sessions divisions,
// separate Juvenile & Family Court. Address per TN AOC site:
// 1 Public Square, Nashville, TN 37201.
var davidson = county_profile.CountyProfile{
	State: "TN", Name: "Davidson", Size: county_profile.SizeLarge,
	Courthouses: []county_profile.Courthouse{
		{ID: "main", Name: "Davidson Justice Center",
			Address: "1 Public Square, Nashville, TN 37201"},
	},
	Courts: []county_profile.CourtSlot{
		{
			Type:    composer.CourtTypeCircuit,
			Count:   8,
			NameFmt: "Davidson County Circuit Court, Part %d",
			Overlays: map[int][]composer.CourtType{
				// Part 7 is the Probate Division (Davidson's probate
				// jurisdiction sits in Circuit Court Part 7, NOT in
				// Chancery — that's the structural distinction from
				// Knox).
				7: {composer.CourtTypeProbate},
			},
		},
		{
			Type:    composer.CourtTypeChancery,
			Count:   4,
			NameFmt: "Davidson County Chancery Court, Part %s", // %s → Roman
			// NO probate ExtraTypes: Davidson Chancery is equity-only.
		},
		{
			Type:    composer.CourtTypeCriminal,
			Count:   6,
			NameFmt: "Davidson County Criminal Court, Division %d",
		},
		{
			Type:       composer.CourtTypeGeneralSessions,
			Count:      4,
			DIDSegment: "gen_sessions_civil",
			NameFmt:    "Davidson County General Sessions Court (Civil), Division %d",
		},
		{
			Type:       composer.CourtTypeGeneralSessions,
			Count:      4,
			DIDSegment: "gen_sessions_criminal",
			ExtraTypes: []composer.CourtType{composer.CourtTypeCriminal},
			NameFmt:    "Davidson County General Sessions Court (Criminal), Division %d",
		},
		{
			Type:       composer.CourtTypeJuvenile,
			Count:      1,
			DIDSegment: "juvenile",
			// Davidson's "Juvenile Court" is officially the Juvenile &
			// Family Court — a single combined court hearing juvenile
			// delinquency, dependency/neglect, AND family-law matters
			// (divorce, custody, adoption). This is per the TN AOC
			// listing for Davidson County which names "Juvenile &
			// Family Courts" as the court type.
			ExtraTypes: []composer.CourtType{composer.CourtTypeFamily},
			NameFmt:    "Davidson County Juvenile & Family Court",
		},
	},
}

// ─── Knox County (Knoxville) ─────────────────────────────────────────
// Large but smaller than Davidson: 4 Circuit Parts, 3 Chancery Parts
// (THAT HEAR PROBATE — Knox has no separate Probate Court), 3
// Criminal Divisions, 4 General Sessions divisions (mixed civil +
// criminal), separate Juvenile Court (NOT combined with Family).
//
// Knox County Clerk (Sherry Witt) operates from Main + 5 satellite
// branches (West, Farragut, North, South, East). Encoded in
// ClerkBranches; the expander attaches these to the County Clerk
// ClerkSlot the state convention generates.
var knox = county_profile.CountyProfile{
	State: "TN", Name: "Knox", Size: county_profile.SizeLarge,
	Courthouses: []county_profile.Courthouse{
		{ID: "main", Name: "City-County Building",
			Address: "City-County Building, 400 Main St, Knoxville, TN 37902"},
	},
	Courts: []county_profile.CourtSlot{
		{
			Type:    composer.CourtTypeCircuit,
			Count:   4,
			NameFmt: "Knox County Circuit Court, Division %d",
		},
		{
			Type:  composer.CourtTypeChancery,
			Count: 3,
			// Knox Chancery hears PROBATE in addition to equity (Knox
			// has no separate Probate Court). The structural
			// distinction from Davidson.
			ExtraTypes: []composer.CourtType{composer.CourtTypeProbate},
			NameFmt:    "Knox County Chancery Court, Part %s",
		},
		{
			Type:    composer.CourtTypeCriminal,
			Count:   3,
			NameFmt: "Knox County Criminal Court, Division %d",
		},
		{
			Type:    composer.CourtTypeGeneralSessions,
			Count:   4,
			NameFmt: "Knox County General Sessions Court, Division %d",
		},
		{
			Type:    composer.CourtTypeJuvenile,
			Count:   1,
			NameFmt: "Knox County Juvenile Court",
		},
	},
	// Knox County Clerk (Sherry Witt) operates from 6 physical
	// locations: the Main Office at the Old Courthouse downtown,
	// plus 5 satellite branches. Each branch handles civic admin
	// (vehicle tags, driver's licenses, marriage licenses, Real IDs).
	// Branches are recorded as metadata on the ClerkSpec for audit-
	// trail clarity.
	ClerkBranches: map[county_profile.ClerkType][]county_profile.Branch{
		county_profile.ClerkTypeCounty: {
			{ID: "main", Name: "Old Courthouse (Main Office)",
				Address: "300 Main St, Knoxville, TN 37902"},
			{ID: "west", Name: "West Knoxville",
				Address: "Cedar Bluff, Knoxville, TN"},
			{ID: "farragut", Name: "Farragut",
				Address: "11409 Municipal Center Dr, Farragut, TN 37934"},
			{ID: "north", Name: "North Knoxville",
				Address: "Halls, Knoxville, TN"},
			{ID: "south", Name: "South Knoxville",
				Address: "South Knoxville, TN"},
			{ID: "east", Name: "East Knoxville",
				Address: "East Knoxville, TN"},
		},
	},
}

// ─── Sullivan County (Bristol / Kingsport / Blountville) ─────────────
// Multi-courthouse demonstrator. Sullivan is one county with THREE
// physical courthouses, each carrying its own Circuit + Chancery +
// General Sessions court instances. Encoded with PerCourthouse: 1
// on each slot — the expander emits 3 × Circuit + 3 × Chancery + 3
// × GS = 9 court Specs, each named per its courthouse.
//
// DIDs use the courthouse ID as the segment ordinal:
//   did:web:state:tn:sullivan:circuit:bristol:1
//   did:web:state:tn:sullivan:circuit:kingsport:1
//   did:web:state:tn:sullivan:circuit:blountville:1
//   ... (and similarly for chancery + gen_sessions)
//
// Sullivan is SizeMedium so state_profile.TN generates 3 clerks
// (County, Circuit-consolidating-Criminal+GS, Clerk and Master).
var sullivan = county_profile.CountyProfile{
	State: "TN", Name: "Sullivan", Size: county_profile.SizeMedium,
	Courthouses: []county_profile.Courthouse{
		{ID: "bristol", Name: "Bristol",
			Address: "801 Anderson St, Bristol, TN 37620"},
		{ID: "kingsport", Name: "Kingsport",
			Address: "225 W Center St, Kingsport, TN 37660"},
		{ID: "blountville", Name: "Blountville",
			Address: "140 Blountville Bypass, Blountville, TN 37617"},
	},
	Courts: []county_profile.CourtSlot{
		{
			Type:          composer.CourtTypeCircuit,
			PerCourthouse: 1,
			NameFmt:       "Sullivan County Circuit Court (%s)",
		},
		{
			Type:          composer.CourtTypeChancery,
			PerCourthouse: 1,
			NameFmt:       "Sullivan County Chancery Court (%s)",
		},
		{
			Type:          composer.CourtTypeGeneralSessions,
			PerCourthouse: 1,
			NameFmt:       "Sullivan County General Sessions Court (%s)",
		},
	},
}
