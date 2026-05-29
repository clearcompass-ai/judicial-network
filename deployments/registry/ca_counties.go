/*
FILE PATH: deployments/registry/ca_counties.go

DESCRIPTION:

	California county DATA. Each Superior Court is a UNIFIED trial
	court — one CourtSlot of CourtTypeUnifiedSuperior per CountyProfile.
	State convention's ClerksFor generates the single Court Executive
	Officer per Superior Court.

	Adding a new CA county = literal in CaliforniaCounties.
*/
package registry

import (
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/county_profile"
)

// CaliforniaCounties returns the list of CA county profiles.
func CaliforniaCounties() []county_profile.CountyProfile {
	return []county_profile.CountyProfile{
		riverside,
		santaClara,
	}
}

var riverside = county_profile.CountyProfile{
	State: "CA", Name: "Riverside", Size: county_profile.SizeLarge,
	Courthouses: []county_profile.Courthouse{
		{ID: "main", Name: "Riverside Hall of Justice",
			Address: "4050 Main St, Riverside, CA 92501"},
	},
	Courts: []county_profile.CourtSlot{
		{
			Type:    composer.CourtTypeUnifiedSuperior,
			Count:   1,
			NameFmt: "Superior Court of California, County of Riverside",
		},
	},
}

var santaClara = county_profile.CountyProfile{
	State: "CA", Name: "Santa Clara", Size: county_profile.SizeLarge,
	Courthouses: []county_profile.Courthouse{
		{ID: "main", Name: "Santa Clara County Hall of Justice",
			Address: "190 W Hedding St, San Jose, CA 95110"},
	},
	Courts: []county_profile.CourtSlot{
		{
			Type:    composer.CourtTypeUnifiedSuperior,
			Count:   1,
			NameFmt: "Superior Court of California, County of Santa Clara",
		},
	},
}
