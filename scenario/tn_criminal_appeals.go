package scenario

// criminalAppealsExchangeDID is the Court of Criminal Appeals' log DID.
//
// NOTE — DEPLOYMENT GAP: unlike Davidson (tn/counties/davidson) and the Supreme
// Court (tn/sup_ct), the Court of Criminal Appeals has NO deployment yet. Its
// bundle (role catalog + cosignature mix, mirroring tn/coa — the civil Court of
// Appeals) must be created before the seeder can provision officers onto it.
// When that deployment lands this DID moves there and is derived, not restated.
// Convention: did:web:state:tn:<court>.
const criminalAppealsExchangeDID = "did:web:state:tn:cca"

// TennesseeCriminalAppeals models the Tennessee Court of Criminal Appeals — the
// intermediate appellate court for felony/misdemeanor appeals + post-conviction
// petitions (created 1967, expanded to 12 judges in 1996) — after the real 2025
// bench. The 12 judges sit in 3-judge panels in Jackson, Knoxville, and
// Nashville. Appellate judges carry the "judge" catalog role (same model as
// tn/coa); the clerk is the shared Appellate Court Clerk (Jim Hivner).
func TennesseeCriminalAppeals() Jurisdiction {
	return Jurisdiction{
		Key:              "tn_criminal_appeals",
		Name:             "Tennessee Court of Criminal Appeals",
		ExchangeDID:      criminalAppealsExchangeDID,
		InstitutionalDID: criminalAppealsExchangeDID,
		AdjudicatorRole:  "judge",
		ClerkRole:        "court_clerk",
		Courts: []Court{
			{
				Name: "Tennessee Court of Criminal Appeals",
				Divisions: []Division{
					{
						Name: "Court of Criminal Appeals", Specialty: "criminal_appellate",
						CaseTypes: []string{"felony_appeal", "misdemeanor_appeal", "post_conviction_petition", "interlocutory_appeal"},
						Bench: []Adjudicator{
							{Name: "Robert H. Montgomery Jr.", Title: "Judge", Role: "judge"},
							{Name: "Camille R. McMullen", Title: "Judge", Role: "judge"},
							{Name: "Robert W. Wedemeyer", Title: "Judge", Role: "judge"},
							{Name: "Robert L. Holloway Jr.", Title: "Judge", Role: "judge"},
							{Name: "Timothy L. Easter", Title: "Judge", Role: "judge"},
							{Name: "Matthew Wilson", Title: "Judge", Role: "judge"},
							{Name: "Tom Greenholtz", Title: "Judge", Role: "judge"},
							{Name: "Jill Bartee Ayers", Title: "Judge", Role: "judge"},
							{Name: "J. Ross Dyer", Title: "Judge", Role: "judge"},
							{Name: "John W. Campbell", Title: "Judge", Role: "judge"},
							{Name: "Kyle A. Hixson", Title: "Judge", Role: "judge"},
							{Name: "Steven W. Sword", Title: "Judge", Role: "judge"},
						},
					},
				},
				Clerk: ClerkOffice{Name: "Jim Hivner, Appellate Court Clerk", Address: "401 Seventh Avenue North, Nashville, TN 37219", Clerks: 1},
			},
		},
		// Criminal appellate practice: defense counsel + prosecutors (the State).
		Bar: Bar{Roles: []string{"defense_counsel", "prosecutor"}, Count: 5},
	}
}
