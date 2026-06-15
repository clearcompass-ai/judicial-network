package scenario

import davidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"

// Case-type vocabularies per division specialty — the case_type payload value a
// filed case carries. Extend these freely; they are pure data.
var (
	domesticCaseTypes = []string{"divorce", "adoption", "child_custody", "child_support", "order_of_protection"}
	probateCaseTypes  = []string{"estate_administration", "will_probate", "guardianship", "conservatorship", "name_change", "emancipation", "legitimation", "trust"}
	juvenileCaseTypes = []string{"child_custody", "child_support", "child_welfare", "delinquency", "dependency_neglect"}
	civilCaseTypes    = []string{"contract_dispute", "condemnation", "civil_tort", "workers_compensation", "estate_administration"}
)

// DavidsonCounty models the Davidson County (Nashville, TN) trial courts after
// the REAL sitting bench: the Circuit Court (its Domestic and Probate divisions
// and a general-civil division) and the Metropolitan Juvenile Court. Officers
// are seeded onto the davidson exchange; the named adjudicators are the real
// bench. Magistrates carry the "judge" catalog role (the Magistrate/Judge
// distinction is a division/scope concern, not a separate cryptographic role).
//
// Extend by adding Court / Division / Adjudicator entries — no code change. The
// 8 circuit courts / 20+ judges and the 10 juvenile magistrates are all data.
func DavidsonCounty() Jurisdiction {
	return Jurisdiction{
		Key:              "davidson",
		Name:             "Davidson County",
		ExchangeDID:      davidson.ExchangeDID, // did:web:state:tn:davidson — derived, not restated
		InstitutionalDID: davidson.ExchangeDID, // a county's institutional root is its own DID
		AdjudicatorRole:  "judge",
		ClerkRole:        "court_clerk",
		Courts: []Court{
			{
				Name: "Davidson County Circuit Court",
				Divisions: []Division{
					{
						Name: "Second Circuit Court", Specialty: "general_civil", CaseTypes: civilCaseTypes,
						Bench: []Adjudicator{{Name: "Amanda McClendon", Title: "Judge", Role: "judge", ElectedYear: 2006}},
					},
					{
						Name: "Third Circuit Court", Specialty: "domestic", CaseTypes: domesticCaseTypes,
						Bench: []Adjudicator{{Name: "Phillip Robinson", Title: "Judge", Role: "judge", ElectedYear: 2012}},
					},
					{
						Name: "Fourth Circuit Court", Specialty: "domestic", CaseTypes: domesticCaseTypes,
						Bench: []Adjudicator{{Name: "Stanley A. Kweller", Title: "Judge", Role: "judge", ElectedYear: 2023}},
					},
					{
						Name: "Seventh Circuit Court — Probate", Specialty: "probate", CaseTypes: probateCaseTypes,
						Bench: []Adjudicator{
							{Name: "Andra Hendrick", Title: "Judge", Role: "judge", ElectedYear: 2022},
							// McClendon also hears conservatorships at the Seventh.
							{Name: "Amanda McClendon", Title: "Judge", Role: "judge", ElectedYear: 2006},
						},
					},
				},
				Clerk: ClerkOffice{Name: "Joseph P. Day, Circuit Court Clerk", Address: "1 Public Square Suite 302, Nashville, TN 37201", Clerks: 1},
			},
			{
				Name: "Davidson County Juvenile Court",
				Divisions: []Division{
					{
						Name: "Metropolitan Juvenile Court", Specialty: "juvenile", CaseTypes: juvenileCaseTypes,
						Bench: []Adjudicator{
							{Name: "Sheila D. J. Calloway", Title: "Judge", Role: "judge", Courtroom: "B"},
							{Name: "Yvette Y. Cain", Title: "Magistrate", Role: "judge", Courtroom: "I"},
							{Name: "Alan Calhoun", Title: "Magistrate", Role: "judge", Courtroom: "MSAC"},
							{Name: "Michael O'Neal", Title: "Magistrate", Role: "judge", Courtroom: "D"},
							{Name: "Julie Ottman", Title: "Magistrate", Role: "judge", Courtroom: "G"},
							{Name: "Paul Robertson", Title: "Magistrate", Role: "judge", Courtroom: "E"},
							{Name: "Scott Rosenberg", Title: "Magistrate", Role: "judge", Courtroom: "H"},
							{Name: "LeAnne Sumner", Title: "Magistrate", Role: "judge", Courtroom: "C"},
							{Name: "Elijah Wilhoite", Title: "Magistrate", Role: "judge", Courtroom: "A"},
							{Name: "Olen Winningham", Title: "Magistrate", Role: "judge", Courtroom: "MSAC"},
						},
					},
				},
				Clerk: ClerkOffice{Name: "Juvenile Court Clerk", Address: "100 Woodland St, Nashville, TN 37213", Clerks: 1},
			},
		},
		// The Davidson bar: 5 attorneys spanning the trial court's civil + criminal
		// docket, each seeded with a key and a TN BPR number, filing under these roles.
		Bar: Bar{Roles: []string{"civil_attorney", "defense_counsel", "prosecutor"}, Count: 5},
	}
}
