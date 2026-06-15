package scenario

import supct "github.com/clearcompass-ai/judicial-network/deployments/tn/sup_ct"

// TennesseeSupremeCourt models the Tennessee Supreme Court — the state's court of
// last resort (five justices) — after the real bench: Chief Justice Bivins plus
// four Justices. They accept civil + criminal appeals from the intermediate
// appellate courts and interpret the TN/US constitutions. Justices carry the
// "justice"/"chief_justice" catalog roles; the clerk is the shared Appellate
// Court Clerk (Jim Hivner). Seeds onto tn/sup_ct (did:web:state:tn:sc).
func TennesseeSupremeCourt() Jurisdiction {
	return Jurisdiction{
		Key:              "tn_supreme",
		Name:             "Tennessee Supreme Court",
		ExchangeDID:      supct.ExchangeDID, // did:web:state:tn:sc — derived, not restated
		InstitutionalDID: supct.ExchangeDID,
		AdjudicatorRole:  "justice",
		ClerkRole:        "court_clerk",
		Courts: []Court{
			{
				Name: "Tennessee Supreme Court",
				Divisions: []Division{
					{
						Name: "Tennessee Supreme Court", Specialty: "appellate",
						CaseTypes: []string{"civil_appeal", "criminal_appeal", "workers_comp_appeal", "constitutional_question", "discretionary_review"},
						Bench: []Adjudicator{
							{Name: "Jeffrey S. Bivins", Title: "Chief Justice", Role: "chief_justice"},
							{Name: "Holly Kirby", Title: "Justice", Role: "justice"},
							{Name: "Sarah Campbell", Title: "Justice", Role: "justice"},
							{Name: "Dwight E. Tarwater", Title: "Justice", Role: "justice"},
							{Name: "Mary L. Wagner", Title: "Justice", Role: "justice"},
						},
					},
				},
				Clerk: ClerkOffice{Name: "Jim Hivner, Appellate Court Clerk", Address: "401 Seventh Avenue North, Nashville, TN 37219", Clerks: 1},
			},
		},
		// Attorneys admitted before the appellate bar (both sides of an appeal).
		Bar: Bar{Roles: []string{"civil_attorney", "defense_counsel", "prosecutor"}, Count: 5},
	}
}
