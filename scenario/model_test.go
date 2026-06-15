package scenario

import "testing"

// TestTennesseeCourts_WellFormed pins the modeled jurisdictions: each must be
// seedable (DID + roles + a non-empty bench, bar, and divisions with case types).
func TestTennesseeCourts_WellFormed(t *testing.T) {
	courts := TennesseeCourts()
	if len(courts) != 3 {
		t.Fatalf("want 3 TN jurisdictions (Davidson, Criminal Appeals, Supreme), got %d", len(courts))
	}
	seen := map[string]bool{}
	for _, j := range courts {
		if seen[j.Key] {
			t.Errorf("duplicate jurisdiction key %q", j.Key)
		}
		seen[j.Key] = true
		if j.ExchangeDID == "" || j.AdjudicatorRole == "" || j.ClerkRole == "" {
			t.Errorf("%s: missing ExchangeDID / AdjudicatorRole / ClerkRole", j.Key)
		}
		if len(j.Adjudicators()) == 0 {
			t.Errorf("%s: empty bench", j.Key)
		}
		if j.Bar.Count < 1 || len(j.Bar.Roles) == 0 {
			t.Errorf("%s: empty bar", j.Key)
		}
		if j.ClerkSlots() < 1 {
			t.Errorf("%s: no clerk slots", j.Key)
		}
		for _, d := range j.Divisions() {
			if len(d.CaseTypes) == 0 {
				t.Errorf("%s / %s: division has no case types", j.Key, d.Name)
			}
			if len(d.Bench) == 0 {
				t.Errorf("%s / %s: division has no bench", j.Key, d.Name)
			}
			for _, a := range d.Bench {
				if a.Name == "" || a.Role == "" {
					t.Errorf("%s / %s: adjudicator missing name/role: %+v", j.Key, d.Name, a)
				}
			}
		}
	}
}

// TestSupremeCourt_HasOneChiefJustice — exactly one Chief Justice (Bivins).
func TestSupremeCourt_HasOneChiefJustice(t *testing.T) {
	chiefs := 0
	for _, a := range TennesseeSupremeCourt().Adjudicators() {
		if a.Role == "chief_justice" {
			chiefs++
		}
	}
	if chiefs != 1 {
		t.Errorf("Supreme Court must have exactly 1 chief_justice, got %d", chiefs)
	}
}

// TestCriminalAppeals_TwelveJudges — the 1996 expansion to 12 judges.
func TestCriminalAppeals_TwelveJudges(t *testing.T) {
	if n := len(TennesseeCriminalAppeals().Adjudicators()); n != 12 {
		t.Errorf("Court of Criminal Appeals must have 12 judges, got %d", n)
	}
}

// TestDavidson_HasRealBench — a spot-check that the modeled bench is the real
// one (not placeholders): the named Circuit + Juvenile adjudicators are present.
func TestDavidson_HasRealBench(t *testing.T) {
	want := map[string]bool{
		"Phillip Robinson": false, "Stanley A. Kweller": false, "Andra Hendrick": false,
		"Amanda McClendon": false, "Sheila D. J. Calloway": false, "Olen Winningham": false,
	}
	for _, a := range DavidsonCounty().Adjudicators() {
		if _, ok := want[a.Name]; ok {
			want[a.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("Davidson bench missing the real adjudicator %q", name)
		}
	}
}
