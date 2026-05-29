// Smoke + invariant tests for the registry layer.
//
// These pin the framework's load behavior across every state's registry:
//   - Every court Spec validates.
//   - Every DID is unique (across courts AND clerks).
//   - Every Bundle satisfies jurisdiction.Validate.
//   - The expected court + clerk counts per state.
//   - AppellatePath references resolve.
//   - Structural facts (Davidson probate in Circuit 7, Knox Chancery
//     handles probate, Davidson Juvenile is Juvenile & Family).
package registry

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

func TestLoadAll_ProducesValidBundles(t *testing.T) {
	bundles := LoadAll()
	if len(bundles) == 0 {
		t.Fatal("LoadAll returned no bundles")
	}
	for _, b := range bundles {
		if err := jurisdiction.Validate(b); err != nil {
			t.Errorf("bundle %s: %v", b.ExchangeDID(), err)
		}
	}
}

func TestLoadAll_AllCourtDIDsUnique(t *testing.T) {
	specs := AllCourtSpecs()
	seen := make(map[string]string, len(specs))
	for _, s := range specs {
		if other, dup := seen[s.DID]; dup {
			t.Errorf("duplicate court DID %q (used by %q and %q)", s.DID, other, s.Name)
		}
		seen[s.DID] = s.Name
	}
}

func TestLoadAll_AllClerkDIDsUnique(t *testing.T) {
	clerks := AllClerkSpecs()
	seen := make(map[string]string, len(clerks))
	for _, c := range clerks {
		if other, dup := seen[c.DID]; dup {
			t.Errorf("duplicate clerk DID %q (used by %q and %q)", c.DID, other, c.Name)
		}
		seen[c.DID] = c.Name
	}
}

func TestLoadAll_NoOverlapBetweenCourtAndClerkDIDs(t *testing.T) {
	// A DID is either a court OR a clerk office, never both.
	courts := AllCourtSpecs()
	clerks := AllClerkSpecs()
	courtDIDs := make(map[string]string, len(courts))
	for _, c := range courts {
		courtDIDs[c.DID] = c.Name
	}
	for _, c := range clerks {
		if other, dup := courtDIDs[c.DID]; dup {
			t.Errorf("DID %q used by court %q AND clerk %q", c.DID, other, c.Name)
		}
	}
}

func TestLoadAll_AppellatePathsResolve(t *testing.T) {
	specs := AllCourtSpecs()
	known := make(map[string]bool, len(specs))
	for _, s := range specs {
		known[s.DID] = true
	}
	for _, s := range specs {
		if s.AppellatePath == "" {
			continue
		}
		if !known[s.AppellatePath] {
			t.Errorf("court %s declares AppellatePath %s which is not in the registry",
				s.Name, s.AppellatePath)
		}
	}
}

func TestLoadAll_CountsPerState(t *testing.T) {
	// Pin expected counts so accidental removal/addition surfaces.
	if got, want := len(FederalSpecs()), 7; got != want {
		t.Errorf("FederalSpecs() = %d, want %d (SCOTUS + 2 Circuits + 4 Districts)",
			got, want)
	}
	// Tennessee state-level: 1 Supreme + 3 COA + 3 COCA = 7.
	if got, want := len(TennesseeStateLevelSpecs()), 7; got != want {
		t.Errorf("TennesseeStateLevelSpecs() = %d, want %d", got, want)
	}
	// California state-level: 1 Supreme + 4 CoA (3 in 4th Dist + 1 in 6th Dist) = 5.
	if got, want := len(CaliforniaStateLevelSpecs()), 5; got != want {
		t.Errorf("CaliforniaStateLevelSpecs() = %d, want %d", got, want)
	}
}

func TestLoadAll_TennesseeCountyCourts(t *testing.T) {
	// Davidson: 8 Circuit + 4 Chancery + 6 Criminal + 4 GS civil
	//           + 4 GS criminal + 1 Juvenile = 27.
	// Knox:     4 Circuit + 3 Chancery + 3 Criminal + 4 GS
	//           + 1 Juvenile = 15.
	// Sullivan: 3 Circuit + 3 Chancery + 3 GS (PerCourthouse:1 × 3
	//           courthouses each) = 9.
	// Total county courts: 51. State-level: 7. Grand total TN: 58.
	specs := AllCourtSpecs()
	tnCount := 0
	for _, s := range specs {
		if s.Jurisdiction.State == "TN" {
			tnCount++
		}
	}
	if tnCount != 58 {
		t.Errorf("TN court count = %d, want 58 (7 state-level + 27 Davidson + 15 Knox + 9 Sullivan)", tnCount)
	}
}

func TestLoadAll_TennesseeClerks(t *testing.T) {
	// Davidson (Large): 4 clerks.
	// Knox (Large): 4 clerks.
	// Sullivan (Medium): 3 clerks (County + Circuit-consolidating-
	//                    Criminal+GS + Clerk and Master).
	// Total: 11.
	clerks := AllClerkSpecs()
	tnClerkCount := 0
	for _, c := range clerks {
		if c.Jurisdiction.State == "TN" {
			tnClerkCount++
		}
	}
	if tnClerkCount != 11 {
		t.Errorf("TN clerk count = %d, want 11 (Davidson 4 + Knox 4 + Sullivan 3)", tnClerkCount)
	}
}

func TestLoadAll_SullivanMultiCourthouseDIDs(t *testing.T) {
	// Sullivan's PerCourthouse: 1 slot for Circuit Court should
	// produce one DID per courthouse, distinguished by the
	// courthouse ID, NOT by an ordinal.
	specs := AllCourtSpecs()
	want := map[string]bool{
		"did:web:state:tn:sullivan:circuit:bristol:1":     false,
		"did:web:state:tn:sullivan:circuit:kingsport:1":   false,
		"did:web:state:tn:sullivan:circuit:blountville:1": false,
	}
	for _, s := range specs {
		if _, ok := want[s.DID]; ok {
			want[s.DID] = true
		}
	}
	for did, found := range want {
		if !found {
			t.Errorf("expected Sullivan multi-courthouse DID %s not in registry", did)
		}
	}
}

func TestLoadAll_KnoxCountyClerkHasSixBranches(t *testing.T) {
	// Knox County Clerk has 1 Main + 5 satellite branches encoded in
	// CountyProfile.ClerkBranches. The expander attaches them to the
	// ClerkTypeCounty slot.
	clerks := AllClerkSpecs()
	for _, c := range clerks {
		if c.DID == "did:web:state:tn:knox:clerk:county" {
			if len(c.Branches) != 6 {
				t.Errorf("Knox County Clerk has %d branches, want 6 (Main + 5 satellites)", len(c.Branches))
			}
			// Validate the expected branch IDs are present.
			wantIDs := map[string]bool{
				"main": false, "west": false, "farragut": false,
				"north": false, "south": false, "east": false,
			}
			for _, b := range c.Branches {
				if _, ok := wantIDs[b.ID]; ok {
					wantIDs[b.ID] = true
				}
			}
			for id, found := range wantIDs {
				if !found {
					t.Errorf("Knox County Clerk missing branch %q", id)
				}
			}
			return
		}
	}
	t.Error("Knox County Clerk not in registry")
}

func TestLoadAll_CaliforniaClerks(t *testing.T) {
	// Riverside + Santa Clara, each with 1 Court Executive Officer = 2.
	clerks := AllClerkSpecs()
	caClerkCount := 0
	for _, c := range clerks {
		if c.Jurisdiction.State == "CA" {
			caClerkCount++
		}
	}
	if caClerkCount != 2 {
		t.Errorf("CA clerk count = %d, want 2 (Riverside CEO + Santa Clara CEO)", caClerkCount)
	}
}

func TestLoadAll_DavidsonProbateInCircuitNotChancery(t *testing.T) {
	specs := AllCourtSpecs()
	for _, s := range specs {
		hasProbate := false
		hasChancery := false
		for _, ct := range s.CourtTypes {
			if ct.String() == "probate" {
				hasProbate = true
			}
			if ct.String() == "chancery" {
				hasChancery = true
			}
		}
		// Davidson chancery MUST NOT carry probate.
		for i := 1; i <= 4; i++ {
			if s.DID == davidsonChanceryDID(i) {
				if hasProbate {
					t.Errorf("%s declares Probate; Davidson probate lives in Circuit Part 7", s.DID)
				}
				if !hasChancery {
					t.Errorf("%s missing Chancery court type", s.DID)
				}
			}
		}
		// Davidson Circuit Part 7 MUST carry probate.
		if s.DID == "did:web:state:tn:davidson:circuit:7" {
			if !hasProbate {
				t.Errorf("Davidson Circuit Part 7 (Probate Division) missing CourtTypeProbate")
			}
		}
	}
}

func TestLoadAll_DavidsonJuvenileIsJuvenileAndFamily(t *testing.T) {
	// Davidson's "Juvenile" court is officially the Juvenile & Family
	// Court — Davidson combines J&F into one institutional court.
	specs := AllCourtSpecs()
	for _, s := range specs {
		if s.DID == "did:web:state:tn:davidson:juvenile:1" {
			hasJuvenile := false
			hasFamily := false
			for _, ct := range s.CourtTypes {
				if ct.String() == "juvenile" {
					hasJuvenile = true
				}
				if ct.String() == "family" {
					hasFamily = true
				}
			}
			if !hasJuvenile || !hasFamily {
				t.Errorf("Davidson Juvenile & Family Court missing types; juvenile=%v family=%v",
					hasJuvenile, hasFamily)
			}
		}
	}
}

func TestLoadAll_KnoxChanceryHandlesProbate(t *testing.T) {
	specs := AllCourtSpecs()
	for i := 1; i <= 3; i++ {
		did := knoxChanceryDID(i)
		found := false
		for _, s := range specs {
			if s.DID != did {
				continue
			}
			found = true
			hasProbate := false
			hasChancery := false
			for _, ct := range s.CourtTypes {
				if ct.String() == "probate" {
					hasProbate = true
				}
				if ct.String() == "chancery" {
					hasChancery = true
				}
			}
			if !hasProbate {
				t.Errorf("%s missing Probate (Knox Chancery handles probate)", did)
			}
			if !hasChancery {
				t.Errorf("%s missing Chancery", did)
			}
		}
		if !found {
			t.Errorf("expected DID %s not in registry", did)
		}
	}
}

// ─── helpers ───────────────────────────────────────────────────────

func davidsonChanceryDID(i int) string { return tnCountyDID("davidson", "chancery", i) }
func knoxChanceryDID(i int) string     { return tnCountyDID("knox", "chancery", i) }
func tnCountyDID(county, kind string, i int) string {
	return "did:web:state:tn:" + county + ":" + kind + ":" + itoa(i)
}
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var out []byte
	for i > 0 {
		out = append([]byte{byte('0' + i%10)}, out...)
		i /= 10
	}
	return string(out)
}
