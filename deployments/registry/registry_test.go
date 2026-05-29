// Smoke + invariant tests for the registry layer.
//
// These pin the framework's load behavior across every state's registry:
//   - Every Spec validates.
//   - Every DID is unique.
//   - Every Bundle satisfies jurisdiction.Validate.
//   - The expected court counts per state.
//   - AppellatePath references resolve (every appeal target exists in the registry).
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

func TestLoadAll_AllDIDsUnique(t *testing.T) {
	specs := AllSpecs()
	seen := make(map[string]string, len(specs))
	for _, s := range specs {
		if other, dup := seen[s.DID]; dup {
			t.Errorf("duplicate DID %q (used by %q and %q)", s.DID, other, s.Name)
		}
		seen[s.DID] = s.Name
	}
}

func TestLoadAll_AppellatePathsResolve(t *testing.T) {
	specs := AllSpecs()
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
	// Pin the expected counts so an accidental removal/addition surfaces.
	if got, want := len(FederalSpecs()), 7; got != want {
		t.Errorf("FederalSpecs() = %d, want %d (SCOTUS + 2 Circuits + 4 Districts)",
			got, want)
	}
	// Tennessee count:
	//   1 Supreme
	//   3 COA grand divisions
	//   3 COCA grand divisions
	//   Davidson: 8 Circuit + 4 Chancery + 6 Criminal + 4 GS civil + 4 GS criminal + 1 Juvenile = 27
	//   Knox:     4 Circuit + 3 Chancery + 3 Criminal + 4 GS + 1 Juvenile = 15
	//   Total: 1 + 3 + 3 + 27 + 15 = 49
	if got, want := len(TennesseeSpecs()), 49; got != want {
		t.Errorf("TennesseeSpecs() = %d, want %d", got, want)
	}
	// California count:
	//   1 Supreme
	//   4 Court of Appeal divisions (3 in 4th District + 1 in 6th District)
	//   2 Superior Courts
	//   Total: 7
	if got, want := len(CaliforniaSpecs()), 7; got != want {
		t.Errorf("CaliforniaSpecs() = %d, want %d", got, want)
	}
}

func TestLoadAll_DavidsonProbateIsInCircuitNotChancery(t *testing.T) {
	// Pin the structural fact: Davidson's Probate jurisdiction is in
	// the 7th Circuit Division, NOT in any Chancery part.
	specs := AllSpecs()
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
		if s.DID == "did:web:state:tn:davidson:chancery:1" || s.DID == "did:web:state:tn:davidson:chancery:2" ||
			s.DID == "did:web:state:tn:davidson:chancery:3" || s.DID == "did:web:state:tn:davidson:chancery:4" {
			if hasProbate {
				t.Errorf("%s declares Probate; Davidson probate lives in Circuit Division 7", s.DID)
			}
			if !hasChancery {
				t.Errorf("%s missing Chancery court type", s.DID)
			}
		}
		// Davidson Circuit Division 7 MUST carry probate.
		if s.DID == "did:web:state:tn:davidson:circuit:7" {
			if !hasProbate {
				t.Errorf("Davidson Circuit Division 7 (Probate Division) missing CourtTypeProbate")
			}
		}
	}
}

func TestLoadAll_KnoxChanceryHandlesProbate(t *testing.T) {
	// Pin the structural fact: Knox Chancery DOES carry probate (no
	// separate Probate Court in Knox).
	specs := AllSpecs()
	for _, s := range specs {
		if s.DID == "did:web:state:tn:knox:chancery:1" ||
			s.DID == "did:web:state:tn:knox:chancery:2" ||
			s.DID == "did:web:state:tn:knox:chancery:3" {
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
				t.Errorf("%s missing Probate (Knox Chancery handles probate)", s.DID)
			}
			if !hasChancery {
				t.Errorf("%s missing Chancery", s.DID)
			}
		}
	}
}
