/*
Package scenario is the data-driven judicial population + workload model.

A Jurisdiction (one court log / exchange) is described as DATA — its courts,
divisions, the real sitting bench, the clerk offices, and the bar — so the
seeder and the case / ruling / transfer generators work for ANY court with no
per-court code. Add a jurisdiction, a court, a division, or a judge by adding a
data entry; nothing else changes.

The model is deliberately separate from the deployment bundles
(deployments/...): a bundle is the network's POLICY (role catalog + cosignature
mix); this model is WHO to provision onto it and WHAT to file. The two meet only
at ExchangeDID + the catalog role names.
*/
package scenario

// Jurisdiction is one court system addressable as a single exchange/log:
// Davidson County, TN (appellate), Federal. Officers are seeded onto its
// ExchangeDID under its adjudicator/clerk catalog roles; cases are filed
// against it.
type Jurisdiction struct {
	Key              string // stable id, e.g. "davidson"
	Name             string // "Davidson County"
	ExchangeDID      string // the court log DID (the entry Destination)
	InstitutionalDID string // the depth-0 granter root (== ExchangeDID for a county)
	AdjudicatorRole  string // catalog signer role for the bench: "judge" | "justice"
	ClerkRole        string // catalog signer role for clerks: "court_clerk"
	Courts           []Court
	Bar              Bar
}

// Court is a court within a jurisdiction (Circuit Court, Juvenile Court).
type Court struct {
	Name      string
	Divisions []Division
	Clerk     ClerkOffice
}

// Division is a specialized division of a court. CaseTypes are the case_type
// payload values this division hears; Bench is its real adjudicators.
type Division struct {
	Name      string
	Specialty string // domestic | probate | juvenile | general_civil | criminal | appellate
	CaseTypes []string
	Bench     []Adjudicator
}

// Adjudicator is a delegated SIGNER (judge / magistrate / justice). Role is the
// catalog role; Title is the human title. Magistrates are modeled as the "judge"
// catalog role per the TN role catalog (subtype is a scope/division concern, not
// a separate cryptographic role).
type Adjudicator struct {
	Name        string
	Title       string // "Judge" | "Magistrate" | "Justice" | "Chief Justice"
	Role        string // catalog role
	ElectedYear int    // 0 if unknown
	Courtroom   string // e.g. "B"; "" when n/a
}

// ClerkOffice seeds court_clerk signers for a court.
type ClerkOffice struct {
	Name    string
	Address string
	Clerks  int // number of court_clerk principals to seed (>=1)
}

// Bar is the jurisdiction's attorney pool: FILER principals (NOT delegated
// signers) — each gets a key + a bar/BPR number and files under one of Roles.
type Bar struct {
	Roles []string // filer roles: civil_attorney | defense_counsel | prosecutor
	Count int      // number of attorney principals to seed
}

// ─── derived views (used by the seeder + generators) ────────────────

// Adjudicators flattens every division's bench across all courts.
func (j Jurisdiction) Adjudicators() []Adjudicator {
	var out []Adjudicator
	for _, c := range j.Courts {
		for _, d := range c.Divisions {
			out = append(out, d.Bench...)
		}
	}
	return out
}

// Divisions flattens every division across all courts.
func (j Jurisdiction) Divisions() []Division {
	var out []Division
	for _, c := range j.Courts {
		out = append(out, c.Divisions...)
	}
	return out
}

// ClerkSlots is the total number of court_clerk principals to seed (>=1 per
// clerk office).
func (j Jurisdiction) ClerkSlots() int {
	n := 0
	for _, c := range j.Courts {
		k := c.Clerk.Clerks
		if k < 1 {
			k = 1
		}
		n += k
	}
	return n
}
