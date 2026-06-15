package scenario

import (
	"context"
	"strings"
	"testing"

	"github.com/baseproof/tooling/libs/auth/identity"
)

var testSeed = []byte("scenario-test-seed-v1")

// uniqueAdjudicatorNames counts the distinct bench members (a judge sitting in
// two divisions is one person), computed from the model so the expectations
// track data edits.
func uniqueAdjudicatorNames(j Jurisdiction) int {
	seen := map[string]bool{}
	for _, a := range j.Adjudicators() {
		seen[a.Name] = true
	}
	return len(seen)
}

// TestBuildRegistry_Deterministic: identical (jurisdiction, seed) ⇒ identical
// DIDs and bar numbers, every time. This is what makes a seeded run reproducible.
func TestBuildRegistry_Deterministic(t *testing.T) {
	a := BuildRegistry(DavidsonCounty(), testSeed)
	b := BuildRegistry(DavidsonCounty(), testSeed)

	if a.Institutional.DID != b.Institutional.DID {
		t.Errorf("institutional DID not stable: %q vs %q", a.Institutional.DID, b.Institutional.DID)
	}
	if len(a.Officers) != len(b.Officers) || len(a.Attorneys) != len(b.Attorneys) {
		t.Fatalf("roster size not stable: officers %d/%d attorneys %d/%d",
			len(a.Officers), len(b.Officers), len(a.Attorneys), len(b.Attorneys))
	}
	for i := range a.Officers {
		if a.Officers[i].DID != b.Officers[i].DID {
			t.Errorf("officer %d DID not stable: %q vs %q", i, a.Officers[i].DID, b.Officers[i].DID)
		}
	}
	for i := range a.Attorneys {
		if a.Attorneys[i].DID != b.Attorneys[i].DID || a.Attorneys[i].BPR != b.Attorneys[i].BPR {
			t.Errorf("attorney %d identity not stable: did %q/%q bpr %q/%q", i,
				a.Attorneys[i].DID, b.Attorneys[i].DID, a.Attorneys[i].BPR, b.Attorneys[i].BPR)
		}
	}

	// A different seed must move the keyspace.
	c := BuildRegistry(DavidsonCounty(), []byte("a-different-seed"))
	if c.Officers[0].DID == a.Officers[0].DID {
		t.Error("a different seed must yield different DIDs")
	}
}

// TestBuildRegistry_DedupAdjudicators: a judge sitting in two divisions is ONE
// principal (Amanda McClendon sits at the Second Circuit and the Seventh Probate).
func TestBuildRegistry_DedupAdjudicators(t *testing.T) {
	reg := BuildRegistry(DavidsonCounty(), testSeed)
	if got, want := len(reg.Adjudicators()), uniqueAdjudicatorNames(DavidsonCounty()); got != want {
		t.Errorf("adjudicator count = %d, want %d unique", got, want)
	}
	count := 0
	for _, p := range reg.Adjudicators() {
		if p.Name == "Amanda McClendon" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Amanda McClendon (two divisions) must be one principal, got %d", count)
	}
}

// TestBuildRegistry_Counts: officers = unique adjudicators + clerk slots;
// attorneys = Bar.Count. Holds for both active jurisdictions.
func TestBuildRegistry_Counts(t *testing.T) {
	for _, j := range ActiveCourts() {
		reg := BuildRegistry(j, testSeed)
		wantOfficers := uniqueAdjudicatorNames(j) + j.ClerkSlots()
		if len(reg.Officers) != wantOfficers {
			t.Errorf("%s: officers = %d, want %d (=%d adjudicators + %d clerk slots)",
				j.Key, len(reg.Officers), wantOfficers, uniqueAdjudicatorNames(j), j.ClerkSlots())
		}
		if len(reg.Attorneys) != j.Bar.Count {
			t.Errorf("%s: attorneys = %d, want %d", j.Key, len(reg.Attorneys), j.Bar.Count)
		}
	}
}

// TestBuildRegistry_DIDsAndKeys: officers/attorneys carry self-certifying
// did:key identities; the institutional root keeps its did:web DID; all DIDs are
// distinct and bind into the IdentityProvider.
func TestBuildRegistry_DIDsAndKeys(t *testing.T) {
	reg := BuildRegistry(DavidsonCounty(), testSeed)

	if !strings.HasPrefix(reg.Institutional.DID, "did:web:") {
		t.Errorf("institutional DID should be the court's did:web, got %q", reg.Institutional.DID)
	}

	seen := map[string]bool{reg.Institutional.DID: true}
	all := append(append([]*Principal{}, reg.Officers...), reg.Attorneys...)
	for _, p := range all {
		if !strings.HasPrefix(p.DID, "did:key:") {
			t.Errorf("%s (%s): want a self-certifying did:key, got %q", p.Name, p.Kind, p.DID)
		}
		if seen[p.DID] {
			t.Errorf("duplicate DID %q (%s)", p.DID, p.Name)
		}
		seen[p.DID] = true
	}

	// Every identity must be signable through the stub.
	sp := identity.NewStubProvider()
	reg.BindKeys(sp)
	for _, did := range []string{reg.Institutional.DID, reg.Officers[0].DID, reg.Attorneys[0].DID} {
		if _, err := sp.PublicKey(context.Background(), did); err != nil {
			t.Errorf("PublicKey(%q) after BindKeys: %v", did, err)
		}
	}
}

// TestBuildRegistry_Attorneys: each attorney is a filer with a bar role from the
// jurisdiction's bar and a 6-digit public BPR number; officers carry no BPR.
func TestBuildRegistry_Attorneys(t *testing.T) {
	j := DavidsonCounty()
	reg := BuildRegistry(j, testSeed)

	barRoles := map[string]bool{}
	for _, r := range j.Bar.Roles {
		barRoles[r] = true
	}
	for _, p := range reg.Attorneys {
		if p.Kind != KindAttorney {
			t.Errorf("%s: kind = %q, want attorney", p.Name, p.Kind)
		}
		if !barRoles[p.FilerRole] {
			t.Errorf("%s: filer role %q not in the bar %v", p.Name, p.FilerRole, j.Bar.Roles)
		}
		if len(p.BPR) != 6 {
			t.Errorf("%s: BPR %q is not a 6-digit bar number", p.Name, p.BPR)
		}
		if p.Delegation != nil {
			t.Errorf("%s: an attorney (filer) must never carry a delegation", p.Name)
		}
	}
	for _, p := range reg.Officers {
		if p.BPR != "" {
			t.Errorf("officer %s should not carry a BPR number", p.Name)
		}
	}
}
