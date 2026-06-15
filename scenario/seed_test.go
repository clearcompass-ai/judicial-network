package scenario

import (
	"context"
	"sync"
	"testing"

	"github.com/baseproof/tooling/libs/auth/identity"
	"github.com/clearcompass-ai/judicial-network/delegation"
	davidsondep "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
	supctdep "github.com/clearcompass-ai/judicial-network/deployments/tn/sup_ct"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// memLedger is an in-memory delegation.LedgerSubmitter: it captures canonical
// bytes and hands back sequential positions, standing in for the ledger so the
// seeder's chain logic is exercised without Docker.
type memLedger struct {
	mu     sync.Mutex
	logDID string
	seq    uint64
}

func (m *memLedger) SubmitCanonical(ctx context.Context, canonical []byte) (schemas.LogPositionRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	return schemas.LogPositionRef{LogDID: m.logDID, Sequence: m.seq}, nil
}

// seedFixture wires a registry + real deployment catalog into a BuildContext and
// runs the seeder against an in-memory ledger.
func seedFixture(t *testing.T, j Jurisdiction, catalog schemas.RoleCatalog) (*Registry, []GrantRecord) {
	t.Helper()
	reg := BuildRegistry(j, testSeed)
	sp := identity.NewStubProvider()
	reg.BindKeys(sp)
	bc := &delegation.BuildContext{
		Identity:         sp,
		Submitter:        &memLedger{logDID: j.ExchangeDID},
		Catalog:          catalog,
		ExchangeDID:      j.ExchangeDID,
		InstitutionalDID: j.InstitutionalDID,
	}
	records, err := Seed(context.Background(), bc, reg)
	if err != nil {
		t.Fatalf("Seed(%s): %v", j.Key, err)
	}
	return reg, records
}

// TestSeed_Davidson drives the REAL TN trial catalog: every modeled officer is
// provisioned, the judges are institutional depth-0 grants, and each clerk is
// granted by a judge of its own court.
func TestSeed_Davidson(t *testing.T) {
	j := DavidsonCounty()
	reg, records := seedFixture(t, j, trial.MustRoleCatalog())

	if len(records) != len(reg.Officers) {
		t.Fatalf("issued %d grants, want one per officer (%d)", len(records), len(reg.Officers))
	}
	for _, p := range reg.Officers {
		if p.Delegation == nil {
			t.Errorf("officer %s (%s) was not committed", p.Name, p.Role)
		}
	}

	// judge.DelegableBy is nil ⇒ every judge is an institutional depth-0 grant;
	// court_clerk.DelegableBy=[judge] ⇒ every clerk is granted by a judge.
	depth0 := 0
	for _, r := range records {
		switch r.GranteeRole {
		case "judge":
			if r.GranterRole != "" {
				t.Errorf("judge %s should be an institutional grant, got granter role %q", r.GranteeName, r.GranterRole)
			}
			depth0++
		case "court_clerk":
			if r.GranterRole != "judge" {
				t.Errorf("clerk %s should be granted by a judge, got %q", r.GranteeName, r.GranterRole)
			}
			if r.Position.Sequence == 0 {
				t.Errorf("clerk %s got a zero position", r.GranteeName)
			}
		}
	}
	if want := uniqueAdjudicatorNames(j); depth0 != want {
		t.Errorf("institutional depth-0 judge grants = %d, want %d", depth0, want)
	}

	assertSameCourtClerks(t, reg, records)
	assertCommitAware(t, records)
}

// TestSeed_Supreme drives the REAL TN Supreme Court catalog: exactly one
// institutional grant (the Chief Justice), who in turn grants the Justices and
// the clerk.
func TestSeed_Supreme(t *testing.T) {
	reg, records := seedFixture(t, TennesseeSupremeCourt(), supctdep.MustRoleCatalog())

	institutional, chief := 0, ""
	justices, clerks := 0, 0
	for _, r := range records {
		switch {
		case r.GranterRole == "":
			institutional++
			if r.GranteeRole != "chief_justice" {
				t.Errorf("the institutional grant should be the chief_justice, got %q", r.GranteeRole)
			}
			chief = r.GranteeDID
		case r.GranteeRole == "justice":
			justices++
			if r.GranterRole != "chief_justice" {
				t.Errorf("justice %s should be granted by the chief_justice, got %q", r.GranteeName, r.GranterRole)
			}
		case r.GranteeRole == "court_clerk":
			clerks++
			if r.GranterRole != "chief_justice" {
				t.Errorf("clerk %s should be granted by the chief_justice, got %q", r.GranteeName, r.GranterRole)
			}
		}
	}
	if institutional != 1 {
		t.Errorf("Supreme Court must have exactly one institutional (chief) grant, got %d", institutional)
	}
	if justices != 4 {
		t.Errorf("want 4 justice grants, got %d", justices)
	}
	if clerks != reg.Jurisdiction.ClerkSlots() {
		t.Errorf("want %d clerk grants, got %d", reg.Jurisdiction.ClerkSlots(), clerks)
	}

	// Every justice/clerk references the chief's on-log delegation.
	for _, r := range records {
		if r.GranterRole == "chief_justice" && r.GranterDID != chief {
			t.Errorf("%s granted by a non-chief DID %q", r.GranteeName, r.GranterDID)
		}
	}
	assertCommitAware(t, records)
}

// TestSeed_RejectsMismatchedInstitution: the seeder refuses a BuildContext whose
// institutional root is not the jurisdiction's — a wiring guard.
func TestSeed_RejectsMismatchedInstitution(t *testing.T) {
	j := DavidsonCounty()
	reg := BuildRegistry(j, testSeed)
	sp := identity.NewStubProvider()
	reg.BindKeys(sp)
	bc := &delegation.BuildContext{
		Identity:         sp,
		Submitter:        &memLedger{logDID: j.ExchangeDID},
		Catalog:          trial.MustRoleCatalog(),
		ExchangeDID:      j.ExchangeDID,
		InstitutionalDID: "did:web:state:tn:someone-else",
	}
	if _, err := Seed(context.Background(), bc, reg); err == nil {
		t.Fatal("expected an error for a mismatched institutional DID")
	}
}

// TestSeed_DerivedFromCatalog: the chain follows the deployment Bundle's own
// catalog (not a hardcoded shape) — seeding through davidson.MustBundle()'s
// RoleCatalog yields the same well-formed result.
func TestSeed_DerivedFromCatalog(t *testing.T) {
	j := DavidsonCounty()
	_, records := seedFixture(t, j, davidsondep.MustBundle().RoleCatalog())
	if len(records) != uniqueAdjudicatorNames(j)+j.ClerkSlots() {
		t.Errorf("bundle-catalog seed issued %d grants, want %d", len(records), uniqueAdjudicatorNames(j)+j.ClerkSlots())
	}
}

// assertSameCourtClerks: from the issued grants, each clerk's granter is an
// adjudicator of the clerk's own court (a Circuit clerk is provisioned by a
// Circuit judge, etc.).
func assertSameCourtClerks(t *testing.T, reg *Registry, records []GrantRecord) {
	t.Helper()
	for _, r := range records {
		grantee := reg.ByDID(r.GranteeDID)
		if grantee == nil || grantee.Kind != KindClerk {
			continue
		}
		granter := reg.ByDID(r.GranterDID)
		if granter == nil {
			t.Errorf("clerk %s: granter %s not in registry", grantee.Name, r.GranterDID)
			continue
		}
		if granter.Kind != KindAdjudicator {
			t.Errorf("clerk %s granted by non-adjudicator %s (%s)", grantee.Name, granter.Name, granter.Kind)
		}
		if granter.Court != grantee.Court {
			t.Errorf("clerk %s (court %q) granted by %s of court %q",
				grantee.Name, grantee.Court, granter.Name, granter.Court)
		}
	}
}

// assertCommitAware: every non-institutional grant references a granter that was
// itself committed earlier in the record stream — the topological invariant.
func assertCommitAware(t *testing.T, records []GrantRecord) {
	t.Helper()
	committed := map[string]bool{}
	for _, r := range records {
		if r.GranterRole != "" && !committed[r.GranterDID] {
			t.Errorf("grant to %s references granter %s that was not committed earlier", r.GranteeName, r.GranterDID)
		}
		committed[r.GranteeDID] = true
	}
}
