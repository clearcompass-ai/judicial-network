package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/tooling/libs/auth/identity"

	"github.com/clearcompass-ai/judicial-network/delegation"
	davidsondep "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// liveishContext wires a registry + the real trial catalog into a BuildContext
// over the in-memory ledger. Unlike seedFixture it does NOT pre-seed — Provision
// runs the seeder itself — and it returns the StubProvider already key-bound so
// every officer + attorney can sign.
func liveishContext(t *testing.T, j Jurisdiction) (*delegation.BuildContext, *Registry) {
	t.Helper()
	reg := BuildRegistry(j, testSeed)
	sp := identity.NewStubProvider()
	reg.BindKeys(sp)
	bc := &delegation.BuildContext{
		Identity:         sp,
		Submitter:        &memLedger{logDID: j.ExchangeDID},
		Catalog:          trial.MustRoleCatalog(),
		ExchangeDID:      j.ExchangeDID,
		InstitutionalDID: j.InstitutionalDID,
	}
	return bc, reg
}

// TestProvision_Davidson_FullLifecycle drives the whole orchestration end to end
// against the in-memory ledger: it seeds every officer, then for each case
// builds → signs (real secp256k1 via the StubProvider) → validates → serializes
// → submits the four lifecycle entries, chaining each follow-on to the
// committed case root. This exercises everything except the live verifier:
// entry construction, the cosigned + single-signer submit pipelines, and the
// dependency ordering.
func TestProvision_Davidson_FullLifecycle(t *testing.T) {
	bc, reg := liveishContext(t, DavidsonCounty())

	rep, err := Provision(context.Background(), bc, reg, nil, ProvisionOptions{
		Cases:      5,
		MasterSeed: testSeed,
		Lifecycle:  true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if len(rep.Grants) != len(reg.Officers) {
		t.Errorf("seeded %d grants, want one per officer (%d)", len(rep.Grants), len(reg.Officers))
	}
	if len(rep.Cases) != 5 {
		t.Fatalf("provisioned %d cases, want 5", len(rep.Cases))
	}
	for _, c := range rep.Cases {
		if c.CaseInitiation.Sequence == 0 {
			t.Errorf("%s: case_initiation not committed", c.Docket)
		}
		if c.CounselAppearance == nil || c.CounselAppearance.Sequence == 0 {
			t.Errorf("%s: counsel_appearance missing", c.Docket)
		}
		if c.ResponsivePleading == nil || c.ResponsivePleading.Sequence == 0 {
			t.Errorf("%s: responsive_pleading missing", c.Docket)
		}
		if c.FinalJudgment == nil || c.FinalJudgment.Sequence == 0 {
			t.Errorf("%s: final_judgment missing", c.Docket)
		}
	}
}

// TestProvision_NoLifecycle: with Lifecycle off, only case_initiation is filed.
func TestProvision_NoLifecycle(t *testing.T) {
	bc, reg := liveishContext(t, DavidsonCounty())
	rep, err := Provision(context.Background(), bc, reg, nil, ProvisionOptions{
		Cases: 3, MasterSeed: testSeed, Lifecycle: false,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	for _, c := range rep.Cases {
		if c.CaseInitiation.Sequence == 0 {
			t.Errorf("%s: case_initiation not committed", c.Docket)
		}
		if c.CounselAppearance != nil || c.ResponsivePleading != nil || c.FinalJudgment != nil {
			t.Errorf("%s: lifecycle entries present despite Lifecycle=false", c.Docket)
		}
	}
}

// TestResponsivePleading_PassesCosignatureGate proves the merits-posture filing
// the lifecycle builds satisfies the REAL tn/trial responsive_pleading rule: an
// attorney filer (filed_by_capacity + bpr_number, who must also cosign) plus a
// distinct court_clerk cosigner besides the primary. CheckCosignature is the
// role/threshold/credential layer (crypto is separate), so DID-only signatures
// exercise exactly the surface under test.
func TestResponsivePleading_PassesCosignatureGate(t *testing.T) {
	j := DavidsonCounty()
	reg, _ := seedFixture(t, j, trial.MustRoleCatalog()) // seeds so the clerk cosigner carries a delegation_ref

	clerks := clerksOfCourt(reg, "Davidson County Circuit Court")
	if len(clerks) < 2 {
		t.Fatalf("need ≥2 circuit clerks, got %d", len(clerks))
	}
	primaryClerk, secondClerk := clerks[0], clerks[1]
	attorney := civilAttorney(t, reg)

	caseRoot := schemas.LogPositionRef{LogDID: davidsondep.ExchangeDID, Sequence: 1}
	entry, err := buildAttorneyFiling(context.Background(), j, caseRoot,
		"responsive_pleading", "responsive_pleading", "Answer", "2026-GC-00001",
		primaryClerk, secondClerk, attorney, time.Now().UTC())
	if err != nil {
		t.Fatalf("buildAttorneyFiling: %v", err)
	}

	// Primary clerk at [0], then the attorney filer and the accepting clerk.
	entry.Signatures = []envelope.Signature{
		{SignerDID: primaryClerk.DID},
		{SignerDID: attorney.DID},
		{SignerDID: secondClerk.DID},
	}

	pol := trial.MustCosignaturePolicy()
	res := verification.NewMapRoleResolver().Bind(secondClerk.DID, "court_clerk", davidsondep.ExchangeDID)
	v := verification.CheckCosignature(entry, pol, res, davidsondep.ExchangeDID)
	if !v.OK {
		t.Fatalf("responsive_pleading should pass the cosignature gate, got %s: %s", v.Rejection, v.Reason)
	}

	// Negative: drop the accepting clerk → the court_clerk threshold fails.
	entry.Signatures = []envelope.Signature{
		{SignerDID: primaryClerk.DID},
		{SignerDID: attorney.DID},
	}
	if v2 := verification.CheckCosignature(entry, pol, res, davidsondep.ExchangeDID); v2.OK {
		t.Errorf("responsive_pleading without a clerk cosigner must fail the gate")
	}
}

// civilAttorney returns a seeded civil_attorney from the registry's bar.
func civilAttorney(t *testing.T, reg *Registry) *Principal {
	t.Helper()
	for _, p := range reg.Attorneys {
		if schemas.FilerRole(p.FilerRole) == schemas.FilerRoleCivilAttorney {
			return p
		}
	}
	t.Fatal("no civil_attorney in the Davidson bar fixture")
	return nil
}
