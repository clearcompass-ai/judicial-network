package scenario

// The provisioning orchestrator: drives a full single-jurisdiction run against
// a live ledger. It seeds the officer delegations, then for each generated case
// submits the lifecycle in dependency order, building every entry INLINE (fresh
// EventTime) right before it is signed and submitted so the ledger's freshness
// gate accepts it and each follow-on can chain to the just-assigned position.
//
// Per case (when Lifecycle is set):
//
//	case_initiation    clerk primary + accepting clerk cosign      (cosigned)
//	→ counsel_appearance attorney files, clerk cosigns, BPR         (cosigned)
//	→ responsive_pleading attorney files, clerk cosigns, BPR        (cosigned, merits posture)
//	→ final_judgment    presiding judge, sole signer, case_decision (single)
//
// The first failure aborts the run and is returned verbatim, so an operator
// bringing the stack up sees exactly which entry the ledger/verifier rejected.

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/baseproof/tooling/libs/auth/identity"

	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ProvisionOptions configures a provisioning run.
type ProvisionOptions struct {
	Cases      int    // number of case_initiation filings to generate
	MasterSeed []byte // deterministic population + selection seed
	Lifecycle  bool   // when true, file counsel_appearance + responsive_pleading + final_judgment per case
}

// CaseRecord is the on-log outcome of one provisioned case. The pointer fields
// are nil when Lifecycle is off or that step was not reached.
type CaseRecord struct {
	Docket             string
	CaseInitiation     schemas.LogPositionRef
	CounselAppearance  *schemas.LogPositionRef
	ResponsivePleading *schemas.LogPositionRef
	FinalJudgment      *schemas.LogPositionRef
}

// ProvisionReport summarizes a run for the CLI to print.
type ProvisionReport struct {
	Grants   []GrantRecord
	Cases    []CaseRecord
	HeadSize uint64
	HeadSigs int
}

// Provision runs the full single-jurisdiction flow against the live ledger
// behind bc.Submitter: seed officers, then submit each generated case's
// lifecycle. reader (optional) is read at the end to report the populated head.
func Provision(ctx context.Context, bc *delegation.BuildContext, reg *Registry, reader *LedgerReader, opts ProvisionOptions) (*ProvisionReport, error) {
	rep := &ProvisionReport{}

	// 1. Seed officers (delegation chain: institution → judges → clerks).
	grants, err := Seed(ctx, bc, reg)
	if err != nil {
		return rep, fmt.Errorf("seed officers: %w", err)
	}
	rep.Grants = grants

	// 2. Plan the cases (deterministic from the master seed).
	plans, err := GenerateCases(reg, opts.Cases, opts.MasterSeed)
	if err != nil {
		return rep, fmt.Errorf("generate cases: %w", err)
	}

	// 3. Submit each case's lifecycle in dependency order.
	for _, pc := range plans {
		cr, err := provisionCase(ctx, bc, reg, pc, opts.MasterSeed, opts.Lifecycle)
		if err != nil {
			return rep, fmt.Errorf("case %s: %w", pc.DocketNumber, err)
		}
		rep.Cases = append(rep.Cases, cr)
	}

	// 4. Confirm the populated head (best-effort).
	if reader != nil {
		if h, herr := reader.Head(ctx); herr == nil {
			rep.HeadSize = h.TreeSize
			rep.HeadSigs = len(h.Signatures)
		}
	}
	return rep, nil
}

// provisionCase submits one case's lifecycle, returning the on-log positions.
func provisionCase(ctx context.Context, bc *delegation.BuildContext, reg *Registry, pc *PlannedCase, masterSeed []byte, lifecycle bool) (CaseRecord, error) {
	cr := CaseRecord{Docket: pc.DocketNumber}
	j := reg.Jurisdiction
	now := time.Now().UTC()

	// case_initiation — rebuilt fresh, cosigned (primary clerk + accepting clerk).
	initEntry, err := pc.InitiationEntry(j, now.UnixMicro())
	if err != nil {
		return cr, err
	}
	root, err := delegation.SignAndSubmitCosigned(ctx, bc, initEntry,
		entryDisplay(j.InstitutionalDID, "CaseInitiation",
			identity.EIP712Field{Name: "event_type", Type: "string", Value: "case_initiation"},
			identity.EIP712Field{Name: "docket_number", Type: "string", Value: pc.DocketNumber}),
		"case_initiation "+pc.DocketNumber, []string{pc.Cosigner.DID})
	if err != nil {
		return cr, fmt.Errorf("case_initiation: %w", err)
	}
	cr.CaseInitiation = root
	if !lifecycle {
		return cr, nil
	}

	// Deterministic per-case selection of the representing attorney + presiding judge.
	rng := rand.New(rand.NewSource(seedInt64(masterSeed, "lifecycle|"+pc.DocketNumber)))
	attorney := pickFilingAttorney(reg, rng)
	if attorney == nil {
		return cr, fmt.Errorf("no civil_attorney/defense_counsel in %s bar (needed to reach final_judgment)", j.Key)
	}
	judge := pickPresidingJudge(reg, pc.Court, rng)
	if judge == nil {
		return cr, fmt.Errorf("no judge available for court %q", pc.Court)
	}

	// counsel_appearance — attorney enters; primary clerk signs, accepting clerk cosigns.
	caEntry, err := buildAttorneyFiling(ctx, j, root, "counsel_appearance",
		"counsel_appearance", "Notice of Appearance", pc.DocketNumber,
		pc.Primary, pc.Cosigner, attorney, now)
	if err != nil {
		return cr, err
	}
	caPos, err := delegation.SignAndSubmitCosigned(ctx, bc, caEntry,
		filingDisplay(j.InstitutionalDID, "counsel_appearance", attorney.DID),
		"counsel_appearance "+pc.DocketNumber, []string{attorney.DID, pc.Cosigner.DID})
	if err != nil {
		return cr, fmt.Errorf("counsel_appearance: %w", err)
	}
	cr.CounselAppearance = &caPos

	// responsive_pleading — the merits-posture ancestor final_judgment requires.
	rpEntry, err := buildAttorneyFiling(ctx, j, root, "responsive_pleading",
		"responsive_pleading", "Answer to Complaint", pc.DocketNumber,
		pc.Primary, pc.Cosigner, attorney, now)
	if err != nil {
		return cr, err
	}
	rpPos, err := delegation.SignAndSubmitCosigned(ctx, bc, rpEntry,
		filingDisplay(j.InstitutionalDID, "responsive_pleading", attorney.DID),
		"responsive_pleading "+pc.DocketNumber, []string{attorney.DID, pc.Cosigner.DID})
	if err != nil {
		return cr, fmt.Errorf("responsive_pleading: %w", err)
	}
	cr.ResponsivePleading = &rpPos

	// final_judgment — presiding judge, sole signer, case_decision scope.
	disposition := dispositions[rng.Intn(len(dispositions))]
	fjEntry, err := buildFinalJudgment(ctx, j, root, pc.DocketNumber, disposition, judge, now)
	if err != nil {
		return cr, err
	}
	fjPos, err := signAndSubmitSingle(ctx, bc, fjEntry,
		entryDisplay(j.InstitutionalDID, "FinalJudgment",
			identity.EIP712Field{Name: "event_type", Type: "string", Value: "final_judgment"},
			identity.EIP712Field{Name: "docket_number", Type: "string", Value: pc.DocketNumber},
			identity.EIP712Field{Name: "disposition", Type: "string", Value: disposition}),
		"final_judgment "+pc.DocketNumber)
	if err != nil {
		return cr, fmt.Errorf("final_judgment: %w", err)
	}
	cr.FinalJudgment = &fjPos
	return cr, nil
}

// filingDisplay builds the wallet display for an attorney filing (the filer DID
// is the load-bearing field every cosigner approves).
func filingDisplay(institutionalDID, eventType, filerDID string) *identity.TypedDataDisplay {
	return entryDisplay(institutionalDID, "AttorneyFiling",
		identity.EIP712Field{Name: "event_type", Type: "string", Value: eventType},
		identity.EIP712Field{Name: "filed_by", Type: "string", Value: filerDID})
}

// pickFilingAttorney returns a bar member who can file the merits-posture
// pleading: civil_attorney or defense_counsel (responsive_pleading forbids
// prosecutor). nil when the bar has none.
func pickFilingAttorney(reg *Registry, rng *rand.Rand) *Principal {
	var pool []*Principal
	for _, p := range reg.Attorneys {
		switch schemas.FilerRole(p.FilerRole) {
		case schemas.FilerRoleCivilAttorney, schemas.FilerRoleDefenseCounsel:
			pool = append(pool, p)
		}
	}
	if len(pool) == 0 {
		return nil
	}
	return pool[rng.Intn(len(pool))]
}

// pickPresidingJudge returns a judge of the case's court, falling back to any
// in-exchange adjudicator (final_judgment is intra-exchange, so any seeded
// Davidson judge satisfies the cosignature exchange + case_decision scope).
func pickPresidingJudge(reg *Registry, court string, rng *rand.Rand) *Principal {
	var ofCourt []*Principal
	for _, p := range reg.Adjudicators() {
		if p.Court == court {
			ofCourt = append(ofCourt, p)
		}
	}
	if len(ofCourt) == 0 {
		ofCourt = reg.Adjudicators()
	}
	if len(ofCourt) == 0 {
		return nil
	}
	return ofCourt[rng.Intn(len(ofCourt))]
}

// dispositions is a small fixed pool of final_judgment outcomes (deterministic
// selection; test population, not real rulings).
var dispositions = []string{
	"judgment_for_plaintiff",
	"judgment_for_defendant",
	"dismissed_with_prejudice",
	"settled_and_dismissed",
}
