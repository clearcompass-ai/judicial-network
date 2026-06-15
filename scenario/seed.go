package scenario

// The officer seeder: provisions a jurisdiction's delegated signers (judges,
// justices, clerks) onto its court log by issuing the delegation chain the
// deployment's role catalog prescribes.
//
// The chain is DERIVED from the catalog's DelegableBy, never hardcoded:
//   - a role with no DelegableBy (judge, chief_justice) is granted by the
//     institutional root at depth 0 (GranterRole == "");
//   - a role with DelegableBy=[X] (justice←chief_justice, court_clerk←judge) is
//     granted by an already-committed officer holding role X — for a clerk,
//     preferring an adjudicator of the SAME court.
//
// This is why one seeder works for every court (Davidson, the Supreme Court,
// and any future appellate or federal court): the topology is data in the
// catalog, not branches in the code.
//
// Attorneys are NOT seeded here. They are FILER principals, not delegated
// signers; they appear on-log only when they file a case (under
// FiledByCapacity), which a court clerk cosigns.

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// GrantRecord is one issued delegation, captured for audit and assertions.
// GranterRole == "" marks an institutional depth-0 grant.
type GrantRecord struct {
	GranterDID  string
	GranterRole string
	GranteeDID  string
	GranteeRole string
	GranteeName string
	Position    schemas.LogPositionRef
}

// Seed provisions every officer in reg onto the court log via delegation.Issue,
// recording each on-log position back onto the principal (p.Delegation) and
// returning the issued grants in commit order. Issuance is commit-aware and
// topologically ordered: an officer is issued only once its granter holds an
// on-log position, which becomes the grantee's granter_delegation_ref.
func Seed(ctx context.Context, bc *delegation.BuildContext, reg *Registry) ([]GrantRecord, error) {
	if bc == nil || bc.Catalog == nil {
		return nil, fmt.Errorf("scenario: nil BuildContext / Catalog")
	}
	if bc.InstitutionalDID != reg.Jurisdiction.InstitutionalDID {
		return nil, fmt.Errorf("scenario: BuildContext InstitutionalDID %q != jurisdiction %q",
			bc.InstitutionalDID, reg.Jurisdiction.InstitutionalDID)
	}
	if bc.ExchangeDID != reg.Jurisdiction.ExchangeDID {
		return nil, fmt.Errorf("scenario: BuildContext ExchangeDID %q != jurisdiction %q",
			bc.ExchangeDID, reg.Jurisdiction.ExchangeDID)
	}

	var records []GrantRecord
	pending := append([]*Principal(nil), reg.Officers...)

	for len(pending) > 0 {
		var deferred []*Principal
		progressed := false

		for _, p := range pending {
			role, err := bc.Catalog.Lookup(p.Role)
			if err != nil {
				return nil, fmt.Errorf("scenario: officer %q role %q: %w", p.Name, p.Role, err)
			}
			granter := selectGranter(reg, p, role.DelegableBy)
			if len(role.DelegableBy) > 0 && granter == nil {
				deferred = append(deferred, p) // granter not committed yet
				continue
			}

			req := delegation.IssueRequest{
				GranteeDID:  p.DID,
				GranteeRole: p.Role,
				Rationale:   fmt.Sprintf("Seed %s (%s) onto %s", p.Name, p.Role, reg.Jurisdiction.Name),
			}
			if granter == nil {
				req.GranterDID = reg.Institutional.DID // depth-0 institutional grant
				req.GranterRole = ""
			} else {
				req.GranterDID = granter.DID
				req.GranterRole = granter.Role
				req.GranterDelegationRef = granter.Delegation
			}

			res, err := delegation.Issue(ctx, bc, req)
			if err != nil {
				return nil, fmt.Errorf("scenario: issue %s (%s): %w", p.Name, p.Role, err)
			}
			pos := res.Position
			p.Delegation = &pos
			records = append(records, GrantRecord{
				GranterDID: req.GranterDID, GranterRole: req.GranterRole,
				GranteeDID: p.DID, GranteeRole: p.Role, GranteeName: p.Name, Position: pos,
			})
			progressed = true
		}

		if !progressed {
			stuck := make([]string, 0, len(deferred))
			for _, p := range deferred {
				stuck = append(stuck, fmt.Sprintf("%s(%s)", p.Name, p.Role))
			}
			return nil, fmt.Errorf("scenario: delegation chain unsatisfiable — no committed granter for: %v", stuck)
		}
		pending = deferred
	}
	return records, nil
}

// selectGranter picks the committed officer that may grant grantee per
// delegableBy. Empty delegableBy ⇒ no signer granter (the institution grants at
// depth 0). Otherwise the first committed officer whose role ∈ delegableBy,
// preferring one of the grantee's OWN court so a court's clerk is granted by a
// judge of that court.
func selectGranter(reg *Registry, grantee *Principal, delegableBy []string) *Principal {
	if len(delegableBy) == 0 {
		return nil
	}
	allowed := map[string]bool{}
	for _, role := range delegableBy {
		allowed[role] = true
	}
	var fallback *Principal
	for _, p := range reg.Officers {
		if p == grantee || p.Delegation == nil {
			continue
		}
		if allowed["*"] || allowed[p.Role] {
			if p.Court == grantee.Court {
				return p
			}
			if fallback == nil {
				fallback = p
			}
		}
	}
	return fallback
}
