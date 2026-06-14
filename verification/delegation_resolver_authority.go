/*
FILE PATH: verification/delegation_resolver_authority.go

The jurisdiction.AuthorityChainResolver projection of the index-walk
(PRE-13b #181, step 3). LedgerDelegationResolver already implements the SDK's
attestation.DelegationResolver (ResolveChain → DelegationChain); this file adds
Resolve → jurisdiction.AuthorityVerdict, so ONE type and ONE walk serve both
consumers (the single index-walk seam — no duplicated walk loop).

The verdict reproduces AuthorityResolver's WALK-ONLY contract (the only one the
gate uses; the catalog action-branch has zero production callers):

  - role-at-tip   = hops[0].role            (the role granted to the signer)
  - EffectiveScope = ∩ over hops of scope    (intersectScope, tip→root)
  - liveness      = newest-grant-wins        (revocation/succession tip ⇒ reject)
  - expiry        = any expired hop ⇒ reject (parity with AuthorityResolver)

REVOCATION WITHOUT AN SMT READ: the position-fetch AuthorityResolver needs
verifier.EvaluateOrigin (an SMT leaf read) per hop because it follows
granter_delegation_ref pointers and cannot see a revocation appended later. The
index-walk sees that revocation directly — the ledger SURFACES it as the newest
delegate_did row (#120) — so newest-grant-wins covers it with no SMT in the
gate's hot path. The SMT-authenticated EvaluateOrigin lane stays for the
external auditor (case_status.go): different consumer, not a downgrade.

RequestedAction is ignored (walk-only): the verdict yields Role + EffectiveScope
and the caller (ChainRoleResolver) does the role-membership check. A future
action-authorization caller layers the RoleCatalog check on top — it does not
exist yet, so it is not built here (no dormant machinery).
*/
package verification

import (
	"context"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/core/envelope"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// Resolve walks the signer's delegation chain via the index and returns a
// jurisdiction.AuthorityVerdict. Never returns an error — every failure is a
// fail-closed verdict (OK=false with a closed-set Rejection token), matching
// the AuthorityChainResolver contract. req.DelegationRef is ignored: the
// index-walk binds to req.SignerDID's OWN incoming delegations
// (QueryByDelegateDID), so a cosigner cannot borrow a real judge's
// delegation_ref — the chain would not start at the cosigner.
func (r *LedgerDelegationResolver) Resolve(
	ctx context.Context, req jurisdiction.AuthorityRequest,
) jurisdiction.AuthorityVerdict {
	if req.SignerDID == "" {
		return jurisdiction.AuthorityVerdict{
			OK: false, Rejection: string(RejectSignerMismatch), Reason: "empty signer_did",
		}
	}
	hops, complete, err := r.walk(ctx, req.SignerDID)
	if err != nil {
		return jurisdiction.AuthorityVerdict{
			OK: false, SignerDID: req.SignerDID,
			Rejection: string(RejectFetchFailed), Reason: err.Error(),
		}
	}
	if len(hops) == 0 {
		return jurisdiction.AuthorityVerdict{
			OK: false, SignerDID: req.SignerDID,
			Rejection: string(RejectMissingChainTip),
			Reason:    "signer has no on-log delegation",
		}
	}

	tipRole := hops[0].role
	now := r.now()
	var effective []string
	for i := range hops {
		h := &hops[i]
		if !h.live {
			return jurisdiction.AuthorityVerdict{
				OK: false, SignerDID: req.SignerDID, Role: tipRole, Depth: i + 1,
				Rejection: string(RejectRevoked),
				Reason:    fmt.Sprintf("hop %d (%s) withdrawn (revocation/succession)", i, h.delegateDID),
			}
		}
		if h.hasExpiry && !h.expiresAt.After(now) {
			return jurisdiction.AuthorityVerdict{
				OK: false, SignerDID: req.SignerDID, Role: tipRole, Depth: i + 1,
				Rejection: string(RejectExpired),
				Reason:    fmt.Sprintf("hop %d (%s) expired at %s", i, h.delegateDID, h.expiresAt.Format(time.RFC3339)),
			}
		}
		if i == 0 {
			effective = append(effective, h.scopes...)
		} else {
			effective = intersectScope(effective, h.scopes)
		}
	}
	if !complete {
		return jurisdiction.AuthorityVerdict{
			OK: false, SignerDID: req.SignerDID, Role: tipRole,
			EffectiveScope: effective, Depth: len(hops),
			Rejection: string(RejectDepthExceeded),
			Reason:    "chain did not terminate at a root (depth cap, cycle, or malformed hop)",
		}
	}
	return jurisdiction.AuthorityVerdict{
		OK: true, SignerDID: req.SignerDID, Role: tipRole,
		EffectiveScope: effective, Depth: len(hops), Rejection: string(RejectNone),
	}
}

// JudicialHopRole, JudicialHopScope, and JudicialHopExpiry are the judicial
// projections the gate wires into LedgerDelegationResolverConfig (Role, Scope,
// Expiry) so the AuthorityVerdict reproduces AuthorityResolver's role-at-tip,
// scope intersection, and per-hop expiry. A payload that is not a judicial
// delegation (e.g. a revocation tip) decodes to the zero value; the not-live
// signal (tipWithdrawsAuthority) carries that case.
func JudicialHopRole(entry *envelope.Entry) string {
	p, err := schemas.UnmarshalJudicialDelegationPayload(entry.DomainPayload)
	if err != nil {
		return ""
	}
	return p.Role
}

// JudicialHopScope extracts the granted scope tokens.
func JudicialHopScope(entry *envelope.Entry) []string {
	p, err := schemas.UnmarshalJudicialDelegationPayload(entry.DomainPayload)
	if err != nil {
		return nil
	}
	return p.Scope
}

// JudicialHopExpiry extracts the delegation's expiry; ok=false when none is
// declared (a malformed/non-judicial payload, or an empty expires_at).
func JudicialHopExpiry(entry *envelope.Entry) (time.Time, bool) {
	p, err := schemas.UnmarshalJudicialDelegationPayload(entry.DomainPayload)
	if err != nil || p.ExpiresAt == "" {
		return time.Time{}, false
	}
	return p.ParsedExpiresAt(), true
}

// Compile-time pin: the index-walk resolver is also a jurisdiction-scoped
// AuthorityChainResolver — the gate seam BundleChainResolver currently fills.
var _ jurisdiction.AuthorityChainResolver = (*LedgerDelegationResolver)(nil)
