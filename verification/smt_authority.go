/*
FILE PATH: verification/smt_authority.go

SMTAuthorityResolver — the G19 authority gate over the canonical SDK+Tooling
delegation walk. Implements jurisdiction.AuthorityChainResolver by pairing the
tooling/libs/authority.SMTChainResolver (the one canonical attestation.Delegation
Resolver) with attestation.EvaluateConstraintOverChain (the SDK policy evaluator).
JN supplies only the domain extractors below + the per-cosigner chain tip; the
walk, the per-hop liveness, the grantee-chain (splice) check, and the expiry
check all live in the SDK+Tooling layer.

It REPLACES the AuthorityResolver/EvaluateOrigin path at the gate. Same verdict
shape (jurisdiction.AuthorityVerdict), but the per-hop liveness is the SDK's
DELEGATION-liveness test (leaf OriginTip == position), not verifier.Evaluate
Origin. EvaluateOrigin read a real self-targeting delegation revocation
(BuildRevocation TargetRoot == the revoked delegation, Path A) as Amended ⇒
LIVE — a false negative the old gate inherited. OriginTip==position catches it.

WALK-ONLY ROLE RESOLUTION. The gate verifies a cosigner's CLAIMED role against
its on-log chain (RequestedAction empty). Resolve returns the chain-tip Role;
ChainRoleResolver compares it to the claim. The OK verdict is the SDK policy
decision (EvaluateConstraintOverChain) over the resolved chain: with the
resolved leaf role as the required attribute, the attribute clause confirms the
extraction is self-consistent and the verdict reduces to the SDK liveness clause
(every hop live). Empty chains / broken links / missing entries fail closed.
*/
package verification

import (
	"context"
	"errors"
	"time"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/tooling/libs/auth/authority"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// roleAttrKey is the opaque capability key under which the gate carries a
// delegation's role into the SDK constraint model (Constraint.RequiredLeaf
// Attributes). The SDK never interprets it; it is JN's capability vocabulary.
const roleAttrKey = "role"

// SMTAuthorityResolver implements jurisdiction.AuthorityChainResolver over the
// libs SMTChainResolver. Safe for concurrent use when fetcher and leaf are.
type SMTAuthorityResolver struct {
	fetcher types.EntryFetcher
	leaf    smt.LeafReader
	now     func() time.Time // nil ⇒ time.Now (injectable for expiry tests)
}

// NewSMTAuthorityResolver builds the process-wide verifying resolver. fetcher
// reads delegation entries by position; leaf reads SMT leaves for the
// OriginTip==position liveness test. A nil fetcher or leaf is a caller error
// (the gate wiring fails closed before constructing this).
func NewSMTAuthorityResolver(fetcher types.EntryFetcher, leaf smt.LeafReader) *SMTAuthorityResolver {
	return &SMTAuthorityResolver{fetcher: fetcher, leaf: leaf}
}

// WithClock overrides the expiry clock (tests). Returns the receiver.
func (r *SMTAuthorityResolver) WithClock(now func() time.Time) *SMTAuthorityResolver {
	r.now = now
	return r
}

// Resolve walks the cosigner's delegation chain from its declared tip and
// returns the gate verdict. Implements jurisdiction.AuthorityChainResolver.
func (r *SMTAuthorityResolver) Resolve(ctx context.Context, req jurisdiction.AuthorityRequest) jurisdiction.AuthorityVerdict {
	if req.SignerDID == "" {
		return authReject(req.SignerDID, "signer_mismatch", "empty signer_did")
	}
	if req.DelegationRef.LogDID == "" {
		return authReject(req.SignerDID, "missing_chain_tip", "missing chain tip log_did")
	}

	tip := types.LogPosition{LogDID: req.DelegationRef.LogDID, Sequence: req.DelegationRef.Sequence}
	resolver := &authority.SMTChainResolver{
		Fetcher:    r.fetcher,
		LeafReader: r.leaf,
		Start: func(context.Context, string) (types.LogPosition, bool, error) {
			return tip, true, nil
		},
		ParentRef:  jnParentRef,
		Scope:      jnScope,
		Attributes: jnAttributes,
		ExpiresAt:  jnExpiresAt,
		Now:        r.now,
	}

	chain, err := resolver.ResolveChain(ctx, req.SignerDID)
	if err != nil {
		// ErrChainBroken: a spliced / missing hop, OR the leaf does not grant to
		// this signer (a cosigner cannot borrow another's delegation_ref — the
		// grantee chain would not start at the cosigner).
		return authReject(req.SignerDID, rejectionForResolveErr(err), err.Error())
	}
	if len(chain.Hops) == 0 {
		return authReject(req.SignerDID, "unknown_delegate", "signer has no on-log delegation")
	}
	role := chain.Hops[0].Attributes[roleAttrKey]
	if role == "" {
		return authReject(req.SignerDID, "malformed_payload", "leaf delegation declares no role")
	}

	// SDK policy decision over the resolved chain (attribute self-consistency +
	// liveness). EvaluateConstraintOverChain no-ops without a chain-walk clause,
	// so the explicit IsLive guard below covers the (non-gate) empty-role caller.
	if cErr := attestation.EvaluateConstraintOverChain(constraintForRole(role), req.SignerDID, chain); cErr != nil {
		return authRejectErr(req.SignerDID, role, len(chain.Hops), cErr)
	}
	if !chain.IsLive() {
		return authRejectErr(req.SignerDID, role, len(chain.Hops), errors.New("delegation chain not live"))
	}

	return jurisdiction.AuthorityVerdict{
		OK:             true,
		SignerDID:      req.SignerDID,
		Role:           role,
		EffectiveScope: chain.LeafScopes(),
		Depth:          len(chain.Hops),
	}
}

// constraintForRole is the ConstraintForEvent for the walk-only role check: the
// leaf delegation must declare the given role. Combined by EvaluateConstraint
// OverChain with the SDK's always-on liveness clause.
func constraintForRole(role string) attestation.Constraint {
	return attestation.Constraint{RequiredLeafAttributes: map[string]string{roleAttrKey: role}}
}

// ─── domain extractors (the ONLY JN-specific vocabulary the walk needs) ──────

// jnDelegation parses the judicial-delegation-v1 payload. A revocation /
// succession / malformed entry returns ok=false; the walk then has no parent
// pointer / role, which fails closed at the origin or role check.
func jnDelegation(e *envelope.Entry) (*schemas.JudicialDelegationPayload, bool) {
	if e == nil {
		return nil, false
	}
	p, err := schemas.UnmarshalJudicialDelegationPayload(e.DomainPayload)
	if err != nil {
		return nil, false
	}
	return p, true
}

// jnParentRef is the chain link — the granter's delegation position, from the
// domain payload (NOT the SDK header).
func jnParentRef(e *envelope.Entry) (types.LogPosition, bool) {
	p, ok := jnDelegation(e)
	if !ok || p.GranterDelegationRef == nil {
		return types.LogPosition{}, false
	}
	return types.LogPosition{LogDID: p.GranterDelegationRef.LogDID, Sequence: p.GranterDelegationRef.Sequence}, true
}

// jnScope is the per-hop scope set.
func jnScope(e *envelope.Entry) []string {
	p, ok := jnDelegation(e)
	if !ok {
		return nil
	}
	return p.Scope
}

// jnAttributes carries the role into the SDK capability model.
func jnAttributes(e *envelope.Entry) map[string]string {
	p, ok := jnDelegation(e)
	if !ok || p.Role == "" {
		return nil
	}
	return map[string]string{roleAttrKey: p.Role}
}

// jnExpiresAt is the per-hop expiry. ok=false when no expiry is declared.
func jnExpiresAt(e *envelope.Entry) (time.Time, bool) {
	p, ok := jnDelegation(e)
	if !ok || p.ExpiresAt == "" {
		return time.Time{}, false
	}
	return p.ParsedExpiresAt(), true
}

// ─── verdict helpers ─────────────────────────────────────────────────────────

func authReject(signerDID, rejection, reason string) jurisdiction.AuthorityVerdict {
	return jurisdiction.AuthorityVerdict{OK: false, SignerDID: signerDID, Rejection: rejection, Reason: reason}
}

func authRejectErr(signerDID, role string, depth int, err error) jurisdiction.AuthorityVerdict {
	rej := "revoked"
	if errors.Is(err, attestation.ErrConstraintAttributeMismatch) {
		rej = "role_mismatch"
	}
	return jurisdiction.AuthorityVerdict{
		OK: false, SignerDID: signerDID, Role: role, Depth: depth,
		Rejection: rej, Reason: err.Error(),
	}
}

func rejectionForResolveErr(err error) string {
	switch {
	case errors.Is(err, attestation.ErrChainBroken):
		return "chain_broken"
	case errors.Is(err, attestation.ErrUnknownDelegate):
		return "unknown_delegate"
	default:
		return "fetch_failed"
	}
}

// Static check.
var _ jurisdiction.AuthorityChainResolver = (*SMTAuthorityResolver)(nil)
