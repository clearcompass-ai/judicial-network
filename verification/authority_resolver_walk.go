/*
FILE PATH: verification/authority_resolver_walk.go

DESCRIPTION:

	The chain-walk algorithm for AuthorityResolver. Split out of
	authority_resolver.go so that file can stay focused on the type
	definitions and callers can navigate the walk independently.

OVERVIEW:

	Resolve — main entry point: walks tip→root, intersects scope per
	          hop, runs catalog validation at the end.

KEY DEPENDENCIES:
  - schemas.LogPositionRef (chain pointer shape)
  - schemas.RoleCatalog (final-pass authority check)
  - authority_resolver_origin.go (per-hop fetchAndValidate)
*/
package verification

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// Resolve walks the chain rooted at signerDelegRef and verifies
// signerDID has authority over requestedAction at the chain's tip.
//
// Inputs:
//   - signerDID: the protocol DID claiming to act.
//   - signerDelegRef: log position of the delegation entry that
//     authorized signerDID. Caller obtains this from the
//     OfficerRegistry or from the entry being verified's
//     DelegationPointers[0].
//   - requestedAction: the scope token the action requires
//     ("case_filing", "invite:judge", "revoke:downstream").
//
// Output: *Authority with OK and Reason populated. Never returns
// nil; the caller can rely on Authority.OK as the verdict.
func (r *AuthorityResolver) Resolve(
	signerDID string,
	signerDelegRef schemas.LogPositionRef,
	requestedAction string,
) *Authority {
	if signerDID == "" {
		return &Authority{Rejection: RejectSignerMismatch, Reason: "empty signer_did"}
	}
	if signerDelegRef.LogDID == "" {
		return &Authority{Rejection: RejectMissingChainTip, Reason: "missing chain tip log_did"}
	}
	now := r.now()

	// Walk: tipPayload → granter_delegation_ref → ... → institutional.
	// The first hop's grantee_did must equal signerDID.
	current := signerDelegRef
	expectedGrantee := signerDID

	var (
		effective []string
		tipRole   string
		depth     int
	)
	first := true

	for current.LogDID != "" {
		depth++
		if depth > MaxDelegationDepth {
			return &Authority{
				SignerDID: signerDID,
				Depth:     depth - 1,
				Rejection: RejectDepthExceeded,
				Reason:    fmt.Sprintf("chain exceeded MaxDelegationDepth=%d", MaxDelegationDepth),
			}
		}

		hop, rej, reason := r.fetchAndValidate(current, expectedGrantee, now)
		if rej != RejectNone {
			return &Authority{SignerDID: signerDID, Depth: depth, Rejection: rej, Reason: reason}
		}

		if first {
			tipRole = hop.payload.Role
			effective = append(effective, hop.payload.Scope...)
			first = false
		} else {
			effective = intersectScope(effective, hop.payload.Scope)
		}

		// Move to the next hop. nil parent → reached institutional
		// DID at depth 0.
		if hop.payload.GranterDelegationRef == nil {
			break
		}
		current = *hop.payload.GranterDelegationRef
		expectedGrantee = hop.payload.GranterDID
	}

	// Catalog validation: confirm requestedAction is in the
	// chain-effective scope, and the role allows it.
	if !contains(effective, requestedAction) {
		return &Authority{
			SignerDID:      signerDID,
			Role:           tipRole,
			EffectiveScope: effective,
			Depth:          depth,
			Rejection:      RejectScopeViolation,
			Reason:         fmt.Sprintf("requested %q not in effective scope %v", requestedAction, effective),
		}
	}
	role, err := r.Catalog.Lookup(tipRole)
	if err != nil {
		return &Authority{
			SignerDID:      signerDID,
			Role:           tipRole,
			EffectiveScope: effective,
			Depth:          depth,
			Rejection:      RejectCatalogViolation,
			Reason:         fmt.Sprintf("role lookup: %v", err),
		}
	}
	if !contains(role.AllowedScope, requestedAction) {
		return &Authority{
			SignerDID:      signerDID,
			Role:           tipRole,
			EffectiveScope: effective,
			Depth:          depth,
			Rejection:      RejectCatalogViolation,
			Reason:         fmt.Sprintf("role %q AllowedScope %v does not include %q", tipRole, role.AllowedScope, requestedAction),
		}
	}

	return &Authority{
		OK:             true,
		SignerDID:      signerDID,
		Role:           tipRole,
		EffectiveScope: effective,
		Depth:          depth,
		Rejection:      RejectNone,
	}
}
