/*
FILE PATH: verification/bundle_chain_resolver.go

DESCRIPTION:
    BundleChainResolver — production adapter wrapping
    *AuthorityResolver and exposing it as a
    jurisdiction.AuthorityChainResolver.

    Each Bundle's AuthorityChainResolver() method returns one
    of these so chain walks are scoped per-jurisdiction:
    Davidson chains validate against Davidson's RoleCatalog;
    Sup Ct chains against the Sup Ct catalog. Cross-exchange
    cosignature events still flow through the cosig fixture's
    IntraExchangeOnly=false machinery; this resolver only
    handles SAME-Bundle chain walks.

    The adapter is a thin shim: the production logic lives in
    AuthorityResolver. Construction is the only complexity —
    callers supply the per-Bundle catalog plus the operator-
    fetcher and SMT leaf reader.

OVERVIEW:
    BundleChainResolver       wraps *AuthorityResolver.
    NewBundleChainResolver    constructor.
    Resolve                   AuthorityRequest →
                              jurisdiction.AuthorityVerdict.
*/
package verification

import (
	"context"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// BundleChainResolver implements jurisdiction.AuthorityChainResolver
// by delegating to a verification.AuthorityResolver scoped to
// one Bundle's RoleCatalog.
type BundleChainResolver struct {
	inner *AuthorityResolver
}

// NewBundleChainResolver constructs a per-Bundle resolver.
//
// catalog is the per-Bundle RoleCatalog (what makes the
// resolver jurisdiction-specific). fetcher reads delegation
// entries by LogPosition (production: HTTP client to operator;
// tests: in-memory fake). leaf reads SMT leaves for
// origin/revocation evaluation.
//
// The returned value satisfies jurisdiction.AuthorityChainResolver
// and is safe for concurrent use as long as fetcher and leaf
// are.
func NewBundleChainResolver(
	catalog schemas.RoleCatalog,
	fetcher types.EntryFetcher,
	leaf smt.LeafReader,
) jurisdiction.AuthorityChainResolver {
	return &BundleChainResolver{
		inner: &AuthorityResolver{
			Fetcher:    fetcher,
			LeafReader: leaf,
			Catalog:    catalog,
		},
	}
}

// Resolve maps the jurisdiction-shaped request to the
// AuthorityResolver's signature, then maps the *Authority
// verdict back to the interface shape.
//
// The mapping is straightforward — both types capture the same
// information; the interface uses jurisdiction-package types so
// the verification package isn't imported by every consumer.
func (b *BundleChainResolver) Resolve(_ context.Context,
	req jurisdiction.AuthorityRequest) jurisdiction.AuthorityVerdict {
	a := b.inner.Resolve(
		req.SignerDID,
		schemas.LogPositionRef{
			LogDID:   req.DelegationRef.LogDID,
			Sequence: req.DelegationRef.Sequence,
		},
		req.RequestedAction,
	)
	if a == nil {
		return jurisdiction.AuthorityVerdict{
			OK:        false,
			SignerDID: req.SignerDID,
			Rejection: "nil_resolver_verdict",
			Reason:    "AuthorityResolver returned nil",
		}
	}
	// Always echo SignerDID — even when the inner resolver
	// rejects before populating its own SignerDID field, the
	// caller-supplied DID belongs in the audit trail.
	signerDID := a.SignerDID
	if signerDID == "" {
		signerDID = req.SignerDID
	}
	return jurisdiction.AuthorityVerdict{
		OK:             a.OK,
		SignerDID:      signerDID,
		Role:           a.Role,
		EffectiveScope: a.EffectiveScope,
		Depth:          a.Depth,
		Rejection:      string(a.Rejection),
		Reason:         a.Reason,
	}
}
