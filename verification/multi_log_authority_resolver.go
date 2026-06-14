/*
FILE PATH: verification/multi_log_authority_resolver.go

PRE-13b #181 step 5 — the production seam that replaces the log-agnostic
position-fetch BundleChainResolver behind the gate's g.Authority.

The position-fetch engine was log-agnostic: it fetched each hop by the
LogPosition carried in granter_delegation_ref, so one resolver spanned every
exchange. The index-walk is per-log (one delegate_did query endpoint per
exchange ledger), so this dispatcher holds one LedgerDelegationResolver per
exchange LogDID and routes each request to the right one by
req.DelegationRef.LogDID.

SECURITY: the LogDID is ROUTING ONLY. The per-log resolver binds the walk to
req.SignerDID (QueryByDelegateDID(signerDID)), never to the ref's chain — so a
cosigner still cannot borrow another judge's delegation_ref; the worst a forged
ref.LogDID does is route to a log where the cosigner has no delegation, which
fails closed. An unknown LogDID fails closed (RejectMissingChainTip).
*/
package verification

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/types"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// MultiLogAuthorityResolver dispatches role verification to a per-log index
// resolver by request LogDID. Implements jurisdiction.AuthorityChainResolver.
type MultiLogAuthorityResolver struct {
	byLog map[string]*LedgerDelegationResolver
}

// NewMultiLogAuthorityResolver builds one index resolver per exchange querier,
// each wired with the judicial role/scope/expiry extractors so its verdict
// reproduces AuthorityResolver's (proven by the parity lock test). Returns an
// error only if a per-log resolver is misconfigured.
func NewMultiLogAuthorityResolver(
	queriers map[string]DelegateDIDQuerier,
	fetcher types.EntryFetcher,
) (*MultiLogAuthorityResolver, error) {
	byLog := make(map[string]*LedgerDelegationResolver, len(queriers))
	for logDID, q := range queriers {
		r, err := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
			Delegate: q,
			Fetcher:  fetcher,
			LogDID:   logDID,
			Role:     JudicialHopRole,
			Scope:    JudicialHopScope,
			Expiry:   JudicialHopExpiry,
		})
		if err != nil {
			return nil, fmt.Errorf("multi-log authority resolver: log %q: %w", logDID, err)
		}
		byLog[logDID] = r
	}
	return &MultiLogAuthorityResolver{byLog: byLog}, nil
}

// Resolve routes by req.DelegationRef.LogDID to the per-log index resolver. An
// unknown log fails closed — never returns an error (the AuthorityChainResolver
// contract is a fail-closed verdict).
func (m *MultiLogAuthorityResolver) Resolve(
	ctx context.Context, req jurisdiction.AuthorityRequest,
) jurisdiction.AuthorityVerdict {
	r, ok := m.byLog[req.DelegationRef.LogDID]
	if !ok {
		return jurisdiction.AuthorityVerdict{
			OK:        false,
			SignerDID: req.SignerDID,
			Rejection: string(RejectMissingChainTip),
			Reason:    fmt.Sprintf("no on-log delegation index for log %q", req.DelegationRef.LogDID),
		}
	}
	return r.Resolve(ctx, req)
}

// Logs reports the exchange LogDIDs this resolver can verify (introspection).
func (m *MultiLogAuthorityResolver) Logs() int { return len(m.byLog) }

// Compile-time pin: the multi-log index dispatcher is the gate's
// AuthorityChainResolver (the seam BundleChainResolver filled).
var _ jurisdiction.AuthorityChainResolver = (*MultiLogAuthorityResolver)(nil)
