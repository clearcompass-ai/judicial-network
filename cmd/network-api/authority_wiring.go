/*
FILE PATH: cmd/network-api/authority_wiring.go

PRE-13b #181: build the process-wide verifying AuthorityChainResolver the
submit gate + verify handler use to check each cosigner's claimed role
against its on-log delegation chain (default-ON, G19). A self-asserted
judge — claims "judge" with no backing chain — is dropped at the gate and
never counts toward quorum.

Step 5 (engine swap): the resolver is the INDEX-WALK engine
(verification.MultiLogAuthorityResolver over the per-exchange delegate_did
queriers), NOT the position-fetch BundleChainResolver. Revocation is
newest-grant-wins from the index projection (#120), so the SMT LeafReader is no
longer an input here — the parity lock test (authority_parity_test.go) proves
the index verdict equals AuthorityResolver's across role / scope / revocation /
succession / expiry. Role verification is walk-only, so no per-jurisdiction
RoleCatalog is consulted; routing is by the request's DelegationRef.LogDID.
*/
package main

import (
	"github.com/baseproof/baseproof/types"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// buildAuthorityResolver returns the verifying resolver injected into the
// submit gate (NewBundleSubmitGate) and the verify handler
// (verification.ServerConfig.Authority). Returns nil when the ledger inputs
// are absent (ledger-less dev/test: no fetcher or no exchange queriers): the
// gates then fail-close any multi-sig entry rather than admit it on an
// unverifiable claim.
func buildAuthorityResolver(
	queriers map[string]verification.DelegateDIDQuerier,
	fetcher types.EntryFetcher,
) jurisdiction.AuthorityChainResolver {
	if fetcher == nil || len(queriers) == 0 {
		return nil
	}
	r, err := verification.NewMultiLogAuthorityResolver(queriers, fetcher)
	if err != nil {
		return nil
	}
	return r
}
