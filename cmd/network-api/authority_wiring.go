/*
FILE PATH: cmd/network-api/authority_wiring.go

PRE-13a/13b #181: build the process-wide verifying AuthorityChainResolver the
submit gate + verify handler use to check each cosigner's claimed role
against its on-log delegation chain (default-ON, G19). A self-asserted
judge — claims "judge" with no backing chain — is dropped at the gate and
never counts toward quorum.

PRE-13a: the walk is now the canonical SDK+Tooling delegation resolver
(tooling/libs/authority.SMTChainResolver via verification.SMTAuthorityResolver),
not the JN-local AuthorityResolver. Liveness is the SDK's delegation-liveness
test (leaf OriginTip == position), which — unlike the retired EvaluateOrigin
path — catches a self-targeting delegation revocation. Role verification is
WALK-ONLY, so the per-jurisdiction RoleCatalog is not consulted here; the
ledger Fetcher + LeafReader are the only inputs that matter.
*/
package main

import (
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// buildAuthorityResolver returns the verifying resolver injected into the
// submit gate (NewBundleSubmitGate) and the verify handler
// (verification.ServerConfig.Authority). Returns nil when the ledger
// inputs are absent (ledger-less dev/test): the gates then fail-close any
// multi-sig entry rather than admit it on an unverifiable claim.
func buildAuthorityResolver(fetcher types.EntryFetcher, leaf smt.LeafReader) jurisdiction.AuthorityChainResolver {
	if fetcher == nil || leaf == nil {
		return nil
	}
	return verification.NewSMTAuthorityResolver(fetcher, leaf)
}
