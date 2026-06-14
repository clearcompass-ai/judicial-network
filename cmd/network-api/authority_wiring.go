/*
FILE PATH: cmd/network-api/authority_wiring.go

PRE-13b #181: build the process-wide verifying AuthorityChainResolver the
submit gate + verify handler use to check each cosigner's claimed role
against its on-log delegation chain (default-ON, G19). A self-asserted
judge — claims "judge" with no backing chain — is dropped at the gate and
never counts toward quorum.

Role verification is WALK-ONLY, so ONE resolver serves every jurisdiction:
the per-jurisdiction RoleCatalog is never consulted; the ledger Fetcher +
LeafReader are the only inputs that matter. The catalog handed to
NewBundleChainResolver is therefore representative (per-jurisdiction
catalog scoping applies only to a future action-authorization caller).
*/
package main

import (
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"

	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
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
	return verification.NewBundleChainResolver(trial.MustRoleCatalog(), fetcher, leaf)
}
