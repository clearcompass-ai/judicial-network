/*
FILE PATH: cmd/network-api/authority_wiring.go

PRE-13b #181: wire the verifying AuthorityChainResolver into the
production Bundle seam so the cosignature gate VERIFIES each cosigner's
claimed role against its on-log delegation chain (default-ON, G19). A
self-asserted judge — claims "judge" with no backing chain — is dropped
at the gate and never counts toward quorum.

Wired AFTER buildJudicialDeps (deps.Fetcher / deps.LeafReader exist) and
before the server serves. SetAuthorityChainResolver sets package-level
vars read per-request, so the already-frozen Bundle registry is
unaffected. All registered bundles route through exactly three resolver
vars — the Davidson + COA umbrellas and the composer (every
registry-loaded court + clerk is composer.Build / BuildClerk) — so three
calls cover the fleet.
*/
package main

import (
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"

	composer "github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
	tncoa "github.com/clearcompass-ai/judicial-network/deployments/tn/coa"
	tndavidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// wireAuthorityResolvers injects one shared verifying resolver into the
// production Bundle seam. One resolver suffices: ChainRoleResolver does a
// WALK-ONLY chain walk for role verification, which never consults the
// per-jurisdiction RoleCatalog — (fetcher, leafReader) are the only
// inputs that matter. The catalog handed to NewBundleChainResolver is
// therefore representative; per-jurisdiction catalog scoping applies only
// to a future action-authorization caller, not to role verification.
//
// When the ledger inputs are absent (ledger-less dev/test), the seam
// stays closed (NoAuthorityChainResolver): the gate then fail-closes any
// multi-sig entry rather than admit it on an unverifiable claim.
func wireAuthorityResolvers(fetcher types.EntryFetcher, leaf smt.LeafReader) {
	if fetcher == nil || leaf == nil {
		return
	}
	authority := verification.NewBundleChainResolver(trial.MustRoleCatalog(), fetcher, leaf)
	tndavidson.SetAuthorityChainResolver(authority)
	tncoa.SetAuthorityChainResolver(authority)
	composer.SetAuthorityChainResolver(authority)
}
