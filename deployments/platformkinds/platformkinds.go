/*
Package platformkinds — the cosignature mixes and prerequisite vocabulary
for the SDK's rc10 PLATFORM registry kinds, shared by every TN deployment.

# PLATFORM KINDS, DOMAIN-INJECTED POLICY (the PRE-4a re-home ruling)

The kind, wire codec, and lifecycle walk live in the SDK (v0.0.5-rc1:
exchange genesis, destination provision/amend/retire). WHO may perform
them — the cosignature mix, the filer rules — is domain policy, and this
package is where the TN networks inject it. The gate keys these rules by
the KIND DISCRIMINATOR itself (verification.CheckCosignature falls back
to `kind` when a payload carries no `event_type`), so platform kinds are
first-class vocabulary in the same closed-set policy table as judicial
events — one table, one lookup, one rejection taxonomy.

# THE MIXES (TN content; other networks inject their own)

Exchange genesis, destination provision, and amend are operator acts
cosigned by a court_clerk intra-exchange. Destination RETIRE is the
sensitive one — it ends a court's on-log life — and requires TWO clerk
cosigners (the same escalation the personnel-appointment precedent uses).
All four are signer-only (no filer capacity; a destination is not a
filing).

# PREREQUISITES

Advisory-only edges (provision should follow its exchange genesis;
amend/retire should follow a provision). The gate's submit-time walker
runs with an empty subtree context, where Hard ancestor rules reject
unconditionally (closed-by-default) — destination lifecycle ordering is
already enforced REPLAY-side by the SDK walker's never-folded taxonomy
(duplicate-provision, amend-after-retire, …) and the aggregator's
projection, so the gate edge is advisory by design, not laxity.
*/
package platformkinds

import (
	"github.com/baseproof/baseproof/kinds"
	"github.com/baseproof/tooling/libs/auth/policy"
	prerequisites "github.com/baseproof/tooling/libs/prereq"
)

// CosignatureRulesWithRoles returns the policy rows for the rc10 platform
// kinds with the deployment's OWN signer-role vocabulary injected — the
// mechanism is one home; the roles are the domain's content (a court
// injects court_clerk; a clerk exchange injects its executive tier).
// Retire always escalates to two cosigners.
func CosignatureRulesWithRoles(signerRoles []string) []policy.CosignatureRule {
	return []policy.CosignatureRule{
		{
			EventType:           kinds.EntryExchangeGenesisV1,
			RequiredSignerRoles: signerRoles,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           kinds.EntryDestinationProvisionV1,
			RequiredSignerRoles: signerRoles,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           kinds.EntryDestinationAmendV1,
			RequiredSignerRoles: signerRoles,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			// Retire ends a destination's on-log life: two cosigners, not one.
			EventType:           kinds.EntryDestinationRetireV1,
			RequiredSignerRoles: signerRoles,
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},
	}
}

// CosignatureRules is the court-bundle default: court_clerk signers.
func CosignatureRules() []policy.CosignatureRule {
	return CosignatureRulesWithRoles([]string{"court_clerk"})
}

// PrerequisiteRules returns the advisory lifecycle edges for the rc10
// platform kinds. Merged into every TN deployment's PrerequisiteRules()
// map (the bundle validator requires every cosignature event_type to be
// in the prerequisite vocabulary).
func PrerequisiteRules() map[string][]prerequisites.Prereq {
	return map[string][]prerequisites.Prereq{
		kinds.EntryExchangeGenesisV1: {},
		kinds.EntryDestinationProvisionV1: {{
			Mode:             prerequisites.PrereqModeAdvisory,
			RequiredAncestor: []string{kinds.EntryExchangeGenesisV1},
			Reason:           "a destination should be provisioned under an on-log exchange genesis",
		}},
		kinds.EntryDestinationAmendV1: {{
			Mode:             prerequisites.PrereqModeAdvisory,
			RequiredAncestor: []string{kinds.EntryDestinationProvisionV1},
			Reason:           "an amend should follow its provision (the SDK replay walker enforces the hard ordering)",
		}},
		kinds.EntryDestinationRetireV1: {{
			Mode:             prerequisites.PrereqModeAdvisory,
			RequiredAncestor: []string{kinds.EntryDestinationProvisionV1},
			Reason:           "a retire should follow its provision (the SDK replay walker enforces the hard ordering)",
		}},
	}
}
