/*
FILE PATH: schemas/attestation_policy_apply.go

DESCRIPTION:

	SetAttestationPolicy — small builder-side helper that threads the
	caller's chosen policy name onto an unsigned entry's
	ControlHeader.AttestationPolicyName.

	# WHY a helper, not direct mutation

	The SDK's builder Params structs (RootEntityParams,
	EnforcementParams, DelegationParams, PathBParams, etc.) do NOT
	expose AttestationPolicyName as a field. JN domain code must set
	it AFTER the SDK builder returns, before the caller signs. This
	helper centralises the nil/empty checks and the pointer
	allocation so each domain builder reads as a single line of
	intent instead of three lines of plumbing.

	# WHY in schemas/

	The policy name constants (PolicyDelegationBoardConcurrence,
	PolicySealingOrderConcurrence, ...) live in
	schemas/attestation_policies.go. Co-locating the apply helper
	with the declarations keeps producer-side coupling in one
	package — callers only import schemas to use either.

KEY DEPENDENCIES:
  - attesta/core/envelope: Entry.Header.AttestationPolicyName *string
*/
package schemas

import "github.com/clearcompass-ai/attesta/core/envelope"

// SetAttestationPolicy applies policyName to entry.Header.AttestationPolicyName
// when policyName is non-nil and non-empty. Returns silently otherwise so
// existing callers that don't adopt a policy stay byte-stable.
//
// Mutating an unsigned entry's header is safe: SDK SigningPayload is
// regenerated at signing time and will cover the new field. Calling this
// AFTER an entry has been signed invalidates the signature; callers MUST
// call this between builder.Build* and the sign step.
//
// IDEMPOTENT. Calling twice with the same policyName is a no-op.
func SetAttestationPolicy(entry *envelope.Entry, policyName *string) {
	if entry == nil || policyName == nil || *policyName == "" {
		return
	}
	name := *policyName
	entry.Header.AttestationPolicyName = &name
}
