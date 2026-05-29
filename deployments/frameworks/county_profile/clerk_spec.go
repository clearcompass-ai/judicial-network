/*
FILE PATH: deployments/frameworks/county_profile/clerk_spec.go

DESCRIPTION:

	ClerkSpec — the declarative recipe for a clerk-office Bundle.
	Parallel to composer.Spec (which is for courts); the composer
	builds both into jurisdiction.Bundle values that satisfy the SDK
	interface.

	A clerk office structurally is a Bundle: it has a role catalog
	(the 6-level pyramid), a cosignature policy (clerk-event rules
	like marriage_license_issued + filing_clerk cosign), and an
	authority chain resolver. It has an empty appellate vocabulary
	(clerk offices don't emit appellate events).

	Why ClerkSpec is separate from composer.Spec instead of a
	"kind" field on Spec: clerk-office policy is fundamentally
	different from court policy. Forcing them into one type would
	mean every Build branch checks "is this a clerk?" — that pattern
	rots quickly. Two types, two Build paths, clean dispatch.
*/
package county_profile

import (
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
)

// ClerkSpec is the declarative description of a single clerk office.
// Produced by expandClerks during Expand(); consumed by the composer
// to build a jurisdiction.Bundle.
type ClerkSpec struct {
	// DID is the canonical institutional identifier. Unique across
	// the registry.
	DID string

	// Name is human-readable. Example: "Knox County Clerk",
	// "Davidson Circuit Court Clerk".
	Name string

	// Type identifies the clerk-office classification.
	Type ClerkType

	// Selection is how the clerk takes office.
	Selection Selection

	// Jurisdiction scopes the clerk politically.
	Jurisdiction composer.Jurisdiction

	// ServesAlso lists other clerk types this office covers when
	// the state convention consolidates roles for this county.
	ServesAlso []ClerkType

	// Branches are the physical satellite offices this clerk runs.
	// Each branch is named in audit trails; per-branch DIDs are
	// derived by appending the branch ID to the clerk's DID.
	Branches []Branch

	// RequiredCredentials are credentials the clerk's signing
	// actors must hold. Typically the state's attorney credential
	// + (eventually) a clerk-certification credential.
	RequiredCredentials []credentials.Credential
}
