/*
FILE PATH: schemas/actor.go

DESCRIPTION:

	Actor classification — the MECHANISM (the three-class enum, its stable
	wire ints + strings, and the key-holding distinction) lives in the
	platform's libs/policy; THIS file re-binds it into the judicial schema
	vocabulary so domain code keeps reading schemas.ActorSigner etc., and
	documents the judicial CONTENT of each class:

	  Actor 1 — Signer.  Adjudicators, Clerks, Court Reporters. HOLD
	            network keys; their roles populate schemas.RoleCatalog and
	            AuthorityResolver chains.
	  Actor 2 — Filer.   Prosecutors, Defense Counsel, Civil Attorneys,
	            Fiduciaries, Guardians ad litem. Own DIDs for cosignature
	            attestation; no catalog entry — the on-log
	            filed_by_capacity claim IS the truth.
	  Actor 3 — Party.   Plaintiffs, Defendants, Pro Se Litigants.
	            Passive metadata subjects via party_binding payloads.

KEY DEPENDENCIES:
  - libs/policy (the enum + String/IsValid/HoldsKeys + ValidateActor).
*/
package schemas

import libpolicy "github.com/baseproof/tooling/libs/policy"

// Actor is the platform classification enum (libs/policy). Stable wire
// values; methods (String, IsValid, HoldsKeys) ride the platform type.
type Actor = libpolicy.Actor

// The three classes, re-bound for the judicial vocabulary.
const (
	ActorUnspecified = libpolicy.ActorUnspecified
	ActorSigner      = libpolicy.ActorSigner
	ActorFiler       = libpolicy.ActorFiler
	ActorParty       = libpolicy.ActorParty
)

// validateActor returns nil iff a is a defined class. Kept as the
// schemas-local door (role_catalog validation calls it) over the platform
// rule.
func validateActor(a Actor) error {
	return libpolicy.ValidateActor(a)
}
