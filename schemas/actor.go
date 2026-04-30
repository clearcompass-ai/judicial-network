/*
FILE PATH: schemas/actor.go

DESCRIPTION:
    Actor classification per the v1.4 Event Dictionary, Part 1.
    Replaces the Phase 3A "Tier" naming with the actor-functional
    labels Signer / Filer / Party. The dictionary still uses the
    words "Tier 1 / Tier 2 / Tier 3"; this code uses functional
    labels because that's what each class DOES on the network.

    Three classes based on cryptographic relationship to the log:

      Actor 1 — Signer (the dictionary's Tier 1).
                Adjudicators, Clerks, Court Reporters. HOLD network
                keys; their roles populate schemas.RoleCatalog and
                AuthorityResolver chains.

      Actor 2 — Filer (the dictionary's Tier 2).
                Prosecutors, Defense Counsel, Civil Attorneys,
                Fiduciaries, Guardians ad litem. They hold their
                own DIDs (Privy wallets) for cosignature attestation
                but have NO entry in the role catalog. Every filing
                they cosign carries a `filed_by_capacity` block in
                the payload (Phase 3C) declaring their role and
                credentials. No off-log registry — the on-log claim
                IS the truth.

      Actor 3 — Party (the dictionary's Tier 3).
                Plaintiffs, Defendants, Pro Se Litigants. Recorded
                only via party_binding payloads bound to case roots.
                Passive metadata subjects.

    Membership-by-actor answers questions like "may this role
    cosign a filer's submission?" — the catalog stores the actor
    class; downstream code (Phase 3C) reads it to enforce the
    cosignature mix.

KEY DEPENDENCIES:
    None — this file is the leaf of the actor-classification surface.
*/
package schemas

import "fmt"

// Actor enumerates the closed-set classification per the v1.4
// Event Dictionary. Integer values are STABLE — the JSON catalog
// loader and the on-log payloads serialize the int. Adding a new
// class appends at the end; never renumber.
type Actor int

const (
	// ActorUnspecified is the zero value. Validate rejects it; it
	// exists only so omitting Actor in code produces a loud error
	// rather than silently classifying as a Signer.
	ActorUnspecified Actor = 0

	// ActorSigner holds network cryptographic keys.
	// Adjudicators, Clerks, Court Reporters.
	ActorSigner Actor = 1

	// ActorFiler is a legal professional who drives litigation.
	// Holds their own DID for cosignature, but has no on-log
	// delegation chain. Prosecutors, Defense Counsel, Civil
	// Attorneys, Fiduciaries, Guardians ad litem.
	ActorFiler Actor = 2

	// ActorParty is a passive metadata subject. Plaintiffs,
	// Defendants, Pro Se Litigants.
	ActorParty Actor = 3
)

// String returns a human-readable name. Used in audit logs and
// error messages. Stable strings — log parsers key on these.
func (a Actor) String() string {
	switch a {
	case ActorUnspecified:
		return "actor_unspecified"
	case ActorSigner:
		return "actor_signer"
	case ActorFiler:
		return "actor_filer"
	case ActorParty:
		return "actor_party"
	default:
		return fmt.Sprintf("actor_unknown_%d", int(a))
	}
}

// IsValid reports whether a is one of the three defined classes.
// ActorUnspecified is NOT valid — calling code must opt in.
func (a Actor) IsValid() bool {
	switch a {
	case ActorSigner, ActorFiler, ActorParty:
		return true
	default:
		return false
	}
}

// HoldsKeys reports whether actors of this class hold network
// cryptographic keys with on-log delegation-chain authority.
// Only ActorSigner does.
//
// ActorFiler holds an OWN DID (e.g., a Privy wallet) sufficient
// to produce a cosignature, but not a "network key" in the
// dictionary's sense — there is no role-catalog entry, no
// AuthorityResolver chain, no scope. The Phase 3C cosignature-mix
// evaluator uses this distinction.
func (a Actor) HoldsKeys() bool {
	return a == ActorSigner
}

// validateActor returns nil iff a is a defined class. Used by
// Role's validateRole.
func validateActor(a Actor) error {
	if !a.IsValid() {
		return fmt.Errorf("schemas/actor: actor must be one of {1, 2, 3}, got %d (%s)",
			int(a), a.String())
	}
	return nil
}
