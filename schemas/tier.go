/*
FILE PATH: schemas/tier.go

DESCRIPTION:
    Tier classification per the v1.3 Event Dictionary, Part 1.

    The judicial network distinguishes three tiers based on
    cryptographic relationship to the log:

      Tier 1 — Cryptographic Signers (key holders).
               Adjudicators, Clerks (& Deputy Clerks), Court Reporters.
               These actors HOLD network keys; their roles populate
               schemas.RoleCatalog and AuthorityResolver chains.

      Tier 2 — Advocates & Proxies (active metadata subjects).
               Prosecutors, Defense Counsel, Civil Attorneys,
               Fiduciaries, Guardians ad litem. They DO NOT hold
               network keys; they are recorded as filed_by /
               attorney_reference fields and require a Tier 1
               cosignature on every event. Tracked by
               directory.AttorneyRegistry.

      Tier 3 — Primary Parties (passive metadata subjects).
               Plaintiffs, Defendants, Pro Se Litigants. Recorded
               only via party_binding payloads bound to case roots.
               No directory; the parties are case-scoped.

    This file defines the closed-set tier value and the validation
    helper used by Role and AttorneyRegistry. Membership-by-tier
    answers questions like "may this role cosign an attorney's
    filing?" — the catalog stores tier; downstream code (Phase 3C)
    will read it to enforce the cosignature mix.

KEY DEPENDENCIES:
    None — this file is the leaf of the tier-classification surface.
*/
package schemas

import "fmt"

// Tier enumerates the closed-set classification per the v1.3
// Event Dictionary. Tier values are stable and ordered; new tiers
// (if ever needed) appended at the end.
type Tier int

const (
	// TierUnspecified is the zero value. Validate rejects it; it
	// exists only so omitting Tier in code produces a loud error
	// rather than silently classifying as Tier 1.
	TierUnspecified Tier = 0

	// Tier1Signer holds network cryptographic keys.
	// Adjudicators, Clerks, Court Reporters.
	Tier1Signer Tier = 1

	// Tier2Advocate is a legal professional who drives litigation
	// but holds no key. Prosecutors, Defense Counsel, Civil
	// Attorneys, Fiduciaries, Guardians ad litem.
	Tier2Advocate Tier = 2

	// Tier3Party is a passive metadata subject. Plaintiffs,
	// Defendants, Pro Se Litigants.
	Tier3Party Tier = 3
)

// String returns a human-readable name for the tier. Used in audit
// logs and error messages.
func (t Tier) String() string {
	switch t {
	case TierUnspecified:
		return "tier_unspecified"
	case Tier1Signer:
		return "tier_1_signer"
	case Tier2Advocate:
		return "tier_2_advocate"
	case Tier3Party:
		return "tier_3_party"
	default:
		return fmt.Sprintf("tier_unknown_%d", int(t))
	}
}

// IsValid reports whether t is one of the three defined tiers.
// TierUnspecified is NOT valid — calling code must opt into a tier.
func (t Tier) IsValid() bool {
	switch t {
	case Tier1Signer, Tier2Advocate, Tier3Party:
		return true
	default:
		return false
	}
}

// HoldsKeys reports whether actors at this tier hold network
// cryptographic keys. Only Tier 1 does. Tier 2 and Tier 3 are
// metadata subjects.
//
// Used by the Phase 3C cosignature-mix evaluator: when a Tier 2
// actor files an event, the verifier asks the role catalog "is
// this cosigner's role a HoldsKeys=true tier?" before accepting
// the cosignature as authoritative.
func (t Tier) HoldsKeys() bool {
	return t == Tier1Signer
}

// validateTier returns nil iff t is a defined tier. Used by Role's
// validateRole and AttorneyRegistry's Register.
func validateTier(t Tier) error {
	if !t.IsValid() {
		return fmt.Errorf("schemas/tier: tier must be one of {1, 2, 3}, got %d (%s)",
			int(t), t.String())
	}
	return nil
}
