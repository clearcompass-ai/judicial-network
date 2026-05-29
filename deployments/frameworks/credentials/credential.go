/*
FILE PATH: deployments/frameworks/credentials/credential.go

DESCRIPTION:

	The Credential abstraction — the JN's reusable, jurisdiction-
	agnostic seam for binding "who is allowed to do what" rules to
	verifiable third-party-issued credentials.

	A Credential answers four questions:

	  1. What is it?           — ID + Category
	  2. Who issues it?        — Issuer
	  3. Where is it valid?    — Jurisdiction
	  4. Is a given value real? — Validator

	The framework deliberately does NOT bake in a fixed list of
	credential classes. Today's needs (attorney bar numbers) and
	tomorrow's needs (expert witness certifications, court
	interpreters, guardians ad litem, certified arbitrators)
	implement this same interface and are bound by court bundles
	identically. A new state, a new credential class, a new
	cooperating credential authority — all extend by adding a new
	implementation, never by modifying the framework.

	# Extensibility model

	State extension:
	  Add a file under credentials/attorney/<state>_<scheme>.go
	  returning a Credential. No framework change.

	New credential category:
	  Add a new Category constant. No framework change to the
	  Credential interface or to court bundles that don't use it.

	New validator backend:
	  ValidatorFunc is the seam. Today's implementations are pure
	  format checks; tomorrow's can call a registry API, an LDAP
	  directory, a verifiable-credential resolver, or a court-clerk
	  attestation index.

	# Where credentials bind to court behavior

	A composer.Spec lists RequiredCredentials []Credential. The
	composer threads each credential's ID into the cosignature
	policy rules that demand it, so a court like Davidson Circuit
	requires "tn_bpr_number" on attorney filings, while Riverside
	Superior requires "ca_bar_number" — same framework, different
	state credential.

	Future court types may list ConditionalCredentials keyed by
	event_type so an expert-witness filing demands the expert
	witness credential, not the attorney bar.
*/
package credentials

import (
	"context"
	"fmt"
)

// Category is the broad class a credential belongs to. Courts choose
// credentials by category when expressing rules ("attorney filing
// requires AttorneyBar", "expert testimony requires ExpertWitness").
type Category string

const (
	// CategoryAttorneyBar — a state or federal bar admission. TN BPR,
	// CA Bar, federal bar admissions all share this category.
	CategoryAttorneyBar Category = "attorney_bar"

	// CategoryExpertWitness — a domain-specific expert certification
	// (medical, forensic, financial). The credential's ID will encode
	// the specific domain (e.g. "ca_expert_medical").
	CategoryExpertWitness Category = "expert_witness"

	// CategoryCourtInterpreter — a state-certified court interpreter
	// authorized to translate testimony.
	CategoryCourtInterpreter Category = "court_interpreter"

	// CategoryNotary — a notary public credential.
	CategoryNotary Category = "notary"

	// CategoryGuardianAdLitem — a court-appointed guardian credential,
	// typically required for minor-party or incapacitated-party cases.
	CategoryGuardianAdLitem Category = "guardian_ad_litem"

	// CategoryProcessServer — a state-certified process server.
	CategoryProcessServer Category = "process_server"
)

// Jurisdiction scopes where a credential is recognized. A TN BPR
// number is valid in TN; a CA Bar number is valid in CA; a federal
// bar admission is valid before a specific court (one entry per
// admission). The framework uses Jurisdiction to refuse credentials
// from a non-recognizing state at composition time.
type Jurisdiction struct {
	// State is the two-letter postal code ("TN", "CA") or empty for
	// federal credentials.
	State string

	// Federal is true for federal credentials (federal bar
	// admissions, federal expert certifications) regardless of State.
	Federal bool

	// CourtScope, when non-empty, restricts the credential to a
	// specific court DID (e.g. a federal bar admission to a specific
	// district court). Empty = state-wide / federal-wide.
	CourtScope string
}

// Credential is the read-only contract every credential class
// implements. It is intentionally narrow: just enough for the
// composer to thread the credential's ID into cosignature rules and
// for verifiers to invoke the validator at admission time.
//
// The interface MUST stay stable. Adding behavior at the Credential
// level forces every implementation to grow; instead, extension
// happens by adding new Categories or new state-specific
// implementations.
type Credential interface {
	// ID is the canonical credential-class identifier. Used by the
	// composer to bind the credential to cosignature rules and by
	// verifiers to record which credential was presented. MUST be
	// stable across releases — changing an ID invalidates every
	// already-issued credential of this class.
	//
	// Convention: <jurisdiction>_<scheme>, e.g. "tn_bpr_number",
	// "ca_bar_number", "fed_bar_admission", "ca_expert_medical",
	// "tn_court_interpreter_spanish".
	ID() string

	// Category groups credentials by what they authorize. Court rules
	// quantify over categories ("any attorney filing needs SOME
	// AttorneyBar credential"); the bundle picks which concrete
	// AttorneyBar credential applies in its jurisdiction.
	Category() Category

	// Issuer is the authoritative human-readable name of the entity
	// that issues this credential class. Surfaced in audit trails and
	// error messages; not used for validation. Example: "Tennessee
	// Board of Professional Responsibility", "State Bar of California".
	Issuer() string

	// Jurisdiction is where the credential is recognized. Used by the
	// composer to refuse a credential whose Jurisdiction doesn't
	// match the court's; a Davidson Circuit court accepts TN-scoped
	// credentials, refuses CA-scoped ones at composition time.
	Jurisdiction() Jurisdiction

	// Validator returns the function that decides whether a presented
	// credential value (e.g. a BPR number) is valid for this
	// credential class. The ValidatorFunc is called at admission time
	// (in the JN gate), NOT at composition time.
	Validator() ValidatorFunc

	// Description is the human-readable explanation surfaced in
	// admission errors when a required credential is missing or
	// invalid. Example: "TN attorney license issued by the Board of
	// Professional Responsibility — verify at https://...".
	Description() string
}

// ValidatorFunc decides whether a presented credential value is
// authentic + currently active.
//
// Implementations should:
//
//   - Be fast (called on every authorized filing). Cache external
//     lookups aggressively.
//   - Distinguish "invalid format" / "unknown to issuer" / "issuer
//     unreachable" / "revoked". Return (false, nil) for the first
//     three (definitive negative); return (false, err) only when the
//     ANSWER is unknown.
//   - Be safe under partial outage. If the issuer registry is
//     temporarily unreachable, returning (false, err) lets the
//     caller fall back to a cached-only check; returning (true, nil)
//     by default would silently admit revoked credentials.
type ValidatorFunc func(ctx context.Context, value string) (bool, error)

// Match reports whether a credential satisfies all of: (a) the
// expected ID, OR (b) the expected category restricted to the given
// jurisdiction. Used by the composer to check that a bundle's
// declared RequiredCredentials match the court's jurisdiction.
func (j Jurisdiction) Accepts(other Jurisdiction) bool {
	if j.Federal && other.Federal {
		// Federal courts accept federal credentials. CourtScope
		// further narrows if set.
		if j.CourtScope != "" && j.CourtScope != other.CourtScope {
			return false
		}
		return true
	}
	if !j.Federal && !other.Federal {
		// State courts accept same-state credentials.
		return j.State == other.State
	}
	return false
}

// AcceptableError is returned by the composer when a credential's
// jurisdiction doesn't match the bundle's. Surfaces at boot, not at
// admission time, so a misconfigured bundle fails loud.
type AcceptableError struct {
	CredentialID string
	CredentialJ  Jurisdiction
	CourtJ       Jurisdiction
}

func (e *AcceptableError) Error() string {
	return fmt.Sprintf(
		"credential %s (%+v) does not match court jurisdiction (%+v)",
		e.CredentialID, e.CredentialJ, e.CourtJ,
	)
}

// CheckAcceptable returns nil iff cred is acceptable under court.
// Composer calls this when threading credentials into a Bundle.
func CheckAcceptable(cred Credential, court Jurisdiction) error {
	if !court.Accepts(cred.Jurisdiction()) {
		return &AcceptableError{
			CredentialID: cred.ID(),
			CredentialJ:  cred.Jurisdiction(),
			CourtJ:       court,
		}
	}
	return nil
}
