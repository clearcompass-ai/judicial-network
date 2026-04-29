/*
FILE PATH: verification/attestation_check.go

DESCRIPTION:
    Read-side verifier for tn-key-attestation-v1 entries — the
    judicial domain's evaluation of "what was the institution-witnessed
    key custody mode for entity X at position P?". Implements the
    pattern documented in ortholog-sdk/docs/attestation-entries.md
    "Verifier surface".

ALGORITHM (per attestation-entries.md):
    1. Query all attestations whose AttestedEntity == entityDID
       (caller-provided AttestationFinder).
    2. Filter to attestations whose admission position ≤ atPosition
       (Decision 52 / ADR-004 time-indexed semantics — authorizations
       valid at action's signing time).
    3. Pick the latest by admission position.
    4. Verify the attesting exchange (entry's SignerDID) is in the
       domain's trusted-exchange list AT THAT SAME POSITION
       (caller-provided TrustedExchangeChecker — same time-indexed
       primitive applied to a different scope).
    5. Validate the deserialized payload (closed-set enum,
       required fields).
    6. Return the resolved attestation as the authoritative
       generation-mode claim.

KEY ARCHITECTURAL DECISIONS:
    - The verifier does NOT make a verdict about WHAT the generation
      mode means legally — that's domain-application policy.
    - "No attestation found" is a distinct outcome from "attestation
      from untrusted exchange" — domains may treat them differently.
    - Time-indexed exchange trust: the exchange that signed an
      attestation may have been trusted at the time but later
      removed. Per ADR-004, authorizations valid at the action's
      signing time remain valid retrospectively. The trust check
      runs at the attestation's admission position, not at the
      verifier's wall-clock.
    - Same package as scope_enforcement.go and delegation_chain.go;
      composes with them via the Verification API surface.
*/
package verification

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// Errors are stable sentinels — audit pipelines key on these.
var (
	// ErrNoAttestation fires when the finder returns zero
	// attestations for the entity. Domains that REQUIRE attestation
	// (e.g., tn-evidence-artifact-v1 issuance) treat this as a hard
	// reject; domains that don't require it ignore.
	ErrNoAttestation = errors.New("attestation_check: no attestation for entity")

	// ErrAttestationStale fires when every attestation found is
	// after the queried position — i.e., the entity had no
	// institution-witnessed key custody claim at that time.
	ErrAttestationStale = errors.New("attestation_check: no attestation at or before requested position")

	// ErrAttestationFromUntrustedExchange fires when the latest
	// attestation's signer is NOT in the trusted-exchange list at
	// that position. This is the load-bearing trust anchor — an
	// attestation by an untrusted exchange has no force.
	ErrAttestationFromUntrustedExchange = errors.New("attestation_check: attestation signed by untrusted exchange at position")

	// ErrAttestationMalformed fires when the payload deserializes
	// or validates as malformed. Wraps the underlying schema-level
	// sentinel (ErrAttestationMissingEntity, etc.).
	ErrAttestationMalformed = errors.New("attestation_check: attestation payload malformed")
)

// AttestationFinder is the caller-injected query surface. Production
// implementations wrap an OperatorQueryAPI to return entries whose
// SchemaRef points at tn-key-attestation-v1 AND whose payload's
// AttestedEntity matches the queried DID. Tests inject a stub.
type AttestationFinder interface {
	// FindAttestations returns every key-attestation entry whose
	// payload's AttestedEntity equals entityDID. Order is not
	// guaranteed; the verifier sorts by admission position. Empty
	// slice + nil error is "no attestations".
	FindAttestations(entityDID string) ([]*types.EntryWithMetadata, error)
}

// TrustedExchangeChecker reports whether exchangeDID was a trusted
// attesting exchange at the named log position. Production
// implementations resolve via core/scope.AuthorizedSetAtPosition
// against the domain's "trusted attesting exchanges" scope. Tests
// inject a stub. Returning nil means trusted; any non-nil error
// surfaces verbatim (including infrastructure failure).
type TrustedExchangeChecker interface {
	IsTrustedAt(exchangeDID string, pos types.LogPosition) (bool, error)
}

// AttestationVerification carries the outcome of VerifyKeyAttestation.
// Callers act on Outcome plus the (optional) Payload.
type AttestationVerification struct {
	// Found is the resolved attestation entry. Nil iff Outcome is
	// not OK.
	Entry *types.EntryWithMetadata

	// Payload is the deserialized + validated payload. Nil iff
	// Outcome is not OK.
	Payload *schemas.KeyAttestationPayload

	// Outcome enumerates the verifier's verdict.
	Outcome AttestationOutcome
}

// AttestationOutcome enumerates the verifier's possible verdicts.
type AttestationOutcome int

const (
	// AttestationOK: attestation found, signed by a trusted
	// exchange at its admission position, payload valid. Domain
	// rules apply on Payload.GenerationMode.
	AttestationOK AttestationOutcome = iota + 1

	// AttestationNotFound: no attestation exists for this entity at
	// all (FindAttestations returned empty).
	AttestationNotFound

	// AttestationStale: every attestation found is after the
	// queried position.
	AttestationStale

	// AttestationUntrustedExchange: the latest attestation is
	// signed by an exchange that was not trusted at that position.
	AttestationUntrustedExchange

	// AttestationMalformed: payload failed deserialize or validate.
	AttestationMalformed
)

// VerifyKeyAttestation runs the attestation-entries.md verifier
// flow: find → filter ≤ position → pick latest → trust-check at
// that position → validate payload. Returns the verdict plus a
// typed sentinel error for the non-OK cases. The error is for
// errors.Is matching; the verdict carries the Outcome enum that
// audit logs key on.
//
// trustedExchanges may be nil; in that case the verifier accepts
// every signer (suitable for tests / single-tenant deployments
// where every attesting exchange is trusted by construction).
// Production deployments inject a real checker.
func VerifyKeyAttestation(
	entityDID string,
	atPosition types.LogPosition,
	finder AttestationFinder,
	trustedExchanges TrustedExchangeChecker,
) (*AttestationVerification, error) {
	if finder == nil {
		return nil, errors.New("attestation_check: nil finder")
	}
	if entityDID == "" {
		return nil, errors.New("attestation_check: empty entityDID")
	}

	all, err := finder.FindAttestations(entityDID)
	if err != nil {
		return nil, fmt.Errorf("attestation_check: find: %w", err)
	}
	if len(all) == 0 {
		return &AttestationVerification{Outcome: AttestationNotFound}, ErrNoAttestation
	}

	// Filter to attestations at or before atPosition, picking the
	// latest by sequence on the same log. Cross-log attestations
	// are rare in practice; we compare by sequence within the
	// caller-supplied log when LogDIDs match, otherwise by
	// AttestationTime as a tie-break.
	var latest *types.EntryWithMetadata
	for _, entry := range all {
		if entry == nil {
			continue
		}
		// Position filter: skip entries past the query position.
		if !atPosition.IsNull() &&
			entry.Position.LogDID == atPosition.LogDID &&
			entry.Position.Sequence > atPosition.Sequence {
			continue
		}
		if latest == nil {
			latest = entry
			continue
		}
		// Pick the later admission — same-log compares Sequence;
		// cross-log compares LogTime.
		if entry.Position.LogDID == latest.Position.LogDID {
			if entry.Position.Sequence > latest.Position.Sequence {
				latest = entry
			}
		} else if entry.LogTime.After(latest.LogTime) {
			latest = entry
		}
	}
	if latest == nil {
		return &AttestationVerification{Outcome: AttestationStale}, ErrAttestationStale
	}

	// Deserialize entry → payload.
	parsed, err := envelope.Deserialize(latest.CanonicalBytes)
	if err != nil {
		return &AttestationVerification{Entry: latest, Outcome: AttestationMalformed},
			fmt.Errorf("%w: deserialize: %v", ErrAttestationMalformed, err)
	}
	payload, err := schemas.DeserializeKeyAttestation(parsed.DomainPayload)
	if err != nil {
		return &AttestationVerification{Entry: latest, Outcome: AttestationMalformed},
			fmt.Errorf("%w: payload: %v", ErrAttestationMalformed, err)
	}
	// Cross-check: payload's claimed entity must match the query.
	if payload.AttestedEntity != entityDID {
		return &AttestationVerification{Entry: latest, Outcome: AttestationMalformed},
			fmt.Errorf("%w: payload entity %q != query %q",
				ErrAttestationMalformed, payload.AttestedEntity, entityDID)
	}

	// Trust check at the attestation's own admission position.
	if trustedExchanges != nil {
		ok, err := trustedExchanges.IsTrustedAt(parsed.Header.SignerDID, latest.Position)
		if err != nil {
			return nil, fmt.Errorf("attestation_check: trust check: %w", err)
		}
		if !ok {
			return &AttestationVerification{
					Entry:   latest,
					Payload: payload,
					Outcome: AttestationUntrustedExchange,
				},
				fmt.Errorf("%w: signer=%q pos=%s",
					ErrAttestationFromUntrustedExchange,
					parsed.Header.SignerDID, latest.Position.String())
		}
	}

	return &AttestationVerification{
		Entry:   latest,
		Payload: payload,
		Outcome: AttestationOK,
	}, nil
}
