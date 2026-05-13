/*
FILE PATH: verification/attestation_binding.go

DESCRIPTION:

	JN adapter for attesta v1.2.0's attestation.IsAttestation —
	the canonical predicate that confirms an entry is bound to a
	specific primary position via Header.CosignatureOf.

	The SDK predicate is a pure bool (true iff entry's
	CosignatureOf is non-nil and equals expectedPos). This file
	adds:

	  - CheckAttestationBinding: error-returning sibling that
	    explains WHY a binding check failed (nil CosignatureOf,
	    position mismatch, log_did mismatch) so JN verification
	    handlers can return granular HTTP error reasons instead of
	    a binary true/false.

	  - FilterAttestationsOf: filters a candidate slice down to
	    only the entries actually pointing at expectedPos. Useful
	    when JN's log.QueryByCosignatureOf returns a broader set
	    than the verifier asked about (e.g., bug-bounded responses
	    or stale-index responses) and the verifier needs to
	    fail-closed.

	# WHY A THIN WRAPPER

	attestation.IsAttestation is a one-line check. Wrapping it
	here lets every JN call site reach for the same disambiguation
	helpers without each handler reinventing them, and gives one
	place to attach OpenTelemetry spans / metrics in a later pass.

	# SCOPE — DISTINCT FROM verification/cosignature_check.go

	cosignature_check.go enforces JN's INTRA-ENTRY signature-mix
	rule (one entry, N inline signatures, role/exchange/threshold).
	This file checks the SDK's SEPARATE-ENTRY attestation binding
	(an attestation entry's Header.CosignatureOf points at a
	primary entry's LogPosition).

	The two mechanics coexist. A multi-judge concurring order is a
	primary entry (signed by the presiding judge) plus N separate
	attestation entries (each signed by a concurring judge, each
	carrying CosignatureOf -> primary_position). The primary's
	signature-mix is governed by cosignature_check.go; the
	attestation entries' binding is governed by this file.

TRUST ALIGNMENT:

	SDK Principle 11 (Cryptographic Domain Separation): the
	binding pointer is part of the entry's signed canonical bytes,
	so a hostile peer cannot fabricate a CosignatureOf without
	invalidating the signature. This file is the read-side
	confirmation step.

KEY DEPENDENCIES:
  - attesta/attestation: IsAttestation, Ref
  - attesta/core/envelope: Entry
  - attesta/types: LogPosition
*/
package verification

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
)

// ErrAttestationBinding wraps every binding-check failure mode
// this file surfaces. The underlying typed sentinels —
// ErrAttestationNilEntry, ErrAttestationMissingCosignatureOf,
// ErrAttestationLogDIDMismatch, ErrAttestationSequenceMismatch —
// remain reachable via errors.Is on the returned error.
var ErrAttestationBinding = errors.New("verification/attestation_binding")

// Typed sentinels — callers errors.Is against these to route
// granular rejection paths (e.g., HTTP 400 vs 422 vs 409).
var (
	// ErrAttestationNilEntry fires when the candidate entry is nil.
	// Always a programming error, never a wire condition.
	ErrAttestationNilEntry = errors.New("nil entry")

	// ErrAttestationMissingCosignatureOf fires when the candidate
	// entry has no Header.CosignatureOf. Means the entry is NOT
	// an attestation; the caller is treating a normal entry as one.
	ErrAttestationMissingCosignatureOf = errors.New("entry has no Header.CosignatureOf — not an attestation entry")

	// ErrAttestationLogDIDMismatch fires when the candidate's
	// CosignatureOf points at a log other than the expected one.
	// Cross-log attestation MUST be explicit; an attestation
	// targeting a different log silently passing a same-Sequence
	// check would let a hostile peer redirect attestations.
	ErrAttestationLogDIDMismatch = errors.New("CosignatureOf.LogDID does not match expected")

	// ErrAttestationSequenceMismatch fires when the candidate's
	// CosignatureOf.Sequence is different from expectedPos.Sequence.
	// Means the entry is an attestation, but of a different
	// position.
	ErrAttestationSequenceMismatch = errors.New("CosignatureOf.Sequence does not match expected")
)

// CheckAttestationBinding is the error-returning sibling of
// attestation.IsAttestation. Returns nil iff entry IS a
// well-formed attestation of expectedPos. Each failure mode is a
// typed sentinel reachable via errors.Is(err, Err*) so handlers
// can map to specific HTTP statuses.
//
// This function does NOT verify the candidate's signature — that
// is the SDK's SignatureVerifier responsibility, exercised via
// attestation.VerifyEntrySignatures (see
// verification/attestation_signature_report.go). This function
// answers ONLY: "does this entry's binding point where the
// caller said it should?".
func CheckAttestationBinding(entry *envelope.Entry, expectedPos types.LogPosition) error {
	if entry == nil {
		return fmt.Errorf("%w: %w", ErrAttestationBinding, ErrAttestationNilEntry)
	}
	if entry.Header.CosignatureOf == nil {
		return fmt.Errorf("%w: %w", ErrAttestationBinding, ErrAttestationMissingCosignatureOf)
	}
	got := *entry.Header.CosignatureOf
	if got.LogDID != expectedPos.LogDID {
		return fmt.Errorf("%w: %w (got %q want %q)",
			ErrAttestationBinding, ErrAttestationLogDIDMismatch, got.LogDID, expectedPos.LogDID)
	}
	if got.Sequence != expectedPos.Sequence {
		return fmt.Errorf("%w: %w (got %d want %d)",
			ErrAttestationBinding, ErrAttestationSequenceMismatch, got.Sequence, expectedPos.Sequence)
	}
	// Defense in depth — the SDK predicate MUST agree. A
	// disagreement here means JN's check drifted from the SDK's
	// definition; surface loudly rather than silently masking it.
	if !attestation.IsAttestation(entry, expectedPos) {
		return fmt.Errorf("%w: SDK attestation.IsAttestation returned false despite field-level match — drift?", ErrAttestationBinding)
	}
	return nil
}

// FilterAttestationsOf returns the subset of candidates that
// pass CheckAttestationBinding against expectedPos. Candidates
// that fail (nil, missing CosignatureOf, wrong target) are
// silently dropped — the helper's contract is "give me the
// matching subset", not "tell me what didn't match".
//
// For the granular-rejection use case (telling the user WHY a
// specific entry was filtered out), call CheckAttestationBinding
// directly on each candidate.
//
// The returned slice preserves input order. Returns nil for a nil
// or empty input.
func FilterAttestationsOf(candidates []*envelope.Entry, expectedPos types.LogPosition) []*envelope.Entry {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]*envelope.Entry, 0, len(candidates))
	for _, c := range candidates {
		if err := CheckAttestationBinding(c, expectedPos); err == nil {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// AttestationRef is the JN re-export of attestation.Ref — a
// (primary position, candidate entry) pair the SDK uses as the
// canonical shape for binding-check inputs. Exported as a JN
// alias so call sites don't have to mix import paths.
type AttestationRef = attestation.Ref

// Compile-time pin: a future SDK rename or signature change to
// IsAttestation surfaces at the JN build.
var _ = attestation.IsAttestation
