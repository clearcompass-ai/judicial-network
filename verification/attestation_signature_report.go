/*
FILE PATH: verification/attestation_signature_report.go

DESCRIPTION:

	JN adapter for attesta v1.2.0's attestation.VerifyEntrySignatures —
	the SDK's GRANULAR per-signature verification primitive. Returns
	one SignatureResult per element of entry.Signatures with Index,
	SignerDID, AlgoID, Err — letting callers diagnose WHICH signer's
	signature failed, not just whether the entry overall verified.

	# WHY GRANULAR REPORTS MATTER FOR JN

	JN's existing cryptographic verification uses
	*did.VerifierRegistry.VerifyEntry, which returns a single error
	for the whole entry. When 4 attorneys cosign a filing and ONE
	signature is bad, .VerifyEntry tells the operator "entry
	rejected" without indicating which signer is at fault. Operators
	then resort to manual signature splitting to diagnose.

	attestation.VerifyEntrySignatures returns a *SignatureReport
	with per-signature Index + SignerDID + Err. JN audit pipelines,
	rejection dashboards, and operator UIs can now show "Signer #3
	(did:web:...) failed: signatures.ErrInvalidSignature" without
	any re-verification step.

	# WHEN TO USE THIS vs THE VERIFIER REGISTRY

	  - Use *did.VerifierRegistry.VerifyEntry when the caller needs
	    a single yes/no answer and any failure is a hard reject
	    (admission gates, fast paths).
	  - Use VerifyEntrySignatureReport (this file) when the caller
	    wants granular per-signer outcomes (audit pipelines, replay
	    diagnostics, operator-facing error displays).

	Both call into the same underlying signature primitives; the
	difference is the shape of the returned diagnosis.

	# SCOPE — DISTINCT FROM verification/cosignature_check.go

	cosignature_check.go applies a ROLE / EXCHANGE / THRESHOLD
	rule across the signatures slice. It assumes cryptographic
	verification has already happened upstream at admission. This
	file is the CRYPTOGRAPHIC verification step — the cleaner
	primitive for offline / replay / audit verification flows.

TRUST ALIGNMENT:

	SDK Principle 3 (Fail-Closed Cryptographic APIs): every
	per-signature failure produces a typed Err reachable via
	errors.Is. The aggregate verdict (ValidCount, FirstError) is
	derived deterministically.
	SDK Principle 5 (Native Multi-Signature Invariant): the SDK
	enforces Signatures[0].SignerDID == Header.SignerDID — a
	primary-DID mismatch surfaces as an envelope-level error
	(ErrPrimaryDIDMismatch), NOT a per-signature one.

KEY DEPENDENCIES:
  - attesta/attestation: VerifyEntrySignatures, SignatureReport,
    SignatureResult, SignatureVerifier, VerifyOption
  - attesta/core/envelope: Entry
*/
package verification

import (
	"context"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
)

// ErrSignatureReport wraps every error path the JN-side signature
// report verifier surfaces. Underlying SDK sentinels
// (attestation.ErrNilEntry, attestation.ErrNilSignatureVerifier,
// attestation.ErrEmptySignatures, attestation.ErrPrimaryDIDMismatch)
// remain reachable via errors.Is.
var ErrSignatureReport = errors.New("verification/attestation_signature_report")

// SignatureReport is JN's alias of attestation.SignatureReport.
// Re-exported so JN call sites don't have to mix import paths
// when consuming the per-signature diagnostic structure.
type SignatureReport = attestation.SignatureReport

// SignatureResult is JN's alias of attestation.SignatureResult.
type SignatureResult = attestation.SignatureResult

// VerifyEntrySignatureReport runs the SDK's per-signature
// verifier and returns the structured report unchanged.
// Envelope-level errors (nil entry, nil verifier, empty
// signatures, primary-DID mismatch) come back as (nil, err) with
// the SDK sentinel wrapped in ErrSignatureReport.
//
// Per-signature failures populate Report.Results[i].Err and
// return err == nil — the caller inspects Report.ValidCount /
// Report.FirstError to decide outcome.
func VerifyEntrySignatureReport(
	ctx context.Context,
	entry *envelope.Entry,
	sigVerifier attestation.SignatureVerifier,
	opts ...attestation.VerifyOption,
) (*SignatureReport, error) {
	if entry == nil {
		return nil, fmt.Errorf("%w: nil entry", ErrSignatureReport)
	}
	if sigVerifier == nil {
		return nil, fmt.Errorf("%w: nil SignatureVerifier", ErrSignatureReport)
	}
	report, err := attestation.VerifyEntrySignatures(ctx, entry, sigVerifier, opts...)
	if err != nil {
		// Wrap, but keep the SDK sentinel reachable via errors.Is.
		return nil, fmt.Errorf("%w: %w", ErrSignatureReport, err)
	}
	return report, nil
}

// AllSignaturesValid reports whether every signature in the
// report verified — a convenience for handler branches that
// want all-or-nothing semantics.
//
// Equivalent to report.ValidCount == report.Total && report.FirstError == nil.
// Returns false on nil report.
func AllSignaturesValid(report *SignatureReport) bool {
	if report == nil {
		return false
	}
	return report.ValidCount == report.Total && report.FirstError == nil
}

// FirstInvalidSigner returns the SignerDID of the first
// signature whose Err is non-nil, or "" when every signature
// verified or the report is nil. Useful for operator-facing
// rejection messages.
func FirstInvalidSigner(report *SignatureReport) string {
	if report == nil {
		return ""
	}
	for _, r := range report.Results {
		if r.Err != nil {
			return r.SignerDID
		}
	}
	return ""
}

// Compile-time pin — a future SDK rename of any of these
// symbols surfaces at the JN build, not at the runtime call.
var (
	_ = attestation.VerifyEntrySignatures
	_ = (*attestation.SignatureReport)(nil)
	_ = (*attestation.SignatureResult)(nil)
)
