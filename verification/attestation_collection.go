/*
FILE PATH: verification/attestation_collection.go

DESCRIPTION:

	JN adapter for attesta v1.2.0's attestation.VerifyCollection —
	the SDK's K-of-N attestation verifier over a candidate set
	pre-materialised from log.QueryByCosignatureOf.

	# CANONICAL PIPELINE

	Verifying a primary entry against a multi-attester policy
	uses two SDK seams composed at the JN layer:

	    primaryPos        := primaryEntry.Position
	    candidates, err   := api.QueryByCosignatureOf(ctx, primaryPos)
	    if err != nil    { return ... }
	    report, err       := verification.VerifyAttestationCollection(
	                            ctx, primaryPos, candidates,
	                            sigVerifier, k,
	                        )

	The SDK's contract (Ledger Principle 8, Pure CQRS): the SDK
	does NOT query the ledger; the caller materialises candidates.
	JN owns the materialisation step (log.LedgerQueryAPI), the SDK
	owns the cryptographic K-of-N math.

	# SCOPE — DISTINCT FROM verification/cosignature_check.go

	cosignature_check.go enforces the JN v1.4 INTRA-ENTRY signature
	mix: one entry, N inline signatures, role/exchange/threshold.
	This file evaluates SEPARATE attestation entries — each
	candidate is its OWN log entry, each signed by its OWN attester,
	each pointing at the primary via Header.CosignatureOf.

	# WHY A THIN WRAPPER

	The SDK function is direct. This file:

	  - Narrows the input type to *envelope.Entry slice (JN code
	    rarely carries types.EntryWithMetadata; we convert once
	    here at the boundary).

	  - Returns a JN-local AttestationCollectionResult that
	    carries the SDK's CollectionReport AND the threshold-met
	    bool flat, so handlers can branch on a single field.

	  - Provides a typed sentinel set so caller code can
	    distinguish "nothing was verified" from "verifier nil" from
	    "threshold negative" without unwrapping multiple layers.

	  - Single-sources the convention: JN's handlers always pass
	    the verifier's *did.VerifierRegistry as the SignatureVerifier
	    (the SDK's interface is structurally satisfied by the
	    registry's VerifyEntry method via a small adapter).

TRUST ALIGNMENT:

	SDK Principle 5 (Encapsulated Quorum Physics): K is supplied
	at call time. The SDK fails closed if K < 0 (ErrNegativeThreshold).
	JN's handler is responsible for choosing K from the relevant
	domain rule.
	Ledger Principle 8 (Pure CQRS): candidate materialisation and
	verification are decoupled. This wrapper holds the boundary.

KEY DEPENDENCIES:
  - attesta/attestation: VerifyCollection, CollectionReport,
    Rejection, SignatureVerifier, VerifyOption
  - attesta/core/envelope: Entry
  - attesta/types: LogPosition, EntryWithMetadata
*/
package verification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/types"
)

// ErrAttestationCollection wraps every error path the
// JN-side collection verifier surfaces. Underlying SDK sentinels
// (attestation.ErrNilSignatureVerifier, attestation.ErrNegativeThreshold,
// attestation.ErrBindingMismatch, etc.) remain reachable via
// errors.Is.
var ErrAttestationCollection = errors.New("verification/attestation_collection")

// CollectionRequest carries the inputs a JN handler has on hand
// after a log query. The handler's typical flow is:
//
//	candidates, _ := api.QueryByCosignatureOf(ctx, primaryPos)
//	req := verification.CollectionRequest{
//	    Target:        primaryPos,
//	    Candidates:    candidates,        // []types.EntryWithMetadata
//	    SigVerifier:   sigVerifier,       // wraps *did.VerifierRegistry
//	    Threshold:     k,
//	}
//	res, err := verification.VerifyAttestationCollection(ctx, req)
type CollectionRequest struct {
	// Target is the primary entry's LogPosition. The SDK
	// confirms every candidate's Header.CosignatureOf equals
	// this position.
	Target types.LogPosition

	// Candidates is the pre-materialised attestation entry set,
	// typically from log.QueryByCosignatureOf. The SDK does NOT
	// query; the caller owns this step.
	Candidates []types.EntryWithMetadata

	// SigVerifier supplies cryptographic verification of each
	// candidate's signature. Required.
	SigVerifier attestation.SignatureVerifier

	// Threshold is K in K-of-N. Must be >= 0. Zero is admitted
	// as a no-op (forward extensibility); a no-op policy always
	// reports ThresholdMet=true.
	Threshold int

	// Options forwards SDK options (e.g., WithLogger). Optional.
	Options []attestation.VerifyOption
}

// CollectionResult flattens the SDK's CollectionReport plus a
// boolean ThresholdMet so handler code can branch on a single
// field without traversing the report struct. The full
// CollectionReport is carried verbatim for diagnostics.
type CollectionResult struct {
	// Report is the SDK's complete verdict. Carries every
	// rejected candidate's typed err for granular diagnosis.
	Report *attestation.CollectionReport

	// ThresholdMet mirrors Report.ThresholdMet — duplicated for
	// the common "if !res.ThresholdMet" branch.
	ThresholdMet bool

	// ValidCount mirrors Report.ValidCount.
	ValidCount int

	// RejectedCount = len(Report.Rejections). Pre-computed for
	// handler dashboards.
	RejectedCount int
}

// VerifyAttestationCollection is the JN entry point for
// SDK-attestation K-of-N verification. Forwards to
// attestation.VerifyCollection and flattens the result.
//
// Returns ErrAttestationCollection on input-guard failures (nil
// verifier, negative threshold). Underlying SDK errors are
// wrapped but reachable via errors.Is — callers detect e.g.
// attestation.ErrNilSignatureVerifier without dropping
// ErrAttestationCollection.
//
// Per-candidate failures (binding mismatch, signature invalid,
// missing CosignatureOf) populate Result.Report.Rejections — they
// are NOT returned as the top-level error. A batch with one bad
// candidate and K-1 good ones still surfaces the good ones; the
// caller's threshold check (ThresholdMet) is the success gate.
func VerifyAttestationCollection(
	ctx context.Context,
	req CollectionRequest,
) (*CollectionResult, error) {
	if req.SigVerifier == nil {
		return nil, fmt.Errorf("%w: nil SignatureVerifier", ErrAttestationCollection)
	}
	if req.Threshold < 0 {
		return nil, fmt.Errorf("%w: negative threshold %d", ErrAttestationCollection, req.Threshold)
	}
	report, err := attestation.VerifyCollection(
		ctx,
		req.Target,
		req.Candidates,
		req.SigVerifier,
		req.Threshold,
		req.Options...,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAttestationCollection, err)
	}
	if report == nil {
		return nil, fmt.Errorf("%w: nil report from SDK (programming bug)", ErrAttestationCollection)
	}
	return &CollectionResult{
		Report:        report,
		ThresholdMet:  report.ThresholdMet,
		ValidCount:    report.ValidCount,
		RejectedCount: len(report.Rejections),
	}, nil
}

// VerifyAttestationCollectionFromBytes is the convenience
// wrapper for callers that have N (canonicalBytes, position,
// logTime) tuples rather than the pre-built EntryWithMetadata
// slice. Production callers materialising from
// log.QueryByCosignatureOf already get EntryWithMetadata
// directly and should call VerifyAttestationCollection — this
// helper is for tests and migrations where the canonical bytes
// are reconstructed independently.
//
// Returns ErrAttestationCollection on a slice-length mismatch.
func VerifyAttestationCollectionFromBytes(
	ctx context.Context,
	target types.LogPosition,
	canonicalBytes [][]byte,
	positions []types.LogPosition,
	logTimes []time.Time,
	sigVerifier attestation.SignatureVerifier,
	threshold int,
	opts ...attestation.VerifyOption,
) (*CollectionResult, error) {
	if len(canonicalBytes) != len(positions) || len(canonicalBytes) != len(logTimes) {
		return nil, fmt.Errorf("%w: slice length mismatch (bytes=%d positions=%d logTimes=%d)",
			ErrAttestationCollection, len(canonicalBytes), len(positions), len(logTimes))
	}
	withMeta := make([]types.EntryWithMetadata, 0, len(canonicalBytes))
	for i := range canonicalBytes {
		withMeta = append(withMeta, types.EntryWithMetadata{
			CanonicalBytes: canonicalBytes[i],
			Position:       positions[i],
			LogTime:        logTimes[i],
		})
	}
	return VerifyAttestationCollection(ctx, CollectionRequest{
		Target:      target,
		Candidates:  withMeta,
		SigVerifier: sigVerifier,
		Threshold:   threshold,
		Options:     opts,
	})
}

// Compile-time pin — a future SDK rename of VerifyCollection or
// any structural break in CollectionReport surfaces at the JN
// build, not at the runtime call.
var (
	_ = attestation.VerifyCollection
	_ = (*attestation.CollectionReport)(nil)
	_ = (*attestation.Rejection)(nil)
)
