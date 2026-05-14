/*
FILE PATH: verification/evidence_chain.go

DESCRIPTION:

	Two distinct facilities live in this file:

	  (A) ReconstructCustodyChain — JN-domain custody-timeline scanner
	      for evidence artifacts. Scans entries forward via
	      log.ScanFromPosition, filters by artifact_cid, classifies via
	      builder.ClassifyEntry, and emits an ordered timeline of
	      custody events (publish → grant → re-encrypt → expunge).
	      Pure JN business logic; the SDK has no equivalent.
	      Algorithm is O(N) over the scan window; production callers
	      bound startSeq/maxEntries.

	  (B) VerifyEvidenceChainViaSDK — JN seam over the SDK v0.7.0+
	      composite verifier.VerifyEvidenceChain (depth-first walk of
	      EvidencePointers with two-color cycle detection + bounded
	      max-depth). Different mechanic from (A): (A) builds a
	      domain audit timeline; (B) cryptographically walks the
	      evidence-pointer graph rooted at an entry to confirm
	      structural integrity.

	The shared filename ("evidence_chain") is preserved for git-blame
	continuity and because both facilities concern evidence-related
	chains. Future readers: pay attention to which one a call site
	uses.

KEY ARCHITECTURAL DECISIONS:
  - (A) and (B) are independent. A caller may need only one. Tests
    are split per facility.
  - (B) wraps the SDK composite with a JN-friendly result type that
    flattens the SDK's per-hop report into a single bool +
    diagnostic counts so handler code branches on one field.
  - (B) does NOT translate JN-domain inputs (artifact CIDs, custody
    event types) — the SDK composite is domain-agnostic and
    operates on EvidencePointers directly.

OVERVIEW:

	ReconstructCustodyChain  → ordered custody events (JN domain)
	VerifyEvidenceChainViaSDK → wraps verifier.VerifyEvidenceChain
	EvidenceChainResult      → flattened JN result for (B)

KEY DEPENDENCIES:
  - attesta/builder: ClassifyEntry (custody scanner)
  - attesta/verifier: VerifyEvidenceChain, WalkParams,
    EvidenceChainReport (SDK seam)
  - attesta/core/envelope, smt, types
*/
package verification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

type CustodyEvent struct {
	EventType string // "publish", "grant", "reencrypt", "expunge"
	Position  types.LogPosition
	SignerDID string
	Path      builder.PathResult
	Timestamp int64
	Details   map[string]string
}

// CustodyScanner is the read-side interface for scanning a log
// forward from a position. v0.3.0: takes ctx so HTTP-backed
// implementations propagate the caller's deadline.
type CustodyScanner interface {
	ScanFromPosition(ctx context.Context, startPos uint64, count int) ([]types.EntryWithMetadata, error)
}

// ReconstructCustodyChain scans entries related to an artifact CID and
// reconstructs the chain of custody.
//
// SCOPE — JN-domain audit-timeline scanner. NOT a parallel impl of
// the SDK's verifier.VerifyEvidenceChain (depth-first
// EvidencePointers walker). See VerifyEvidenceChainViaSDK below for
// the SDK seam.
func ReconstructCustodyChain(
	ctx context.Context,
	artifactCIDStr string,
	scanner CustodyScanner,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
	logDID string,
	startSeq uint64,
	maxEntries int,
) ([]CustodyEvent, error) {
	if maxEntries <= 0 {
		maxEntries = 1000
	}

	entries, err := scanner.ScanFromPosition(ctx, startSeq, maxEntries)
	if err != nil {
		return nil, fmt.Errorf("verification/evidence_chain: scan: %w", err)
	}

	var chain []CustodyEvent
	for _, meta := range entries {
		entry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil || len(entry.DomainPayload) == 0 {
			continue
		}

		var payload map[string]interface{}
		if json.Unmarshal(entry.DomainPayload, &payload) != nil {
			continue
		}

		// Check if this entry references our artifact.
		cidVal, hasCID := payload["artifact_cid"]
		_, hasGrant := payload["grant_type"]
		if !hasCID && !hasGrant {
			continue
		}

		cidStr, _ := cidVal.(string)
		if hasCID && cidStr != artifactCIDStr {
			continue
		}

		classification, _ := builder.ClassifyEntry(ctx, builder.ClassifyParams{
			Entry:       entry,
			Position:    meta.Position,
			LeafReader:  leafReader,
			Fetcher:     fetcher,
			LocalLogDID: logDID,
		})

		event := CustodyEvent{
			Position:  meta.Position,
			SignerDID: entry.Header.SignerDID,
			Timestamp: entry.Header.EventTime,
			Details:   make(map[string]string),
		}

		if classification != nil {
			event.Path = classification.Path
		}

		if _, ok := payload["grant_type"]; ok {
			event.EventType = "grant"
		} else if _, ok := payload["amendment_type"]; ok {
			event.EventType = "reencrypt"
		} else {
			event.EventType = "publish"
		}

		for k, v := range payload {
			if s, ok := v.(string); ok {
				event.Details[k] = s
			}
		}

		chain = append(chain, event)
	}

	return chain, nil
}

// ─── SDK seam: verifier.VerifyEvidenceChain ────────────────────

// ErrEvidenceChainSDK wraps every error path from the SDK-seam
// wrapper. SDK sentinels (verifier.ErrNilFetcher, etc.) remain
// reachable via errors.Is.
var ErrEvidenceChainSDK = errors.New("verification/evidence_chain: SDK walk")

// EvidenceChainResult flattens the SDK's *EvidenceChainReport into
// a JN-friendly shape: a single boolean + scalar counts so handler
// code can branch without traversing the report struct. The full
// SDK report is carried verbatim for diagnostics.
type EvidenceChainResult struct {
	// Report is the SDK's full verdict — per-hop diagnostics, errors,
	// visited-set state. Use for granular auditing.
	Report *verifier.EvidenceChainReport

	// Clean is true iff the SDK walk completed without HasErrors and
	// produced at least the root hop.
	Clean bool

	// HopCount is len(Report.Hops). Convenience accessor.
	HopCount int

	// FirstError surfaces the first per-hop Err encountered, or nil
	// when Clean. Mirrors the SDK's first-error-wins discipline.
	FirstError error
}

// VerifyEvidenceChainViaSDK is the JN seam over the SDK's
// verifier.VerifyEvidenceChain composite. Walks EvidencePointers
// in depth-first order rooted at rootPos, with two-color cycle
// detection and bounded max-depth. Returns the SDK's structured
// report flattened into EvidenceChainResult.
//
// SCOPE — for callers needing the SDK's cryptographic
// evidence-graph walk. Different mechanic from
// ReconstructCustodyChain above (which scans a log forward filtering
// by artifact_cid for domain audit purposes).
//
// Returns ErrEvidenceChainSDK on input-guard failures (nil fetcher);
// underlying SDK errors are wrapped but reachable via errors.Is.
// Per-hop failures populate Result.Report.Hops[i].Err and surface as
// Result.Clean=false; they are NOT returned as the top-level error.
func VerifyEvidenceChainViaSDK(
	ctx context.Context,
	rootPos types.LogPosition,
	fetcher types.EntryFetcher,
	params verifier.WalkParams,
) (*EvidenceChainResult, error) {
	if fetcher == nil {
		return nil, fmt.Errorf("%w: nil fetcher", ErrEvidenceChainSDK)
	}
	report, err := verifier.VerifyEvidenceChain(ctx, rootPos, fetcher, params)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvidenceChainSDK, err)
	}
	if report == nil {
		return nil, fmt.Errorf("%w: nil report from SDK", ErrEvidenceChainSDK)
	}
	res := &EvidenceChainResult{
		Report:   report,
		HopCount: len(report.Hops),
	}
	for i := range report.Hops {
		if report.Hops[i].Err != nil {
			res.FirstError = report.Hops[i].Err
			break
		}
	}
	res.Clean = res.FirstError == nil && res.HopCount > 0
	return res, nil
}

// Compile-time pin — the SDK symbols this file delegates to.
var (
	_ = verifier.VerifyEvidenceChain
	_ = (*verifier.EvidenceChainReport)(nil)
)
