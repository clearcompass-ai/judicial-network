/*
FILE PATH: verification/evidence_chain.go
DESCRIPTION: Chain of custody reconstruction for evidence artifacts.
KEY ARCHITECTURAL DECISIONS:
  - Uses ScanFromPosition + ClassifyEntry for entry discovery.
  - Uses artifact.PRE_VerifyCFrag for per-cfrag verification (no private key).
  - Reconstructs: publish → grant → re-encrypt → expunge timeline.

OVERVIEW: ReconstructCustodyChain → ordered custody events.
KEY DEPENDENCIES: attesta/builder, attesta/log
*/
package verification

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
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
