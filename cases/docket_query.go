/*
FILE PATH: cases/docket_query.go
DESCRIPTION: Read-side: docket number → case root position.
KEY ARCHITECTURAL DECISIONS:
    - SDK correction #2: Uses verifier.EvaluateOrigin for case state instead
      of raw SMT leaf reads. Catches succession and path compression that
      raw OriginTip reads miss.
    - Queries operator entry index for docket number in Domain Payload.
    - Read-only: no SMT mutations, no entry creation.
OVERVIEW: LookupDocket → case root position + status via EvaluateOrigin.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/core/smt, ortholog-sdk/verifier
*/
package cases

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

type DocketQueryResult struct {
	CaseRootPos  types.LogPosition
	DocketNumber string
	CaseType     string
	Status       string
	OriginState  verifier.OriginState
	OriginTip    types.LogPosition
	AuthorityTip types.LogPosition
	IsSealed     bool
	IsRevoked    bool
}

type DocketScanner interface {
	QueryBySignerDID(did string) ([]types.EntryWithMetadata, error)
}

// LookupDocket searches for a case by docket number using EvaluateOrigin
// for state evaluation (SDK correction #2).
func LookupDocket(
	docketNumber string,
	signerDID string,
	scanner DocketScanner,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
) (*DocketQueryResult, error) {
	if docketNumber == "" {
		return nil, fmt.Errorf("cases/docket_query: empty docket number")
	}

	entries, err := scanner.QueryBySignerDID(signerDID)
	if err != nil {
		return nil, fmt.Errorf("cases/docket_query: query: %w", err)
	}

	for _, meta := range entries {
		entry, desErr := envelope.Deserialize(meta.CanonicalBytes)
		if desErr != nil || entry.Header.TargetRoot != nil {
			continue
		}
		if len(entry.DomainPayload) == 0 {
			continue
		}

		var payload struct {
			DocketNumber string `json:"docket_number"`
			CaseType     string `json:"case_type"`
			Status       string `json:"status"`
		}
		if json.Unmarshal(entry.DomainPayload, &payload) != nil {
			continue
		}
		if payload.DocketNumber != docketNumber {
			continue
		}

		result := &DocketQueryResult{
			CaseRootPos:  meta.Position,
			DocketNumber: payload.DocketNumber,
			CaseType:     payload.CaseType,
			Status:       payload.Status,
		}

		// SDK correction #2: Use EvaluateOrigin for entity state.
		// Handles path compression, revocation, succession that raw reads miss.
		leafKey := smt.DeriveKey(meta.Position)
		eval, evalErr := verifier.EvaluateOrigin(leafKey, leafReader, fetcher)
		if evalErr == nil && eval != nil {
			result.OriginState = eval.State
			result.OriginTip = eval.TipPosition
			if eval.State == verifier.OriginRevoked || eval.State == verifier.OriginSucceeded {
				result.IsRevoked = true
			}
		}

		// Authority lane for sealing.
		leaf, leafErr := leafReader.Get(leafKey)
		if leafErr == nil && leaf != nil {
			result.AuthorityTip = leaf.AuthorityTip
			if !leaf.AuthorityTip.Equal(meta.Position) &&
				!leaf.AuthorityTip.Equal(leaf.OriginTip) {
				result.IsSealed = true
			}
		}

		return result, nil
	}

	return nil, fmt.Errorf("cases/docket_query: docket %s not found", docketNumber)
}
